package ssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

// ExecResult is a finished (or timed-out) command. Stdout and Stderr are
// capped per ExecOptions.MaxOutputBytes; Truncated reports that either was.
type ExecResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	TimedOut  bool
	Truncated bool
	Duration  time.Duration
}

type FileType string

const (
	FileTypeFile      FileType = "file"
	FileTypeDirectory FileType = "directory"
	FileTypeSymlink   FileType = "symlink"
	FileTypeOther     FileType = "other"
)

type FileEntry struct {
	Name        string   `json:"name"`
	Type        FileType `json:"type"`
	Size        int64    `json:"size"`
	ModifiedAt  string   `json:"modifiedAt"`
	Permissions string   `json:"permissions"`
	// Target is where a symlink points.
	Target string `json:"target,omitempty"`
}

type Ops struct {
	pool *Pool

	// fileLimit bounds one file operation (see withSFTP).
	fileLimit time.Duration

	mu       sync.Mutex
	chrooted map[string]bool // poolKey -> SFTP is chrooted to DocRoot
	indexes  map[string]*fileIndex
	sessions map[string]*sftpSession // poolKey -> shared SFTP session
}

func NewOps(pool *Pool) *Ops {
	return &Ops{pool: pool, fileLimit: sftpLimit, chrooted: map[string]bool{}, indexes: map[string]*fileIndex{}, sessions: map[string]*sftpSession{}}
}

// ExecOptions controls Exec. Cwd is wrapped via ShellEscape. Stdin, when
// set, is fed to the command. MaxOutputBytes caps stdout and stderr each
// (0 = unlimited), keeping the head and the tail.
type ExecOptions struct {
	Cwd            string
	TimeoutMs      int
	Stdin          string
	MaxOutputBytes int
}

// killGrace is how long Exec waits for output to drain after killing a
// command, so the partial output it returns is complete.
const killGrace = 500 * time.Millisecond

// newSession opens a session, redialling once when the pooled connection
// turns out to be dead (a laptop that slept, a dropped network).
func (o *Ops) newSession(host, user string) (*xssh.Session, error) {
	for attempt := 0; ; attempt++ {
		client, err := o.pool.Get(host, user)
		if err != nil {
			return nil, err
		}
		session, err := client.NewSession()
		if err == nil {
			return session, nil
		}
		if attempt == 1 {
			return nil, fmt.Errorf("ssh new session: %w", err)
		}
		o.pool.Drop(host, user)
	}
}

// Exec runs command and returns what it printed. A timeout is not an
// error: the result has TimedOut set and carries the output so far.
// Cancelling ctx returns ctx's error. Either way the command is killed on
// the server (see remoteCommand).
func (o *Ops) Exec(ctx context.Context, host, user, command string, opts ExecOptions) (*ExecResult, error) {
	session, err := o.newSession(host, user)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	full := remoteCommand(command, opts)

	stdout, stderr := newCapture(opts.MaxOutputBytes), newCapture(opts.MaxOutputBytes)
	session.Stdout = stdout
	session.Stderr = stderr
	// stdin stays open until the command is done or unwanted: its end is
	// what tells the remote watchdog to kill (see remoteCommand).
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh stdin: %w", err)
	}
	defer stdin.Close()

	started := time.Now()
	if err := session.Start(full); err != nil {
		return nil, fmt.Errorf("ssh start: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	if opts.Stdin != "" {
		go func() { _, _ = io.WriteString(stdin, opts.Stdin) }()
	}

	var timeout <-chan time.Time
	if opts.TimeoutMs > 0 {
		t := time.NewTimer(time.Duration(opts.TimeoutMs) * time.Millisecond)
		defer t.Stop()
		timeout = t.C
	}
	result := func(exitCode int) *ExecResult {
		return &ExecResult{
			Stdout:    stdout.String(),
			Stderr:    stderr.String(),
			ExitCode:  exitCode,
			Truncated: stdout.Truncated() || stderr.Truncated(),
			Duration:  time.Since(started),
		}
	}
	kill := func() {
		_ = stdin.Close() // the watchdog's cue
		_ = session.Signal(xssh.SIGKILL)
		select {
		case werr := <-done:
			_ = werr // the command was killed: its exit status says nothing
		case <-time.After(killGrace):
		}
		_ = session.Close()
	}

	select {
	case werr := <-done:
		exitCode := 0
		if werr != nil {
			var exitErr *xssh.ExitError
			if errors.As(werr, &exitErr) {
				exitCode = exitErr.ExitStatus()
			} else {
				var missing *xssh.ExitMissingError
				if !errors.As(werr, &missing) {
					return nil, werr
				}
				// No exit status: killed by a signal or the channel dropped.
				// Never report that as success.
				exitCode = -1
				_, _ = stderr.Write([]byte("\n[no exit status: the command was killed or the connection closed]"))
			}
		}
		return result(exitCode), nil
	case <-timeout:
		kill()
		res := result(-1)
		res.TimedOut = true
		return res, nil
	case <-ctx.Done():
		kill()
		return nil, fmt.Errorf("Command cancelled: %w", ctx.Err())
	}
}

// remoteCommand builds the command line sent to the server: the command,
// in its working directory, guarded by a watchdog.
//
// Pressable's sshd ignores the SSH "signal" request and leaves a command
// running after its channel closes, and every session has its own PID
// namespace, so nothing outside the session can stop a command (verified
// 2026-11-14: a timed-out `sleep; touch` still touched; `kill` from a second
// session reached nothing). What does reach the session is the end of its
// standard input. So Exec keeps stdin open for as long as it wants the
// command to live, and the watchdog — a background subshell holding the
// real stdin on fd 3 — kills the shell's whole process group when stdin
// ends while the shell is still running. That covers a timeout, a
// cancelled call and this process dying.
//
// The command's own stdin is a pipe fed with exactly stdinBytes bytes of
// the real stdin, then EOF. The watchdog starts reading only after those
// bytes are taken. If the shell has already exited when stdin ends (the
// normal case), the watchdog does nothing, so it never kills a job the
// command left in the background on purpose. (On Pressable the platform
// ends those itself when the session finishes, even under setsid nohup.)
func remoteCommand(command string, opts ExecOptions) string {
	var b strings.Builder
	b.WriteString("exec 3<&0\n{ ")
	if n := len(opts.Stdin); n > 0 {
		fmt.Fprintf(&b, "head -c %d <&3 2>/dev/null; ", n)
	}
	// No redirection on this group: dash would save the real stderr on a
	// spare descriptor, the watchdog would inherit it, and a server that
	// waits for the output pipes to close would never see the command end.
	b.WriteString("(cat <&3; kill -0 $$ && kill -KILL 0) >/dev/null 2>&1 & } | {\n")
	if opts.Cwd != "" {
		// "|| exit" on its own line, not "&&": with a multi-statement
		// command, "cd X && a; b" would still run b in the wrong place.
		b.WriteString("cd " + ShellEscape(opts.Cwd) + " || exit 1\n")
	}
	b.WriteString(command)
	b.WriteString("\n} 3<&-")
	return b.String()
}

// capture is a concurrency-safe output buffer that keeps at most max bytes:
// the first half and the last half of what was written.
type capture struct {
	mu      sync.Mutex
	max     int
	head    []byte
	tail    []byte
	written int64
}

func newCapture(max int) *capture { return &capture{max: max} }

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	c.written += int64(n)
	if c.max <= 0 {
		c.head = append(c.head, p...)
		return n, nil
	}
	headCap := c.max / 2
	if room := headCap - len(c.head); room > 0 {
		take := min(room, len(p))
		c.head = append(c.head, p[:take]...)
		p = p[take:]
	}
	tailCap := c.max - headCap
	c.tail = append(c.tail, p...)
	if len(c.tail) > 2*tailCap {
		c.tail = append(c.tail[:0], c.tail[len(c.tail)-tailCap:]...)
	}
	return n, nil
}

func (c *capture) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max > 0 && c.written > int64(c.max)
}

func (c *capture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max <= 0 || c.written <= int64(c.max) {
		return string(c.head) + string(c.tail)
	}
	tail := c.tail
	if tailCap := c.max - c.max/2; len(tail) > tailCap {
		tail = tail[len(tail)-tailCap:]
	}
	// Don't split a multi-byte character at either cut.
	head := trimPartialRune(c.head)
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	omitted := c.written - int64(len(head)) - int64(len(tail))
	return fmt.Sprintf("%s\n[… %d of %d bytes omitted …]\n%s", head, omitted, c.written, tail)
}

// trimPartialRune drops an incomplete UTF-8 sequence from the end of b.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && len(b) > 0; i++ {
		if r, size := utf8.DecodeLastRune(b); r != utf8.RuneError || size != 1 {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}

// sftpSession is an SFTP session and the SSH connection it runs on.
type sftpSession struct {
	conn *xssh.Client
	c    *sftp.Client
}

// sftp returns the SFTP session for a login and reports whether it is
// chrooted to the docroot. Detection (does DocRoot exist as a path?) runs
// once per login. A dead pooled connection is redialled once.
//
// The session is shared and kept for as long as its connection lives:
// starting one costs about a second on Pressable (measured 2026-11-14: a
// small read took 1.7 s with a session per call), and pkg/sftp's client is
// safe for concurrent use. Callers must not close it.
func (o *Ops) sftp(host, user string) (*sftp.Client, bool, error) {
	key := poolKey(host, user)
	var c *sftp.Client
	for attempt := 0; ; attempt++ {
		conn, err := o.pool.Get(host, user)
		if err != nil {
			return nil, false, err
		}
		o.mu.Lock()
		if s := o.sessions[key]; s != nil && s.conn == conn {
			c = s.c
		}
		o.mu.Unlock()
		if c != nil {
			break
		}
		fresh, err := sftp.NewClient(conn)
		if err != nil {
			if attempt == 1 {
				return nil, false, fmt.Errorf("sftp session: %w", err)
			}
			o.pool.Drop(host, user)
			continue
		}
		o.mu.Lock()
		if s := o.sessions[key]; s != nil && s.conn == conn {
			c = s.c // someone else got there first: use theirs
		} else {
			c = fresh
			o.sessions[key] = &sftpSession{conn: conn, c: fresh}
		}
		o.mu.Unlock()
		if c != fresh {
			_ = fresh.Close()
			break
		}
		go func() {
			_ = fresh.Wait() // until the session or its connection ends
			o.forget(key, fresh)
		}()
		break
	}
	o.mu.Lock()
	chrooted, known := o.chrooted[key]
	o.mu.Unlock()
	if !known {
		_, statErr := c.Stat(DocRoot)
		switch {
		case statErr == nil:
			chrooted = false
		case errors.Is(statErr, fs.ErrNotExist) || os.IsNotExist(statErr):
			chrooted = true
		default:
			// Transient failure: don't cache a guess.
			return nil, false, fmt.Errorf("sftp: detect web root: %w", statErr)
		}
		o.mu.Lock()
		o.chrooted[key] = chrooted
		o.mu.Unlock()
	}
	return c, chrooted, nil
}

// forget drops the shared session for key if it is still c.
func (o *Ops) forget(key string, c *sftp.Client) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if s := o.sessions[key]; s != nil && s.c == c {
		delete(o.sessions, key)
	}
}

// open is the shared start of every file operation: the SFTP session plus
// the path to send and the shell spelling to show.
func (o *Ops) open(host, user, path string) (c *sftp.Client, remote, display string, err error) {
	c, chrooted, err := o.sftp(host, user)
	if err != nil {
		return nil, "", "", err
	}
	remote, err = SFTPPath(path, chrooted)
	if err != nil {
		return nil, "", "", err
	}
	return c, remote, DisplayPath(remote, chrooted), nil
}

// sftpLimit bounds one file operation. Transfers of large files are slow
// but not this slow; past it the connection is taken to have stalled.
const sftpLimit = 10 * time.Minute

// withSFTP runs fn with an SFTP session for path, and gives up when ctx is
// cancelled or the file limit passes: pkg/sftp has no deadlines of its own, so a
// stalled connection would otherwise hang the call for good. Giving up
// closes the shared session and drops the pooled connection, which fails
// whatever request fn (or another call on that session) is blocked in; the
// next call redials.
func (o *Ops) withSFTP(ctx context.Context, host, user, path string, fn func(c *sftp.Client, remote, display string) error) error {
	var mu sync.Mutex
	var client *sftp.Client
	abandoned := false
	done := make(chan error, 1)
	go func() {
		c, remote, display, err := o.open(host, user, path)
		if err != nil {
			done <- err
			return
		}
		mu.Lock()
		if abandoned {
			mu.Unlock()
			done <- context.Canceled
			return
		}
		client = c
		mu.Unlock()
		err = fn(c, remote, display)
		if err != nil {
			err = insideRootHint(c, remote, err)
		}
		done <- err
	}()
	limit := time.NewTimer(o.fileLimit)
	defer limit.Stop()
	var cause error
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		cause = fmt.Errorf("File operation cancelled: %w", ctx.Err())
	case <-limit.C:
		cause = fmt.Errorf("File operation gave up after %s: the connection to %s stalled. Retry it; a file too large to move in that time is better compressed or split with pressable_ssh_exec first", o.fileLimit, host)
	}
	mu.Lock()
	abandoned = true
	c := client
	mu.Unlock()
	if c != nil {
		_ = c.Close()
		o.forget(poolKey(host, user), c)
	}
	o.pool.Drop(host, user)
	select {
	case err := <-done:
		_ = err // abandoned: whatever it returned, the caller gets cause
	case <-time.After(killGrace):
	}
	return cause
}

// insideRootHint completes a "does not exist" error for a path outside the
// web root when the same path exists inside it. A full path means what it
// means in a shell, so /lib/x is the server's /lib even when the site has
// a lib folder; the model most likely meant the site's.
func insideRootHint(c *sftp.Client, remote string, err error) error {
	if remote == DocRoot || strings.HasPrefix(remote, DocRoot+"/") || !strings.HasPrefix(remote, "/") {
		return err
	}
	if !strings.Contains(err.Error(), "does not exist") && !strings.Contains(err.Error(), "no such file") {
		return err
	}
	inside := DocRoot + remote
	if _, statErr := c.Stat(inside); statErr != nil {
		return err
	}
	return fmt.Errorf("%s. %s exists, though: a path starting with /%s is the server's own, not the site's folder of that name. Use %s", err.Error(), inside, strings.SplitN(strings.TrimPrefix(remote, "/"), "/", 2)[0], inside)
}

// ReadOptions selects the part of a text file to return: lines from Offset
// (1-based; 0 means 1), at most Limit lines (0 = no line limit) and at most
// MaxBytes bytes (0 = unlimited).
type ReadOptions struct {
	Offset   int
	Limit    int
	MaxBytes int
}

// FileSlice is part (or all) of a text file.
type FileSlice struct {
	Path    string
	Content string
	Size    int64 // of the whole file, in bytes
	// Offset is the first line asked for (1-based).
	Offset int
	// FirstLine and LastLine are the lines Content covers (0 when empty).
	FirstLine, LastLine int
	// TotalLines is the file's line count, or 0 when the file was too large
	// to count past the returned slice.
	TotalLines int
	// More reports that lines follow LastLine.
	More bool
	// LineCut reports that LastLine alone exceeded MaxBytes and was cut.
	LineCut bool
	// Encoding names the file's encoding when it isn't UTF-8 (Content is
	// always UTF-8): one of the Encoding* constants.
	Encoding string
}

// Whole reports that Content is the entire file.
func (s *FileSlice) Whole() bool { return s.Offset <= 1 && !s.More && !s.LineCut }

// BinaryError is a file that isn't text.
type BinaryError struct {
	Path string
	Size int64
}

func (e *BinaryError) Error() string {
	return fmt.Sprintf("%s is a binary file (%d bytes), not text. Download it with pressable_sftp_read and local_path instead", e.Path, e.Size)
}

// countLinesUpTo is the largest file whose lines are counted to the end
// when only a slice of it is returned.
const countLinesUpTo = 8 << 20

// lineMark is where a line starts in a file.
type lineMark struct {
	line int
	off  int64
}

// markEvery is how often a read records a lineMark.
const markEvery = 200

// maxIndexes bounds how many files' line indexes Ops keeps.
const maxIndexes = 32

// fileIndex remembers line positions in one version of a file, so reading
// its next page seeks to the page instead of downloading everything before
// it again, and already knows the line count.
type fileIndex struct {
	size  int64
	mtime time.Time

	mu    sync.Mutex
	total int        // line count; 0 until a read reached the end
	marks []lineMark // ascending
}

// nearest returns the last recorded line start at or before line.
func (x *fileIndex) nearest(line int) lineMark {
	x.mu.Lock()
	defer x.mu.Unlock()
	i := sort.Search(len(x.marks), func(i int) bool { return x.marks[i].line > line })
	if i == 0 {
		return lineMark{line: 1}
	}
	return x.marks[i-1]
}

func (x *fileIndex) add(line int, off int64) {
	x.mu.Lock()
	defer x.mu.Unlock()
	i := sort.Search(len(x.marks), func(i int) bool { return x.marks[i].line >= line })
	if i < len(x.marks) && x.marks[i].line == line {
		return
	}
	x.marks = append(x.marks, lineMark{})
	copy(x.marks[i+1:], x.marks[i:])
	x.marks[i] = lineMark{line: line, off: off}
}

func (x *fileIndex) lines() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.total
}

func (x *fileIndex) setLines(n int) {
	x.mu.Lock()
	x.total = n
	x.mu.Unlock()
}

// index returns the line index for a file as it is now (size and
// modification time); a changed file starts a fresh one.
func (o *Ops) index(key string, size int64, mtime time.Time) *fileIndex {
	o.mu.Lock()
	defer o.mu.Unlock()
	if x, ok := o.indexes[key]; ok && x.size == size && x.mtime.Equal(mtime) {
		return x
	}
	if len(o.indexes) >= maxIndexes {
		for k := range o.indexes {
			delete(o.indexes, k)
			break
		}
	}
	x := &fileIndex{size: size, mtime: mtime}
	o.indexes[key] = x
	return x
}

// ReadFile reads a text file, or a range of its lines. path accepts shell
// or SFTP spellings (see SFTPPath).
func (o *Ops) ReadFile(ctx context.Context, host, user, path string, opts ReadOptions) (*FileSlice, error) {
	var out *FileSlice
	err := o.withSFTP(ctx, host, user, path, func(c *sftp.Client, remote, display string) (err error) {
		out, err = readRemote(c, remote, display, opts, func(size int64, mtime time.Time) *fileIndex {
			return o.index(poolKey(host, user)+":"+remote, size, mtime)
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readRemote reads a range of a file's lines. indexFor, when given, supplies
// the file's line index, which lets a later page start where it should.
func readRemote(c *sftp.Client, remote, display string, opts ReadOptions, indexFor func(size int64, mtime time.Time) *fileIndex) (*FileSlice, error) {
	f, err := c.Open(remote)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s: %s", display, err.Error())
	}
	defer f.Close()
	fail := func(err error) (*FileSlice, error) {
		var bin *BinaryError
		if errors.As(err, &bin) {
			bin.Path = display
			return nil, bin
		}
		return nil, fmt.Errorf("Failed to read %s: %s", display, err.Error())
	}
	var size int64
	var mtime time.Time
	if st, err := f.Stat(); err == nil {
		if st.IsDir() {
			return nil, fmt.Errorf("Failed to read %s: it is a directory. List it with pressable_sftp_list", display)
		}
		size, mtime = st.Size(), st.ModTime()
	}
	sc := scan{countAll: size <= countLinesUpTo}

	var idx *fileIndex
	if indexFor != nil {
		idx = indexFor(size, mtime)
		start := idx.nearest(max(opts.Offset, 1))
		sc.startLine, sc.startOff, sc.knownTotal, sc.mark = start.line, start.off, idx.lines(), idx.add
	}
	var src io.Reader = f
	if sc.startOff > 0 {
		if _, err := f.Seek(sc.startOff, io.SeekStart); err != nil {
			return fail(err)
		}
	} else {
		// UTF-16 announces itself with a byte-order mark. It is decoded as
		// a stream, so it gets no byte positions and is never indexed.
		head := bufio.NewReaderSize(f, 64<<10)
		src = head
		if bom, _ := head.Peek(2); utf16Order(bom) != nil {
			order := utf16Order(bom)
			_, _ = head.Discard(2)
			sc.mark = nil
			slice, err := readSlice(newUTF16Reader(head, order), size, opts, sc)
			if err != nil {
				return fail(err)
			}
			slice.Path, slice.Encoding = display, utf16Name(order)
			return slice, nil
		}
	}
	slice, err := readSlice(src, size, opts, sc)
	if err != nil {
		return fail(err)
	}
	if idx != nil && slice.TotalLines > 0 {
		idx.setLines(slice.TotalLines)
	}
	slice.Path = display
	return slice, nil
}

// scan tells readSlice where its reader stands in the file and what is
// already known about it.
type scan struct {
	// startLine is the line the reader is positioned at (0 means 1) and
	// startOff its byte offset.
	startLine int
	startOff  int64
	// knownTotal is the file's line count when a previous read learned it.
	knownTotal int
	// countAll asks to read on to the end to learn the line count.
	countAll bool
	// mark, when set, is told where lines start.
	mark func(line int, off int64)
}

// readSlice streams r and keeps the lines opts selects. Whole lines are
// kept where they fit; a single line longer than MaxBytes is cut. Lines
// that aren't UTF-8 are shown decoded (see displayText).
func readSlice(r io.Reader, size int64, opts ReadOptions, sc scan) (*FileSlice, error) {
	offset := max(opts.Offset, 1)
	// A fragment that fills the buffer is by construction over budget, so
	// only complete lines are ever appended.
	br := bufio.NewReaderSize(r, max(64<<10, opts.MaxBytes+1))
	if peek, _ := br.Peek(8000); bytes.IndexByte(peek, 0) >= 0 {
		return nil, &BinaryError{Size: size}
	}
	out := &FileSlice{Size: size, Offset: offset}
	var b strings.Builder
	keep := func(raw []byte) {
		text, enc := displayText(raw)
		if enc != "" {
			out.Encoding = enc
		}
		b.WriteString(text)
	}
	mark := func(line int, off int64) {
		if sc.mark != nil {
			sc.mark(line, off)
		}
	}
	line, pos := max(sc.startLine, 1), sc.startOff
	kept := 0 // raw bytes kept, which is what MaxBytes limits
	full, continued, appending, eof := false, false, false, false
	for !eof {
		frag, err := br.ReadSlice('\n')
		switch {
		case err == io.EOF:
			eof = true
		case err != nil && !errors.Is(err, bufio.ErrBufferFull):
			return nil, err
		}
		if len(frag) == 0 {
			break
		}
		switch {
		case continued:
			// The rest of a line longer than the buffer: it belongs with
			// its start, which was kept only when nothing limits the size.
			if appending {
				keep(frag)
			}
		case line >= offset:
			appending = false
			switch {
			case full:
				out.More = true
			case opts.Limit > 0 && line >= offset+opts.Limit:
				full, out.More = true, true
				mark(line, pos) // where the next page starts
			case opts.MaxBytes > 0 && kept+len(frag) > opts.MaxBytes:
				if kept == 0 {
					cut := frag[:opts.MaxBytes]
					if trimmed := trimPartialRune(cut); utf8.Valid(trimmed) {
						cut = trimmed
					}
					keep(cut)
					out.FirstLine, out.LastLine, out.LineCut = line, line, true
				} else {
					mark(line, pos)
				}
				full, out.More = true, true
			default:
				keep(frag)
				kept += len(frag)
				appending = true
				if out.FirstLine == 0 {
					out.FirstLine = line
				}
				out.LastLine = line
			}
		}
		pos += int64(len(frag))
		if continued = frag[len(frag)-1] != '\n'; !continued {
			line++
			if (line-1)%markEvery == 0 {
				mark(line, pos)
			}
		}
		// Enough is kept: stop unless the rest is worth reading for the
		// line count, which a previous read may already have.
		if full && (sc.knownTotal > 0 || !sc.countAll) {
			break
		}
	}
	switch {
	case eof && continued:
		out.TotalLines = line
	case eof:
		out.TotalLines = line - 1
	default:
		out.TotalLines = sc.knownTotal
	}
	out.Content = b.String()
	return out, nil
}

// Download copies a remote file to w, byte for byte, and returns its shell
// path and size.
func (o *Ops) Download(ctx context.Context, host, user, path string, w io.Writer) (string, int64, error) {
	var shown string
	var n int64
	err := o.withSFTP(ctx, host, user, path, func(c *sftp.Client, remote, display string) error {
		f, err := c.Open(remote)
		if err != nil {
			return fmt.Errorf("Failed to read %s: %s", display, err.Error())
		}
		defer f.Close()
		copied, err := io.Copy(w, f)
		if err != nil {
			return fmt.Errorf("Failed to read %s: %s", display, err.Error())
		}
		shown, n = display, copied
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return shown, n, nil
}

// WriteFile overwrites (or creates) a file with what src yields and returns
// its shell path and size.
func (o *Ops) WriteFile(ctx context.Context, host, user, path string, src io.Reader, createDirs bool) (string, int64, error) {
	var shown string
	var n int64
	err := o.withSFTP(ctx, host, user, path, func(c *sftp.Client, remote, display string) error {
		written, err := writeRemote(c, remote, display, src, createDirs)
		shown, n = display, written
		return err
	})
	if err != nil {
		return "", 0, err
	}
	return shown, n, nil
}

// maxLinkDepth bounds how many symlinks a write follows.
const maxLinkDepth = 8

// resolveLink follows remote while it is a symlink and returns the file it
// ends at (which need not exist). A write must go to that file: renaming a
// temp file over the path itself would replace the link with a regular
// file — on Pressable, wp-content/object-cache.php and advanced-cache.php
// are links into the platform's own drop-ins.
func resolveLink(c *sftp.Client, remote string) (string, error) {
	for range maxLinkDepth {
		st, err := c.Lstat(remote)
		if err != nil || st.Mode()&os.ModeSymlink == 0 {
			return remote, nil
		}
		target, err := c.ReadLink(remote)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(target, "/") {
			target = pathpkg.Dir(remote) + "/" + target
		}
		remote = pathpkg.Clean(target)
	}
	return "", errors.New("too many levels of symbolic links")
}

// writeRemote writes to a sibling temp file, then renames over the target,
// so a dropped connection never leaves a half-written file (think
// wp-config.php). The original's permissions are carried over, and a
// symlink is written through, not replaced.
func writeRemote(c *sftp.Client, remote, display string, src io.Reader, createDirs bool) (int64, error) {
	return writeRemoteIf(c, remote, display, src, createDirs, nil)
}

// writeRemoteIf is writeRemote with a last check: proceed, when given,
// runs after the new content is uploaded and right before it replaces the
// target, and its error abandons the write.
func writeRemoteIf(c *sftp.Client, remote, display string, src io.Reader, createDirs bool, proceed func() error) (int64, error) {
	if createDirs {
		if i := strings.LastIndex(remote, "/"); i > 0 {
			if err := c.MkdirAll(remote[:i]); err != nil {
				return 0, fmt.Errorf("Failed to create directories for %s: %s", display, err.Error())
			}
		}
	}
	target, err := resolveLink(c, remote)
	if err != nil {
		return 0, fmt.Errorf("Failed to write %s: %s", display, err.Error())
	}
	if target != remote {
		display += " (a symlink to " + target + ")"
	}
	fail := func(err error) (int64, error) {
		msg := err.Error()
		if !createDirs && target == remote && (errors.Is(err, fs.ErrNotExist) || os.IsNotExist(err)) {
			msg += " (the folder may not exist: pass create_dirs to create it)"
		}
		return 0, fmt.Errorf("Failed to write %s: %s", display, msg)
	}
	mode := os.FileMode(0o644)
	if st, err := c.Stat(target); err == nil {
		if st.IsDir() {
			return 0, fmt.Errorf("Failed to write %s: it is a directory", display)
		}
		mode = st.Mode().Perm()
	}
	// The clock alone is not unique: Windows ticks coarsely enough for two
	// writes to get the same name.
	tmp := target + ".presswrench-" + strconv.FormatInt(time.Now().UnixNano(), 36) + strconv.FormatUint(tmpSeq.Add(1), 36) + ".tmp"
	f, err := c.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fail(err)
	}
	n, err := io.Copy(f, src)
	if err != nil {
		_ = f.Close()
		_ = c.Remove(tmp)
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = c.Remove(tmp)
		return fail(err)
	}
	_ = c.Chmod(tmp, mode)
	if proceed != nil {
		if err := proceed(); err != nil {
			_ = c.Remove(tmp)
			return 0, err
		}
	}
	if err := replaceFile(c, tmp, target); err != nil {
		_ = c.Remove(tmp)
		return fail(err)
	}
	return n, nil
}

// tmpSeq tells apart temp files made in the same clock tick.
var tmpSeq atomic.Uint64

// mover is the part of *sftp.Client replaceFile uses.
type mover interface {
	PosixRename(oldname, newname string) error
	Rename(oldname, newname string) error
	Remove(path string) error
	Lstat(path string) (os.FileInfo, error)
}

// replaceFile moves tmp over target. The atomic way is posix-rename; a
// server without that extension only has a rename that refuses to
// overwrite, so the original is first moved aside and is put back if the
// swap fails. It is never deleted before the new file is in place.
func replaceFile(c mover, tmp, target string) error {
	posixErr := c.PosixRename(tmp, target)
	if posixErr == nil {
		return nil
	}
	if _, err := c.Lstat(target); err != nil {
		return c.Rename(tmp, target) // nothing to overwrite
	}
	aside := strings.TrimSuffix(tmp, ".tmp") + ".orig"
	if err := c.Rename(target, aside); err != nil {
		return posixErr // the original is untouched
	}
	if err := c.Rename(tmp, target); err != nil {
		if back := c.Rename(aside, target); back != nil {
			return fmt.Errorf("%s. The original could not be put back and is saved as %s", err.Error(), aside)
		}
		return err
	}
	_ = c.Remove(aside)
	return nil
}

// EditResult describes a finished EditFile.
type EditResult struct {
	Path         string
	Replacements int
	Lines        []int // line of each replacement, in the original file
	Size         int   // of the file after the edit, in bytes
}

// maxEditSize is the largest file EditFile will load.
const maxEditSize = 10 << 20

// EditFile replaces oldText with newText in a text file: exactly one
// occurrence, or every occurrence with all. The file is read, changed in
// memory and written back atomically.
func (o *Ops) EditFile(ctx context.Context, host, user, path, oldText, newText string, all bool) (*EditResult, error) {
	var out *EditResult
	err := o.withSFTP(ctx, host, user, path, func(c *sftp.Client, remote, display string) (err error) {
		out, err = editRemote(c, remote, display, oldText, newText, all)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// unchangedSince returns a check that fails once remote no longer has the
// size and modification time it had in before. An edit is computed from
// what was read a moment earlier: if someone (a deploy, a plugin update,
// another agent) changed the file since, writing it back would silently
// undo their change.
func unchangedSince(c *sftp.Client, remote, display string, before os.FileInfo) func() error {
	return func() error {
		after, err := c.Stat(remote)
		if before == nil || err != nil {
			return nil // can't tell: don't block the edit
		}
		if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return fmt.Errorf("Failed to edit %s: the file changed on the server while it was being edited, so nothing was written. Read it again with pressable_sftp_read and redo the edit", display)
		}
		return nil
	}
}

func editRemote(c *sftp.Client, remote, display, oldText, newText string, all bool) (*EditResult, error) {
	f, err := c.Open(remote)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s: %s", display, err.Error())
	}
	before, _ := f.Stat()
	unchanged := unchangedSince(c, remote, display, before)
	var buf bytes.Buffer
	_, err = buf.ReadFrom(io.LimitReader(f, maxEditSize+1))
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s: %s", display, err.Error())
	}
	if buf.Len() > maxEditSize {
		return nil, fmt.Errorf("%s is larger than %d MB, too large to edit in place. Edit it with pressable_ssh_exec (sed, or a script)", display, maxEditSize>>20)
	}
	if utf16Order(buf.Bytes()) == nil && bytes.IndexByte(buf.Bytes()[:min(buf.Len(), 8000)], 0) >= 0 {
		return nil, &BinaryError{Path: display, Size: int64(buf.Len())}
	}
	updated, lines, err := editEncoded(buf.String(), oldText, newText, all)
	if err != nil {
		return nil, fmt.Errorf("Failed to edit %s: %s", display, err.Error())
	}
	if _, err := writeRemoteIf(c, remote, display, strings.NewReader(updated), false, unchanged); err != nil {
		return nil, err
	}
	return &EditResult{Path: display, Replacements: len(lines), Lines: lines, Size: len(updated)}, nil
}

// errNoMatch is applyEdit finding nothing to replace.
var errNoMatch = errors.New("old_string was not found. It must match the file exactly, including whitespace and indentation: read those lines again with pressable_sftp_read")

// editEncoded is applyEdit for a file in any encoding reads can show.
// oldText and newText are UTF-8, as the model saw and wrote them; they are
// encoded the way the file is, and the file's other bytes are left alone.
func editEncoded(content, oldText, newText string, all bool) (string, []int, error) {
	if order := utf16Order([]byte(content)); order != nil {
		enc := func(s string) string { return encodeUTF16(s, order) }
		if !strings.Contains(oldText, "\r") && strings.Contains(content, enc("\r\n")) {
			crlf := strings.NewReplacer("\n", "\r\n")
			oldText, newText = crlf.Replace(oldText), crlf.Replace(strings.ReplaceAll(newText, "\r\n", "\n"))
		}
		return replaceIn(content, enc(oldText), enc(newText), all, enc("\n"), 2)
	}
	updated, lines, err := applyEdit(content, oldText, newText, all)
	if !errors.Is(err, errNoMatch) || utf8.ValidString(content) {
		return updated, lines, err
	}
	// Not found as UTF-8 in a file that isn't all UTF-8: the lines in
	// question were shown decoded from Windows-1252.
	oldEncoded, ok := encode1252(oldText)
	if !ok || oldEncoded == oldText {
		return "", nil, err
	}
	newEncoded, ok := encode1252(newText)
	if !ok {
		return "", nil, errors.New("new_string has characters that this file's encoding (Windows-1252) can't hold. Use only characters that encoding has, or replace the whole file as UTF-8 with pressable_sftp_write")
	}
	return applyEdit(content, oldEncoded, newEncoded, all)
}

// applyEdit replaces oldText with newText in content and returns the line
// of each replacement. Without all, oldText must occur exactly once. A
// file with CRLF line endings matches an oldText written with LF.
func applyEdit(content, oldText, newText string, all bool) (string, []int, error) {
	if !strings.Contains(content, oldText) && strings.Contains(content, "\r\n") && !strings.Contains(oldText, "\r") {
		crlf := strings.NewReplacer("\n", "\r\n")
		oldText, newText = crlf.Replace(oldText), crlf.Replace(strings.ReplaceAll(newText, "\r\n", "\n"))
	}
	return replaceIn(content, oldText, newText, all, "\n", 1)
}

// replaceIn does the replacing for applyEdit on raw bytes: newline is how
// the content's encoding writes a line break (to number lines) and unit is
// its code-unit size, on whose boundaries a match must start.
func replaceIn(content, oldText, newText string, all bool, newline string, unit int) (string, []int, error) {
	if oldText == "" {
		return "", nil, errors.New("old_string is empty. To create or replace a whole file use pressable_sftp_write")
	}
	if oldText == newText {
		return "", nil, errors.New("old_string and new_string are the same")
	}
	var at []int // offsets of the matches
	for from := 0; ; {
		i := strings.Index(content[from:], oldText)
		if i < 0 {
			break
		}
		if (from+i)%unit != 0 {
			from += i + 1 // straddles two characters: not a real match
			continue
		}
		at = append(at, from+i)
		from += i + len(oldText)
	}
	switch {
	case len(at) == 0:
		return "", nil, errNoMatch
	case len(at) > 1 && !all:
		shown := make([]string, 0, 10)
		for i, off := range at {
			if i == 10 {
				shown = append(shown, "…")
				break
			}
			shown = append(shown, strconv.Itoa(1+strings.Count(content[:off], newline)))
		}
		return "", nil, fmt.Errorf("old_string matches %d places (lines %s). Include more surrounding lines to make it unique, or set replace_all", len(at), strings.Join(shown, ", "))
	}
	var b strings.Builder
	lines := make([]int, 0, len(at))
	prev := 0
	for _, off := range at {
		lines = append(lines, 1+strings.Count(content[:off], newline))
		b.WriteString(content[prev:off])
		b.WriteString(newText)
		prev = off + len(oldText)
	}
	b.WriteString(content[prev:])
	return b.String(), lines, nil
}

// ListDir lists a directory and returns its shell path; an empty path is
// the docroot.
func (o *Ops) ListDir(ctx context.Context, host, user, path string, showHidden bool) (string, []FileEntry, error) {
	var shown string
	var out []FileEntry
	err := o.withSFTP(ctx, host, user, path, func(c *sftp.Client, remote, display string) (err error) {
		shown = display
		out, err = listRemote(c, remote, display, showHidden)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return shown, out, nil
}

func listRemote(c *sftp.Client, remote, display string, showHidden bool) ([]FileEntry, error) {
	infos, err := c.ReadDir(remote)
	if err != nil {
		return nil, fmt.Errorf("Failed to list %s: %s", display, err.Error())
	}
	out := make([]FileEntry, 0, len(infos))
	for _, info := range infos {
		name := info.Name()
		if !showHidden && strings.HasPrefix(name, ".") {
			continue
		}
		// pkg/sftp exposes the raw POSIX mode (with type bits) via Sys().
		var rawMode uint32
		if st, ok := info.Sys().(*sftp.FileStat); ok {
			rawMode = st.Mode
		}
		e := FileEntry{
			Name:        name,
			Type:        classifyMode(rawMode),
			Size:        info.Size(),
			ModifiedAt:  info.ModTime().UTC().Format("2006-01-02T15:04:05.000Z"),
			Permissions: fmt.Sprintf("%03o", rawMode&0o777),
		}
		if e.Type == FileTypeSymlink {
			e.Target, _ = c.ReadLink(strings.TrimSuffix(remote, "/") + "/" + name)
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, bj := out[i], out[j]
		if ai.Type == FileTypeDirectory && bj.Type != FileTypeDirectory {
			return true
		}
		if ai.Type != FileTypeDirectory && bj.Type == FileTypeDirectory {
			return false
		}
		return ai.Name < bj.Name
	})
	return out, nil
}

// classifyMode decodes the S_IFMT bits of a POSIX file mode.
func classifyMode(mode uint32) FileType {
	switch mode & 0o170000 {
	case 0o040000:
		return FileTypeDirectory
	case 0o100000:
		return FileTypeFile
	case 0o120000:
		return FileTypeSymlink
	default:
		return FileTypeOther
	}
}
