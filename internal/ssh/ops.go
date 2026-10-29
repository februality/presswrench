package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
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
}

type Ops struct {
	pool *Pool

	mu       sync.Mutex
	chrooted map[string]bool // poolKey -> SFTP is chrooted to DocRoot
}

func NewOps(pool *Pool) *Ops { return &Ops{pool: pool, chrooted: map[string]bool{}} }

// ExecOptions controls Exec. Cwd is wrapped via ShellEscape.
type ExecOptions struct {
	Cwd       string
	TimeoutMs int
}

func (o *Ops) Exec(host, user, command string, opts ExecOptions) (*ExecResult, error) {
	client, err := o.pool.Get(host, user)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh new session: %w", err)
	}
	defer session.Close()

	full := command
	if opts.Cwd != "" {
		// "|| exit" on its own line, not "&&": with a multi-statement
		// command, "cd X && a; b" would still run b in the wrong place.
		full = "cd " + ShellEscape(opts.Cwd) + " || exit 1\n" + command
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Start(full); err != nil {
		return nil, fmt.Errorf("ssh start: %w", err)
	}

	type waitRes struct{ err error }
	doneCh := make(chan waitRes, 1)
	go func() { doneCh <- waitRes{err: session.Wait()} }()

	var ctx context.Context
	var cancel context.CancelFunc
	if opts.TimeoutMs > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(opts.TimeoutMs)*time.Millisecond)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	select {
	case res := <-doneCh:
		exitCode := 0
		if res.err != nil {
			var exitErr *xssh.ExitError
			if errors.As(res.err, &exitErr) {
				exitCode = exitErr.ExitStatus()
			} else {
				var missing *xssh.ExitMissingError
				if !errors.As(res.err, &missing) {
					return nil, res.err
				}
				// No exit status: killed by a signal or the channel dropped.
				// Never report that as success.
				exitCode = -1
				stderr.WriteString("\n[no exit status: the command was killed or the connection closed]")
			}
		}
		return &ExecResult{
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			ExitCode: exitCode,
		}, nil
	case <-ctx.Done():
		_ = session.Signal(xssh.SIGKILL)
		return nil, fmt.Errorf("command timed out after %dms: %s", opts.TimeoutMs, command)
	}
}

// sftp opens an SFTP session and reports whether it is chrooted to the
// docroot. Detection (does DocRoot exist as a path?) runs once per login.
func (o *Ops) sftp(host, user string) (*sftp.Client, bool, error) {
	client, err := o.pool.Get(host, user)
	if err != nil {
		return nil, false, err
	}
	c, err := sftp.NewClient(client)
	if err != nil {
		return nil, false, fmt.Errorf("sftp session: %w", err)
	}
	key := poolKey(host, user)
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
			_ = c.Close()
			return nil, false, fmt.Errorf("sftp: detect web root: %w", statErr)
		}
		o.mu.Lock()
		o.chrooted[key] = chrooted
		o.mu.Unlock()
	}
	return c, chrooted, nil
}

// ReadFile reads a file. path accepts shell or SFTP spellings (see SFTPPath).
func (o *Ops) ReadFile(host, user, path string, maxLines int) (string, error) {
	c, chrooted, err := o.sftp(host, user)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	remote := SFTPPath(path, chrooted)
	path = DisplayPath(remote, chrooted)
	f, err := c.Open(remote)
	if err != nil {
		return "", fmt.Errorf("Failed to read %s: %s", path, err.Error())
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		return "", fmt.Errorf("Failed to read %s: %s", path, err.Error())
	}
	content := buf.String()
	if maxLines > 0 {
		lines := strings.Split(content, "\n")
		if len(lines) > maxLines {
			content = strings.Join(lines[:maxLines], "\n") +
				fmt.Sprintf("\n... (truncated, %d more lines)", len(lines)-maxLines)
		}
	}
	return content, nil
}

// WriteFile overwrites (or creates) a file and returns its shell path.
func (o *Ops) WriteFile(host, user, path, content string, createDirs bool) (string, error) {
	c, chrooted, err := o.sftp(host, user)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	remote := SFTPPath(path, chrooted)
	path = DisplayPath(remote, chrooted)
	if createDirs {
		if i := strings.LastIndex(remote, "/"); i > 0 {
			if err := c.MkdirAll(remote[:i]); err != nil {
				return "", fmt.Errorf("Failed to create directories for %s: %s", path, err.Error())
			}
		}
	}
	// Write to a sibling temp file, then rename over the target, so a
	// dropped connection never leaves a half-written file (think
	// wp-config.php). The original's permissions are carried over.
	mode := os.FileMode(0o644)
	if st, err := c.Stat(remote); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := remote + ".presswrench-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".tmp"
	f, err := c.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return "", fmt.Errorf("Failed to write %s: %s", path, err.Error())
	}
	if _, err := f.Write([]byte(content)); err != nil {
		_ = f.Close()
		_ = c.Remove(tmp)
		return "", fmt.Errorf("Failed to write %s: %s", path, err.Error())
	}
	if err := f.Close(); err != nil {
		_ = c.Remove(tmp)
		return "", fmt.Errorf("Failed to write %s: %s", path, err.Error())
	}
	_ = c.Chmod(tmp, mode)
	if err := c.PosixRename(tmp, remote); err != nil {
		// Server without the posix-rename extension: plain rename refuses
		// to overwrite, so remove the target first.
		_ = c.Remove(remote)
		if err := c.Rename(tmp, remote); err != nil {
			_ = c.Remove(tmp)
			return "", fmt.Errorf("Failed to write %s: %s", path, err.Error())
		}
	}
	return path, nil
}

// ListDir lists a directory; an empty path is the docroot.
func (o *Ops) ListDir(host, user, path string, showHidden bool) ([]FileEntry, error) {
	c, chrooted, err := o.sftp(host, user)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	remote := SFTPPath(path, chrooted)
	path = DisplayPath(remote, chrooted)
	infos, err := c.ReadDir(remote)
	if err != nil {
		return nil, fmt.Errorf("Failed to list %s: %s", path, err.Error())
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
		out = append(out, FileEntry{
			Name:        name,
			Type:        classifyMode(rawMode),
			Size:        info.Size(),
			ModifiedAt:  info.ModTime().UTC().Format("2006-01-02T15:04:05.000Z"),
			Permissions: fmt.Sprintf("%03o", rawMode&0o777),
		})
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
