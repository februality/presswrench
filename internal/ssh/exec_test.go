//go:build !windows

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

// sshServer is an SSH server on a loopback port that accepts any key, runs
// "exec" requests with the local sh and serves SFTP from memory.
type sshServer struct {
	port int
	// stubborn makes it behave like Pressable's sshd: the "signal" request
	// is ignored and a command keeps running after its channel closes.
	stubborn bool
	// shell runs the commands; "sh" when empty.
	shell atomic.Value
	files sftp.Handlers
}

func startSSHServer(t *testing.T, stubborn bool) *sshServer {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &xssh.ServerConfig{
		PublicKeyCallback: func(xssh.ConnMetadata, xssh.PublicKey) (*xssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &sshServer{port: ln.Addr().(*net.TCPAddr).Port, stubborn: stubborn, files: sftp.InMemHandler()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(conn, cfg)
		}
	}()
	return srv
}

func (srv *sshServer) serve(conn net.Conn, cfg *xssh.ServerConfig) {
	sconn, chans, reqs, err := xssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sconn.Close() }()
	go xssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(xssh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go srv.session(ch, creqs)
	}
}

func (srv *sshServer) session(ch xssh.Channel, reqs <-chan *xssh.Request) {
	defer func() { _ = ch.Close() }()
	var cmd *exec.Cmd
	kill := func() {
		if cmd != nil && cmd.Process != nil && !srv.stubborn {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	defer kill()
	exited := make(chan int, 1)
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return // the client closed the channel
			}
			switch req.Type {
			case "exec":
				var payload struct{ Command string }
				_ = xssh.Unmarshal(req.Payload, &payload)
				shell, _ := srv.shell.Load().(string)
				if shell == "" {
					shell = "sh"
				}
				cmd = exec.Command(shell, "-c", payload.Command)
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
				stdin, _ := cmd.StdinPipe()
				go func() { _, _ = io.Copy(stdin, ch); _ = stdin.Close() }()
				_ = req.Reply(cmd.Start() == nil, nil)
				go func() {
					code := 0
					if err := cmd.Wait(); err != nil {
						code = 1
						if ee, ok := err.(*exec.ExitError); ok {
							code = ee.ExitCode()
						}
					}
					exited <- code
				}()
			case "subsystem":
				_ = req.Reply(true, nil)
				_ = sftp.NewRequestServer(ch, srv.files).Serve()
				return
			case "signal":
				kill()
			default:
				_ = req.Reply(false, nil)
			}
		case code := <-exited:
			_, _ = ch.SendRequest("exit-status", false, xssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			return
		}
	}
}

func newTestOps(t *testing.T) *Ops {
	t.Helper()
	ops, _ := newTestOpsOn(t, false)
	return ops
}

func newTestOpsOn(t *testing.T, stubborn bool) (*Ops, *sshServer) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "id")
	if _, err := EnsureKeyPair(keyPath, "test"); err != nil {
		t.Fatal(err)
	}
	pool := NewPool(keyPath, 5000, NewHostKeyVerifier(filepath.Join(t.TempDir(), "known_hosts"), true))
	srv := startSSHServer(t, stubborn)
	pool.port = srv.port
	t.Cleanup(pool.Close)
	return NewOps(pool), srv
}

func TestExec(t *testing.T) {
	ops := newTestOps(t)
	ctx := context.Background()
	run := func(command string, opts ExecOptions) *ExecResult {
		t.Helper()
		res, err := ops.Exec(ctx, "127.0.0.1", "u", command, opts)
		if err != nil {
			t.Fatalf("Exec(%q): %v", command, err)
		}
		return res
	}

	res := run("echo out; echo err >&2; exit 3", ExecOptions{})
	if res.Stdout != "out\n" || res.Stderr != "err\n" || res.ExitCode != 3 || res.TimedOut || res.Truncated {
		t.Errorf("plain: %+v", res)
	}

	dir := t.TempDir()
	if res = run("pwd -P", ExecOptions{Cwd: dir}); !strings.HasSuffix(strings.TrimSpace(res.Stdout), filepath.Base(dir)) {
		t.Errorf("cwd: %+v", res)
	}
	if res = run("echo never", ExecOptions{Cwd: "/no/such/dir"}); res.ExitCode != 1 || res.Stdout != "" {
		t.Errorf("missing cwd must not run the command: %+v", res)
	}

	if res = run("cat; echo end", ExecOptions{Stdin: "line 1\nline 2\n"}); res.Stdout != "line 1\nline 2\nend\n" {
		t.Errorf("stdin: %+v", res)
	}

	// Output over the cap keeps its start and its end.
	res = run("seq 1 20000", ExecOptions{MaxOutputBytes: 1000})
	if !res.Truncated || !strings.HasPrefix(res.Stdout, "1\n2\n") || !strings.HasSuffix(res.Stdout, "19999\n20000\n") ||
		!strings.Contains(res.Stdout, "bytes omitted") || len(res.Stdout) > 1100 {
		t.Errorf("cap: truncated=%v len=%d", res.Truncated, len(res.Stdout))
	}

	// A dead pooled connection is replaced, not reported.
	client, err := ops.pool.Get("127.0.0.1", "u")
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if res = run("echo again", ExecOptions{}); res.Stdout != "again\n" {
		t.Errorf("after reconnect: %+v", res)
	}
}

// A timeout returns what the command printed before it was killed.
func TestExec_TimeoutKeepsPartialOutput(t *testing.T) {
	ops := newTestOps(t)
	started := time.Now()
	res, err := ops.Exec(context.Background(), "127.0.0.1", "u", "echo started; sleep 30; echo done", ExecOptions{TimeoutMs: 500})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Stdout != "started\n" || res.ExitCode == 0 {
		t.Errorf("got %+v", res)
	}
	if took := time.Since(started); took > 10*time.Second {
		t.Errorf("took %s", took)
	}
}

func TestExec_CancelKillsTheCommand(t *testing.T) {
	ops := newTestOps(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	started := time.Now()
	_, err := ops.Exec(ctx, "127.0.0.1", "u", "sleep 30", ExecOptions{})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err = %v", err)
	}
	if took := time.Since(started); took > 10*time.Second {
		t.Errorf("took %s", took)
	}
}

// The server ignores kill signals and keeps commands running after their
// channel closes, as Pressable's does. A timed-out or cancelled command
// must still be dead before it reaches its next step.
func TestExec_KillsOnAStubbornServer(t *testing.T) {
	ops, _ := newTestOpsOn(t, true)
	dir := t.TempDir()

	timedOut := filepath.Join(dir, "timed-out")
	res, err := ops.Exec(context.Background(), "127.0.0.1", "u", "echo started; sleep 2; touch "+ShellEscape(timedOut), ExecOptions{TimeoutMs: 300})
	if err != nil || !res.TimedOut || res.Stdout != "started\n" {
		t.Fatalf("timeout: %+v, %v", res, err)
	}

	cancelled := filepath.Join(dir, "cancelled")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	if _, err = ops.Exec(ctx, "127.0.0.1", "u", "sleep 2; touch "+ShellEscape(cancelled), ExecOptions{}); err == nil {
		t.Fatal("cancelled command returned no error")
	}

	// A command left alone does reach its next step: the check below means something.
	control := filepath.Join(dir, "control")
	if _, err = ops.Exec(context.Background(), "127.0.0.1", "u", "sleep 2; touch "+ShellEscape(control), ExecOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	for _, marker := range []string{timedOut, cancelled} {
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("%s exists: the command kept running", filepath.Base(marker))
		}
	}
	if _, err := os.Stat(control); err != nil {
		t.Errorf("control command didn't finish: %v", err)
	}
}

// stderr comes back without the PID line, whatever else is on it.
func TestExec_StderrIsUntouched(t *testing.T) {
	ops := newTestOps(t)
	res, err := ops.Exec(context.Background(), "127.0.0.1", "u", "echo one >&2; echo two >&2", ExecOptions{TimeoutMs: 5000})
	if err != nil || res.Stderr != "one\ntwo\n" || res.Stdout != "" {
		t.Fatalf("got %+v, %v", res, err)
	}
}

// File operations end to end, over SSH, against the in-memory SFTP server
// (which has no /srv/htdocs, so the login counts as confined to the docroot).
func TestOps_Files(t *testing.T) {
	ops, _ := newTestOpsOn(t, false)
	ctx := context.Background()
	const host, user = "127.0.0.1", "u"

	shown, n, err := ops.WriteFile(ctx, host, user, "wp-content/a.txt", strings.NewReader("one\ntwo\nthree\n"), true)
	if err != nil || shown != "/srv/htdocs/wp-content/a.txt" || n != 14 {
		t.Fatalf("write: %q %d %v", shown, n, err)
	}
	slice, err := ops.ReadFile(ctx, host, user, "/srv/htdocs/wp-content/a.txt", ReadOptions{Offset: 2, Limit: 1})
	if err != nil || slice.Content != "two\n" || slice.TotalLines != 3 || slice.Path != shown {
		t.Fatalf("read: %+v %v", slice, err)
	}
	edit, err := ops.EditFile(ctx, host, user, "wp-content/a.txt", "two", "2", false)
	if err != nil || edit.Replacements != 1 || edit.Lines[0] != 2 {
		t.Fatalf("edit: %+v %v", edit, err)
	}
	var buf strings.Builder
	if _, n, err = ops.Download(ctx, host, user, "wp-content/a.txt", &buf); err != nil || buf.String() != "one\n2\nthree\n" || n != 12 {
		t.Fatalf("download: %q %d %v", buf.String(), n, err)
	}
	dir, entries, err := ops.ListDir(ctx, host, user, "wp-content", false)
	if err != nil || dir != "/srv/htdocs/wp-content" || len(entries) != 1 || entries[0].Name != "a.txt" {
		t.Fatalf("list: %q %+v %v", dir, entries, err)
	}

	// On a confined login a system path is refused, not remapped.
	var outside *OutsideRootError
	if _, _, err = ops.WriteFile(ctx, host, user, "/tmp/dump.sql", strings.NewReader("x"), true); !errors.As(err, &outside) || !outside.Confined {
		t.Fatalf("write to /tmp on a confined login: %v", err)
	}
}

// blockingReader never returns until released.
type blockingReader struct{ release chan struct{} }

func (b blockingReader) Read([]byte) (int, error) { <-b.release; return 0, io.EOF }

func TestOps_FileOperationsCanBeCancelled(t *testing.T) {
	ops, _ := newTestOpsOn(t, false)
	src := blockingReader{release: make(chan struct{})}
	defer close(src.release)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	started := time.Now()
	_, _, err := ops.WriteFile(ctx, "127.0.0.1", "u", "stuck.txt", src, false)
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err = %v", err)
	}
	if took := time.Since(started); took > 5*time.Second {
		t.Errorf("took %s", took)
	}

	// The same thing when nothing cancels: the limit ends it.
	ops.fileLimit = 200 * time.Millisecond
	_, _, err = ops.WriteFile(context.Background(), "127.0.0.1", "u", "stuck.txt", src, false)
	if err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("err = %v", err)
	}

	// The connection was dropped; the next call gets a fresh one.
	if _, _, err = ops.WriteFile(context.Background(), "127.0.0.1", "u", "fine.txt", strings.NewReader("ok"), false); err != nil {
		t.Fatalf("after giving up: %v", err)
	}
}

func TestKeepalive_KeepsAHealthyConnection(t *testing.T) {
	ops := newTestOps(t)
	ops.pool.pingEvery, ops.pool.pingWait = 50*time.Millisecond, 200*time.Millisecond
	client, err := ops.pool.Get("127.0.0.1", "u")
	if err != nil {
		t.Fatal(err)
	}
	// A live connection survives its pings.
	time.Sleep(300 * time.Millisecond)
	if again, _ := ops.pool.Get("127.0.0.1", "u"); again != client {
		t.Fatal("a healthy connection was replaced")
	}
}

// The wrapper must not change what a command sees or returns.
func TestExec_WrapperIsTransparent(t *testing.T) {
	ops := newTestOps(t)
	run := func(command string, opts ExecOptions) *ExecResult {
		t.Helper()
		res, err := ops.Exec(context.Background(), "127.0.0.1", "u", command, opts)
		if err != nil {
			t.Fatalf("Exec(%q): %v", command, err)
		}
		return res
	}
	// No stdin given: the command reads EOF at once instead of hanging.
	if res := run("cat; echo eof", ExecOptions{}); res.Stdout != "eof\n" {
		t.Errorf("empty stdin: %+v", res)
	}
	// Stdin larger than a pipe buffer, without a trailing newline.
	big := strings.Repeat("0123456789abcdef", 20000) // 320 KB
	if res := run("wc -c | tr -d ' '", ExecOptions{Stdin: big}); strings.TrimSpace(res.Stdout) != "320000" {
		t.Errorf("large stdin: %q", res.Stdout)
	}
	// A command that ignores its stdin still finishes.
	if res := run("echo ignored", ExecOptions{Stdin: big}); res.Stdout != "ignored\n" {
		t.Errorf("ignored stdin: %+v", res)
	}
	// Multi-line scripts, heredocs, comments on the last line, exit codes.
	script := "x=1\ncat <<'EOT'\nhere $x\nEOT\necho \"x=$x\" # trailing comment"
	if res := run(script, ExecOptions{}); res.Stdout != "here $x\nx=1\n" || res.ExitCode != 0 {
		t.Errorf("script: %+v", res)
	}
	if res := run("false", ExecOptions{}); res.ExitCode != 1 {
		t.Errorf("exit code: %+v", res)
	}
	if res := run("exit 7", ExecOptions{}); res.ExitCode != 7 {
		t.Errorf("exit: %+v", res)
	}
}

// A job the command leaves in the background on purpose outlives a normal
// finish; the watchdog only fires when the command is cut short.
func TestExec_BackgroundJobSurvivesANormalFinish(t *testing.T) {
	ops, _ := newTestOpsOn(t, true)
	marker := filepath.Join(t.TempDir(), "background")
	res, err := ops.Exec(context.Background(), "127.0.0.1", "u",
		"(sleep 1; touch "+ShellEscape(marker)+") >/dev/null 2>&1 &\necho launched", ExecOptions{})
	if err != nil || res.Stdout != "launched\n" {
		t.Fatalf("got %+v, %v", res, err)
	}
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the background job was killed: %v", err)
	}
}

// A login that isn't confined to the web root: a full path means the
// server's path. When that doesn't exist but the site has a folder of the
// same name, the error says where the file is.
func TestOps_UnconfinedLogin(t *testing.T) {
	ops, _ := newTestOpsOn(t, false)
	ctx := context.Background()
	const host, user = "127.0.0.1", "u"

	// Give the server a /srv/htdocs before the first file operation, so
	// the login is detected as unconfined.
	client, err := ops.pool.Get(host, user)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/srv/htdocs/lib", "/tmp"} {
		if err := raw.MkdirAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	_ = raw.Close()

	if shown, _, err := ops.WriteFile(ctx, host, user, "lib/helper.php", strings.NewReader("<?php\n"), false); err != nil || shown != "/srv/htdocs/lib/helper.php" {
		t.Fatalf("write: %q %v", shown, err)
	}
	// /tmp is the real /tmp, not a folder in the web root.
	if shown, _, err := ops.WriteFile(ctx, host, user, "/tmp/dump.sql", strings.NewReader("x"), false); err != nil || shown != "/tmp/dump.sql" {
		t.Fatalf("write to /tmp: %q %v", shown, err)
	}
	if _, entries, err := ops.ListDir(ctx, host, user, "", false); err != nil || len(entries) != 1 || entries[0].Name != "lib" {
		t.Fatalf("web root holds %+v, %v (the dump must not be in it)", entries, err)
	}

	_, err = ops.ReadFile(ctx, host, user, "/lib/helper.php", ReadOptions{})
	if err == nil || !strings.Contains(err.Error(), "Use /srv/htdocs/lib/helper.php") {
		t.Fatalf("read of /lib/helper.php: %v", err)
	}
	// No such file anywhere: no hint.
	if _, err = ops.ReadFile(ctx, host, user, "/lib/nope.php", ReadOptions{}); err == nil || strings.Contains(err.Error(), "Use /srv/htdocs") {
		t.Fatalf("read of a missing file: %v", err)
	}
}

// countReads counts the bytes the SFTP server hands out.
type countReads struct {
	sftp.FileReader
	n *int64
}

func (c countReads) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	ra, err := c.FileReader.Fileread(r)
	if err != nil {
		return nil, err
	}
	return countingReaderAt{ra, c.n}, nil
}

type countingReaderAt struct {
	io.ReaderAt
	n *int64
}

func (c countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.ReaderAt.ReadAt(p, off)
	atomic.AddInt64(c.n, int64(n))
	return n, err
}

// The second page of a big file is fetched from where it starts, not from
// the top, and already knows how many lines the file has.
func TestOps_LaterPagesSeek(t *testing.T) {
	ops, srv := newTestOpsOn(t, false)
	var served int64
	srv.files.FileGet = countReads{srv.files.FileGet, &served}
	ctx := context.Background()
	const host, user = "127.0.0.1", "u"

	var file strings.Builder
	for i := 1; i <= 20000; i++ {
		fmt.Fprintf(&file, "line %05d of a fairly ordinary log file, padded out a little\n", i)
	}
	size := int64(file.Len()) // ~1.3 MB
	if _, _, err := ops.WriteFile(ctx, host, user, "big.log", strings.NewReader(file.String()), false); err != nil {
		t.Fatal(err)
	}

	first, err := ops.ReadFile(ctx, host, user, "big.log", ReadOptions{Limit: 100, MaxBytes: 60000})
	if err != nil || first.TotalLines != 20000 || first.LastLine != 100 || !first.More {
		t.Fatalf("first page: %+v, %v", first, err)
	}
	firstCost := atomic.SwapInt64(&served, 0)

	page, err := ops.ReadFile(ctx, host, user, "big.log", ReadOptions{Offset: 15001, Limit: 3, MaxBytes: 60000})
	if err != nil || page.TotalLines != 20000 || !strings.HasPrefix(page.Content, "line 15001 ") || page.LastLine != 15003 {
		t.Fatalf("later page: %+v, %v", page, err)
	}
	laterCost := atomic.SwapInt64(&served, 0)
	if laterCost > size/10 {
		t.Errorf("a 3-line page cost %d bytes of a %d-byte file (the first read cost %d)", laterCost, size, firstCost)
	}

	// The next page continues from the recorded end of the previous one.
	if page, err = ops.ReadFile(ctx, host, user, "big.log", ReadOptions{Offset: 15004, Limit: 1, MaxBytes: 60000}); err != nil || !strings.HasPrefix(page.Content, "line 15004 ") {
		t.Fatalf("next page: %+v, %v", page, err)
	}

	// A changed file is read afresh: no stale positions, no stale count.
	if _, _, err := ops.WriteFile(ctx, host, user, "big.log", strings.NewReader("only\ntwo lines now\n"), false); err != nil {
		t.Fatal(err)
	}
	if page, err = ops.ReadFile(ctx, host, user, "big.log", ReadOptions{Offset: 2}); err != nil || page.Content != "two lines now\n" || page.TotalLines != 2 {
		t.Fatalf("after the file changed: %+v, %v", page, err)
	}
}

// The wrapper must behave the same under every shell a server may give
// us. dash once kept the output pipes open through the watchdog, so a
// finished command never ended (Linux CI, where sh is dash).
func TestExec_UnderEachShell(t *testing.T) {
	for _, shell := range []string{"dash", "bash", "zsh"} {
		path, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		t.Run(shell, func(t *testing.T) {
			ops, srv := newTestOpsOn(t, true)
			srv.shell.Store(path)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			res, err := ops.Exec(ctx, "127.0.0.1", "u", "echo out; echo err >&2; exit 3", ExecOptions{})
			if err != nil || res.Stdout != "out\n" || res.Stderr != "err\n" || res.ExitCode != 3 {
				t.Fatalf("plain: %+v, %v", res, err)
			}
			res, err = ops.Exec(ctx, "127.0.0.1", "u", "cat; echo end", ExecOptions{Stdin: "line\n"})
			if err != nil || res.Stdout != "line\nend\n" {
				t.Fatalf("stdin: %+v, %v", res, err)
			}
			marker := filepath.Join(t.TempDir(), "survived")
			res, err = ops.Exec(ctx, "127.0.0.1", "u", "echo started; sleep 2; touch "+ShellEscape(marker), ExecOptions{TimeoutMs: 300})
			if err != nil || !res.TimedOut || res.Stdout != "started\n" {
				t.Fatalf("timeout: %+v, %v", res, err)
			}
			time.Sleep(2500 * time.Millisecond)
			if _, err := os.Stat(marker); err == nil {
				t.Error("the timed-out command kept running")
			}
		})
	}
}
