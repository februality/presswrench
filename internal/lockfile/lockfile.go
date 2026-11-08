// Package lockfile provides cross-process lockfiles that stay fresh while held.
//
// A lock is an O_EXCL file whose mtime is touched every Heartbeat by the
// holder. A lock not touched for StaleAfter belongs to a dead process and is
// broken by the next Acquire, so long-running holders are never mistaken for
// crashed ones.
package lockfile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Tunables; tests shrink them.
var (
	StaleAfter = 60 * time.Second
	Heartbeat  = 15 * time.Second
	Poll       = 100 * time.Millisecond
)

// HeldError reports that another process held the lock for the whole wait.
type HeldError struct {
	Path   string
	Reason string // holder's note (trimmed file content), if any
}

func (e *HeldError) Error() string {
	s := "Timed out waiting for another PressWrench process (lock " + e.Path + ")"
	if e.Reason != "" {
		s += ": " + e.Reason
	}
	return s
}

// Lock is a held lockfile.
type Lock struct {
	path  string
	id    os.FileInfo // identity of the file we created
	nonce string      // written into the file; tells our file from a successor
	stop  chan struct{}
	done  chan struct{}

	mu       sync.Mutex // serializes file writes/touches/removal
	released bool
	once     sync.Once
}

// idPrefix starts the line that carries the holder's nonce. The file's
// first line is the reason (possibly empty).
const idPrefix = "lock-id: "

// Acquire creates the lockfile at path, waiting up to wait for a current
// holder. A lock untouched for StaleAfter is broken. On timeout it returns a
// *HeldError; when ctx ends first it returns ctx.Err().
func Acquire(ctx context.Context, path string, wait time.Duration) (*Lock, error) {
	return AcquireTakingOver(ctx, path, wait, nil)
}

// AcquireTakingOver is Acquire, except that a live lock whose reason
// satisfies takeOver is broken at once instead of waited for. Breaking is
// serialized like stale-lock breaking and re-checked under the breaker, so
// of several takers exactly one wins and the rest wait for it. The former
// holder sees Held() == false and never removes or rewrites the new file.
func AcquireTakingOver(ctx context.Context, path string, wait time.Duration, takeOver func(reason string) bool) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("Could not create the lock directory: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		l, err := create(path)
		if err == nil {
			go l.beat(Heartbeat)
			return l, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		st, serr := os.Stat(path)
		if errors.Is(serr, os.ErrNotExist) {
			continue // released between our create and stat: retry at once
		}
		if serr == nil {
			stale := func(cur os.FileInfo) bool { return time.Since(cur.ModTime()) > StaleAfter }
			matches := func(os.FileInfo) bool { return takeOver != nil && takeOver(ReadReason(path)) }
			if (stale(st) && breakIf(path, st, stale)) || (matches(st) && breakIf(path, st, matches)) {
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !time.Now().Before(deadline) {
			return nil, &HeldError{Path: path, Reason: ReadReason(path)}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(Poll):
		}
	}
}

// create makes a new lockfile with O_EXCL and writes our nonce into it.
// An existing file yields an error matching os.ErrExist.
func create(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, err
		}
		return nil, fmt.Errorf("Could not create lock %s: %w", path, err)
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	_, werr := f.WriteString(content("", nonce))
	info, serr := f.Stat()
	_ = f.Close() // close before Chtimes/Remove (Windows)
	if werr != nil || serr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("Could not write lock %s: %w", path, errors.Join(werr, serr))
	}
	return &Lock{path: path, id: info, nonce: nonce, stop: make(chan struct{}), done: make(chan struct{})}, nil
}

func content(reason, nonce string) string {
	return reason + "\n" + idPrefix + nonce + "\n"
}

// ReadReason returns the holder's note from the lockfile at path (its first
// line, trimmed), or "" when there is none or the file can't be read.
func ReadReason(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

// nonceIn returns the nonce recorded in lockfile content b.
func nonceIn(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), idPrefix); ok {
			return v
		}
	}
	return ""
}

// breakerStale is how old a ".break" file must be to be treated as left
// behind by a crashed breaker.
const breakerStale = 5 * time.Second

// tryBreaker takes path's ".break" file, the short-lived lock that
// serializes judging-and-removing the lockfile, and returns its release
// function, or nil when another process has it.
func tryBreaker(path string) func() {
	bp := path + ".break"
	f, err := os.OpenFile(bp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if st, serr := os.Stat(bp); serr == nil && time.Since(st.ModTime()) > breakerStale {
			_ = os.Remove(bp)
		}
		return nil
	}
	_ = f.Close()
	return func() { _ = os.Remove(bp) }
}

// breakIf removes the lock at path if, under the breaker, it is still the
// file judged and still satisfies cond, so two waiters cannot both judge the
// same file and have the slower one delete the faster one's fresh lock. It
// reports whether it removed it.
func breakIf(path string, judged os.FileInfo, cond func(cur os.FileInfo) bool) bool {
	release := tryBreaker(path)
	if release == nil {
		return false
	}
	defer release()
	cur, err := os.Stat(path)
	if err != nil || !os.SameFile(judged, cur) || !cond(cur) {
		return false
	}
	return os.Remove(path) == nil
}

// ours reports whether path is still the file this lock created: the same
// file and our nonce (a successor can reuse a freed inode). Caller holds
// l.mu.
func (l *Lock) ours() bool {
	f, err := os.Open(l.path)
	if err != nil {
		return false
	}
	defer f.Close()
	return l.oursFile(f)
}

func (l *Lock) oursFile(f *os.File) bool {
	cur, err := f.Stat()
	if err != nil || !os.SameFile(l.id, cur) {
		return false
	}
	b, err := io.ReadAll(f)
	return err == nil && nonceIn(b) == l.nonce
}

// Held reports whether this lock is still held: not released and its file
// not broken or taken over by another process. A nil lock is not held.
func (l *Lock) Held() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.released && l.ours()
}

func (l *Lock) beat(every time.Duration) {
	defer close(l.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.mu.Lock()
			if l.released || !l.ours() {
				l.mu.Unlock()
				return // lock was taken over (e.g. after a long stall)
			}
			now := time.Now()
			_ = os.Chtimes(l.path, now, now)
			l.mu.Unlock()
		}
	}
}

// SetReason rewrites the lockfile's first line with a one-line, non-secret
// note that waiting processes show when they time out. It writes through a
// handle it has checked is ours, so it never clobbers a successor's file.
func (l *Lock) SetReason(reason string) error {
	reason = strings.TrimSpace(strings.ReplaceAll(reason, "\n", " "))
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	f, err := os.OpenFile(l.path, os.O_RDWR, 0)
	if err != nil {
		return nil // gone: not ours any more
	}
	defer f.Close()
	if !l.oursFile(f) {
		return nil
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err = f.WriteAt([]byte(content(reason, l.nonce)), 0)
	return err
}

// Release stops the heartbeat and removes the lockfile if it is still ours.
// The check-and-remove runs under the breaker so it can't delete a lock a
// taker has just created. Safe to call twice.
func (l *Lock) Release() {
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		l.mu.Lock()
		defer l.mu.Unlock()
		l.released = true
		release := tryBreaker(l.path)
		for i := 0; release == nil && i < 100; i++ { // a breaker holds it for microseconds
			time.Sleep(10 * time.Millisecond)
			release = tryBreaker(l.path)
		}
		if release != nil {
			defer release()
		}
		for i := 0; i < 5 && l.ours(); i++ { // Windows: a reader may briefly block removal
			if os.Remove(l.path) == nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}
