// Package lockfile provides cross-process lockfiles that stay fresh while held.
//
// A lock is an O_EXCL file whose mtime is touched every Heartbeat by the
// holder. A lock not touched for StaleAfter belongs to a dead process and is
// broken by the next Acquire, so long-running holders are never mistaken for
// crashed ones.
package lockfile

import (
	"context"
	"errors"
	"fmt"
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
	path string
	id   os.FileInfo // identity of the file we created
	stop chan struct{}
	done chan struct{}

	mu       sync.Mutex // serializes file writes/touches/removal
	released bool
	once     sync.Once
}

// Acquire creates the lockfile at path, waiting up to wait for a current
// holder. A lock untouched for StaleAfter is broken. On timeout it returns a
// *HeldError; when ctx ends first it returns ctx.Err().
func Acquire(ctx context.Context, path string, wait time.Duration) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("Could not create the lock directory: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			info, serr := f.Stat()
			_ = f.Close() // close before Chtimes/Remove (Windows)
			if serr != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("Could not inspect lock %s: %w", path, serr)
			}
			l := &Lock{path: path, id: info, stop: make(chan struct{}), done: make(chan struct{})}
			go l.beat(Heartbeat)
			return l, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("Could not create lock %s: %w", path, err)
		}
		st, serr := os.Stat(path)
		if errors.Is(serr, os.ErrNotExist) {
			continue // released between our create and stat: retry at once
		}
		if serr == nil && time.Since(st.ModTime()) > StaleAfter {
			breakStale(path, st)
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !time.Now().Before(deadline) {
			reason := ""
			if b, rerr := os.ReadFile(path); rerr == nil {
				reason = strings.TrimSpace(string(b))
			}
			return nil, &HeldError{Path: path, Reason: reason}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(Poll):
		}
	}
}

// breakerStale is how old a ".break" file must be to be treated as left
// behind by a crashed breaker.
const breakerStale = 5 * time.Second

// breakStale removes the stale lock at path, serialized through a short-lived
// ".break" file so two waiters cannot both judge the same stale file and have
// the slower one delete the faster one's fresh lock. Under the breaker it
// re-checks that path is still the file judged stale and still stale.
func breakStale(path string, judged os.FileInfo) {
	bp := path + ".break"
	f, err := os.OpenFile(bp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if st, serr := os.Stat(bp); serr == nil && time.Since(st.ModTime()) > breakerStale {
			_ = os.Remove(bp)
		}
		return
	}
	_ = f.Close()
	defer func() { _ = os.Remove(bp) }()
	cur, err := os.Stat(path)
	if err != nil || !os.SameFile(judged, cur) || time.Since(cur.ModTime()) <= StaleAfter {
		return
	}
	_ = os.Remove(path)
}

// ours reports whether path is still the file this lock created.
func (l *Lock) ours() bool {
	cur, err := os.Stat(l.path)
	return err == nil && os.SameFile(l.id, cur)
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

// SetReason rewrites the lockfile's content with a one-line, non-secret note
// that waiting processes show when they time out.
func (l *Lock) SetReason(reason string) error {
	reason = strings.TrimSpace(strings.ReplaceAll(reason, "\n", " "))
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released || !l.ours() {
		return nil
	}
	return os.WriteFile(l.path, []byte(reason+"\n"), 0o600)
}

// Release stops the heartbeat and removes the lockfile. Safe to call twice.
func (l *Lock) Release() {
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		l.mu.Lock()
		l.released = true
		if l.ours() {
			_ = os.Remove(l.path)
		}
		l.mu.Unlock()
	})
}
