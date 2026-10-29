package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/februality/presswrench/internal/creds"
)

const (
	lockStaleAfter = 60 * time.Second
	lockWait       = 30 * time.Second
	lockPoll       = 100 * time.Millisecond
)

// lockDir is where refresh locks live; overridable in tests.
var lockDir = func() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, creds.ServiceName), nil
}

// acquireRefreshLock takes a cross-process lock for refreshing one
// account's session. It's an O_EXCL lockfile rather than flock so it works
// the same on every OS; a lock older than lockStaleAfter is assumed to be
// left by a crashed process and broken.
func acquireRefreshLock(ctx context.Context, account string) (func(), error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	name := "refresh.lock"
	if account != "" {
		name = "refresh-" + account + ".lock"
	}
	path := filepath.Join(dir, name)
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("refresh lock: %w", err)
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > lockStaleAfter {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for another presswrench process to refresh the session (lock %s)", path)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}
