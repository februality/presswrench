package auth

import (
	"context"
	"path/filepath"
	"time"

	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/lockfile"
)

// lockWait bounds how long an operation waits for another process holding
// the account lock; tests shrink it.
var lockWait = 30 * time.Second

// lockDir is where account locks live; overridable in tests.
var lockDir = creds.ConfigDir

// lockAccount takes the cross-process lock that serializes every
// read-modify-write of one account's session: refresh, login's two short
// store steps, logout and remove. Pressable rotates refresh tokens, so two
// processes must never spend the same one. The lock is heartbeated while
// held (see lockfile), so a slow refresh is never mistaken for a crash.
//
// Take it before any store call in the critical section, never while a
// store call is in flight: the store's own index/file locks nest inside it.
// On timeout the error is a *lockfile.HeldError.
func lockAccount(ctx context.Context, account string) (*lockfile.Lock, error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	name := "session.lock"
	if account != "" {
		name = "session-" + account + ".lock"
	}
	return lockfile.Acquire(ctx, filepath.Join(dir, name), lockWait)
}
