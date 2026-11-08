package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/lockfile"
)

// shortLockWait makes lock waits fail fast for one test.
func shortLockWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := lockWait
	lockWait = d
	t.Cleanup(func() { lockWait = old })
}

func TestSignIn_DoesNotHoldLockDuringBrowser(t *testing.T) {
	_, srv := newFakeAS(t)
	store := newStore(t)
	shortLockWait(t, 100*time.Millisecond)
	var lockErr error
	open := func(u string) error {
		l, err := lockAccount(context.Background(), "")
		if err != nil {
			lockErr = err
		} else {
			l.Release()
		}
		return browserFollow(u)
	}
	if _, err := SignIn(context.Background(), store, "", LoginOptions{AuthURL: srv.URL, OpenBrowser: open, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if lockErr != nil {
		t.Fatalf("account lock was held during the browser wait: %v", lockErr)
	}
	if r, _ := store.Load(""); !r.SignedIn() {
		t.Errorf("not signed in after SignIn: %+v", r)
	}
}

func TestSignIn_InterruptedKeepsClientOnly(t *testing.T) {
	f, srv := newFakeAS(t)
	store := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The user closes the browser / presses Ctrl-C while signing in.
	interrupted := func(string) error { cancel(); return errors.New("no browser") }
	if _, err := SignIn(ctx, store, "", LoginOptions{AuthURL: srv.URL, OpenBrowser: interrupted, Timeout: 10 * time.Second}); err == nil {
		t.Fatal("interrupted SignIn succeeded")
	}
	r, err := store.Load("")
	if err != nil {
		t.Fatalf("Load after interrupted login: %v", err)
	}
	if r.ClientID == "" || r.RefreshToken != "" {
		t.Errorf("record = %+v, want client id only", r)
	}
	if accts, _ := store.Accounts(); len(accts) != 0 {
		t.Errorf("interrupted account listed: %q", accts)
	}
	if _, err := SignIn(context.Background(), store, "", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("second SignIn: %v", err)
	}
	f.mu.Lock()
	regs := f.registrations
	f.mu.Unlock()
	if regs != 1 {
		t.Errorf("registrations = %d, want 1 (second login must reuse the client)", regs)
	}
}

func TestSignIn_StoreErrorDoesNotRegister(t *testing.T) {
	for name, kind := range map[string]creds.Kind{
		"locked": creds.KindLocked, "denied": creds.KindDenied, "timeout": creds.KindTimeout,
		"unavailable": creds.KindUnavailable, "other": creds.KindOther,
	} {
		t.Run(name, func(t *testing.T) {
			f, srv := newFakeAS(t)
			fs := &faultyStore{Store: newStore(t), loadErr: &creds.Error{Kind: kind, Account: "acme"}}
			_, err := SignIn(context.Background(), fs, "acme", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second})
			if creds.KindOf(err) != kind {
				t.Fatalf("err = %v, want kind %v", err, kind)
			}
			f.mu.Lock()
			regs := f.registrations
			f.mu.Unlock()
			if regs != 0 || fs.saves != 0 {
				t.Errorf("registrations = %d, saves = %d; want none", regs, fs.saves)
			}
		})
	}
}

func TestSignIn_CorruptRecordReRegisters(t *testing.T) {
	f, srv := newFakeAS(t)
	fs := &faultyStore{Store: newStore(t), loadErr: &creds.Error{Kind: creds.KindCorrupt, Account: "acme"}}
	if _, err := SignIn(context.Background(), fs, "acme", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("SignIn over a corrupt record: %v", err)
	}
	fs.loadErr = nil
	if r, err := fs.Load("acme"); err != nil || !r.SignedIn() {
		t.Fatalf("record after login = %+v, %v", r, err)
	}
	if f.registrations != 1 {
		t.Errorf("registrations = %d, want 1", f.registrations)
	}
}

func TestSession_SlowRefreshNotDoubleSpent(t *testing.T) {
	oldStale, oldBeat := lockfile.StaleAfter, lockfile.Heartbeat
	lockfile.StaleAfter, lockfile.Heartbeat = 100*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { lockfile.StaleAfter, lockfile.Heartbeat = oldStale, oldBeat })

	f, srv := newFakeAS(t)
	f.rotate = true
	_, store := signedInSession(t, f, srv)
	expire(t, store, "")
	f.mu.Lock()
	f.delay = 300 * time.Millisecond // longer than StaleAfter: only the heartbeat keeps the lock
	f.mu.Unlock()

	a, b := NewSession(store, "", srv.URL), NewSession(store, "", srv.URL)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, s := range []*Session{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Token(context.Background())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("session %d: %v", i, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refreshes != 1 {
		t.Errorf("refreshes = %d, want 1 (the refresh token was spent twice)", f.refreshes)
	}
}

func TestSession_LockTimeoutIsHeldError(t *testing.T) {
	f, srv := newFakeAS(t)
	s, store := signedInSession(t, f, srv)
	expire(t, store, "")
	l, err := lockAccount(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	shortLockWait(t, 100*time.Millisecond)
	_, err = s.Token(context.Background())
	var held *lockfile.HeldError
	if !errors.As(err, &held) {
		t.Fatalf("err = %v, want *lockfile.HeldError", err)
	}
	if !strings.Contains(Explain(err), "Another PressWrench process") {
		t.Errorf("Explain = %q", Explain(err))
	}
	if f.refreshes != 0 {
		t.Errorf("refreshed without the lock")
	}
}

func TestLockAccount_PathPerAccount(t *testing.T) {
	newStore(t) // points lockDir at a temp dir
	shortLockWait(t, 100*time.Millisecond)
	def, err := lockAccount(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer def.Release()
	acme, err := lockAccount(context.Background(), "my-site-2")
	if err != nil {
		t.Fatalf("named account blocked by the default account's lock: %v", err)
	}
	defer acme.Release()
	_, err = lockAccount(context.Background(), "my-site-2")
	var held *lockfile.HeldError
	if !errors.As(err, &held) || !strings.HasSuffix(held.Path, "session-my-site-2.lock") {
		t.Fatalf("second lock = %v", err)
	}
}

func TestSignOut_TakesAccountLock(t *testing.T) {
	f, srv := newFakeAS(t)
	_, store := signedInSession(t, f, srv)
	l, err := lockAccount(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	shortLockWait(t, 100*time.Millisecond)
	var held *lockfile.HeldError
	if err := SignOut(context.Background(), store, "", srv.URL); !errors.As(err, &held) {
		t.Fatalf("SignOut while locked = %v, want *lockfile.HeldError", err)
	}
	if err := RemoveAccount(context.Background(), store, "", srv.URL); !errors.As(err, &held) {
		t.Fatalf("RemoveAccount while locked = %v, want *lockfile.HeldError", err)
	}
	if r, _ := store.Load(""); !r.SignedIn() || f.revokes != 0 {
		t.Errorf("session touched without the lock: %+v, revokes=%d", r, f.revokes)
	}
}

func TestRemoveAccount_DeletesRecord(t *testing.T) {
	f, srv := newFakeAS(t)
	store := newStore(t)
	if _, err := SignIn(context.Background(), store, "acme", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAccount(context.Background(), store, "acme", srv.URL); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	if _, err := store.Load("acme"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("Load after remove: %v, want ErrNotFound", err)
	}
	if accts, _ := store.Accounts(); len(accts) != 0 {
		t.Errorf("removed account still listed: %q", accts)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokes == 0 {
		t.Error("tokens were not revoked")
	}
}

func TestRemoveAccount_ReturnsDeleteError(t *testing.T) {
	f, srv := newFakeAS(t)
	_, store := signedInSession(t, f, srv)
	locked := &creds.Error{Kind: creds.KindLocked}
	fs := &faultyStore{Store: store, deleteErr: locked}
	if err := RemoveAccount(context.Background(), fs, "", srv.URL); creds.KindOf(err) != creds.KindLocked {
		t.Fatalf("RemoveAccount err = %v, want the Delete error", err)
	}
}

func TestRemoveAccount_MissingIsNotAnError(t *testing.T) {
	store := newStore(t)
	if err := RemoveAccount(context.Background(), store, "ghost", ""); err != nil {
		t.Fatalf("RemoveAccount of a missing account: %v", err)
	}
}
