package lockfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func lockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sub", "x.lock")
}

func TestAcquire_Serializes(t *testing.T) {
	p := lockPath(t)
	l, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Acquire(context.Background(), p, 50*time.Millisecond)
	var he *HeldError
	if !errors.As(err, &he) {
		t.Fatalf("want *HeldError, got %v", err)
	}
	if he.Path != p {
		t.Errorf("Path = %q", he.Path)
	}
	l.Release()
	l2, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	l2.Release()
}

func TestAcquire_BreaksStale(t *testing.T) {
	p := lockPath(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-61 * time.Second)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	l, err := Acquire(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("stale lock not broken: %v", err)
	}
	l.Release()
}

func TestHeartbeat_KeepsLockFresh(t *testing.T) {
	oldS, oldH := StaleAfter, Heartbeat
	StaleAfter, Heartbeat = 100*time.Millisecond, 20*time.Millisecond
	defer func() { StaleAfter, Heartbeat = oldS, oldH }()

	p := lockPath(t)
	l, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	time.Sleep(300 * time.Millisecond)
	_, err = Acquire(context.Background(), p, 250*time.Millisecond)
	var he *HeldError
	if !errors.As(err, &he) {
		t.Fatalf("want *HeldError, got %v", err)
	}
}

func TestHeldError_CarriesReason(t *testing.T) {
	p := lockPath(t)
	l, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if err := l.SetReason("x couldn't save"); err != nil {
		t.Fatal(err)
	}
	_, err = Acquire(context.Background(), p, 50*time.Millisecond)
	var he *HeldError
	if !errors.As(err, &he) {
		t.Fatalf("want *HeldError, got %v", err)
	}
	if he.Reason != "x couldn't save" {
		t.Errorf("Reason = %q", he.Reason)
	}
	want := "Timed out waiting for another PressWrench process (lock " + p + "): x couldn't save"
	if he.Error() != want {
		t.Errorf("Error() = %q", he.Error())
	}
}

func TestHeldError_NoReason(t *testing.T) {
	e := &HeldError{Path: "/p"}
	if e.Error() != "Timed out waiting for another PressWrench process (lock /p)" {
		t.Errorf("Error() = %q", e.Error())
	}
}

func TestAcquire_ContextCancelled(t *testing.T) {
	p := lockPath(t)
	l, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Acquire(ctx, p, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestRelease_Idempotent(t *testing.T) {
	p := lockPath(t)
	l, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	l.Release()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("lock file still present: %v", err)
	}
}
