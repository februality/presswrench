package lockfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

func TestAcquire_StaleBreakContention(t *testing.T) {
	p := lockPath(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	var holders, maxHolders atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := Acquire(context.Background(), p, 10*time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			n := holders.Add(1)
			for {
				m := maxHolders.Load()
				if n <= m || maxHolders.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			holders.Add(-1)
			l.Release()
		}()
	}
	wg.Wait()
	if maxHolders.Load() != 1 {
		t.Fatalf("max concurrent holders = %d, want 1", maxHolders.Load())
	}
}

func TestRelease_AfterTakeoverKeepsNewHolder(t *testing.T) {
	p := lockPath(t)
	first, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	defer second.Release()
	if err := second.SetReason("second"); err != nil {
		t.Fatal(err)
	}
	first.Release()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("new holder's lock was deleted: %v", err)
	}
	if r := ReadReason(p); r != "second" {
		t.Errorf("reason = %q", r)
	}
	if err := first.SetReason("late"); err != nil {
		t.Fatal(err)
	}
	if r := ReadReason(p); r != "second" {
		t.Errorf("former holder overwrote new lock: %q", r)
	}
	if first.Held() || !second.Held() {
		t.Errorf("Held: first %v, second %v; want false, true", first.Held(), second.Held())
	}
}

func isUnsaved(reason string) bool { return strings.HasPrefix(reason, "unsaved: ") }

func TestAcquireTakingOver_BreaksMatchingReason(t *testing.T) {
	p := lockPath(t)
	holder, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	if err := holder.SetReason("unsaved: x"); err != nil {
		t.Fatal(err)
	}
	if !holder.Held() {
		t.Fatal("holder not Held before takeover")
	}
	start := time.Now()
	taker, err := AcquireTakingOver(context.Background(), p, 10*time.Second, isUnsaved)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("takeover waited %v", d)
	}
	if holder.Held() || !taker.Held() {
		t.Errorf("Held: holder %v, taker %v; want false, true", holder.Held(), taker.Held())
	}
	holder.Release()
	if !taker.Held() {
		t.Error("former holder's Release removed the taker's lock")
	}
	taker.Release()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("taker's Release left the file: %v", err)
	}
}

func TestAcquireTakingOver_WaitsForOtherReasons(t *testing.T) {
	p := lockPath(t)
	holder, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	if err := holder.SetReason("busy"); err != nil {
		t.Fatal(err)
	}
	_, err = AcquireTakingOver(context.Background(), p, 50*time.Millisecond, isUnsaved)
	var he *HeldError
	if !errors.As(err, &he) || he.Reason != "busy" {
		t.Fatalf("err = %v, want *HeldError with reason busy", err)
	}
	if !holder.Held() {
		t.Error("holder lost a lock that didn't match")
	}
}

func TestAcquireTakingOver_OneTakerWins(t *testing.T) {
	p := lockPath(t)
	holder, err := Acquire(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	if err := holder.SetReason("unsaved: x"); err != nil {
		t.Fatal(err)
	}
	var holders, maxHolders atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := AcquireTakingOver(context.Background(), p, 10*time.Second, isUnsaved)
			if err != nil {
				t.Error(err)
				return
			}
			n := holders.Add(1)
			for {
				m := maxHolders.Load()
				if n <= m || maxHolders.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			holders.Add(-1)
			l.Release()
		}()
	}
	wg.Wait()
	if maxHolders.Load() != 1 {
		t.Fatalf("max concurrent holders = %d, want 1", maxHolders.Load())
	}
}

func TestHeld_NilAndReleased(t *testing.T) {
	var nl *Lock
	if nl.Held() {
		t.Error("nil lock Held")
	}
	l, err := Acquire(context.Background(), lockPath(t), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	if l.Held() {
		t.Error("released lock Held")
	}
}
