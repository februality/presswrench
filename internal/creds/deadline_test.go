package creds

import (
	"errors"
	"testing"
	"time"
)

func shortKeychainTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := keychainTimeout
	keychainTimeout = d
	t.Cleanup(func() { keychainTimeout = old })
}

func TestCallWithin_TimesOutAndSerializes(t *testing.T) {
	shortKeychainTimeout(t, 50*time.Millisecond)
	sem := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)

	start := time.Now()
	_, err := callWithin(sem, "reading", func() ([]byte, error) {
		<-release // a keyring waiting on an unlock prompt
		return []byte("late"), nil
	})
	if KindOf(err) != KindTimeout {
		t.Fatalf("kind = %v (%v), want KindTimeout", KindOf(err), err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v", d)
	}

	// The hung call still holds the keyring: the next one waits, times out,
	// and never runs (so it can't land out of order later).
	ran := false
	_, err = callWithin(sem, "saving to", func() (struct{}, error) { ran = true; return struct{}{}, nil })
	if KindOf(err) != KindTimeout || ran {
		t.Fatalf("second call: kind = %v, ran = %v", KindOf(err), ran)
	}
}

func TestCallWithin_PassesResultsThrough(t *testing.T) {
	sem := make(chan struct{}, 1)
	boom := errors.New("boom")
	v, err := callWithin(sem, "reading", func() (string, error) { return "v", boom })
	if v != "v" || !errors.Is(err, boom) {
		t.Fatalf("got %q, %v", v, err)
	}
	// The keyring is free again once a call returns.
	if v, err := callWithin(sem, "reading", func() (string, error) { return "w", nil }); v != "w" || err != nil {
		t.Fatalf("got %q, %v", v, err)
	}
}
