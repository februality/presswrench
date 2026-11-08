package creds

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestError_KindsAndIs(t *testing.T) {
	nf := &Error{Kind: KindNotFound, Account: "acme", Op: "load"}
	if !errors.Is(nf, ErrNotFound) || !errors.Is(fmt.Errorf("wrapped: %w", nf), ErrNotFound) {
		t.Error("NotFound *Error should match ErrNotFound")
	}
	if errors.Is(&Error{Kind: KindLocked}, ErrNotFound) {
		t.Error("Locked must not match ErrNotFound")
	}
	if KindOf(errors.New("plain")) != KindOther || KindOf(nil) != KindOther {
		t.Error("non-*Error should be KindOther")
	}
	if KindOf(fmt.Errorf("wrapped: %w", &Error{Kind: KindDenied})) != KindDenied {
		t.Error("KindOf should unwrap")
	}
	inner := errors.New("boom")
	if !errors.Is(&Error{Kind: KindOther, Err: inner}, inner) {
		t.Error("Unwrap should expose Err")
	}
	for k, want := range map[Kind]bool{
		KindDenied: true, KindTooLarge: true, KindCorrupt: true, KindNewerFormat: true,
		KindOther: false, KindNotFound: false, KindLocked: false, KindTimeout: false, KindUnavailable: false,
	} {
		if got := Permanent(&Error{Kind: k}); got != want {
			t.Errorf("Permanent(kind %d) = %v, want %v", k, got, want)
		}
	}
	if Permanent(errors.New("plain")) {
		t.Error("plain error should not be permanent")
	}
}

func TestBroken(t *testing.T) {
	cause := errors.New("no keyring")
	s := Broken(cause)
	if _, err := s.Load("x"); err != cause {
		t.Errorf("Load err = %v", err)
	}
	if err := s.Save("x", Record{}); err != cause {
		t.Errorf("Save err = %v", err)
	}
	if err := s.Delete("x"); err != cause {
		t.Errorf("Delete err = %v", err)
	}
	if _, err := s.Accounts(); err != cause {
		t.Errorf("Accounts err = %v", err)
	}
	if info := s.Info(); info.Source != SourceNotFound || info.Description != "unavailable" || info.Warning != "no keyring" {
		t.Errorf("Info = %+v", info)
	}
}

func TestConfigDirAndDefaultFilePath(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	t.Cleanup(func() { configDir = old })
	configDir = func() (string, error) { return dir, nil }
	got, err := ConfigDir()
	must(t, err)
	if got != dir {
		t.Errorf("ConfigDir = %q", got)
	}
	p, err := DefaultFilePath()
	must(t, err)
	if p != filepath.Join(dir, "credentials.json") {
		t.Errorf("DefaultFilePath = %q", p)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
