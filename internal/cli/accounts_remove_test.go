package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/ui"
)

type failingDelete struct {
	creds.Store
	err error
}

func (f failingDelete) Delete(string) error { return f.err }

func TestRemoveSession_ReportsDeleteFailure(t *testing.T) {
	withTempHome(t)
	store := failingDelete{
		Store: creds.NewFileStore(filepath.Join(t.TempDir(), "credentials.json")),
		err:   &creds.Error{Kind: creds.KindLocked, Account: "acme", Op: "delete"},
	}
	var out bytes.Buffer
	err := removeSession(ui.NewTest(&out, false, false, 100), store, "acme", "")
	if err == nil || !ui.IsReported(err) || ui.ExitCode(err) == 0 {
		t.Fatalf("err = %v, want a reported non-zero error", err)
	}
	if s := out.String(); strings.Contains(s, "removed the stored session") || !strings.Contains(s, "locked") {
		t.Errorf("output = %q, want a failure line explaining the lock", s)
	}
}

func TestRemoveSession_DeletesRecord(t *testing.T) {
	withTempHome(t)
	store := creds.NewFileStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err := store.Save("acme", creds.Record{ClientID: "c", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := removeSession(ui.NewTest(&out, false, false, 100), store, "acme", ""); err != nil {
		t.Fatalf("removeSession: %v", err)
	}
	if _, err := store.Load("acme"); creds.KindOf(err) != creds.KindNotFound {
		t.Errorf("Load after remove = %v", err)
	}
	if !strings.Contains(out.String(), "removed the stored session") {
		t.Errorf("output = %q", out.String())
	}
}

type failingLoad struct {
	creds.Store
	err error
}

func (f failingLoad) Load(string) (creds.Record, error) { return creds.Record{}, f.err }

func TestSignOut_ReportsFailure(t *testing.T) {
	withTempHome(t)
	store := failingLoad{
		Store: creds.NewFileStore(filepath.Join(t.TempDir(), "credentials.json")),
		err:   &creds.Error{Kind: creds.KindLocked, Account: "acme", Op: "load"},
	}
	var out bytes.Buffer
	err := signOut(ui.NewTest(&out, false, false, 100), store, "acme", "")
	if err == nil || !ui.IsReported(err) || ui.ExitCode(err) == 0 {
		t.Fatalf("err = %v, want a reported non-zero error", err)
	}
	if s := out.String(); !strings.Contains(s, "Could not sign out") || !strings.Contains(s, "locked") {
		t.Errorf("output = %q, want a failure line explaining the lock", s)
	}
}

func TestSignOut_SignedOut(t *testing.T) {
	withTempHome(t)
	store := creds.NewFileStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err := store.Save("acme", creds.Record{ClientID: "c", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := signOut(ui.NewTest(&out, false, false, 100), store, "acme", ""); err != nil {
		t.Fatalf("signOut: %v", err)
	}
	if r, _ := store.Load("acme"); r.RefreshToken != "" || r.ClientID != "c" {
		t.Errorf("record after sign-out = %+v", r)
	}
	if !strings.Contains(out.String(), "Signed out") {
		t.Errorf("output = %q", out.String())
	}
}
