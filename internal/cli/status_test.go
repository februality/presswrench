package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/ui"
)

// lockedStore fails every Load like a locked keychain.
type lockedStore struct{ creds.Store }

func (lockedStore) Load(account string) (creds.Record, error) {
	return creds.Record{}, &creds.Error{Kind: creds.KindLocked, Account: account, Op: "load"}
}

// infoStore overrides Info on a temp file store.
type infoStore struct {
	creds.Store
	info creds.Info
}

func (s infoStore) Info() creds.Info { return s.info }

func tempStore(t *testing.T) creds.Store {
	t.Helper()
	return creds.NewFileStore(filepath.Join(t.TempDir(), "creds.json"))
}

func useStore(t *testing.T, s creds.Store) {
	t.Helper()
	old := openStore
	openStore = func() (creds.Store, error) { return s, nil }
	t.Cleanup(func() { openStore = old })
}

func TestBuildAccountStatus_LockedKeychain(t *testing.T) {
	withTempHome(t)
	as := buildAccountStatus(lockedStore{tempStore(t)}, "")
	if as.Session.SignedIn {
		t.Fatal("SignedIn with a locked keychain")
	}
	if !strings.Contains(as.Session.Problem, "unlock") {
		t.Fatalf("Problem = %q", as.Session.Problem)
	}
}

func TestBuildAccountStatus_NotSignedInHasNoProblem(t *testing.T) {
	withTempHome(t)
	as := buildAccountStatus(tempStore(t), "")
	if as.Session.SignedIn || as.Session.Problem != "" {
		t.Fatalf("session = %+v", as.Session)
	}
}

func TestBuildStatus_ShowsStoreAndWarning(t *testing.T) {
	isolate(t)
	useStore(t, infoStore{tempStore(t), creds.Info{Source: creds.SourceFile, Description: "file /x", Warning: "x"}})
	out := buildStatus()
	if out.Store != "file /x" || out.StoreWarning != "x" {
		t.Fatalf("store = %q, warning = %q", out.Store, out.StoreWarning)
	}
}

func TestBuildStatus_OpenFailureShowsProblem(t *testing.T) {
	isolate(t)
	old := openStore
	openStore = func() (creds.Store, error) {
		return nil, &creds.Error{Kind: creds.KindUnavailable, Detail: "no dbus"}
	}
	t.Cleanup(func() { openStore = old })
	out := buildStatus()
	if len(out.Accounts) != 1 || out.Accounts[0].Session.Problem == "" || out.StoreWarning == "" {
		t.Fatalf("out = %+v", out)
	}
}

func TestPrintStatusHuman_StoreOnceAndProblem(t *testing.T) {
	s := statusOutput{
		Version: "v", BinaryPath: "/bin/pw", Store: "file /x (chosen at first sign-in)", StoreWarning: "careful",
		Accounts: []accountStatus{
			{Name: "", Session: sessionStatus{Problem: "The keychain is locked."}},
			{Name: "b"},
		},
	}
	var buf bytes.Buffer
	// printStatusHuman writes to stdout via fmt; capture through the UI only for marks.
	u := ui.NewTest(&buf, false, false, 80)
	got := captureStdout(t, func() { printStatusHuman(u, s) })
	if n := strings.Count(got, "Credentials:"); n != 1 {
		t.Fatalf("Credentials lines = %d\n%s", n, got)
	}
	if !strings.Contains(got, "careful") || !strings.Contains(got, "The keychain is locked.") {
		t.Fatalf("missing warning/problem:\n%s", got)
	}
	if strings.Count(got, "Not signed in.") != 1 {
		t.Fatalf("problem account must not print 'Not signed in':\n%s", got)
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	f()
	_ = w.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(r)
	return b.String()
}
