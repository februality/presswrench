package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/mcpserver"
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
	want := "The system keyring is locked"
	if runtime.GOOS == "darwin" {
		want = "security unlock-keychain"
	}
	if !strings.Contains(as.Session.Problem, want) {
		t.Fatalf("Problem = %q, want it to contain %q", as.Session.Problem, want)
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
	// printStatusHuman writes to stdout via fmt; the UI only supplies marks.
	u := ui.NewTest(&bytes.Buffer{}, false, false, 80)
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
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = b.ReadFrom(r)
		done <- b.String()
	}()
	defer func() { os.Stdout = old }()
	f()
	_ = w.Close()
	return <-done
}

func failOpen(t *testing.T) {
	t.Helper()
	old := openStore
	openStore = func() (creds.Store, error) {
		return nil, &creds.Error{Kind: creds.KindUnavailable, Detail: "no dbus"}
	}
	t.Cleanup(func() { openStore = old })
}

func TestRunDoctor_DegradedStoreWarns(t *testing.T) {
	isolate(t)
	useStore(t, infoStore{tempStore(t), creds.Info{Source: creds.SourceFile, Description: "file /x (keyring unavailable: no dbus)"}})
	var buf bytes.Buffer
	_ = captureStdout(t, func() { _ = runDoctor(ui.NewTest(&buf, false, false, 100), "") })
	if !strings.Contains(buf.String(), "▲") && !strings.Contains(buf.String(), "!") {
		t.Fatalf("no warn mark:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "keyring unavailable") {
		t.Fatalf("store not shown:\n%s", buf.String())
	}
}

func TestRunDoctor_OpenFailureDoesNotClaimNoAccounts(t *testing.T) {
	isolate(t)
	failOpen(t)
	var buf bytes.Buffer
	var err error
	_ = captureStdout(t, func() { err = runDoctor(ui.NewTest(&buf, false, false, 100), "") })
	if err == nil || !ui.IsReported(err) {
		t.Fatalf("err = %v, want a reported store error", err)
	}
	if strings.Contains(buf.String(), "No accounts configured") || strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("claimed no accounts:\n%s\n%v", buf.String(), err)
	}
	if !strings.Contains(buf.String(), "PRESSWRENCH_CREDENTIAL_STORE=file") {
		t.Fatalf("missing fix:\n%s", buf.String())
	}
}

func TestAccountsList_StoreErrorNoClients(t *testing.T) {
	withTempHome(t)
	isolate(t)
	failOpen(t)
	cmd := NewAccounts()
	cmd.SetArgs([]string{"list"})
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	if err == nil || !ui.IsReported(err) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(out, "No accounts configured") || !strings.Contains(out, "Could not read the stored sessions") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestSetup_OpenStoreFailureIsExplained(t *testing.T) {
	isolate(t)
	failOpen(t)
	cmd := NewSetup()
	cmd.SetArgs([]string{"--unattended", "--skip-ssh", "--skip-clients"})
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	if err == nil || !ui.IsReported(err) {
		t.Fatalf("err = %v, want reported", err)
	}
	if !strings.Contains(out, "PRESSWRENCH_CREDENTIAL_STORE=file") || strings.Contains(out, "open credentials store:") {
		t.Fatalf("output:\n%s", out)
	}
}

// doctor closes the session it builds, so a session that couldn't save
// never keeps the account lock after doctor exits.
func TestDoctorAccount_ClosesSession(t *testing.T) {
	isolate(t)
	var deps *mcpserver.Deps
	old := buildDeps
	buildDeps = func(c *config.Config, st creds.Store) *mcpserver.Deps {
		deps = old(c, st)
		return deps
	}
	t.Cleanup(func() { buildDeps = old })
	var buf bytes.Buffer
	_ = captureStdout(t, func() { _ = doctorAccount(ui.NewTest(&buf, false, false, 100), tempStore(t), "", "") })
	if deps == nil {
		t.Fatal("doctor built no deps")
	}
	if _, err := deps.Session.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Errorf("session not closed: Token err = %v", err)
	}
}
