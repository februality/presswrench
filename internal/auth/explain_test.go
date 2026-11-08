package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/lockfile"
)

func TestAccountLabel(t *testing.T) {
	if AccountLabel("") != "default" || AccountLabel("acme") != "acme" {
		t.Error("AccountLabel")
	}
}

func TestExplain(t *testing.T) {
	locked := "The system keyring is locked. Unlock it, then retry."
	timeout := "The system keyring is waiting for you to unlock or approve access for PressWrench. Approve it, then retry."
	if runtime.GOOS == "darwin" {
		locked = "The macOS keychain is locked or can't show a prompt here (for example over SSH). Unlock it with `security unlock-keychain`, then retry."
		timeout = "macOS is waiting for you to approve keychain access for PressWrench. Approve the dialog (Always Allow), then retry."
	}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"login", &LoginRequiredError{Account: "acme"}, "Not signed in to Pressable (account acme). Run `presswrench login --account acme` in a terminal, then retry."},
		{"login default", fmt.Errorf("x: %w", &LoginRequiredError{}), "Not signed in to Pressable (account default). Run `presswrench login` in a terminal, then retry."},
		{"expired", &LoginRequiredError{Account: "acme", Expired: true}, "The Pressable sign-in for account acme expired or was revoked. Run `presswrench login --account acme` in a terminal, then retry."},
		{"locked", &creds.Error{Kind: creds.KindLocked, Account: "acme"}, locked},
		{"denied", &creds.Error{Kind: creds.KindDenied}, "Access to PressWrench's keychain item was denied. Retry and choose Always Allow when macOS asks."},
		{"timeout", &creds.Error{Kind: creds.KindTimeout}, timeout},
		{"unavailable", &creds.Error{Kind: creds.KindUnavailable, Detail: "no dbus"}, "The system keyring isn't available (no dbus). Start it, or set PRESSWRENCH_CREDENTIAL_STORE=file and sign in again with `presswrench login`."},
		{"corrupt", &creds.Error{Kind: creds.KindCorrupt, Account: "acme"}, "The stored PressWrench session for account acme is damaged. Run `presswrench login --account acme` to sign in again."},
		{"newer", &creds.Error{Kind: creds.KindNewerFormat, Account: "acme"}, "The session for account acme was saved by a newer PressWrench. Upgrade PressWrench, or sign in again with `presswrench login --account acme`."},
		{"toolarge", &creds.Error{Kind: creds.KindTooLarge, Account: "acme", Detail: "3000 > 2560 bytes"}, "The PressWrench session for account acme is too large for the system keyring (3000 > 2560 bytes). Set PRESSWRENCH_CREDENTIAL_STORE=file and sign in again."},
		{"held reason", &lockfile.HeldError{Path: "p", Reason: "keychain locked"}, "Another PressWrench process holds a newer session it couldn't save: keychain locked"},
		{"held unsaved", &lockfile.HeldError{Path: "p", Reason: unsavedPrefix + "account default: Boom. Sign in again with `presswrench login` to replace it."}, "Another PressWrench process holds a newer session it couldn't save: account default: Boom. Sign in again with `presswrench login` to replace it."},
		{"held wrapped", &creds.Error{Kind: creds.KindOther, Err: &lockfile.HeldError{Path: "p"}}, "Another PressWrench process is using the Pressable session. Retry in a moment."},
		{"other", errors.New("boom"), "boom"},
	}
	for _, c := range cases {
		if got := Explain(c.err); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// setLoginEnv makes LoginCommand see a credential-store override.
func setLoginEnv(t *testing.T, v string) {
	t.Helper()
	old := loginEnv
	loginEnv = func() string { return v }
	t.Cleanup(func() { loginEnv = old })
}

func TestLoginCommand_RepeatsStoreOverride(t *testing.T) {
	setLoginEnv(t, "file")
	want := "PRESSWRENCH_CREDENTIAL_STORE=file presswrench login --account dev"
	if runtime.GOOS == "windows" {
		want = `$env:PRESSWRENCH_CREDENTIAL_STORE="file"; presswrench login --account dev`
	}
	if got := LoginCommand("dev"); got != want {
		t.Errorf("LoginCommand = %q, want %q", got, want)
	}
	if got := Explain(&LoginRequiredError{Account: "dev"}); !strings.Contains(got, "`"+want+"`") {
		t.Errorf("Explain = %q, want it to give %q", got, want)
	}
	// The keyring-unavailable hint already says to set the variable.
	got := Explain(&creds.Error{Kind: creds.KindUnavailable, Detail: "no dbus"})
	if strings.Count(got, "PRESSWRENCH_CREDENTIAL_STORE") != 1 {
		t.Errorf("Explain(unavailable) = %q", got)
	}
}

func TestExplain_LoginRequiredCarriesStoreWarning(t *testing.T) {
	w := "PRESSWRENCH_CREDENTIAL_STORE=file overrides the keyring store used at sign-in; sessions saved there aren't visible."
	got := Explain(&LoginRequiredError{Account: "dev", StoreWarning: w})
	if !strings.HasPrefix(got, "Not signed in to Pressable (account dev).") || !strings.HasSuffix(got, " "+w) {
		t.Errorf("Explain = %q", got)
	}
}

func TestExplain_StoreMarker(t *testing.T) {
	got := Explain(&creds.Error{Kind: creds.KindUnavailable, Op: "marker", Detail: "the credential-store marker /x/store contains \"kyring\"; delete it or set PRESSWRENCH_CREDENTIAL_STORE=keyring or file"})
	want := "PressWrench can't tell which credential store holds your sessions: the credential-store marker /x/store contains \"kyring\"; delete it or set PRESSWRENCH_CREDENTIAL_STORE=keyring or file, then retry."
	if got != want {
		t.Errorf("Explain = %q\nwant      %q", got, want)
	}
}

func TestExplain_FileDeniedAndIndex(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&creds.Error{Kind: creds.KindDenied, Backend: creds.SourceFile, Op: "load", Detail: "reading credentials file /x/credentials.json: permission denied"},
			"PressWrench can't read or write its credentials file (reading credentials file /x/credentials.json: permission denied). Fix its permissions (it should be yours, mode 0600), then retry."},
		{&creds.Error{Kind: creds.KindCorrupt, Op: "index"},
			"PressWrench's list of signed-in accounts is damaged. Sign in again with `presswrench login` (and `--account <name>` for other accounts) to rebuild it."},
		{&creds.Error{Kind: creds.KindNewerFormat, Op: "index"},
			"PressWrench's list of signed-in accounts was saved by a newer PressWrench. Upgrade PressWrench."},
	}
	for _, c := range cases {
		if got := Explain(c.err); got != c.want {
			t.Errorf("Explain(%v)\n got %q\nwant %q", c.err, got, c.want)
		}
	}
}

// A credentials file we can't read surfaces as the file-permissions hint.
func TestExplain_UnreadableCredentialsFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	store := creds.NewFileStore(path)
	if err := store.Save("acme", creds.Record{RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	_, err := store.Load("acme")
	if got := Explain(err); !strings.HasPrefix(got, "PressWrench can't read or write its credentials file (") || !strings.Contains(got, path) {
		t.Errorf("Explain = %q", got)
	}
}
