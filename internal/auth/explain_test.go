package auth

import (
	"errors"
	"fmt"
	"runtime"
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
	if runtime.GOOS == "darwin" {
		locked = "The macOS keychain is locked or can't show a prompt here (for example over SSH). Unlock it with `security unlock-keychain`, then retry."
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
		{"timeout", &creds.Error{Kind: creds.KindTimeout}, "macOS is waiting for you to approve keychain access for PressWrench. Approve the dialog (Always Allow), then retry."},
		{"unavailable", &creds.Error{Kind: creds.KindUnavailable, Detail: "no dbus"}, "The system keyring isn't available (no dbus). Start it, or set PRESSWRENCH_CREDENTIAL_STORE=file and sign in again with `presswrench login`."},
		{"corrupt", &creds.Error{Kind: creds.KindCorrupt, Account: "acme"}, "The stored PressWrench session for account acme is damaged. Run `presswrench login --account acme` to sign in again."},
		{"newer", &creds.Error{Kind: creds.KindNewerFormat, Account: "acme"}, "The session for account acme was saved by a newer PressWrench. Upgrade PressWrench, or sign in again with `presswrench login --account acme`."},
		{"toolarge", &creds.Error{Kind: creds.KindTooLarge, Account: "acme", Detail: "3000 > 2560 bytes"}, "The PressWrench session for account acme is too large for the system keyring (3000 > 2560 bytes). Set PRESSWRENCH_CREDENTIAL_STORE=file and sign in again."},
		{"held reason", &lockfile.HeldError{Path: "p", Reason: "keychain locked"}, "Another PressWrench process holds a newer session it couldn't save: keychain locked"},
		{"held wrapped", &creds.Error{Kind: creds.KindOther, Err: &lockfile.HeldError{Path: "p"}}, "Another PressWrench process is refreshing the Pressable session. Retry in a moment."},
		{"other", errors.New("boom"), "boom"},
	}
	for _, c := range cases {
		if got := Explain(c.err); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
