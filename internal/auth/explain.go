package auth

import (
	"errors"
	"runtime"
	"strings"

	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/lockfile"
)

// LoginRequiredError means there is no usable session for Account. Expired
// is true when Pressable rejected the refresh token (invalid_grant).
// StoreWarning is the store's Info().Warning, if any: an override that hides
// the store used at sign-in explains a "not signed in" that a terminal
// login wouldn't fix. It matches ErrLoginRequired with errors.Is.
type LoginRequiredError struct {
	Account      string
	Expired      bool
	StoreWarning string
}

func (e *LoginRequiredError) Error() string {
	if e.Expired {
		return "Pressable sign-in expired (account " + AccountLabel(e.Account) + ")"
	}
	return "not signed in to Pressable (account " + AccountLabel(e.Account) + ")"
}

func (e *LoginRequiredError) Is(target error) bool { return target == ErrLoginRequired }

// loginEnv returns this process's credential-store override (see
// creds.Override); a var for tests.
var loginEnv = creds.Override

// LoginCommand is the command that signs the account in. When this process
// runs with PRESSWRENCH_CREDENTIAL_STORE set (e.g. in an MCP client's env),
// the command sets it too, so a sign-in from a terminal lands in the store
// this process reads.
func LoginCommand(account string) string {
	cmd := bareLoginCommand(account)
	v := loginEnv()
	switch {
	case v == "":
		return cmd
	case runtime.GOOS == "windows":
		return `$env:` + creds.EnvCredentialStore + `="` + v + `"; ` + cmd
	}
	return creds.EnvCredentialStore + "=" + v + " " + cmd
}

func bareLoginCommand(account string) string {
	if account == "" {
		return "presswrench login"
	}
	return "presswrench login --account " + account
}

// AccountLabel renders an account name for humans: "default" for "".
func AccountLabel(account string) string {
	if account == "" {
		return "default"
	}
	return account
}

// Explain turns any storage or auth error into one actionable sentence.
func Explain(err error) string {
	if err == nil {
		return ""
	}
	var lr *LoginRequiredError
	if !errors.As(err, &lr) && errors.Is(err, ErrLoginRequired) {
		lr = &LoginRequiredError{} // bare sentinel: no account known
	}
	if lr != nil {
		cmd, label := "`"+LoginCommand(lr.Account)+"`", AccountLabel(lr.Account)
		msg := "Not signed in to Pressable (account " + label + "). Run " + cmd + " in a terminal, then retry."
		if lr.Expired {
			msg = "The Pressable sign-in for account " + label + " expired or was revoked. Run " + cmd + " in a terminal, then retry."
		}
		if lr.StoreWarning != "" {
			msg += " " + sentence(lr.StoreWarning)
		}
		return msg
	}
	var held *lockfile.HeldError
	if errors.As(err, &held) {
		if held.Reason != "" {
			return "Another PressWrench process holds a newer session it couldn't save: " + strings.TrimPrefix(held.Reason, unsavedPrefix)
		}
		return "Another PressWrench process is using the Pressable session. Retry in a moment."
	}
	var ce *creds.Error
	if errors.As(err, &ce) {
		cmd, label := "`"+LoginCommand(ce.Account)+"`", AccountLabel(ce.Account)
		switch ce.Kind {
		case creds.KindLocked:
			if runtime.GOOS == "darwin" {
				return "The macOS keychain is locked or can't show a prompt here (for example over SSH). Unlock it with `security unlock-keychain`, then retry."
			}
			return "The system keyring is locked. Unlock it, then retry."
		case creds.KindDenied:
			if ce.Backend == creds.SourceFile {
				return "PressWrench can't read or write its credentials file (" + ce.Detail + "). Fix its permissions (it should be yours, mode 0600), then retry."
			}
			return "Access to PressWrench's keychain item was denied. Retry and choose Always Allow when macOS asks."
		case creds.KindTimeout:
			if runtime.GOOS == "darwin" {
				return "macOS is waiting for you to approve keychain access for PressWrench. Approve the dialog (Always Allow), then retry."
			}
			return "The system keyring is waiting for you to unlock or approve access for PressWrench. Approve it, then retry."
		case creds.KindUnavailable:
			if ce.Op == "marker" {
				return "PressWrench can't tell which credential store holds your sessions: " + ce.Detail + ", then retry."
			}
			return "The system keyring isn't available (" + ce.Detail + "). Start it, or set PRESSWRENCH_CREDENTIAL_STORE=file and sign in again with `" + bareLoginCommand(ce.Account) + "`."
		case creds.KindCorrupt:
			if ce.Op == "index" {
				return "PressWrench's list of signed-in accounts is damaged. Sign in again with `" + LoginCommand("") + "` (and `--account <name>` for other accounts) to rebuild it."
			}
			return "The stored PressWrench session for account " + label + " is damaged. Run " + cmd + " to sign in again."
		case creds.KindNewerFormat:
			if ce.Op == "index" {
				return "PressWrench's list of signed-in accounts was saved by a newer PressWrench. Upgrade PressWrench."
			}
			return "The session for account " + label + " was saved by a newer PressWrench. Upgrade PressWrench, or sign in again with " + cmd + "."
		case creds.KindTooLarge:
			return "The PressWrench session for account " + label + " is too large for the system keyring (" + ce.Detail + "). Set PRESSWRENCH_CREDENTIAL_STORE=file and sign in again."
		}
	}
	return err.Error()
}
