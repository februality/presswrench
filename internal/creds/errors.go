package creds

import (
	"errors"
	"strings"
)

// Kind classifies a storage failure so callers can tell "not signed in"
// apart from a store they can't reach right now.
type Kind int

const (
	KindOther       Kind = iota
	KindNotFound         // no item under the key
	KindLocked           // keychain locked or can't show a prompt here
	KindDenied           // the user (or ACL) refused access
	KindTimeout          // our deadline for a keychain call passed
	KindUnavailable      // the backend can't be opened at all
	KindCorrupt          // the stored value doesn't decode
	KindNewerFormat      // saved by a newer PressWrench
	KindTooLarge         // the record exceeds the backend's size limit
)

// ErrNotFound matches (errors.Is) every *Error of KindNotFound.
var ErrNotFound = errors.New("credential not found")

// Error is a classified storage error.
type Error struct {
	Kind    Kind
	Account string // "" is the default account
	Op      string // "open", "load", "save", "delete", "list", "index", "marker", "file"
	Backend Source
	Detail  string
	Err     error
}

func (e *Error) Error() string {
	var b strings.Builder
	switch e.Kind {
	case KindNotFound:
		b.WriteString("No stored PressWrench session")
	case KindLocked:
		b.WriteString("The credential store is locked or can't show a prompt here")
	case KindDenied:
		b.WriteString("Access to the stored PressWrench session was denied")
	case KindTimeout:
		b.WriteString("Timed out waiting for the credential store")
	case KindUnavailable:
		b.WriteString("The credential store is unavailable")
	case KindCorrupt:
		b.WriteString("The stored PressWrench session can't be read")
	case KindNewerFormat:
		b.WriteString("The stored PressWrench session was saved by a newer PressWrench")
	case KindTooLarge:
		b.WriteString("The PressWrench session is too large for the credential store")
	default:
		b.WriteString("Credential store error")
	}
	var ctx []string
	if e.Account != "" || e.Op == "load" || e.Op == "save" || e.Op == "delete" {
		ctx = append(ctx, "account "+accountLabel(e.Account))
	}
	if e.Op != "" {
		ctx = append(ctx, e.Op)
	}
	if e.Backend != "" {
		ctx = append(ctx, string(e.Backend))
	}
	if len(ctx) > 0 {
		b.WriteString(" (" + strings.Join(ctx, ", ") + ")")
	}
	switch {
	case e.Detail != "":
		b.WriteString(": " + e.Detail)
	case e.Err != nil:
		b.WriteString(": " + e.Err.Error())
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrNotFound) true for KindNotFound.
func (e *Error) Is(target error) bool {
	return target == ErrNotFound && e.Kind == KindNotFound
}

// KindOf returns the Kind of the first *Error in err's chain, or KindOther.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindOther
}

// Permanent reports whether retrying the same operation can't succeed.
func Permanent(err error) bool {
	switch KindOf(err) {
	case KindDenied, KindTooLarge, KindCorrupt, KindNewerFormat:
		return true
	}
	return false
}

// accountLabel is the human name of an account ("default" for "").
func accountLabel(account string) string {
	if account == DefaultAccount {
		return defaultStorageName
	}
	return account
}
