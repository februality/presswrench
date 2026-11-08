package creds

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// securityPath is Apple's keychain CLI. Every keychain read and write goes
// through it, so new items' ACLs trust /usr/bin/security (a stably signed
// system binary) instead of presswrench itself. Our binary is ad-hoc signed,
// the keychain pins those by cdhash, and the cdhash changes on every build.
const securityPath = "/usr/bin/security"

// keychainTimeout bounds every call to `security`; a locked keychain with no
// UI to prompt on would otherwise hang forever.
var keychainTimeout = 60 * time.Second

// runFunc runs `security` with args, feeding stdin. exit is the process exit
// code (0 when it didn't start, -1 when a signal killed it); err is non-nil
// when it failed to run or exited non-zero.
type runFunc func(ctx context.Context, stdin string, args ...string) (stdout, stderr []byte, exit int, err error)

type securityBackend struct {
	service string
	run     runFunc
}

func newSecurityBackend(service string, run runFunc) rawBackend {
	return &securityBackend{service: service, run: run}
}

// classifySecurity maps a `security` exit code to a Kind.
func classifySecurity(exit int, timedOut bool) Kind {
	if timedOut {
		return KindTimeout
	}
	switch exit {
	case 44:
		return KindNotFound
	case 36:
		return KindLocked
	case 128, 51:
		return KindDenied
	}
	return KindOther
}

// call runs one security invocation under the keychain timeout and turns a
// failure into a classified *Error.
func (s *securityBackend) call(what, stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keychainTimeout)
	defer cancel()
	stdout, stderr, exit, err := s.run(ctx, stdin, args...)
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	if err == nil && !timedOut {
		return stdout, nil
	}
	kind := classifySecurity(exit, timedOut)
	if kind == KindNotFound {
		return nil, &Error{Kind: KindNotFound, Backend: SourceKeyring, Err: err}
	}
	detail := strings.TrimSpace(string(stderr))
	switch {
	case timedOut:
		detail = fmt.Sprintf("%s the macOS keychain timed out after %s; unlock the keychain or approve its prompt and try again", what, keychainTimeout)
	case exit == 0 && err != nil:
		// The process never started: say so.
		kind = KindUnavailable
		detail = fmt.Sprintf("%s the macOS keychain: could not run %s: %v", what, securityPath, err)
	case exit < 0:
		// A signal (not our timeout, checked above) stopped it.
		detail = fmt.Sprintf("%s the macOS keychain failed: %s was killed by a signal (%v)", what, securityPath, err)
	case detail == "":
		detail = fmt.Sprintf("%s the macOS keychain failed (security exit %d)", what, exit)
	default:
		detail = fmt.Sprintf("%s the macOS keychain failed (security exit %d): %s", what, exit, detail)
	}
	return nil, &Error{Kind: kind, Backend: SourceKeyring, Detail: detail, Err: err}
}

func (s *securityBackend) get(key string) ([]byte, error) {
	out, err := s.call("reading", "", "find-generic-password", "-s", s.service, "-a", key, "-w")
	if err != nil {
		return nil, err
	}
	b, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if derr != nil {
		return nil, &Error{Kind: KindCorrupt, Backend: SourceKeyring, Detail: fmt.Sprintf("keychain item %q is not base64", key), Err: derr}
	}
	return b, nil
}

// setLine builds the `security -i` command that stores value. The secret
// goes to `security -i` on stdin, never argv (visible in ps).
func (s *securityBackend) setLine(key, label string, value []byte) (string, error) {
	qs, err := quoteSecurityArg(s.service)
	if err != nil {
		return "", err
	}
	qk, err := quoteSecurityArg(key)
	if err != nil {
		return "", err
	}
	ql, err := quoteSecurityArg(label)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("add-generic-password -U -s %s -a %s -l %s -w %s\n", qs, qk, ql, base64.StdEncoding.EncodeToString(value)), nil
}

func (s *securityBackend) set(key, label string, value []byte) error {
	line, err := s.setLine(key, label, value)
	if err != nil {
		return err
	}
	// Second guard behind maxValue: a longer line would be split and store
	// a truncated value over the good item.
	if len(line) > securityLineLimit {
		return &Error{Kind: KindTooLarge, Backend: SourceKeyring, Detail: fmt.Sprintf("the macOS keychain command would be %d bytes, the limit is %d", len(line), securityLineLimit)}
	}
	_, err = s.call("saving to", line, "-i")
	return err
}

func (s *securityBackend) del(key string) error {
	_, err := s.call("deleting from", "", "delete-generic-password", "-s", s.service, "-a", key)
	if err == nil || KindOf(err) == KindNotFound {
		return nil
	}
	return err
}

// securityLineLimit caps each `security -i` command line. security reads
// its commands in lines of about 4 KB and runs whatever follows the cut as a
// separate command (verified in the final review: the cut falls between 4093 and 4103
// bytes), so a longer add-generic-password would store a truncated value
// over the good item. 4000 leaves a margin.
const securityLineLimit = 4000

// maxAccountName is the longest account name the CLI accepts (see
// cli.validateAccount); maxValue sizes the cap for it.
const maxAccountName = 31

// maxValue is the largest raw value whose add line, for the longest account
// name, stays within securityLineLimit (about 2.9 KB). set re-checks the
// actual line.
func (s *securityBackend) maxValue() int {
	worst := strings.Repeat("a", maxAccountName)
	line, err := s.setLine(sessionKey(worst), itemLabel(worst), nil)
	if err != nil {
		return 1 // unquotable service name: every set fails anyway
	}
	return (securityLineLimit - len(line)) / 4 * 3 // base64: 4 bytes per 3
}

// quoteSecurityArg double-quotes a value for a `security -i` command line.
func quoteSecurityArg(v string) (string, error) {
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", &Error{Kind: KindOther, Backend: SourceKeyring, Detail: fmt.Sprintf("%q contains a line break and can't be stored in the macOS keychain", v)}
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(v) + `"`, nil
}
