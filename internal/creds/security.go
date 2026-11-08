package creds

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
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
// code (0 when it didn't run); err is non-nil when it failed to run or exited
// non-zero.
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
		// The process never ran (or was killed): say so.
		kind = KindUnavailable
		detail = fmt.Sprintf("%s the macOS keychain: could not run %s: %v", what, securityPath, err)
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

func (s *securityBackend) set(key, label string, value []byte) error {
	qs, err := quoteSecurityArg(s.service)
	if err != nil {
		return err
	}
	qk, err := quoteSecurityArg(key)
	if err != nil {
		return err
	}
	ql, err := quoteSecurityArg(label)
	if err != nil {
		return err
	}
	// The secret goes to `security -i` on stdin, never argv (visible in ps).
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -l %s -w %s\n", qs, qk, ql, base64.StdEncoding.EncodeToString(value))
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

func (s *securityBackend) maxValue() int { return 0 }

// quoteSecurityArg double-quotes a value for a `security -i` command line.
func quoteSecurityArg(v string) (string, error) {
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", &Error{Kind: KindOther, Backend: SourceKeyring, Detail: fmt.Sprintf("%q contains a line break and can't be stored in the macOS keychain", v)}
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(v) + `"`, nil
}

// execSecurity is the real runner on /usr/bin/security.
func execSecurity(ctx context.Context, stdin string, args ...string) (stdout, stderr []byte, exit int, err error) {
	cmd := exec.CommandContext(ctx, securityPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		exit = ee.ExitCode()
	}
	return so.Bytes(), se.Bytes(), exit, err
}
