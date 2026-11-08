//go:build darwin

package creds

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

func openKeyring() (rawBackend, Info, error) {
	if _, err := os.Stat(securityPath); err != nil {
		return nil, Info{}, &Error{Kind: KindUnavailable, Op: "open", Backend: SourceKeyring, Detail: "macOS keychain unavailable: " + err.Error(), Err: err}
	}
	return newSecurityBackend(ServiceName, execSecurity), Info{Source: SourceKeyring, Description: "macOS login keychain"}, nil
}

// execSecurity is the real runner on /usr/bin/security.
func execSecurity(ctx context.Context, stdin string, args ...string) (stdout, stderr []byte, exit int, err error) {
	return runCommand(ctx, securityPath, stdin, args...)
}

// waitDelay bounds how long runCommand waits for the output pipes after the
// timeout killed the process (a grandchild may hold them open).
var waitDelay = 5 * time.Second

// runCommand runs path with args, feeding stdin. exit is the exit code: 0
// when the process never started, -1 when a signal killed it.
func runCommand(ctx context.Context, path, stdin string, args ...string) (stdout, stderr []byte, exit int, err error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = waitDelay
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
