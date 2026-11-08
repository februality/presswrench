//go:build darwin

package creds

import "os"

func openKeyring() (rawBackend, Info, error) {
	if _, err := os.Stat(securityPath); err != nil {
		return nil, Info{}, &Error{Kind: KindUnavailable, Op: "open", Backend: SourceKeyring, Detail: "macOS keychain unavailable: " + err.Error(), Err: err}
	}
	return newSecurityBackend(ServiceName, execSecurity), Info{Source: SourceKeyring, Description: "macOS login keychain"}, nil
}
