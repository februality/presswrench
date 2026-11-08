//go:build darwin

package creds

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"

	"github.com/zalando/go-keyring"
)

// securityPath is Apple's keychain CLI. Every read and write goes through it
// (via zalando/go-keyring), so new items' ACLs trust /usr/bin/security — a
// stably signed system binary — instead of presswrench itself. Our binary is
// ad-hoc signed, the keychain pins ad-hoc binaries by cdhash, and the cdhash
// changes on every build and upgrade; trusting it directly meant a password
// prompt from every new `serve` process after each update.
const securityPath = "/usr/bin/security"

// keychainBackend stores raw values as generic passwords with service
// "presswrench" and account = the storage key. The value is base64 of the
// raw bytes. Interim: labels aren't set until the direct `security` wrapper
// replaces zalando.
type keychainBackend struct {
	service string
}

func openKeyring() (rawBackend, Info, error) {
	if err := exec.Command(securityPath, "default-keychain").Run(); err != nil {
		return nil, Info{}, &Error{Kind: KindUnavailable, Op: "open", Backend: SourceKeyring, Detail: "macOS keychain unavailable: " + err.Error(), Err: err}
	}
	return &keychainBackend{service: ServiceName}, Info{Source: SourceKeyring, Description: "macOS login keychain"}, nil
}

func (k *keychainBackend) get(key string) ([]byte, error) {
	v, err := keyring.Get(k.service, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, &Error{Kind: KindNotFound}
	}
	if err != nil {
		return nil, &Error{Kind: KindOther, Detail: fmt.Sprintf("reading %q from the macOS keychain: %v", key, err), Err: err}
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, &Error{Kind: KindCorrupt, Detail: fmt.Sprintf("keychain item %q is not base64", key), Err: err}
	}
	return b, nil
}

func (k *keychainBackend) set(key, _ string, value []byte) error {
	err := keyring.Set(k.service, key, base64.StdEncoding.EncodeToString(value))
	if errors.Is(err, keyring.ErrSetDataTooBig) {
		return &Error{Kind: KindTooLarge, Detail: fmt.Sprintf("%d bytes is too large for the macOS keychain", len(value)), Err: err}
	}
	if err != nil {
		return &Error{Kind: KindOther, Detail: fmt.Sprintf("saving %q to the macOS keychain: %v", key, err), Err: err}
	}
	return nil
}

func (k *keychainBackend) del(key string) error {
	err := keyring.Delete(k.service, key)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return &Error{Kind: KindOther, Detail: fmt.Sprintf("deleting %q from the macOS keychain: %v", key, err), Err: err}
}

func (k *keychainBackend) maxValue() int { return 0 }
