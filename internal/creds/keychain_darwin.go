//go:build darwin

package creds

import (
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

// Items are generic passwords with service "presswrench" and account = the
// storage key ("<account>:<attr>", or the bare attr for the default account).
type keychainStore struct {
	service string
}

func openKeyring() (Store, error) {
	if err := exec.Command(securityPath, "default-keychain").Run(); err != nil {
		return nil, fmt.Errorf("macOS keychain unavailable: %w", err)
	}
	return &keychainStore{service: ServiceName}, nil
}

func (k *keychainStore) GetFor(account, attr string) (string, error) {
	v, err := keyring.Get(k.service, accountKey(account, attr))
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("Reading %q from the macOS keychain: %w", accountKey(account, attr), err)
	}
	return v, nil
}

func (k *keychainStore) SetFor(account, attr, value string) error {
	if err := keyring.Set(k.service, accountKey(account, attr), value); err != nil {
		return fmt.Errorf("Saving %q to the macOS keychain: %w", accountKey(account, attr), err)
	}
	return nil
}

func (k *keychainStore) DeleteFor(account, attr string) error {
	err := keyring.Delete(k.service, accountKey(account, attr))
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("Deleting %q from the macOS keychain: %w", accountKey(account, attr), err)
}

// Accounts lists items from `security dump-keychain` without -d: attributes
// only, so it reads no secrets and never prompts.
func (k *keychainStore) Accounts() ([]string, error) {
	out, err := exec.Command(securityPath, "dump-keychain").Output()
	if err != nil {
		return nil, fmt.Errorf("Listing macOS keychain items: %w", err)
	}
	return accountsFromKeys(keysFromKeychainDump(string(out), k.service)), nil
}

func (k *keychainStore) Backend() Source { return SourceKeyring }
