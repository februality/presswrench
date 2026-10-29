// Package creds persists the per-install Pressable OAuth session: the
// dynamically registered OAuth client ID, the refresh token, the current
// access token and its expiry, and the signed-in identity (for display).
//
// Backends, in order of preference:
//
//  1. OS keychain (macOS Keychain, Windows Credential Manager, Linux
//     Secret Service) via github.com/99designs/keyring.
//  2. File fallback at <user config dir>/presswrench/credentials.json
//     (mode 0600) for headless Linux / WSL / Docker.
//
// PRESSWRENCH_ACCESS_TOKEN in the environment bypasses the store entirely
// (see internal/auth) — useful for CI and ephemeral containers.
//
// Multi-account model: attributes for named accounts are stored under
// composite keys ("<account>:<attr>"). DefaultAccount ("") uses the bare
// attribute name.
package creds

import (
	"errors"
)

const (
	ServiceName = "presswrench"

	KeyOAuthClientID = "oauth_client_id"
	KeyRefreshToken  = "refresh_token"
	KeyAccessToken   = "access_token"
	// KeyAccessExpiry is the access token's expiry as Unix seconds.
	KeyAccessExpiry = "access_expiry"
	// KeyIdentity is "Name <email>" of the signed-in Pressable user.
	KeyIdentity = "identity"

	// DefaultAccount is the empty-string sentinel for the unnamed account.
	DefaultAccount = ""
)

// SessionKeys lists every attribute that makes up a stored session, in the
// order they're deleted on logout.
var SessionKeys = []string{KeyAccessToken, KeyAccessExpiry, KeyRefreshToken, KeyIdentity, KeyOAuthClientID}

// Source tags where a credential came from. Surfaced in status / doctor.
type Source string

const (
	SourceEnv      Source = "env"
	SourceKeyring  Source = "keyring"
	SourceFile     Source = "file"
	SourceNotFound Source = "not_found"
)

// accountKey returns the storage key for an (account, attr) pair.
func accountKey(account, attr string) string {
	if account == DefaultAccount {
		return attr
	}
	return account + ":" + attr
}

// isSessionAttr reports whether attr is one of ours. Used to recognise
// account names when enumerating backend keys.
func isSessionAttr(attr string) bool {
	for _, k := range SessionKeys {
		if k == attr {
			return true
		}
	}
	return false
}

// Store is the persistence backend.
type Store interface {
	GetFor(account, attr string) (string, error)
	SetFor(account, attr, value string) error
	DeleteFor(account, attr string) error
	// Accounts returns every account with a stored refresh token.
	// DefaultAccount ("") is included when it has one.
	Accounts() ([]string, error)
	Backend() Source
}

// ErrNotFound is returned by GetFor when the requested key is absent.
var ErrNotFound = errors.New("credential not found")

// Open returns the best available Store for this environment. Tries the OS
// keychain first; falls back to FileStore on systems without one.
func Open() (Store, error) {
	if ks, err := openKeyring(); err == nil {
		return ks, nil
	}
	return OpenFile()
}

// ListAccounts returns every account with a stored session, sorted
// (DefaultAccount first when present).
func ListAccounts() ([]string, error) {
	store, err := Open()
	if err != nil {
		return nil, err
	}
	return store.Accounts()
}

// DeleteSession removes every stored attribute for the account. Missing
// attributes are not an error.
func DeleteSession(store Store, account string) error {
	var firstErr error
	for _, k := range SessionKeys {
		if err := store.DeleteFor(account, k); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
