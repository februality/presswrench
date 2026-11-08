// Package creds persists each account's Pressable OAuth session: the
// dynamically registered OAuth client ID, the refresh token, the current
// access token and its expiry, and the signed-in identity (for display).
//
// Each account is one versioned JSON Record stored under the key
// "session:<account>" ("session:default" for the default account), plus an
// account index under "accounts". Record encoding, versioning, size checks
// and the index live in recordStore; each backend only stores bytes by key:
//
//  1. OS keychain. macOS: the login keychain via /usr/bin/security, so the
//     item's ACL trusts Apple's stably signed tool rather than our ad-hoc
//     signed binary, whose cdhash changes on every build and re-triggers the
//     keychain prompt. Windows Credential Manager / Linux Secret Service:
//     github.com/99designs/keyring.
//  2. File fallback at <user config dir>/presswrench/credentials.json
//     (mode 0600) for headless Linux / WSL / Docker.
//
// PRESSWRENCH_ACCESS_TOKEN in the environment bypasses the store entirely
// (see internal/auth) — useful for CI and ephemeral containers.
package creds

import (
	"os"
	"path/filepath"
)

const (
	ServiceName = "presswrench"

	// DefaultAccount is the empty-string sentinel for the unnamed account.
	DefaultAccount = ""
)

// Source tags where a credential came from. Surfaced in status / doctor.
type Source string

const (
	SourceEnv      Source = "env"
	SourceKeyring  Source = "keyring"
	SourceFile     Source = "file"
	SourceNotFound Source = "not_found"
)

// Info describes a store for status / doctor.
type Info struct {
	Source      Source
	Description string // e.g. "macOS login keychain", or the file path
	Warning     string // why this store is in use or degraded, if notable
}

// Store persists one Record per account.
type Store interface {
	// Load returns the account's record; an error matching ErrNotFound
	// when there is none.
	Load(account string) (Record, error)
	// Save writes the whole record in one operation and indexes the account.
	Save(account string, r Record) error
	// Delete removes the record and its index entry; absent is not an error.
	Delete(account string) error
	// Accounts returns every signed-in account, sorted (DefaultAccount ""
	// first when present).
	Accounts() ([]string, error)
	Info() Info
}

// rawBackend stores opaque values by key. get of an absent key returns an
// *Error of KindNotFound; del of an absent key returns nil. maxValue is the
// largest value the backend accepts, 0 for unlimited.
type rawBackend interface {
	get(key string) ([]byte, error)
	set(key, label string, value []byte) error
	del(key string) error
	maxValue() int
}

// configDir is <user config dir>/presswrench; overridable in tests.
var configDir = func() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ServiceName), nil
}

// ConfigDir returns PressWrench's directory in the user config dir (lock
// files, the credentials file). Honors XDG_CONFIG_HOME on Unix.
func ConfigDir() (string, error) { return configDir() }

// DefaultFilePath returns the canonical credentials-file path for this OS.
func DefaultFilePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

// Open returns the best available Store for this environment: the OS
// keychain, else the file fallback.
func Open() (Store, error) {
	path, err := DefaultFilePath()
	if err != nil {
		return nil, err
	}
	if raw, info, err := openKeyring(); err == nil {
		return newRecordStore(raw, info, filepath.Dir(path)), nil
	}
	return NewFileStore(path), nil
}

// ListAccounts returns every signed-in account in the default store.
func ListAccounts() ([]string, error) {
	store, err := Open()
	if err != nil {
		return nil, err
	}
	return store.Accounts()
}

// Broken returns a Store whose every operation fails with err, so callers
// that couldn't open a store still have one to report through.
func Broken(err error) Store { return brokenStore{err} }

type brokenStore struct{ err error }

func (b brokenStore) Load(string) (Record, error) { return Record{}, b.err }
func (b brokenStore) Save(string, Record) error   { return b.err }
func (b brokenStore) Delete(string) error         { return b.err }
func (b brokenStore) Accounts() ([]string, error) { return nil, b.err }
func (b brokenStore) Info() Info {
	return Info{Source: SourceNotFound, Description: "unavailable", Warning: b.err.Error()}
}
