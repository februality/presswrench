package creds

import (
	"errors"
	"sort"
	"strings"

	"github.com/99designs/keyring"
)

type keyringStore struct {
	r keyring.Keyring
}

// openKeyring opens an OS-native keychain. Restricts to backends that don't
// prompt for a passphrase: macOS Keychain, Windows Credential Manager,
// Linux Secret Service. Returns an error on systems where none are present
// (headless Linux, Docker without a host bridge, WSL minimal).
func openKeyring() (Store, error) {
	r, err := keyring.Open(keyring.Config{
		ServiceName: ServiceName,
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.WinCredBackend,
			keyring.SecretServiceBackend,
		},
		KeychainTrustApplication:       true,
		KeychainAccessibleWhenUnlocked: true,
	})
	if err != nil {
		return nil, err
	}
	// Probe: a working backend should let us List() without error. This
	// surfaces "no D-Bus session" failures here instead of on first Set().
	if _, err := r.Keys(); err != nil {
		return nil, err
	}
	return &keyringStore{r: r}, nil
}

func (k *keyringStore) GetFor(account, attr string) (string, error) {
	item, err := k.r.Get(accountKey(account, attr))
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return "", ErrNotFound
		}
		return "", err
	}
	return string(item.Data), nil
}

func (k *keyringStore) SetFor(account, attr, value string) error {
	key := accountKey(account, attr)
	return k.r.Set(keyring.Item{
		Key:         key,
		Data:        []byte(value),
		Label:       ServiceName + "/" + key,
		Description: "PressWrench session",
	})
}

func (k *keyringStore) DeleteFor(account, attr string) error {
	err := k.r.Remove(accountKey(account, attr))
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil
	}
	return err
}

func (k *keyringStore) Accounts() ([]string, error) {
	keys, err := k.r.Keys()
	if err != nil {
		return nil, err
	}
	return accountsFromKeys(keys), nil
}

func (k *keyringStore) Backend() Source { return SourceKeyring }

// accountsFromKeys derives account names from raw backend keys: an account
// counts when it has a refresh token stored.
func accountsFromKeys(keys []string) []string {
	seen := map[string]struct{}{}
	for _, key := range keys {
		account, attr := DefaultAccount, key
		if idx := strings.LastIndex(key, ":"); idx >= 1 {
			account, attr = key[:idx], key[idx+1:]
		}
		if attr == KeyRefreshToken {
			seen[account] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
