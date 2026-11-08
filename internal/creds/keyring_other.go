//go:build !darwin

package creds

import (
	"errors"
	"runtime"

	"github.com/99designs/keyring"
)

// winCredLimit is Windows Credential Manager's blob size limit.
const winCredLimit = 2560

// keyringSem serializes calls into the keyring library: one call in flight
// per process (see callWithin).
var keyringSem = make(chan struct{}, 1)

// keyringBackend stores raw values in Windows Credential Manager or the
// Linux Secret Service. Every call is bounded by keychainTimeout and
// serialized through sem (see callWithin).
type keyringBackend struct {
	r   keyring.Keyring
	sem chan struct{}
}

// openKeyring opens an OS-native keyring. Restricts to backends that don't
// prompt for a passphrase: Windows Credential Manager, Linux Secret
// Service. Fails (KindUnavailable) on systems where none are present
// (headless Linux, Docker without a host bridge, WSL minimal).
func openKeyring() (rawBackend, Info, error) {
	unavailable := func(err error) (rawBackend, Info, error) {
		return nil, Info{}, &Error{Kind: KindUnavailable, Op: "open", Backend: SourceKeyring, Detail: err.Error(), Err: err}
	}
	r, err := keyring.Open(keyring.Config{
		ServiceName: ServiceName,
		AllowedBackends: []keyring.BackendType{
			keyring.WinCredBackend,
			keyring.SecretServiceBackend,
		},
	})
	if err != nil {
		return unavailable(err)
	}
	// Probe: a working backend should let us List() without error. This
	// surfaces "no D-Bus session" failures here instead of on first Set().
	// A probe that times out (waiting on an unlock prompt) is reported as
	// such: the keyring exists, so it must not fall back to the file.
	if _, err := callWithin(keyringSem, "opening", r.Keys); err != nil {
		if KindOf(err) == KindTimeout {
			return nil, Info{}, err
		}
		return unavailable(err)
	}
	desc := "Secret Service keyring"
	if runtime.GOOS == "windows" {
		desc = "Windows Credential Manager"
	}
	return &keyringBackend{r: r, sem: keyringSem}, Info{Source: SourceKeyring, Description: desc}, nil
}

func (k *keyringBackend) get(key string) ([]byte, error) {
	item, err := callWithin(k.sem, "reading", func() (keyring.Item, error) { return k.r.Get(key) })
	if KindOf(err) == KindTimeout {
		return nil, err
	}
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil, &Error{Kind: KindNotFound}
	}
	if err != nil {
		return nil, &Error{Kind: KindOther, Detail: err.Error(), Err: err}
	}
	return item.Data, nil
}

func (k *keyringBackend) set(key, label string, value []byte) error {
	_, err := callWithin(k.sem, "saving to", func() (struct{}, error) {
		return struct{}{}, k.r.Set(keyring.Item{
			Key:         key,
			Data:        value,
			Label:       label,
			Description: "PressWrench session",
		})
	})
	if KindOf(err) == KindTimeout {
		return err
	}
	if err != nil {
		return &Error{Kind: KindOther, Detail: err.Error(), Err: err}
	}
	return nil
}

func (k *keyringBackend) del(key string) error {
	_, err := callWithin(k.sem, "deleting from", func() (struct{}, error) { return struct{}{}, k.r.Remove(key) })
	if err == nil || errors.Is(err, keyring.ErrKeyNotFound) {
		return nil
	}
	if KindOf(err) == KindTimeout {
		return err
	}
	return &Error{Kind: KindOther, Detail: err.Error(), Err: err}
}

func (k *keyringBackend) maxValue() int {
	if runtime.GOOS == "windows" {
		return winCredLimit
	}
	return 0
}
