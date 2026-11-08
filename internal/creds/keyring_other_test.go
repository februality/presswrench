//go:build !darwin

package creds

import (
	"testing"
	"time"

	"github.com/99designs/keyring"
)

// hungKeyring blocks every call, like a locked Secret Service collection
// waiting on an unlock prompt.
type hungKeyring struct {
	keyring.Keyring
	release chan struct{}
}

func (h hungKeyring) Get(string) (keyring.Item, error) { <-h.release; return keyring.Item{}, nil }
func (h hungKeyring) Set(keyring.Item) error           { <-h.release; return nil }
func (h hungKeyring) Remove(string) error              { <-h.release; return nil }

func TestKeyringBackend_CallsTimeOut(t *testing.T) {
	shortKeychainTimeout(t, 50*time.Millisecond)
	release := make(chan struct{})
	defer close(release)
	k := &keyringBackend{r: hungKeyring{release: release}, sem: make(chan struct{}, 1)}
	if _, err := k.get("session:x"); KindOf(err) != KindTimeout {
		t.Errorf("get: kind = %v (%v)", KindOf(err), err)
	}
	if err := k.set("session:x", "L", []byte("v")); KindOf(err) != KindTimeout {
		t.Errorf("set: kind = %v (%v)", KindOf(err), err)
	}
	if err := k.del("session:x"); KindOf(err) != KindTimeout {
		t.Errorf("del: kind = %v (%v)", KindOf(err), err)
	}
}
