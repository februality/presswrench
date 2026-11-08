package creds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/februality/presswrench/internal/lockfile"
)

const (
	// indexKey holds {"v":1,"accounts":[...]} with storage names.
	indexKey     = "accounts"
	indexVersion = 1
	indexLabel   = "PressWrench accounts"

	// defaultStorageName stands for DefaultAccount ("") in keys and the
	// index; "default" is reserved as an account name.
	defaultStorageName = "default"

	indexLockName = "accounts.lock"
	indexLockWait = 30 * time.Second
)

// sessionKey is the storage key of an account's record.
func sessionKey(account string) string { return "session:" + storageName(account) }

func storageName(account string) string {
	if account == DefaultAccount {
		return defaultStorageName
	}
	return account
}

func accountFromStorage(name string) string {
	if name == defaultStorageName {
		return DefaultAccount
	}
	return name
}

func itemLabel(account string) string {
	return "PressWrench session (" + accountLabel(account) + ")"
}

type indexValue struct {
	V        int      `json:"v"`
	Accounts []string `json:"accounts"`
}

// recordStore implements Store over any rawBackend: record encoding,
// versioning, the size check and the account index live here once.
type recordStore struct {
	raw     rawBackend
	info    Info
	lockDir string // where accounts.lock lives
}

func newRecordStore(raw rawBackend, info Info, lockDir string) Store {
	return &recordStore{raw: raw, info: info, lockDir: lockDir}
}

func (s *recordStore) Info() Info { return s.info }

// fail returns err as an *Error carrying op, account and backend.
func (s *recordStore) fail(op, account string, err error) error {
	var e *Error
	if errors.As(err, &e) {
		c := *e
		if c.Account == "" {
			c.Account = account
		}
		if c.Op == "" {
			c.Op = op
		}
		if c.Backend == "" {
			c.Backend = s.info.Source
		}
		return &c
	}
	return &Error{Kind: KindOther, Account: account, Op: op, Backend: s.info.Source, Err: err}
}

func (s *recordStore) Load(account string) (Record, error) {
	b, err := s.raw.get(sessionKey(account))
	if err != nil {
		return Record{}, s.fail("load", account, err)
	}
	r, err := decodeRecord(b)
	if err != nil {
		return Record{}, s.fail("load", account, err)
	}
	return r, nil
}

// Save writes the record, then adds the account to the index if it's
// missing (so a crash between the two leaves a record the next Save indexes).
func (s *recordStore) Save(account string, r Record) error {
	b, err := encodeRecord(r)
	if err != nil {
		return s.fail("save", account, err)
	}
	if err := s.checkSize(b); err != nil {
		return s.fail("save", account, err)
	}
	if err := s.raw.set(sessionKey(account), itemLabel(account), b); err != nil {
		return s.fail("save", account, err)
	}
	name := storageName(account)
	// Unlocked fast path, so steady-state saves skip the index lock. It can
	// race heal (heal sees the record absent, we write it, read the stale
	// index, heal drops the name): the record is then unindexed until its
	// next Save, which re-adds it. Needs a crash-left ghost plus a re-login
	// at that instant, so it's accepted.
	if names, err := s.readIndex(); err == nil && slices.Contains(names, name) {
		return nil
	}
	return s.updateIndex(account, indexLockWait, func(names []string) []string {
		if slices.Contains(names, name) {
			return names
		}
		return append(slices.Clone(names), name)
	})
}

// Delete removes the record, then its index entry.
func (s *recordStore) Delete(account string) error {
	if err := s.raw.del(sessionKey(account)); err != nil {
		return s.fail("delete", account, err)
	}
	name := storageName(account)
	if names, err := s.readIndex(); err == nil && !slices.Contains(names, name) {
		return nil
	}
	return s.updateIndex(account, indexLockWait, func(names []string) []string {
		return slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == name })
	})
}

// Accounts lists indexed accounts whose record holds a refresh token. A
// record that exists but can't be read right now (locked keychain, corrupt)
// is still listed, so status shows the real problem instead of hiding the
// account. Names whose record is gone are dropped from the index (best
// effort).
func (s *recordStore) Accounts() ([]string, error) {
	names, err := s.readIndex()
	if err != nil {
		return nil, s.fail("list", "", err)
	}
	out := []string{}
	var gone []string
	for _, n := range names {
		account := accountFromStorage(n)
		r, err := s.Load(account)
		switch {
		case err == nil:
			if r.SignedIn() {
				out = append(out, account)
			}
		case KindOf(err) == KindNotFound:
			gone = append(gone, n)
		default:
			out = append(out, account)
		}
	}
	if len(gone) > 0 {
		s.heal(gone)
	}
	sort.Strings(out)
	return out, nil
}

// heal drops names from the index whose record is (still) absent. It never
// waits for the index lock: listing must not block on another process.
func (s *recordStore) heal(gone []string) {
	_ = s.updateIndex("", 0, func(names []string) []string {
		return slices.DeleteFunc(slices.Clone(names), func(n string) bool {
			if !slices.Contains(gone, n) {
				return false
			}
			_, err := s.raw.get(sessionKey(accountFromStorage(n)))
			return KindOf(err) == KindNotFound
		})
	})
}

func (s *recordStore) checkSize(b []byte) error {
	if limit := s.raw.maxValue(); limit > 0 && len(b) > limit {
		return &Error{Kind: KindTooLarge, Detail: fmt.Sprintf("%d bytes, the limit is %d", len(b), limit)}
	}
	return nil
}

// readIndex returns the indexed storage names (nil when there's no index).
func (s *recordStore) readIndex() ([]string, error) {
	b, err := s.raw.get(indexKey)
	if KindOf(err) == KindNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var idx indexValue
	if err := decodeVersioned(b, indexVersion, &idx); err != nil {
		return nil, err
	}
	return idx.Accounts, nil
}

// updateIndex applies change to the index under the cross-process index
// lock. A corrupt index is rebuilt from scratch: it is derived data, and
// accounts it loses reappear on their next Save. An index that becomes
// empty is deleted.
func (s *recordStore) updateIndex(account string, wait time.Duration, change func([]string) []string) error {
	lock, err := lockfile.Acquire(context.Background(), filepath.Join(s.lockDir, indexLockName), wait)
	if err != nil {
		return s.fail("index", account, err)
	}
	defer lock.Release()

	names, err := s.readIndex()
	corrupt := KindOf(err) == KindCorrupt
	if err != nil && !corrupt {
		return s.fail("index", account, err)
	}
	next := change(names)
	sort.Strings(next)
	next = slices.Compact(next)
	if !corrupt && slices.Equal(next, sortedCopy(names)) {
		return nil
	}
	if len(next) == 0 {
		if err := s.raw.del(indexKey); err != nil {
			return s.fail("index", account, err)
		}
		return nil
	}
	b, err := json.Marshal(indexValue{V: indexVersion, Accounts: next})
	if err != nil {
		return s.fail("index", account, err)
	}
	if err := s.checkSize(b); err != nil {
		return s.fail("index", account, err)
	}
	if err := s.raw.set(indexKey, indexLabel, b); err != nil {
		return s.fail("index", account, err)
	}
	return nil
}

func sortedCopy(names []string) []string {
	c := slices.Clone(names)
	sort.Strings(c)
	return slices.Compact(c)
}
