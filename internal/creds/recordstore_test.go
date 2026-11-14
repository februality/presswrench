package creds

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeRaw is an in-memory rawBackend with a settable size limit and
// per-key error injection.
type fakeRaw struct {
	mu     sync.Mutex
	items  map[string][]byte
	max    int
	getErr map[string]error
	setErr map[string]error
	delErr map[string]error
}

func newFakeRaw() *fakeRaw {
	return &fakeRaw{items: map[string][]byte{}, getErr: map[string]error{}, setErr: map[string]error{}, delErr: map[string]error{}}
}

func (f *fakeRaw) get(key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.getErr[key]; err != nil {
		return nil, err
	}
	v, ok := f.items[key]
	if !ok {
		return nil, &Error{Kind: KindNotFound}
	}
	return append([]byte(nil), v...), nil
}

func (f *fakeRaw) set(key, _ string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.setErr[key]; err != nil {
		return err
	}
	f.items[key] = append([]byte(nil), value...)
	return nil
}

func (f *fakeRaw) del(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.delErr[key]; err != nil {
		return err
	}
	delete(f.items, key)
	return nil
}

func (f *fakeRaw) maxValue() int { return f.max }

func (f *fakeRaw) indexNames(t *testing.T) []string {
	t.Helper()
	b, err := f.get(indexKey)
	if err != nil {
		if KindOf(err) == KindNotFound {
			return nil
		}
		t.Fatal(err)
	}
	var idx struct {
		Accounts []string `json:"accounts"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	return idx.Accounts
}

func newFakeStore(t *testing.T) (*fakeRaw, Store) {
	raw := newFakeRaw()
	return raw, newRecordStore(raw, Info{Source: SourceKeyring, Description: "fake keyring"}, t.TempDir())
}

func TestRecord_RoundTripAndVersion(t *testing.T) {
	for name, s := range map[string]Store{
		"file": NewFileStore(filepath.Join(t.TempDir(), "sub", "credentials.json")),
		"raw":  func() Store { _, s := newFakeStore(t); return s }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Load("acme"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("empty store: err = %v, want ErrNotFound", err)
			}
			in := Record{
				ClientID: "c1", RefreshToken: "r1", AccessToken: `a"b$c\n` + "é",
				AccessExpiry: 1794101512, Identity: "Jane Doe <jane@example.com>",
			}
			must(t, s.Save("acme", in))
			got, err := s.Load("acme")
			must(t, err)
			want := in
			want.V = RecordVersion
			if got != want {
				t.Errorf("Load = %+v, want %+v", got, want)
			}
			if got.V != 1 {
				t.Errorf("V = %d, want 1", got.V)
			}
		})
	}
}

func TestRecord_NewerFormat(t *testing.T) {
	raw, s := newFakeStore(t)
	must(t, raw.set(sessionKey("acme"), "", []byte(`{"v":2,"refresh_token":"r","shiny":{"x":1}}`)))
	_, err := s.Load("acme")
	if KindOf(err) != KindNewerFormat {
		t.Fatalf("kind = %v (err %v), want KindNewerFormat", KindOf(err), err)
	}
	var e *Error
	if !errors.As(err, &e) || e.Account != "acme" {
		t.Fatalf("err = %#v, want *Error with Account acme", err)
	}
	if !Permanent(err) {
		t.Error("NewerFormat should be permanent")
	}
}

func TestRecord_Corrupt(t *testing.T) {
	raw, s := newFakeStore(t)
	for _, v := range []string{"not json", `{"refresh_token":"r"}`} { // garbled; no version
		must(t, raw.set(sessionKey("acme"), "", []byte(v)))
		if _, err := s.Load("acme"); KindOf(err) != KindCorrupt {
			t.Errorf("%q: kind = %v (err %v), want KindCorrupt", v, KindOf(err), err)
		}
	}
}

func TestSessionKey(t *testing.T) {
	if got := sessionKey(""); got != "session:default" {
		t.Errorf(`sessionKey("") = %q`, got)
	}
	if got := sessionKey("acme"); got != "session:acme" {
		t.Errorf(`sessionKey("acme") = %q`, got)
	}
}

func TestAccounts_OnlySignedIn(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "credentials.json"))
	must(t, s.Save("", Record{ClientID: "c0", RefreshToken: "r0"}))
	must(t, s.Save("acme", Record{ClientID: "c1", RefreshToken: "r1"}))
	must(t, s.Save("half", Record{ClientID: "c2"}))
	accts, err := s.Accounts()
	must(t, err)
	if !reflect.DeepEqual(accts, []string{"", "acme"}) {
		t.Errorf("accounts = %q, want [\"\" \"acme\"]", accts)
	}
}

func TestAccounts_SelfHealsIndex(t *testing.T) {
	raw, s := newFakeStore(t)
	must(t, s.Save("acme", Record{ClientID: "c", RefreshToken: "r"}))
	must(t, raw.set(indexKey, "", []byte(`{"v":1,"accounts":["acme","ghost"]}`)))

	accts, err := s.Accounts()
	must(t, err)
	if !reflect.DeepEqual(accts, []string{"acme"}) {
		t.Errorf("accounts = %q, want [acme]", accts)
	}
	if idx := raw.indexNames(t); !reflect.DeepEqual(idx, []string{"acme"}) {
		t.Errorf("index after heal = %q, want [acme]", idx)
	}

	// A record without an index entry (crash between the two writes) is
	// picked up by its next Save.
	b, err := json.Marshal(Record{V: RecordVersion, ClientID: "c", RefreshToken: "r"})
	must(t, err)
	must(t, raw.set(sessionKey("orphan"), "", b))
	if accts, _ := s.Accounts(); !reflect.DeepEqual(accts, []string{"acme"}) {
		t.Errorf("unindexed record listed early: %q", accts)
	}
	must(t, s.Save("orphan", Record{ClientID: "c", RefreshToken: "r2"}))
	accts, err = s.Accounts()
	must(t, err)
	if !reflect.DeepEqual(accts, []string{"acme", "orphan"}) {
		t.Errorf("accounts = %q, want [acme orphan]", accts)
	}
}

// An indexed account whose record exists but can't be read (corrupt,
// locked keychain) stays listed, so status shows the real problem instead
// of "not signed in"; an indexed account whose record is gone is not.
func TestAccounts_ListsUnreadableNotAbsent(t *testing.T) {
	raw, s := newFakeStore(t)
	must(t, s.Save("ok", Record{ClientID: "c", RefreshToken: "r"}))
	must(t, raw.set(sessionKey("broken"), "", []byte("not json")))
	must(t, raw.set(sessionKey("locked"), "", []byte(`{"v":1,"refresh_token":"r"}`)))
	raw.getErr[sessionKey("locked")] = &Error{Kind: KindLocked}
	must(t, raw.set(indexKey, "", []byte(`{"v":1,"accounts":["absent","broken","locked","ok"]}`)))

	accts, err := s.Accounts()
	must(t, err)
	if want := []string{"broken", "locked", "ok"}; !reflect.DeepEqual(accts, want) {
		t.Errorf("accounts = %q, want %q", accts, want)
	}
	if idx := raw.indexNames(t); !reflect.DeepEqual(idx, []string{"broken", "locked", "ok"}) {
		t.Errorf("index = %q: only the absent record should be dropped", idx)
	}
}

func TestAccounts_ConcurrentSavesBothIndexed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	stores := []Store{NewFileStore(path), NewFileStore(path)}
	names := []string{"a", "b"}
	var wg sync.WaitGroup
	errs := make(chan error, 2*20)
	for i := range stores {
		wg.Add(1)
		go func(s Store, name string) {
			defer wg.Done()
			for round := 0; round < 20; round++ {
				if err := s.Save(name, Record{ClientID: "c", RefreshToken: name + "-" + string(rune('A'+round))}); err != nil {
					errs <- err
				}
			}
		}(stores[i], names[i])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	accts, err := NewFileStore(path).Accounts()
	must(t, err)
	if !reflect.DeepEqual(accts, []string{"a", "b"}) {
		t.Errorf("accounts = %q, want [a b]", accts)
	}
	for _, name := range names {
		r, err := stores[0].Load(name)
		must(t, err)
		if want := name + "-" + string(rune('A'+19)); r.RefreshToken != want {
			t.Errorf("%s refresh = %q, want %q (a write was lost)", name, r.RefreshToken, want)
		}
	}
}

// Each writer saves once, so no later Save can re-add what a racing write
// dropped: every record and index entry must survive.
func TestFileStore_ConcurrentWritersLoseNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			s := NewFileStore(path) // one instance per writer, like separate processes
			<-start
			if err := s.Save(name, Record{ClientID: "c", RefreshToken: "r-" + name}); err != nil {
				errs <- err
			}
		}(string(rune('a' + i)))
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	s := NewFileStore(path)
	accts, err := s.Accounts()
	must(t, err)
	if len(accts) != n {
		t.Errorf("accounts = %q, want %d", accts, n)
	}
	for i := 0; i < n; i++ {
		name := string(rune('a' + i))
		if r, err := s.Load(name); err != nil || r.RefreshToken != "r-"+name {
			t.Errorf("%s: %+v, %v (write lost)", name, r, err)
		}
	}
}

func TestDelete_RemovesRecordAndIndex(t *testing.T) {
	raw, s := newFakeStore(t)
	must(t, s.Save("acme", Record{ClientID: "c", RefreshToken: "r"}))
	must(t, s.Save("beta", Record{ClientID: "c", RefreshToken: "r"}))
	must(t, s.Delete("acme"))
	if _, err := s.Load("acme"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Load after Delete: err = %v, want ErrNotFound", err)
	}
	accts, err := s.Accounts()
	must(t, err)
	if !reflect.DeepEqual(accts, []string{"beta"}) {
		t.Errorf("accounts = %q, want [beta]", accts)
	}
	if idx := raw.indexNames(t); !reflect.DeepEqual(idx, []string{"beta"}) {
		t.Errorf("index = %q, want [beta]", idx)
	}
	must(t, s.Delete("acme")) // absent: not an error
	must(t, s.Delete("never"))
	must(t, s.Delete("beta"))
	if _, ok := raw.items[indexKey]; ok {
		t.Error("empty index item should be deleted")
	}
}

func TestSave_TooLarge(t *testing.T) {
	raw, s := newFakeStore(t)
	raw.max = 2560
	err := s.Save("acme", Record{ClientID: "c", RefreshToken: "r", AccessToken: strings.Repeat("x", 3000)})
	if KindOf(err) != KindTooLarge {
		t.Fatalf("kind = %v (err %v), want KindTooLarge", KindOf(err), err)
	}
	if !Permanent(err) {
		t.Error("TooLarge should be permanent")
	}
	if len(raw.items) != 0 {
		t.Errorf("raw store touched: %q", raw.items)
	}
}

func TestFileStore_ModeAndRemovalWhenEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "credentials.json")
	s := NewFileStore(path)
	if info := s.Info(); info.Source != SourceFile || info.Description != path {
		t.Errorf("Info = %+v", info)
	}
	must(t, s.Save("acme", Record{ClientID: "c", RefreshToken: "r"}))
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		must(t, err)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %o, want 600", st.Mode().Perm())
		}
	}
	must(t, s.Delete("acme"))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should be removed when empty, stat err = %v", err)
	}
}

// A damaged index is not any account's record: its errors say "index".
func TestAccounts_CorruptIndexIsAnIndexError(t *testing.T) {
	raw, s := newFakeStore(t)
	raw.items[indexKey] = []byte("{not json")
	_, err := s.Accounts()
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindCorrupt || e.Op != "index" || e.Account != "" {
		t.Fatalf("err = %#v, want a KindCorrupt index error", err)
	}
	// The next Save rebuilds it.
	if err := s.Save("acme", Record{RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Accounts(); err != nil || len(got) != 1 || got[0] != "acme" {
		t.Fatalf("Accounts = %q, %v", got, err)
	}
}

// A damaged or newer credentials file isn't one record's problem: every
// load, save and listing reports it with Op "file", because signing in again
// (a save) can't get past it.
func TestFileStore_DamagedFileIsAFileError(t *testing.T) {
	for _, c := range []struct {
		content string
		kind    Kind
	}{
		{"{not json", KindCorrupt},
		{`{"v":1,"items":[1]}`, KindCorrupt},
		{`{"v":99,"items":{}}`, KindNewerFormat},
	} {
		path := filepath.Join(t.TempDir(), "credentials.json")
		if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		s := NewFileStore(path)
		_, lerr := s.Load("acme")
		serr := s.Save("acme", Record{RefreshToken: "r"})
		_, aerr := s.Accounts()
		for name, err := range map[string]error{"load": lerr, "save": serr, "accounts": aerr} {
			var e *Error
			if !errors.As(err, &e) || e.Kind != c.kind || e.Op != "file" {
				t.Errorf("%q %s: err = %#v, want Kind %v Op file", c.content, name, err, c.kind)
			}
		}
	}
}
