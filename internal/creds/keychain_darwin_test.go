//go:build darwin

package creds

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Touches the real login keychain under a throwaway service name, so it only
// runs when asked: PRESSWRENCH_KEYCHAIN_TEST=1 go test ./internal/creds/
func TestKeychainStore_RealKeychain(t *testing.T) {
	if os.Getenv("PRESSWRENCH_KEYCHAIN_TEST") != "1" {
		t.Skip("set PRESSWRENCH_KEYCHAIN_TEST=1 to run against the real keychain")
	}
	if _, _, err := openKeyring(); err != nil {
		t.Fatal(err)
	}
	raw := newSecurityBackend(fmt.Sprintf("presswrench-test-%d", time.Now().UnixNano()), execSecurity)
	s := newRecordStore(raw, Info{Source: SourceKeyring}, t.TempDir())
	t.Cleanup(func() {
		for _, a := range []string{"", "acme", "my-site-2"} {
			_ = s.Delete(a)
		}
		_ = raw.del(indexKey)
	})

	if _, err := s.Load(""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing record: err = %v, want ErrNotFound", err)
	}
	// JWT-sized access token, plus characters that need shell quoting.
	big := strings.Repeat("eyJhbGciOi.", 230) + ` it's "quoted" $HOME` + "\n é"
	want := Record{V: RecordVersion, ClientID: "c0", RefreshToken: "r0", AccessToken: big, AccessExpiry: 1794101512}
	must(t, s.Save("", want))
	must(t, s.Save("acme", Record{RefreshToken: "r1"}))
	must(t, s.Save("acme", Record{RefreshToken: "r2"})) // overwrite in place
	must(t, s.Save("my-site-2", Record{RefreshToken: "r3"}))

	if got, err := s.Load(""); err != nil || got != want {
		t.Fatalf("round-trip: err=%v, len=%d want %d", err, len(got.AccessToken), len(big))
	}
	if r, _ := s.Load("acme"); r.RefreshToken != "r2" {
		t.Errorf("acme refresh = %q, want r2", r.RefreshToken)
	}
	accts, err := s.Accounts()
	must(t, err)
	if !reflect.DeepEqual(accts, []string{"", "acme", "my-site-2"}) {
		t.Errorf("accounts = %q", accts)
	}

	must(t, s.Delete("acme"))
	must(t, s.Delete("acme")) // already gone: not an error
	if _, err := s.Load("acme"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: err = %v", err)
	}
}
