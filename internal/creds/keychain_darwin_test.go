//go:build darwin

package creds

import (
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
	if _, err := openKeyring(); err != nil {
		t.Fatal(err)
	}
	k := &keychainStore{service: fmt.Sprintf("presswrench-test-%d", time.Now().UnixNano())}
	t.Cleanup(func() {
		for _, a := range []string{"", "acme"} {
			_ = DeleteSession(k, a)
		}
	})

	if _, err := k.GetFor("", KeyRefreshToken); err != ErrNotFound {
		t.Fatalf("missing key: err = %v, want ErrNotFound", err)
	}
	// JWT-sized access token, plus characters that need shell quoting.
	big := strings.Repeat("eyJhbGciOi.", 230) + ` it's "quoted" $HOME`
	must(t, k.SetFor("", KeyAccessToken, big))
	must(t, k.SetFor("", KeyRefreshToken, "r0"))
	must(t, k.SetFor("acme", KeyRefreshToken, "r1"))
	must(t, k.SetFor("acme", KeyRefreshToken, "r2")) // overwrite in place

	if v, err := k.GetFor("", KeyAccessToken); err != nil || v != big {
		t.Fatalf("access token round-trip: err=%v, len=%d want %d", err, len(v), len(big))
	}
	if v, _ := k.GetFor("acme", KeyRefreshToken); v != "r2" {
		t.Errorf("acme refresh = %q, want r2", v)
	}
	accts, err := k.Accounts()
	must(t, err)
	if !reflect.DeepEqual(accts, []string{"", "acme"}) {
		t.Errorf("accounts = %q", accts)
	}

	must(t, DeleteSession(k, "acme"))
	must(t, k.DeleteFor("acme", KeyRefreshToken)) // already gone: not an error
	if _, err := k.GetFor("acme", KeyRefreshToken); err != ErrNotFound {
		t.Errorf("after delete: err = %v", err)
	}
}
