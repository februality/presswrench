package creds

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestFileStore_RoundTripAndAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "credentials.json")
	s := NewFileStore(path)

	if _, err := s.GetFor("", KeyRefreshToken); err != ErrNotFound {
		t.Fatalf("empty store: err = %v", err)
	}
	must(t, s.SetFor("", KeyRefreshToken, "r0"))
	must(t, s.SetFor("acme", KeyRefreshToken, "r1"))
	must(t, s.SetFor("acme", KeyOAuthClientID, "c1"))
	must(t, s.SetFor("half", KeyOAuthClientID, "c2")) // no refresh token: not an account

	if v, _ := s.GetFor("acme", KeyRefreshToken); v != "r1" {
		t.Errorf("acme refresh = %q", v)
	}
	accts, err := s.Accounts()
	must(t, err)
	if !reflect.DeepEqual(accts, []string{"", "acme"}) {
		t.Errorf("accounts = %q", accts)
	}

	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		must(t, err)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %o, want 600", st.Mode().Perm())
		}
	}

	must(t, DeleteSession(s, "acme"))
	must(t, DeleteSession(s, "half"))
	must(t, DeleteSession(s, ""))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should be removed when empty, stat err = %v", err)
	}
}

func TestAccountsFromKeys(t *testing.T) {
	keys := []string{
		"refresh_token", "access_token",
		"acme:refresh_token", "acme:oauth_client_id",
		"half:oauth_client_id",
		"weird:key:refresh_token",
	}
	got := accountsFromKeys(keys)
	want := []string{"", "acme", "weird:key"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("accountsFromKeys = %q, want %q", got, want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
