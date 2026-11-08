package cli

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/creds"
)

// withTempHome redirects HOME so patcher constructors compute paths under
// the temp dir. Mirror of clients/patcher_test.go's helper.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
		t.Setenv("APPDATA", dir+"\\AppData\\Roaming")
	}
	t.Setenv("XDG_CONFIG_HOME", dir+"/.config")
	return dir
}

func TestListAccounts_DiscoversFromClientConfigs(t *testing.T) {
	withTempHome(t)
	// An empty temp store: the only accounts we discover come from client configs.
	store := creds.NewFileStore(filepath.Join(t.TempDir(), "creds.json"))

	// Patch claude-code with legacy and one named entry.
	if _, _, err := clients.ByID("claude-code", "").Patch("/usr/local/bin/presswrench", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clients.ByID("claude-code", "acme").Patch("/usr/local/bin/presswrench", map[string]string{"PRESSWRENCH_ACCOUNT": "acme"}, false); err != nil {
		t.Fatal(err)
	}

	rows, err := listAccounts(store)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"": false, "acme": false}
	for _, r := range rows {
		if _, ok := want[r.Name]; ok {
			want[r.Name] = true
		}
		// HasCredentials may be false since we didn't write creds, but the
		// entry-discovery side should still surface the account.
		if len(r.ClientEntries) == 0 {
			t.Errorf("account %q has no client entries (rows: %+v)", r.Name, rows)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("account %q not discovered (got rows: %+v)", name, rows)
		}
	}
}

func TestListAccounts_EmptyState(t *testing.T) {
	withTempHome(t)
	store := creds.NewFileStore(filepath.Join(t.TempDir(), "creds.json"))
	rows, err := listAccounts(store)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows = %+v, err = %v", rows, err)
	}
}

func TestListAccounts_StoreErrorStillListsClients(t *testing.T) {
	withTempHome(t)
	if _, _, err := clients.ByID("claude-code", "acme").Patch("/usr/local/bin/presswrench", map[string]string{"PRESSWRENCH_ACCOUNT": "acme"}, false); err != nil {
		t.Fatal(err)
	}
	store := creds.Broken(&creds.Error{Kind: creds.KindLocked, Op: "list"})
	rows, err := listAccounts(store)
	if err == nil || creds.KindOf(err) != creds.KindLocked {
		t.Fatalf("err = %v, want a locked-keychain error", err)
	}
	if len(rows) != 1 || rows[0].Name != "acme" || rows[0].HasCredentials {
		t.Fatalf("rows = %+v", rows)
	}
}
