package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/februality/presswrench/internal/creds"
)

// TestMain points the user config dir at a temp dir so SignIn's
// creds.RememberBackend never writes a marker into the real one, and clears
// the variables that would steer the session or the store.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "presswrench-auth-test")
	if err != nil {
		panic(err)
	}
	for _, k := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA"} {
		os.Setenv(k, dir)
	}
	for _, k := range []string{"PRESSWRENCH_ACCESS_TOKEN", "PRESSWRENCH_CREDENTIAL_STORE", "PRESSWRENCH_ACCOUNT"} {
		os.Unsetenv(k)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// The config dir every lock and marker resolves to must be the temp one.
func TestMain_ConfigDirIsIsolated(t *testing.T) {
	dir, err := creds.ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Clean(dir), filepath.Clean(os.TempDir())) {
		t.Fatalf("config dir %s is outside the temp dir", dir)
	}
}
