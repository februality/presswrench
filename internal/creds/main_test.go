package creds

import (
	"os"
	"testing"
)

// TestMain points HOME and the user config dir at a temp dir, so no test
// can reach the real PressWrench config dir (session locks, the store
// marker, credentials.json) through creds.ConfigDir. It also clears the
// variables that would steer the session or the store.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "presswrench-creds-test")
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
