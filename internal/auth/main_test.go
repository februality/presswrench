package auth

import (
	"os"
	"testing"
)

// TestMain points the user config dir at a temp dir so SignIn's
// creds.RememberBackend never writes a marker into the real one.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "presswrench-auth-test")
	if err != nil {
		panic(err)
	}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "APPDATA"} {
		os.Setenv(k, dir)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
