package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
)

func TestNewServeDeps_OpenFailureStillServes(t *testing.T) {
	t.Setenv(auth.EnvAccessToken, "")
	open := func() (creds.Store, error) {
		return nil, &creds.Error{Kind: creds.KindUnavailable, Detail: "no dbus"}
	}
	deps := newServeDeps(&config.Config{}, open)
	if deps == nil {
		t.Fatal("deps is nil")
	}
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	_, err := deps.Session.Token(context.Background())
	if err == nil || !strings.Contains(auth.Explain(err), "PRESSWRENCH_CREDENTIAL_STORE=file") {
		t.Fatalf("Explain = %q (err %v)", auth.Explain(err), err)
	}
}

func TestNewServeDeps_NotSignedInStillServes(t *testing.T) {
	t.Setenv(auth.EnvAccessToken, "")
	open := func() (creds.Store, error) {
		return creds.NewFileStore(filepath.Join(t.TempDir(), "creds.json")), nil
	}
	start := time.Now()
	deps := newServeDeps(&config.Config{AuthURL: "http://127.0.0.1:1"}, open)
	if deps == nil {
		t.Fatal("deps is nil")
	}
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("newServeDeps took %v", d)
	}
}
