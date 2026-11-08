package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
)

// isolate keeps anything that resolves the config dir out of the real one.
func isolate(t *testing.T) {
	t.Helper()
	d := t.TempDir()
	t.Setenv("HOME", d)
	t.Setenv("XDG_CONFIG_HOME", d)
	t.Setenv("APPDATA", d)
	t.Setenv(auth.EnvAccessToken, "")
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startup check did not finish")
	}
}

func TestNewServeDeps_OpenFailureStillServes(t *testing.T) {
	isolate(t)
	open := func() (creds.Store, error) {
		return nil, &creds.Error{Kind: creds.KindUnavailable, Detail: "no dbus"}
	}
	deps, done := startServeDeps(context.Background(), &config.Config{}, open)
	if deps == nil {
		t.Fatal("deps is nil")
	}
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	waitDone(t, done)
	_, err := deps.Session.Token(context.Background())
	if err == nil || !strings.Contains(auth.Explain(err), "PRESSWRENCH_CREDENTIAL_STORE=file") {
		t.Fatalf("Explain = %q (err %v)", auth.Explain(err), err)
	}
}

func TestNewServeDeps_NotSignedInStillServes(t *testing.T) {
	isolate(t)
	open := func() (creds.Store, error) {
		return creds.NewFileStore(filepath.Join(t.TempDir(), "creds.json")), nil
	}
	deps, done := startServeDeps(context.Background(), &config.Config{}, open)
	if deps == nil {
		t.Fatal("deps is nil")
	}
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	waitDone(t, done)
	if _, err := deps.Session.State(); !errors.Is(err, auth.ErrLoginRequired) {
		t.Fatalf("State err = %v", err)
	}
}

// blockingStore blocks Load until released, like a slow keychain.
type blockingStore struct {
	creds.Store
	release chan struct{}
}

func (b *blockingStore) Load(account string) (creds.Record, error) {
	<-b.release
	return b.Store.Load(account)
}

func TestStartServeDeps_DoesNotBlockOnSlowStore(t *testing.T) {
	isolate(t)
	bs := &blockingStore{
		Store:   creds.NewFileStore(filepath.Join(t.TempDir(), "creds.json")),
		release: make(chan struct{}),
	}
	start := time.Now()
	deps, done := startServeDeps(context.Background(), &config.Config{}, func() (creds.Store, error) { return bs, nil })
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("startServeDeps took %v with Load blocked", d)
	}
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	select {
	case <-done:
		t.Fatal("check finished while Load was blocked")
	case <-time.After(50 * time.Millisecond):
	}
	close(bs.release)
	waitDone(t, done)
}

func TestStartServeDeps_EnvTokenOpensNoStore(t *testing.T) {
	isolate(t)
	t.Setenv(auth.EnvAccessToken, "env-token")
	open := func() (creds.Store, error) {
		t.Error("open called with an env token")
		return nil, errors.New("unexpected")
	}
	deps, done := startServeDeps(context.Background(), &config.Config{}, open)
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	waitDone(t, done)
	tok, err := deps.Session.Token(context.Background())
	if err != nil || tok != "env-token" {
		t.Fatalf("Token = %q, %v", tok, err)
	}
}

func TestStartServeDeps_LogsStoreWarning(t *testing.T) {
	isolate(t)
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	w := "PRESSWRENCH_CREDENTIAL_STORE=file overrides the keyring store used at sign-in; sessions saved there aren't visible."
	store := infoStore{tempStore(t), creds.Info{Source: creds.SourceFile, Description: "file x", Warning: w}}
	deps, done := startServeDeps(context.Background(), &config.Config{}, func() (creds.Store, error) { return store, nil })
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	waitDone(t, done)
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "sessions saved there aren't visible") {
		t.Errorf("log = %q, want the store warning at WARN", out)
	}
}
