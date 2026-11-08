package creds

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fakeKeyring(ok bool) func() (rawBackend, Info, error) {
	return func() (rawBackend, Info, error) {
		if !ok {
			return nil, Info{}, errors.New("no secret service")
		}
		return &fileBackend{path: filepath.Join(os.TempDir(), "unused-keyring-fake")}, Info{Source: SourceKeyring, Description: "fake keyring"}, nil
	}
}

func TestOpenWith_Selection(t *testing.T) {
	cases := []struct {
		name, env, marker string
		keyringOK         bool
		wantSource        Source
		wantKind          Kind
		wantErr           string
		wantDesc          string
		wantWarn          bool
	}{
		{name: "fresh keyring ok", keyringOK: true, wantSource: SourceKeyring},
		{name: "fresh keyring fails", wantSource: SourceFile, wantDesc: "keyring unavailable"},
		{name: "marker keyring unreachable", marker: "keyring", wantKind: KindUnavailable},
		{name: "marker file keyring ok", marker: "file", keyringOK: true, wantSource: SourceFile, wantDesc: "chosen at first sign-in"},
		{name: "env file over keyring marker", env: "file", marker: "keyring", keyringOK: true, wantSource: SourceFile, wantWarn: true, wantDesc: "PRESSWRENCH_CREDENTIAL_STORE=file"},
		{name: "env keyring unreachable", env: "keyring", wantKind: KindUnavailable},
		{name: "env bogus", env: "bogus", keyringOK: true, wantErr: "PRESSWRENCH_CREDENTIAL_STORE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			o := selectOpts{
				env:         tc.env,
				markerPath:  filepath.Join(dir, "store"),
				filePath:    filepath.Join(dir, "credentials.json"),
				lockDir:     dir,
				openKeyring: fakeKeyring(tc.keyringOK),
			}
			if tc.marker != "" {
				if err := os.WriteFile(o.markerPath, []byte(tc.marker+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			s, err := openWith(o)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if tc.wantKind != KindOther {
				var e *Error
				if !errors.As(err, &e) || e.Kind != tc.wantKind {
					t.Fatalf("err = %v, want kind %v", err, tc.wantKind)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			info := s.Info()
			if info.Source != tc.wantSource {
				t.Fatalf("source = %v, want %v", info.Source, tc.wantSource)
			}
			if !strings.Contains(info.Description, tc.wantDesc) {
				t.Fatalf("description %q lacks %q", info.Description, tc.wantDesc)
			}
			if (info.Warning != "") != tc.wantWarn {
				t.Fatalf("warning = %q, want warn=%v", info.Warning, tc.wantWarn)
			}
		})
	}
}

func TestRememberBackend_WritesMarker(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	configDir = func() (string, error) { return filepath.Join(dir, "cfg"), nil }
	t.Cleanup(func() { configDir = old })

	s := NewFileStore(filepath.Join(dir, "credentials.json"))
	if err := RememberBackend(s); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "cfg", "store")
	b, err := os.ReadFile(marker)
	if err != nil || string(b) != "file\n" {
		t.Fatalf("marker = %q, %v", b, err)
	}
	st, _ := os.Stat(marker)
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(marker, past, past); err != nil {
		t.Fatal(err)
	}
	if err := RememberBackend(s); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(marker)
	if !st2.ModTime().Equal(past) {
		t.Fatal("marker rewritten although unchanged")
	}
	if err := RememberBackend(Broken(errors.New("x"))); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(marker)
	if string(b) != "file\n" {
		t.Fatalf("broken store changed marker: %q", b)
	}
}
