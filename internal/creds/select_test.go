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

func TestOverride(t *testing.T) {
	for env, want := range map[string]string{"": "", "file": "file", " KeyRing\n": "keyring", "bogus": ""} {
		t.Setenv(EnvCredentialStore, env)
		if got := Override(); got != want {
			t.Errorf("Override() with %q = %q, want %q", env, got, want)
		}
	}
}

// A keyring waiting on an unlock prompt exists: report the wait instead of
// silently falling back to the file.
func TestOpenWith_KeyringTimeoutDoesNotFallBack(t *testing.T) {
	dir := t.TempDir()
	for _, env := range []string{"", "keyring"} {
		_, err := openWith(selectOpts{
			env:        env,
			markerPath: filepath.Join(dir, "store"),
			filePath:   filepath.Join(dir, "credentials.json"),
			lockDir:    dir,
			openKeyring: func() (rawBackend, Info, error) {
				return nil, Info{}, keyringTimeout("opening")
			},
		})
		if KindOf(err) != KindTimeout {
			t.Errorf("env %q: kind = %v (%v), want KindTimeout", env, KindOf(err), err)
		}
	}
}

func TestOpenWith_Marker(t *testing.T) {
	open := func(t *testing.T, env string, write func(path string)) (Store, error) {
		t.Helper()
		dir := t.TempDir()
		marker := filepath.Join(dir, "store")
		write(marker)
		return openWith(selectOpts{
			env: env, markerPath: marker, filePath: filepath.Join(dir, "credentials.json"),
			lockDir: dir, openKeyring: fakeKeyring(true),
		})
	}
	content := func(v string) func(string) {
		return func(p string) {
			if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
				panic(err)
			}
		}
	}
	unreadable := func(p string) { // a directory where the file should be
		if err := os.MkdirAll(p, 0o700); err != nil {
			panic(err)
		}
	}

	t.Run("case and whitespace", func(t *testing.T) {
		s, err := open(t, "", content("  FILE \r\n"))
		if err != nil || s.Info().Source != SourceFile {
			t.Fatalf("store = %v, err = %v; want the file store", s, err)
		}
	})
	for name, write := range map[string]func(string){"garbled": content("kyring\n"), "empty": content(""), "unreadable": unreadable} {
		t.Run(name, func(t *testing.T) {
			_, err := open(t, "", write)
			var e *Error
			if !errors.As(err, &e) || e.Kind != KindUnavailable || e.Op != "marker" {
				t.Fatalf("err = %#v, want a KindUnavailable marker error", err)
			}
			if !strings.Contains(e.Detail, "store") || !strings.Contains(e.Detail, EnvCredentialStore) {
				t.Errorf("Detail = %q, want the marker path and the fix", e.Detail)
			}
		})
		t.Run(name+" with override", func(t *testing.T) {
			s, err := open(t, "file", write)
			if err != nil || s.Info().Source != SourceFile {
				t.Fatalf("store = %v, err = %v; the override must still work", s, err)
			}
		})
	}
}

func TestRememberBackend_ReplacesGarbledMarker(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	configDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { configDir = old })
	marker := filepath.Join(dir, "store")
	if err := os.WriteFile(marker, []byte("kyring\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RememberBackend(NewFileStore(filepath.Join(dir, "credentials.json"))); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(marker); string(b) != "file\n" {
		t.Fatalf("marker = %q, want file", b)
	}
}
