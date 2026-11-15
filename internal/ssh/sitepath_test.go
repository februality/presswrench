package ssh

import (
	"errors"
	"strings"
	"testing"
)

func TestSFTPPath(t *testing.T) {
	cases := []struct {
		in       string
		chrooted bool
		want     string
	}{
		{"", true, "/"},
		{"wp-content/themes", true, "/wp-content/themes"},
		{"/srv/htdocs/wp-content/themes", true, "/wp-content/themes"},
		{"/srv/htdocs", true, "/"},
		{"~/htdocs/wp-config.php", true, "/wp-config.php"},
		{"htdocs/wp-config.php", true, "/wp-config.php"},
		{"/wp-content/../wp-config.php", true, "/wp-config.php"},
		{"htdocs-old/x", true, "/htdocs-old/x"},
		{"~/htdocs", true, "/"},
		{"tmp/x", true, "/tmp/x"},
		{"/srv/htdocs/tmp/x", true, "/tmp/x"},
		{"wp-content/../wp-config.php", true, "/wp-config.php"},

		{"", false, "/srv/htdocs"},
		{"wp-content", false, "/srv/htdocs/wp-content"},
		{"/srv/htdocs/wp-content", false, "/srv/htdocs/wp-content"},
		{"/wp-content", false, "/srv/htdocs/wp-content"},
		{"/tmp/dump.sql", false, "/tmp/dump.sql"},
	}
	for _, c := range cases {
		got, err := SFTPPath(c.in, c.chrooted)
		if err != nil || got != c.want {
			t.Errorf("SFTPPath(%q, %v) = %q, %v; want %q", c.in, c.chrooted, got, err, c.want)
		}
	}
}

// A shell path outside the web root is refused, never remapped into it.
func TestSFTPPath_OutsideRoot(t *testing.T) {
	for _, in := range []string{"/tmp", "/tmp/dump.sql", "/home/123/x", "/etc/passwd", "/srv/htdocsx/file",
		"/srv", "~/x", "~", "~/htdocs-backup/x", "../../etc/passwd", "wp-content/../../x", "/srv/htdocs/../../etc/passwd"} {
		got, err := SFTPPath(in, true)
		var out *OutsideRootError
		if !errors.As(err, &out) {
			t.Errorf("SFTPPath(%q) = %q, %v; want OutsideRootError", in, got, err)
			continue
		}
		if !strings.Contains(err.Error(), in) || !strings.Contains(err.Error(), "pressable_ssh_exec") {
			t.Errorf("SFTPPath(%q) error = %q", in, err)
		}
	}
	for _, in := range []string{"~/x", "../x"} {
		if _, err := SFTPPath(in, false); err == nil {
			t.Errorf("SFTPPath(%q, unchrooted) accepted", in)
		}
	}
}

func TestDisplayPath(t *testing.T) {
	if got := DisplayPath("/", true); got != "/srv/htdocs" {
		t.Errorf("got %q", got)
	}
	if got := DisplayPath("/wp-content", true); got != "/srv/htdocs/wp-content" {
		t.Errorf("got %q", got)
	}
	if got := DisplayPath("/srv/htdocs/x", false); got != "/srv/htdocs/x" {
		t.Errorf("got %q", got)
	}
}

func TestExecDir(t *testing.T) {
	cases := map[string]string{
		"":                       "/srv/htdocs",
		"wp-content":             "/srv/htdocs/wp-content",
		"/tmp":                   "/tmp",
		"/srv/htdocs/../htdocs/": "/srv/htdocs",
	}
	for in, want := range cases {
		if got := ExecDir(in); got != want {
			t.Errorf("ExecDir(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzSFTPPath: the chrooted result is always absolute and never contains
// a ".." segment.
func FuzzSFTPPath(f *testing.F) {
	for _, s := range []string{"", "..", "../../x", "/srv/htdocs/../..", "a/./b/../c", "~/htdocs/.."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := SFTPPath(in, true)
		if err != nil {
			return
		}
		if !strings.HasPrefix(got, "/") {
			t.Fatalf("SFTPPath(%q) = %q: not absolute", in, got)
		}
		for _, seg := range strings.Split(got, "/") {
			if seg == ".." {
				t.Fatalf("SFTPPath(%q) = %q: contains ..", in, got)
			}
		}
	})
}
