package ssh

import (
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
		{"../../etc/passwd", true, "/etc/passwd"},
		{"/srv/htdocsx/file", true, "/srv/htdocsx/file"},
		{"~/htdocs-backup/x", true, "/~/htdocs-backup/x"},
		{"htdocs-old/x", true, "/htdocs-old/x"},
		{"~/htdocs", true, "/"},

		{"", false, "/srv/htdocs"},
		{"wp-content", false, "/srv/htdocs/wp-content"},
		{"/srv/htdocs/wp-content", false, "/srv/htdocs/wp-content"},
		{"/wp-content", false, "/srv/htdocs/wp-content"},
	}
	for _, c := range cases {
		if got := SFTPPath(c.in, c.chrooted); got != c.want {
			t.Errorf("SFTPPath(%q, %v) = %q, want %q", c.in, c.chrooted, got, c.want)
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
		got := SFTPPath(in, true)
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
