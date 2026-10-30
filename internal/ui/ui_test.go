package ui

import (
	"errors"
	"testing"
)

func TestUnicodeDetection(t *testing.T) {
	cases := []struct {
		name string
		goos string
		env  map[string]string
		want bool
	}{
		{"linux utf8", "linux", map[string]string{"LANG": "en_US.UTF-8"}, true},
		{"linux C", "linux", map[string]string{"LANG": "C"}, false},
		{"linux console", "linux", map[string]string{"TERM": "linux", "LANG": "en_US.UTF-8"}, false},
		{"darwin LC_ALL", "darwin", map[string]string{"LC_ALL": "en_US.utf8"}, true},
		{"windows terminal", "windows", map[string]string{"WT_SESSION": "x"}, true},
		{"windows conhost", "windows", map[string]string{}, false},
		{"forced ascii", "linux", map[string]string{"LANG": "en_US.UTF-8", "PRESSWRENCH_ASCII": "1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detectUnicode(c.goos, func(k string) string { return c.env[k] })
			if got != c.want {
				t.Fatalf("detectUnicode = %v, want %v", got, c.want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	if ExitCode(nil) != 0 {
		t.Fatal("nil should exit 0")
	}
	if ExitCode(ErrCancelled) != 130 {
		t.Fatal("cancelled should exit 130")
	}
	if ExitCode(Reported(ErrCancelled)) != 130 {
		t.Fatal("reported cancelled should exit 130")
	}
	if ExitCode(errors.New("x")) != 1 {
		t.Fatal("plain error should exit 1")
	}
	plain := errors.New("x")
	if !IsReported(Reported(plain)) {
		t.Fatal("Reported should be detected")
	}
	if IsReported(plain) {
		t.Fatal("plain error must not be reported")
	}
	if !errors.Is(Reported(ErrCancelled), ErrCancelled) {
		t.Fatal("Reported must unwrap to the cause")
	}
}
