package ui

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func signIn(u *UI) spinModel {
	return newSpinModel(u, "Sign in to Pressable in your browser", "Waiting for you to approve access…",
		[]string{"If the browser didn't open: https://auth.example/x"})
}

func TestSpin_View(t *testing.T) {
	m := signIn(NewTest(io.Discard, true, true, 80))
	want := "◆  Sign in to Pressable in your browser\n" +
		"│  ⠋ Waiting for you to approve access…\n" +
		"│  If the browser didn't open: https://auth.example/x\n" +
		"└\n"
	if got := m.View(); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestSpin_StatusAndDone(t *testing.T) {
	m := upd(signIn(NewTest(io.Discard, true, true, 80)), spinStatusMsg("attempt 2 of 4")).(spinModel)
	if !strings.Contains(m.View(), "⠋ attempt 2 of 4\n") {
		t.Fatalf("status not updated: %q", m.View())
	}
	m = upd(m, spinDoneMsg{Level: Done, Text: "Signed in as a · 3 sites"}).(spinModel)
	if got := m.View(); got != "◇  Signed in as a · 3 sites\n" {
		t.Fatalf("final %q", got)
	}
}

func TestSpin_WarnOutcome(t *testing.T) {
	m := upd(signIn(NewTest(io.Discard, true, true, 80)), spinDoneMsg{Level: Warn, Text: "SSH not working yet · denied"}).(spinModel)
	if got := m.View(); got != "▲  SSH not working yet · denied\n" {
		t.Fatalf("final %q", got)
	}
	m = upd(signIn(NewTest(io.Discard, true, true, 80)), spinDoneMsg{Level: Fail, Text: "boom"}).(spinModel)
	if got := m.View(); got != "■  boom\n" {
		t.Fatalf("final %q", got)
	}
}

func TestSpin_NonInteractive(t *testing.T) {
	var b bytes.Buffer
	u := NewTest(&b, false, true, 80)
	calls := 0
	err := u.Spin("T", "working…", []string{"d"}, func(set func(string), note func(...string)) Outcome {
		calls++
		set("ignored")
		note("https://example/very-long-url")
		return Outcome{Level: Done, Text: "ok"}
	})
	if err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if b.String() != "◆  T\n│  d\n│  https://example/very-long-url\n◇  ok\n" {
		t.Fatalf("got %q", b.String())
	}
}

func TestSpin_SyncInTestUI(t *testing.T) {
	// NewTest(interactive=true) still runs Spin synchronously so wizard
	// tests never start a Bubble Tea program.
	var b bytes.Buffer
	u := NewTest(&b, true, true, 80)
	err := u.Spin("T", "w", nil, func(func(string), func(...string)) Outcome { return Outcome{Level: Done, Text: "ok"} })
	if err != nil || b.String() != "◆  T\n◇  ok\n" {
		t.Fatalf("err=%v got %q", err, b.String())
	}
}
