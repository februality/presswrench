package ui

import (
	"errors"
	"io"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func required(s string) error {
	if s == "" {
		return errors.New("Required")
	}
	return nil
}

func pasteURL(u *UI) textModel {
	return newTextModel(u, "Paste the URL your browser landed on", "http://127.0.0.1:53682/…", required)
}

func TestText_View(t *testing.T) {
	v := pasteURL(NewTest(io.Discard, true, true, 80)).View()
	if !strings.HasPrefix(v, "◆  Paste the URL your browser landed on\n│  ") {
		t.Fatalf("view %q", v)
	}
	if !strings.Contains(v, "http://127.0.0.1:53682/…") || !strings.HasSuffix(v, "\n└\n") {
		t.Fatalf("view %q", v)
	}
}

func TestText_ValidateBlocks(t *testing.T) {
	m := upd(pasteURL(NewTest(io.Discard, true, true, 80)), key(tea.KeyEnter)).(textModel)
	if m.done {
		t.Fatal("empty value must not complete")
	}
	if !strings.Contains(m.View(), "▲ Required") {
		t.Fatalf("view lacks validation line: %q", m.View())
	}
}

func TestText_Done(t *testing.T) {
	m := upd(pasteURL(NewTest(io.Discard, true, true, 80)), runes("abc"), key(tea.KeyEnter)).(textModel)
	if !m.done || m.value() != "abc" {
		t.Fatalf("done=%v value=%q", m.done, m.value())
	}
	if got := m.View(); got != "◇  Paste the URL your browser landed on · abc\n" {
		t.Fatalf("final %q", got)
	}
}

func TestText_Cancel(t *testing.T) {
	m := upd(pasteURL(NewTest(io.Discard, true, true, 80)), key(tea.KeyEsc)).(textModel)
	if !m.cancelled || m.View() != "■  Cancelled.\n" {
		t.Fatalf("cancelled=%v view=%q", m.cancelled, m.View())
	}
}

func TestText_NonInteractive(t *testing.T) {
	u := NewTest(io.Discard, false, true, 80)
	if _, err := u.Text("T", "", nil); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("err %v", err)
	}
}
