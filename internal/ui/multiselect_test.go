package ui

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/termenv"
)

var toolOptions = []Option{
	{Label: "Claude Code", Value: "claude"},
	{Label: "Cursor", Value: "cursor"},
	{Label: "Windsurf", Value: "windsurf", Hint: "(not detected)", Dim: true},
}

func tools(u *UI) multiSelectModel {
	return newMultiSelectModel(u, "Configure which AI tools?", toolOptions, []string{"claude", "cursor"})
}

func TestMultiSelect_View(t *testing.T) {
	m := tools(NewTest(io.Discard, true, true, 80))
	want := "◆  Configure which AI tools?\n" +
		"│  ▸ ◼ Claude Code\n" +
		"│    ◼ Cursor\n" +
		"│    ◻ Windsurf  (not detected)\n" +
		"│  space toggle · enter confirm · esc cancel\n" +
		"└\n"
	if got := m.View(); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestMultiSelect_Toggle(t *testing.T) {
	m := upd(tools(NewTest(io.Discard, true, true, 80)), key(tea.KeyDown), key(tea.KeySpace)).(multiSelectModel)
	if m.checked[1] {
		t.Fatal("space should uncheck Cursor")
	}
	m = upd(m, key(tea.KeyEnter)).(multiSelectModel)
	if !m.done || !reflect.DeepEqual(m.values(), []string{"claude"}) {
		t.Fatalf("done=%v values=%v", m.done, m.values())
	}
	if got := m.View(); got != "◇  Configure which AI tools? · Claude Code\n" {
		t.Fatalf("final %q", got)
	}
}

func TestMultiSelect_None(t *testing.T) {
	m := upd(tools(NewTest(io.Discard, true, true, 80)), key(tea.KeySpace), key(tea.KeyDown), key(tea.KeySpace), key(tea.KeyEnter)).(multiSelectModel)
	if len(m.values()) != 0 {
		t.Fatalf("values %v", m.values())
	}
	if got := m.View(); got != "◇  Configure which AI tools? · none\n" {
		t.Fatalf("final %q", got)
	}
}

func TestMultiSelect_Cancel(t *testing.T) {
	m := upd(tools(NewTest(io.Discard, true, true, 80)), key(tea.KeyCtrlC)).(multiSelectModel)
	if !m.cancelled || m.View() != "■  Cancelled.\n" {
		t.Fatalf("cancelled=%v view=%q", m.cancelled, m.View())
	}
}

func TestMultiSelect_ASCII(t *testing.T) {
	m := tools(NewTest(io.Discard, true, false, 80))
	want := "*  Configure which AI tools?\n" +
		"|  > [x] Claude Code\n" +
		"|    [x] Cursor\n" +
		"|    [ ] Windsurf  (not detected)\n" +
		"|  space toggle - enter confirm - esc cancel\n" +
		"+\n"
	if got := m.View(); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestMultiSelect_NonInteractive(t *testing.T) {
	u := NewTest(io.Discard, false, true, 80)
	if _, err := u.MultiSelect("T", toolOptions, nil); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("err %v", err)
	}
}

func TestMultiSelect_EmptyDoesNotPanic(t *testing.T) {
	m := newMultiSelectModel(NewTest(io.Discard, true, true, 80), "T", nil, nil)
	m = upd(m, key(tea.KeyDown), key(tea.KeySpace), key(tea.KeyUp), runes("a"), key(tea.KeyEnter)).(multiSelectModel)
	if !m.done || len(m.values()) != 0 {
		t.Fatalf("done=%v values=%v", m.done, m.values())
	}
}

// A ticked box must read as ticked on every row, so the state is carried
// by colour (green on, dim off) and never by the focus highlight, which
// hides the glyph shape.
func TestMultiSelect_TickStateIsColourNotFocus(t *testing.T) {
	u := NewTest(io.Discard, true, true, 80)
	u.r.SetColorProfile(termenv.ANSI)
	u.st = newStyles(u.r)
	v := tools(u).View()
	if strings.Contains(v, "\x1b[46m") {
		t.Fatalf("checkbox uses a background highlight: %q", v)
	}
	if !strings.Contains(v, "\x1b[32m◼") {
		t.Fatalf("ticked box on the focused row is not green: %q", v)
	}
	if strings.Count(v, "\x1b[32m◼") != 2 {
		t.Fatalf("every ticked box should be green: %q", v)
	}
	if !strings.Contains(v, "\x1b[90m◻") {
		t.Fatalf("unticked box is not dim: %q", v)
	}
}
