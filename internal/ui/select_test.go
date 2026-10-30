package ui

import (
	"bytes"
	"errors"
	"io"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func key(t tea.KeyType) tea.KeyMsg { return tea.KeyMsg{Type: t} }
func runes(s string) tea.KeyMsg    { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

func threeWay(u *UI) selectModel {
	return newSelectModel(u, "Added the key?", []Option{
		{Label: "Test SSH now", Value: "test"},
		{Label: "Show the key", Value: "show"},
		{Label: "Skip", Value: "skip"},
	}, "test")
}

func upd(m tea.Model, msgs ...tea.Msg) tea.Model {
	for _, msg := range msgs {
		m, _ = m.Update(msg)
	}
	return m
}

func TestSelect_View(t *testing.T) {
	m := threeWay(NewTest(io.Discard, true, true, 80))
	want := "◆  Added the key?\n│  ● Test SSH now  ○ Show the key  ○ Skip\n└\n"
	if got := m.View(); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestSelect_Keys(t *testing.T) {
	m := upd(threeWay(NewTest(io.Discard, true, true, 80)), key(tea.KeyRight)).(selectModel)
	if m.cursor != 1 {
		t.Fatalf("right: cursor %d", m.cursor)
	}
	m = upd(m, key(tea.KeyRight), key(tea.KeyRight)).(selectModel)
	if m.cursor != 0 {
		t.Fatalf("wrap: cursor %d", m.cursor)
	}
	m = upd(m, runes("3")).(selectModel)
	if m.cursor != 2 {
		t.Fatalf("digit: cursor %d", m.cursor)
	}
	m = upd(m, key(tea.KeyEnter)).(selectModel)
	if !m.done || m.value() != "skip" {
		t.Fatalf("enter: done=%v value=%q", m.done, m.value())
	}
	if got := m.View(); got != "◇  Added the key? · Skip\n" {
		t.Fatalf("final view %q", got)
	}
}

func TestSelect_YN(t *testing.T) {
	u := NewTest(io.Discard, true, true, 80)
	m := newSelectModel(u, "Run in read-only mode?", confirmOptions, "no")
	if got := m.View(); got != "◆  Run in read-only mode?\n│  ○ Yes  ● No\n└\n" {
		t.Fatalf("view %q", got)
	}
	m = upd(m, runes("y")).(selectModel)
	if !m.done || m.value() != "yes" {
		t.Fatalf("y: done=%v value=%q", m.done, m.value())
	}
}

func TestSelect_Cancel(t *testing.T) {
	for _, k := range []tea.KeyMsg{key(tea.KeyEsc), key(tea.KeyCtrlC)} {
		m := upd(threeWay(NewTest(io.Discard, true, true, 80)), k).(selectModel)
		if !m.cancelled {
			t.Fatalf("%v: not cancelled", k)
		}
		if got := m.View(); got != "■  Cancelled.\n" {
			t.Fatalf("view %q", got)
		}
	}
}

func TestSelect_ASCII(t *testing.T) {
	u := NewTest(io.Discard, true, false, 80)
	m := newSelectModel(u, "T", confirmOptions, "yes")
	if got := m.View(); got != "*  T\n|  (*) Yes  ( ) No\n+\n" {
		t.Fatalf("view %q", got)
	}
}

func TestSelect_NonInteractive(t *testing.T) {
	var b bytes.Buffer
	u := NewTest(&b, false, true, 80)
	if _, err := u.Select("T", confirmOptions, "yes"); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("err %v", err)
	}
	if _, err := u.Confirm("T", true); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("confirm err %v", err)
	}
	if b.Len() != 0 {
		t.Fatalf("wrote %q", b.String())
	}
}

func TestSelect_EmptyDoesNotPanic(t *testing.T) {
	m := newSelectModel(NewTest(io.Discard, true, true, 80), "T", nil, "")
	m = upd(m, key(tea.KeyRight), key(tea.KeyLeft), runes("1"), runes("y"), key(tea.KeyEnter)).(selectModel)
	if !m.done || m.value() != "" {
		t.Fatalf("done=%v value=%q", m.done, m.value())
	}
}
