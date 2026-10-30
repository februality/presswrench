package ui

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func writeSample(u *UI) {
	u.Intro("PressWrench setup", "v0.1.0")
	u.Step("SSH key", "~/k")
	u.Step("Done", "")
	u.Warn("W", "d")
	u.Fail("F", "")
	u.Blank()
	u.Outro("Done.")
}

func TestLines_Unicode(t *testing.T) {
	var b bytes.Buffer
	writeSample(NewTest(&b, false, true, 80))
	want := "┌  PressWrench setup  v0.1.0\n│\n◇  SSH key · ~/k\n◇  Done\n▲  W · d\n■  F\n│\n└  Done.\n"
	if b.String() != want {
		t.Fatalf("got:\n%q\nwant:\n%q", b.String(), want)
	}
}

func TestLines_ASCII(t *testing.T) {
	var b bytes.Buffer
	writeSample(NewTest(&b, false, false, 80))
	want := "+  PressWrench setup  v0.1.0\n|\no  SSH key · ~/k\no  Done\n!  W · d\nx  F\n|\n+  Done.\n"
	if b.String() != want {
		t.Fatalf("got:\n%q\nwant:\n%q", b.String(), want)
	}
}

func TestNote_Wraps(t *testing.T) {
	var b bytes.Buffer
	u := NewTest(&b, false, true, 50)
	u.Note(strings.Repeat("aaaa bbbb ", 6)) // 60 chars incl. trailing space
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), lines)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "│  ") {
			t.Fatalf("line lacks rail prefix: %q", l)
		}
		if utf8.RuneCountInString(l) > 49 {
			t.Fatalf("line too long (%d): %q", utf8.RuneCountInString(l), l)
		}
	}
}

func TestWrap_NarrowFloor(t *testing.T) {
	var b bytes.Buffer
	u := NewTest(&b, false, true, 20)
	u.Note(strings.Repeat("ab ", 10)) // 30 chars: fits the 40-column floor
	if strings.Count(b.String(), "\n") != 1 {
		t.Fatalf("want a single line at the 40-col floor, got %q", b.String())
	}
}

func TestNoteRaw_NoWrap(t *testing.T) {
	var b bytes.Buffer
	u := NewTest(&b, false, true, 80)
	s := strings.Repeat("x", 200)
	u.NoteRaw(s)
	if b.String() != "│  "+s+"\n" {
		t.Fatalf("got %q", b.String())
	}
}
