package ui

import (
	"strings"
	"unicode/utf8"
)

const minWrapWidth = 40

// Intro prints the opening line of a run: "┌  title  detail" and an
// empty rail line.
func (u *UI) Intro(title, detail string) {
	line := u.st.dim.Render(u.g.intro) + "  " + u.st.bold.Render(title)
	if detail != "" {
		line += "  " + u.st.dim.Render(detail)
	}
	u.printf("%s\n", line)
	u.Blank()
}

// Step prints a finished step.
func (u *UI) Step(title, detail string) { u.printf("%s\n", u.line(Done, title, detail)) }

// Warn prints a warning line.
func (u *UI) Warn(title, detail string) { u.printf("%s\n", u.line(Warn, title, detail)) }

// Fail prints a failure line.
func (u *UI) Fail(title, detail string) { u.printf("%s\n", u.line(Fail, title, detail)) }

// Skip prints a neutral "nothing to do" line.
func (u *UI) Skip(title, detail string) { u.printf("%s\n", u.line(Skip, title, detail)) }

// Line returns a finished line for the given level, without a newline.
// Prompts and spinners use it for their final view.
func (u *UI) Line(level Level, title, detail string) string {
	return u.line(level, title, detail)
}

// Mark returns the styled glyph for a level, for callers that keep their
// own layout (status, doctor).
func (u *UI) Mark(level Level) string {
	switch level {
	case Warn:
		return u.st.warn.Render(u.g.warn)
	case Fail:
		return u.st.fail.Render(u.g.fail)
	case Skip:
		return u.st.dim.Render(u.g.skip)
	default:
		return u.st.done.Render(u.g.done)
	}
}

func (u *UI) line(level Level, title, detail string) string {
	s := u.Mark(level) + "  " + title
	if detail == "" {
		return s
	}
	// Warnings and failures carry what went wrong in the detail; keep it
	// readable (colour 8 vanishes on some dark themes).
	if level == Warn || level == Fail {
		return s + u.g.sep + detail
	}
	return s + u.st.dim.Render(u.g.sep+detail)
}

// Sep returns " · " (ASCII " - "), the separator used between a title and
// its detail, for callers that build such text themselves.
func (u *UI) Sep() string { return u.g.sep }

// Arrow returns "→" (ASCII "->"), for "Profile → Settings" style paths.
func (u *UI) Arrow() string { return u.g.arrow }

// Ellipsis returns "…" (ASCII "..."), for in-progress status text.
func (u *UI) Ellipsis() string { return u.g.ellipsis }

// Dash returns "—" (ASCII "-"), for separating a name from a description.
func (u *UI) Dash() string { return u.g.dash }

// Blank prints an empty rail line.
func (u *UI) Blank() { u.printf("%s\n", u.st.dim.Render(u.g.rail)) }

// Note prints text under the rail, word-wrapped to the terminal width.
func (u *UI) Note(lines ...string) {
	for _, l := range lines {
		for _, w := range wrap(l, u.wrapWidth()) {
			u.NoteRaw(w)
		}
	}
}

// NoteRaw prints text under the rail without wrapping: use it for keys and
// URLs the user has to copy or click.
func (u *UI) NoteRaw(lines ...string) {
	for _, l := range lines {
		u.printf("%s  %s\n", u.st.dim.Render(u.g.rail), l)
	}
}

// Outro prints the closing line. An empty msg prints the bare glyph.
func (u *UI) Outro(msg string) {
	if msg == "" {
		u.printf("%s\n", u.st.dim.Render(u.g.outro))
		return
	}
	u.printf("%s  %s\n", u.st.dim.Render(u.g.outro), msg)
}

func (u *UI) wrapWidth() int {
	w := u.width - 4
	if w < minWrapWidth {
		w = minWrapWidth
	}
	return w
}

// wrap breaks s into lines of at most width runes at spaces. A single word
// longer than width stays on its own line.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var out []string
	cur := ""
	for _, w := range words {
		switch {
		case cur == "":
			cur = w
		case utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(w) <= width:
			cur += " " + w
		default:
			out = append(out, cur)
			cur = w
		}
	}
	return append(out, cur)
}
