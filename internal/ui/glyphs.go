package ui

import (
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"
)

type glyphs struct {
	intro, rail, done, active, warn, fail, skip, outro string
	radioOn, radioOff, checkOn, checkOff, cursor       string
	// Punctuation that also needs an ASCII form so a run on a legacy
	// console never shows mojibake.
	sep, ellipsis, arrow, dash string
	spinner                    spinner.Spinner
}

var unicodeGlyphs = glyphs{
	intro: "┌", rail: "│", done: "◇", active: "◆", warn: "▲", fail: "■", skip: "·", outro: "└",
	radioOn: "●", radioOff: "○", checkOn: "◼", checkOff: "◻", cursor: "▸",
	sep: " · ", ellipsis: "…", arrow: "→", dash: "—",
	spinner: spinner.Spinner{
		Frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		FPS:    time.Second / 12,
	},
}

var asciiGlyphs = glyphs{
	intro: "+", rail: "|", done: "o", active: "*", warn: "!", fail: "x", skip: "-", outro: "+",
	radioOn: "(*)", radioOff: "( )", checkOn: "[x]", checkOff: "[ ]", cursor: ">",
	sep: " - ", ellipsis: "...", arrow: "->", dash: "-",
	spinner: spinner.Spinner{
		Frames: []string{"-", "\\", "|", "/"},
		FPS:    time.Second / 8,
	},
}

// styles are the ANSI-16 colours used throughout, so output follows the
// user's terminal theme and stays readable on light backgrounds.
type styles struct {
	dim, done, active, warn, fail, bold lipgloss.Style
	// focus is the filled highlight on the focused radio/checkbox glyph.
	focus lipgloss.Style
}

func newStyles(r *lipgloss.Renderer) styles {
	return styles{
		dim:    r.NewStyle().Foreground(lipgloss.Color("8")),
		done:   r.NewStyle().Foreground(lipgloss.Color("2")),
		active: r.NewStyle().Foreground(lipgloss.Color("6")),
		warn:   r.NewStyle().Foreground(lipgloss.Color("3")),
		fail:   r.NewStyle().Foreground(lipgloss.Color("1")),
		bold:   r.NewStyle().Bold(true),
		focus:  r.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("6")),
	}
}
