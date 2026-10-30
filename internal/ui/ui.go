// Package ui renders PressWrench's terminal output in a compact "rail"
// style: a vertical rail ties a run together, finished steps collapse to a
// single line, and the active prompt or spinner is the only thing that
// redraws. Static lines are written with fmt; prompts and spinners are
// small inline Bubble Tea programs whose final View is the collapsed line
// they leave behind.
package ui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"

	"github.com/februality/presswrench/internal/config"
)

// UI writes rail-style output to a terminal (or any writer).
type UI struct {
	out         io.Writer
	in          *os.File
	interactive bool
	unicode     bool
	width       int
	r           *lipgloss.Renderer
	g           glyphs
	st          styles
	// syncSpin makes Spin run its function synchronously without a
	// Bubble Tea program even when interactive; set by NewTest so wizard
	// tests can use an "interactive" UI with a scripted Prompter.
	syncSpin bool
}

// Option is one choice in a Select or MultiSelect prompt.
type Option struct {
	Label string
	Value string
	Hint  string // rendered dim after the label, e.g. "(not detected)"
	Dim   bool   // render the label dim (still selectable)
}

// Level is the severity of a finished line.
type Level int

const (
	Done Level = iota
	Warn
	Fail
	// Skip marks a neutral "nothing to do" line (dim).
	Skip
)

// Outcome is what a Spin's function reports when it finishes.
type Outcome struct {
	Level Level
	Text  string
}

// ErrCancelled is returned when the user presses Esc or Ctrl+C in a prompt.
var ErrCancelled = errors.New("Cancelled")

// ErrNoTerminal is returned by prompts when stdin/stdout aren't a TTY.
var ErrNoTerminal = errors.New("Setup needs a terminal. Use --unattended for scripted installs.")

type reportedError struct{ err error }

func (e *reportedError) Error() string { return e.err.Error() }
func (e *reportedError) Unwrap() error { return e.err }

// Reported wraps an error that the UI has already shown to the user, so
// main doesn't print it a second time.
func Reported(err error) error {
	if err == nil {
		return nil
	}
	return &reportedError{err: err}
}

// IsReported reports whether err was wrapped by Reported.
func IsReported(err error) bool {
	var re *reportedError
	return errors.As(err, &re)
}

// ExitCode maps an error to a process exit status: 0 for nil, 130 for a
// user cancellation, 1 otherwise.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, ErrCancelled):
		return 130
	default:
		return 1
	}
}

// New builds a UI for the given streams, detecting whether they are a
// terminal, whether it can show Unicode glyphs, and how wide it is.
func New(out io.Writer, in *os.File) *UI {
	u := &UI{out: out, in: in, width: 80}
	outTTY := false
	if f, ok := out.(*os.File); ok && isatty.IsTerminal(f.Fd()) {
		outTTY = true
		if w, _, err := term.GetSize(f.Fd()); err == nil && w > 0 {
			u.width = w
		}
	}
	inTTY := in != nil && isatty.IsTerminal(in.Fd())
	u.interactive = inTTY && outTTY
	u.unicode = detectUnicode(runtime.GOOS, os.Getenv)
	u.r = lipgloss.NewRenderer(out)
	u.finish()
	return u
}

// NewTest builds a UI with explicit settings and no colour, for tests.
func NewTest(out io.Writer, interactive, unicode bool, width int) *UI {
	u := &UI{out: out, interactive: interactive, unicode: unicode, width: width, syncSpin: true}
	u.r = lipgloss.NewRenderer(out)
	u.r.SetColorProfile(termenv.Ascii)
	u.finish()
	return u
}

func (u *UI) finish() {
	if u.unicode {
		u.g = unicodeGlyphs
	} else {
		u.g = asciiGlyphs
	}
	u.st = newStyles(u.r)
}

// Interactive reports whether prompts can be shown.
func (u *UI) Interactive() bool { return u.interactive }

// detectUnicode decides whether the terminal can show the Unicode glyph
// set. PRESSWRENCH_ASCII=1 forces ASCII everywhere.
func detectUnicode(goos string, env func(string) string) bool {
	if config.IsTrueEnv(env("PRESSWRENCH_ASCII")) {
		return false
	}
	if goos == "windows" {
		return env("WT_SESSION") != "" || env("TERM_PROGRAM") != "" || env("ConEmuTask") != ""
	}
	if env("TERM") == "linux" {
		return false
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := env(k); v != "" {
			v = strings.ToLower(v)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return false
}

func (u *UI) printf(format string, args ...any) {
	fmt.Fprintf(u.out, format, args...)
}
