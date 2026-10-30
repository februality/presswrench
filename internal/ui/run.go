package ui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// finisher is implemented by every prompt model so runProgram can tell
// whether the user cancelled.
type finisher interface {
	tea.Model
	isCancelled() bool
}

// runProgram runs m inline (no alternate screen) on the UI's streams and
// returns the final model. The final View stays on screen, so models end
// their finished view with a newline: Bubble Tea erases the line the
// cursor rests on when the program exits.
func (u *UI) runProgram(m finisher) (tea.Model, error) {
	p := tea.NewProgram(m, tea.WithInput(u.in), tea.WithOutput(u.out))
	final, err := p.Run()
	if err != nil {
		return final, err
	}
	if f, ok := final.(finisher); ok && f.isCancelled() {
		return final, ErrCancelled
	}
	return final, nil
}

// cancelledView is the final view shared by every prompt on Esc/Ctrl+C.
func (u *UI) cancelledView() string { return u.Line(Fail, "Cancelled.", "") + "\n" }

// activeHeader renders the "◆  title" line of an active prompt.
func (u *UI) activeHeader(title string) string {
	return u.st.active.Render(u.g.active) + "  " + u.st.bold.Render(title) + "\n"
}

// railLine renders "│  body" for an active prompt, with the rail in the
// active colour.
func (u *UI) railLine(body string) string {
	return u.st.active.Render(u.g.rail) + "  " + body + "\n"
}

// activeFooter renders the closing "└" of an active prompt.
func (u *UI) activeFooter() string { return u.st.active.Render(u.g.outro) + "\n" }
