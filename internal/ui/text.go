package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// Text asks for a line of input. validate (optional) runs on Enter; its
// error is shown under the input and the prompt stays open.
func (u *UI) Text(title, placeholder string, validate func(string) error) (string, error) {
	if !u.interactive {
		return "", ErrNoTerminal
	}
	final, err := u.runProgram(newTextModel(u, title, placeholder, validate))
	if err != nil {
		return "", err
	}
	return final.(textModel).value(), nil
}

type textModel struct {
	u         *UI
	title     string
	input     textinput.Model
	validate  func(string) error
	err       error
	done      bool
	cancelled bool
}

func newTextModel(u *UI, title, placeholder string, validate func(string) error) textModel {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = placeholder
	in.PlaceholderStyle = u.st.dim
	in.Width = u.wrapWidth()
	in.Focus()
	return textModel{u: u, title: title, input: in, validate: validate}
}

func (m textModel) isCancelled() bool { return m.cancelled }
func (m textModel) Init() tea.Cmd     { return textinput.Blink }
func (m textModel) value() string     { return strings.TrimSpace(m.input.Value()) }

func (m textModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.done || m.cancelled {
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyEsc, tea.KeyCtrlC:
			m.cancelled = true
			return m, tea.Quit
		case tea.KeyEnter:
			if m.validate != nil {
				if err := m.validate(m.value()); err != nil {
					m.err = err
					return m, nil
				}
			}
			m.done = true
			return m, tea.Quit
		}
		m.err = nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m textModel) View() string {
	u := m.u
	switch {
	case m.cancelled:
		return u.cancelledView()
	case m.done:
		return u.Line(Done, m.title, m.value()) + "\n"
	}
	s := u.activeHeader(m.title) + u.railLine(m.input.View())
	if m.err != nil {
		s += u.railLine(u.st.warn.Render(u.g.warn + " " + m.err.Error()))
	}
	return s + u.activeFooter()
}
