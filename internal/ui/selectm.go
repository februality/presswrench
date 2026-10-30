package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// confirmOptions back Confirm: a two-way Select.
var confirmOptions = []Option{{Label: "Yes", Value: "yes"}, {Label: "No", Value: "no"}}

// Select asks the user to pick one option, shown as a horizontal radio
// row. def is the pre-selected value. Returns ErrCancelled on Esc/Ctrl+C
// and ErrNoTerminal when not interactive.
func (u *UI) Select(title string, options []Option, def string) (string, error) {
	if !u.interactive {
		return "", ErrNoTerminal
	}
	final, err := u.runProgram(newSelectModel(u, title, options, def))
	if err != nil {
		return "", err
	}
	return final.(selectModel).value(), nil
}

// Confirm asks a Yes/No question. y/n keys answer directly.
func (u *UI) Confirm(title string, def bool) (bool, error) {
	d := "no"
	if def {
		d = "yes"
	}
	v, err := u.Select(title, confirmOptions, d)
	if err != nil {
		return false, err
	}
	return v == "yes", nil
}

type selectModel struct {
	u         *UI
	title     string
	opts      []Option
	cursor    int
	done      bool
	cancelled bool
}

func newSelectModel(u *UI, title string, opts []Option, def string) selectModel {
	m := selectModel{u: u, title: title, opts: opts}
	for i, o := range opts {
		if o.Value == def {
			m.cursor = i
		}
	}
	return m
}

func (m selectModel) isCancelled() bool { return m.cancelled }
func (m selectModel) Init() tea.Cmd     { return nil }

func (m selectModel) value() string {
	if len(m.opts) == 0 {
		return ""
	}
	return m.opts[m.cursor].Value
}

func (m selectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok || m.done || m.cancelled {
		return m, nil
	}
	n := len(m.opts)
	switch k.Type {
	case tea.KeyEsc, tea.KeyCtrlC:
		m.cancelled = true
		return m, tea.Quit
	case tea.KeyEnter:
		m.done = true
		return m, tea.Quit
	case tea.KeyLeft, tea.KeyShiftTab:
		m.cursor = (m.cursor + n - 1) % n
		return m, nil
	case tea.KeyRight, tea.KeyTab:
		m.cursor = (m.cursor + 1) % n
		return m, nil
	case tea.KeyRunes:
		s := strings.ToLower(string(k.Runes))
		switch {
		case s == "h":
			m.cursor = (m.cursor + n - 1) % n
		case s == "l":
			m.cursor = (m.cursor + 1) % n
		case len(s) == 1 && s[0] >= '1' && s[0] <= '9' && int(s[0]-'1') < n:
			m.cursor = int(s[0] - '1')
		case s == "y" || s == "n":
			for i, o := range m.opts {
				if strings.HasPrefix(strings.ToLower(o.Label), s) {
					m.cursor = i
					m.done = true
					return m, tea.Quit
				}
			}
		}
	}
	return m, nil
}

func (m selectModel) View() string {
	u := m.u
	switch {
	case m.cancelled:
		return u.cancelledView()
	case m.done:
		return u.Line(Done, m.title, m.opts[m.cursor].Label) + "\n"
	}
	parts := make([]string, 0, len(m.opts))
	for i, o := range m.opts {
		if i == m.cursor {
			parts = append(parts, u.st.focus.Render(u.g.radioOn)+" "+o.Label)
		} else {
			parts = append(parts, u.st.dim.Render(u.g.radioOff+" "+o.Label))
		}
	}
	return u.activeHeader(m.title) + u.railLine(strings.Join(parts, "  ")) + u.activeFooter()
}
