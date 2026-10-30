package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// MultiSelect asks the user to tick any number of options, shown as a
// vertical checklist. defaults are the values pre-ticked. Returns the
// chosen values in option order.
func (u *UI) MultiSelect(title string, options []Option, defaults []string) ([]string, error) {
	if !u.interactive {
		return nil, ErrNoTerminal
	}
	final, err := u.runProgram(newMultiSelectModel(u, title, options, defaults))
	if err != nil {
		return nil, err
	}
	return final.(multiSelectModel).values(), nil
}

type multiSelectModel struct {
	u         *UI
	title     string
	opts      []Option
	checked   []bool
	cursor    int
	done      bool
	cancelled bool
}

func newMultiSelectModel(u *UI, title string, opts []Option, defaults []string) multiSelectModel {
	m := multiSelectModel{u: u, title: title, opts: opts, checked: make([]bool, len(opts))}
	def := map[string]bool{}
	for _, d := range defaults {
		def[d] = true
	}
	for i, o := range opts {
		m.checked[i] = def[o.Value]
	}
	return m
}

func (m multiSelectModel) isCancelled() bool { return m.cancelled }
func (m multiSelectModel) Init() tea.Cmd     { return nil }

func (m multiSelectModel) values() []string {
	out := []string{}
	for i, o := range m.opts {
		if m.checked[i] {
			out = append(out, o.Value)
		}
	}
	return out
}

func (m multiSelectModel) labels() []string {
	out := []string{}
	for i, o := range m.opts {
		if m.checked[i] {
			out = append(out, o.Label)
		}
	}
	return out
}

func (m multiSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
	case tea.KeyUp:
		m.cursor = (m.cursor + n - 1) % n
	case tea.KeyDown:
		m.cursor = (m.cursor + 1) % n
	case tea.KeySpace:
		m.toggle()
	case tea.KeyRunes:
		switch strings.ToLower(string(k.Runes)) {
		case "k":
			m.cursor = (m.cursor + n - 1) % n
		case "j":
			m.cursor = (m.cursor + 1) % n
		case "x", " ":
			m.toggle()
		case "a":
			all := true
			for _, c := range m.checked {
				all = all && c
			}
			for i := range m.checked {
				m.checked[i] = !all
			}
		}
	}
	return m, nil
}

func (m *multiSelectModel) toggle() {
	// checked is a slice shared across value copies of the model; copy
	// before writing so an old model (e.g. held by a test) isn't mutated.
	c := make([]bool, len(m.checked))
	copy(c, m.checked)
	c[m.cursor] = !c[m.cursor]
	m.checked = c
}

func (m multiSelectModel) View() string {
	u := m.u
	switch {
	case m.cancelled:
		return u.cancelledView()
	case m.done:
		detail := strings.Join(m.labels(), ", ")
		if detail == "" {
			detail = "none"
		}
		return u.Line(Done, m.title, detail) + "\n"
	}
	var b strings.Builder
	b.WriteString(u.activeHeader(m.title))
	pad := strings.Repeat(" ", len([]rune(u.g.cursor)))
	for i, o := range m.opts {
		box := u.g.checkOff
		if m.checked[i] {
			box = u.g.checkOn
		}
		label := o.Label
		if o.Dim {
			label = u.st.dim.Render(label)
		}
		if o.Hint != "" {
			label += "  " + u.st.dim.Render(o.Hint)
		}
		var row string
		if i == m.cursor {
			row = u.st.active.Render(u.g.cursor) + " " + u.st.focus.Render(box) + " " + label
		} else {
			row = pad + " " + u.st.dim.Render(box) + " " + label
		}
		b.WriteString(u.railLine(row))
	}
	b.WriteString(u.railLine(u.st.dim.Render("space toggle · enter confirm · esc cancel")))
	b.WriteString(u.activeFooter())
	return b.String()
}
