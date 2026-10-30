package ui

import (
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type spinStatusMsg string
type spinDoneMsg Outcome

// Spin shows title as the active step with a spinner and status beneath,
// plus optional raw detail lines (never wrapped). fn runs in a goroutine;
// set replaces the status text and note prints rail lines into the
// scrollback above the spinner. Bubble Tea truncates the managed status
// line to the terminal width, so anything the user must read in full (a
// URL, a key) goes through note, never set. fn's Outcome becomes the
// step's final line. Returns ErrCancelled if the user presses Ctrl+C while
// waiting, in which case fn is abandoned.
//
// When the UI isn't interactive, the title and detail are printed once,
// fn runs synchronously and the outcome line follows.
func (u *UI) Spin(title, status string, detail []string, fn func(set func(status string), note func(lines ...string)) Outcome) error {
	if !u.interactive || u.syncSpin {
		u.printf("%s", u.activeHeader(title))
		u.NoteRaw(detail...)
		out := fn(func(string) {}, u.NoteRaw)
		u.printf("%s\n", u.line(out.Level, out.Text, ""))
		return nil
	}
	m := newSpinModel(u, title, status, detail)
	p := tea.NewProgram(m, tea.WithInput(u.in), tea.WithOutput(u.out))
	note := func(lines ...string) {
		for _, l := range lines {
			p.Println(u.st.dim.Render(u.g.rail) + "  " + l)
		}
	}
	go func() {
		out := fn(func(s string) { p.Send(spinStatusMsg(s)) }, note)
		p.Send(spinDoneMsg(out))
	}()
	final, err := p.Run()
	if err != nil {
		return err
	}
	if final.(spinModel).cancelled {
		return ErrCancelled
	}
	return nil
}

type spinModel struct {
	u         *UI
	title     string
	status    string
	detail    []string
	sp        spinner.Model
	outcome   *Outcome
	cancelled bool
}

func newSpinModel(u *UI, title, status string, detail []string) spinModel {
	sp := spinner.New(spinner.WithSpinner(u.g.spinner))
	sp.Style = u.st.active
	return spinModel{u: u, title: title, status: status, detail: detail, sp: sp}
}

func (m spinModel) Init() tea.Cmd { return m.sp.Tick }

func (m spinModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.cancelled = true
			return m, tea.Quit
		}
		return m, nil
	case spinStatusMsg:
		m.status = string(msg)
		return m, nil
	case spinDoneMsg:
		out := Outcome(msg)
		m.outcome = &out
		return m, tea.Quit
	}
	var cmd tea.Cmd
	m.sp, cmd = m.sp.Update(msg)
	return m, cmd
}

func (m spinModel) View() string {
	u := m.u
	switch {
	case m.cancelled:
		return u.cancelledView()
	case m.outcome != nil:
		return u.Line(m.outcome.Level, m.outcome.Text, "") + "\n"
	}
	s := u.activeHeader(m.title) + u.railLine(m.sp.View()+" "+m.status)
	for _, d := range m.detail {
		s += u.railLine(d)
	}
	return s + u.activeFooter()
}
