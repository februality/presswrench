package wizard

import "github.com/februality/presswrench/internal/ui"

// Prompter is the wizard's test seam for interactive questions. *ui.UI
// implements it; tests substitute a scripted implementation.
type Prompter interface {
	Text(title, placeholder string, validate func(string) error) (string, error)
	Confirm(title string, def bool) (bool, error)
	Select(title string, options []ui.Option, def string) (string, error)
	MultiSelect(title string, options []ui.Option, defaults []string) ([]string, error)
}

// SelectOption is kept as an alias for callers that predate internal/ui.
type SelectOption = ui.Option

var _ Prompter = (*ui.UI)(nil)
