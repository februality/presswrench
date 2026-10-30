// Package wizard runs the interactive setup flow that the install scripts
// launch after dropping the binary in place: sign in to Pressable in the
// browser, create an SSH key and walk the user through adding it in
// MyPressable, then patch every detected MCP-client config.
//
// Output is rendered by internal/ui in the "rail" style: one line per
// finished step, an inline prompt or spinner for the active one. Prompts
// go through the Prompter interface and side effects through Hooks so
// tests (and the --unattended path) never touch a terminal or Pressable.
package wizard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/mcpserver"
	"github.com/februality/presswrench/internal/ui"
)

// Options configure a wizard run.
type Options struct {
	Out         io.Writer
	UI          *ui.UI   // nil → ui.New(Out, os.Stdin)
	Prompter    Prompter // nil → UI
	Hooks       *Hooks   // nil → DefaultHooks
	Account     string   // "" = default account; otherwise a named account slug
	Unattended  bool     // skip prompts; requires an existing session or PRESSWRENCH_ACCESS_TOKEN
	ManualLogin bool     // paste the redirect URL instead of using a loopback listener
	BinaryPath  string   // path to install into MCP-client configs
	SkipSSH     bool     // skip SSH key creation and testing
	SkipClients bool     // skip patching MCP-client configs
	OnlyClients []string // limit which client patchers to use
	// ReadOnly bakes PRESSWRENCH_READ_ONLY=1 into the patched client configs.
	ReadOnly bool
	// BlockedOperations, when non-nil, bakes PRESSWRENCH_BLOCKED_OPERATIONS
	// into the client configs ("none" clears the default blocklist).
	BlockedOperations *string
}

// Run executes the setup flow. Errors the UI has already shown come back
// wrapped by ui.Reported so main doesn't print them twice.
func Run(opts Options) error {
	ctx := context.Background()
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.UI == nil {
		opts.UI = ui.New(opts.Out, os.Stdin)
	}
	u := opts.UI
	if !u.Interactive() && !opts.Unattended {
		return ui.ErrNoTerminal
	}
	if opts.Prompter == nil {
		opts.Prompter = u
	}
	if opts.BinaryPath == "" {
		bp, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve binary path: %w", err)
		}
		opts.BinaryPath = bp
	}
	// Bind this process to the account so config.Load picks per-account
	// defaults (key path, label, known_hosts).
	if err := os.Setenv("PRESSWRENCH_ACCOUNT", opts.Account); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if opts.Hooks == nil {
		store, err := creds.Open()
		if err != nil {
			return fmt.Errorf("open credentials store: %w", err)
		}
		opts.Hooks = DefaultHooks(cfg, store)
	}
	h := opts.Hooks

	u.Intro("PressWrench setup", "v"+mcpserver.ServerVersion)
	if opts.Account != "" {
		u.Note(fmt.Sprintf("Account %q · entry %s", opts.Account, clients.EntryName(opts.Account)))
		u.Blank()
	}

	err = runSteps(ctx, u, opts, cfg, h)
	switch {
	case errors.Is(err, ui.ErrCancelled):
		// The prompt already printed "■ Cancelled."; close the rail.
		u.Outro("")
		return ui.Reported(err)
	case err != nil:
		return err
	}
	return nil
}

func runSteps(ctx context.Context, u *ui.UI, opts Options, cfg *config.Config, h *Hooks) error {
	siteCount, err := signIn(ctx, u, opts, cfg, h)
	if err != nil {
		return err
	}
	_ = siteCount

	var patched []string
	warnOfficial(u, h.Official())
	u.Blank()
	if len(patched) > 0 {
		u.Outro("Done. Restart your AI tool, then run `presswrench doctor`.")
	} else {
		u.Outro("Done. Run `presswrench doctor` to verify.")
	}
	return nil
}

// fail prints err as a failure line and marks it reported.
func fail(u *ui.UI, err error) error {
	u.Fail(err.Error(), "")
	return ui.Reported(err)
}

// signIn makes sure there's a session and returns the number of sites it
// can see.
func signIn(ctx context.Context, u *ui.UI, opts Options, cfg *config.Config, h *Hooks) (int, error) {
	signedIn := func(identity string) (ui.Outcome, int, error) {
		list, err := h.ListSites(ctx)
		if err != nil {
			return ui.Outcome{Level: ui.Fail, Text: fmt.Sprintf("Verify session (list_sites): %s", err)}, 0, err
		}
		text := fmt.Sprintf("Signed in as %s · %d sites", orDefault(identity, "your Pressable user"), len(list))
		if h.StoreLabel != "" {
			text += fmt.Sprintf(" · session in %s (0600)", h.StoreLabel)
		}
		return ui.Outcome{Level: ui.Done, Text: text}, len(list), nil
	}

	if identity, ok := h.Session(ctx); ok {
		var n int
		var err error
		spinErr := u.Spin("Checking Pressable access", "Listing sites…", nil, func(func(string)) ui.Outcome {
			var out ui.Outcome
			out, n, err = signedIn(identity)
			return out
		})
		if spinErr != nil {
			return 0, spinErr
		}
		if err != nil {
			return 0, ui.Reported(err)
		}
		return n, nil
	}
	if opts.Unattended {
		return 0, errors.New("--unattended needs an existing session (run `presswrench login`) or PRESSWRENCH_ACCESS_TOKEN")
	}

	lo := auth.LoginOptions{
		AuthURL:     cfg.AuthURL,
		OpenBrowser: auth.OpenBrowser,
		Manual:      opts.ManualLogin,
	}

	if opts.ManualLogin {
		lo.OnAuthorizeURL = func(url string, _ bool) {
			u.NoteRaw("Open this URL and sign in to Pressable:", url)
			u.Note("After approving, your browser lands on a 127.0.0.1 page that fails to load.")
		}
		lo.ReadLine = func() (string, error) {
			return opts.Prompter.Text("Paste the URL your browser landed on", "http://127.0.0.1:53682/callback?…", requireNonEmpty)
		}
		if !u.Interactive() {
			reader := bufio.NewReader(os.Stdin)
			lo.ReadLine = func() (string, error) { return reader.ReadString('\n') }
		}
		identity, err := h.SignIn(ctx, lo)
		if err != nil {
			if errors.Is(err, ui.ErrCancelled) {
				return 0, err
			}
			return 0, fail(u, err)
		}
		out, n, err := signedIn(identity)
		if err != nil {
			u.Fail(out.Text, "")
			return 0, ui.Reported(err)
		}
		u.Step(out.Text, "")
		return n, nil
	}

	var n int
	var err error
	spinErr := u.Spin("Sign in to Pressable in your browser", "Opening the browser…", nil, func(set func(string)) ui.Outcome {
		lo.OnAuthorizeURL = func(url string, opened bool) {
			if opened {
				set("Waiting for you to approve access · if the browser didn't open: " + url)
			} else {
				set("Open this URL and sign in: " + url)
			}
		}
		var identity string
		identity, err = h.SignIn(ctx, lo)
		if err != nil {
			return ui.Outcome{Level: ui.Fail, Text: err.Error()}
		}
		var out ui.Outcome
		out, n, err = signedIn(identity)
		return out
	})
	if spinErr != nil {
		return 0, spinErr
	}
	if err != nil {
		return 0, ui.Reported(err)
	}
	return n, nil
}

func requireNonEmpty(s string) error {
	if s == "" {
		return errors.New("Paste the full URL")
	}
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// WarnOfficial prints a notice when an AI tool also has Pressable's hosted
// MCP server configured: with both loaded, the model can reach Pressable
// directly and skip read-only mode and the operation blocklist. Reports
// whether anything was found.
func WarnOfficial(u *ui.UI) bool {
	return warnOfficial(u, clients.FindOfficial())
}

func warnOfficial(u *ui.UI, found []clients.OfficialEntry) bool {
	if len(found) == 0 {
		return false
	}
	u.Warn(fmt.Sprintf("Pressable's official MCP server (%s) is also configured", clients.OfficialHost), "")
	for _, e := range found {
		u.Note(fmt.Sprintf("%s — %s  (%s)", e.Client, e.Name, e.Path))
	}
	u.Note("With both loaded the AI can bypass read-only mode and blocked operations. Remove that entry if you rely on them.")
	return true
}
