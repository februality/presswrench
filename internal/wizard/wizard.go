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
	"path/filepath"
	"strings"
	"time"

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
	if !opts.SkipSSH {
		if err := setupSSH(ctx, u, opts, cfg, h, siteCount); err != nil {
			return err
		}
	}

	var patched []string
	if !opts.SkipClients {
		if !opts.Unattended {
			ro, err := readOnlyStep(u, opts)
			if err != nil {
				return err
			}
			opts.ReadOnly = ro
		}
		if patched, err = patchClients(u, opts, h); err != nil {
			return err
		}
	}
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

const (
	sshPollAttempts = 4
	sshPollSites    = 3
)

// setupSSH creates the key pair, tells the user how to add it in
// MyPressable, and offers to test the login until it works or they skip.
func setupSSH(ctx context.Context, u *ui.UI, opts Options, cfg *config.Config, h *Hooks, siteCount int) error {
	pair, err := h.EnsureKey(cfg.SSHKeyPath, cfg.SSHKeyLabel)
	if err != nil {
		return fail(u, fmt.Errorf("Create SSH key: %w", err))
	}
	pub := strings.TrimSpace(pair.PublicKey)
	copied := h.Clipboard(pub) == nil
	detail := shortHome(cfg.SSHKeyPath)
	if copied {
		detail += " · copied to clipboard"
	}
	u.Step("SSH key", detail)

	instructions := fmt.Sprintf("Add it in MyPressable → Profile → Settings → SSH Keys, named %q.", cfg.SSHKeyLabel)
	if opts.Unattended {
		u.NoteRaw(pub)
		u.Note(instructions)
		return nil
	}
	u.Note(instructions)
	if !copied {
		u.NoteRaw(pub)
	}
	u.Blank()

	if siteCount == 0 {
		u.Step("SSH test", "no sites to test against yet")
		return nil
	}

	options := []ui.Option{{Label: "Test SSH now", Value: "test"}}
	if copied {
		options = append(options, ui.Option{Label: "Show the key", Value: "show"})
	}
	options = append(options, ui.Option{Label: "Skip", Value: "skip"})

	for {
		choice, err := opts.Prompter.Select("Added the key?", options, "test")
		if err != nil {
			return err
		}
		switch choice {
		case "show":
			u.NoteRaw(pub)
		case "skip":
			u.Step("SSH test", "skipped, check later with presswrench doctor")
			return nil
		default:
			var ok bool
			if err := u.Spin("Checking SSH access", "attempt 1 of 4", nil, func(set func(string)) ui.Outcome {
				name, user, err := pollSSH(ctx, h, set)
				if err != nil {
					return ui.Outcome{Level: ui.Warn, Text: "SSH not working yet · " + err.Error()}
				}
				ok = true
				return ui.Outcome{Level: ui.Done, Text: fmt.Sprintf("SSH works · %s as %s", name, user)}
			}); err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
	}
}

// pollSSH tries the first few sites, polling briefly: Pressable can take
// a few seconds to create per-site logins after a key is added.
func pollSSH(ctx context.Context, h *Hooks, set func(string)) (string, string, error) {
	list, err := h.ListSites(ctx)
	if err != nil {
		return "", "", err
	}
	if len(list) > sshPollSites {
		list = list[:sshPollSites]
	}
	var lastErr error
	for attempt := 1; attempt <= sshPollAttempts; attempt++ {
		if attempt > 1 {
			time.Sleep(h.PollDelay)
		}
		set(fmt.Sprintf("attempt %d of %d", attempt, sshPollAttempts))
		for _, s := range list {
			name, user, err := h.CheckSSH(ctx, fmt.Sprint(s.ID))
			if err == nil {
				return name, user, nil
			}
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no site accepted the key")
	}
	return "", "", lastErr
}

// readOnlyStep asks whether to bake read-only mode into the client configs.
// The prompt's own finished line is the record; nothing else is printed.
func readOnlyStep(u *ui.UI, opts Options) (bool, error) {
	u.Note("Hides shell, WP-CLI and file writes; allows only read-only Pressable calls.")
	return opts.Prompter.Confirm("Run in read-only mode?", opts.ReadOnly)
}

// patchEnv builds the env block for each client's server entry. nil when
// nothing is set so a plain install has no env block at all.
func patchEnv(opts Options) map[string]string {
	env := map[string]string{}
	if opts.ReadOnly {
		env["PRESSWRENCH_READ_ONLY"] = "1"
	}
	if opts.Account != "" {
		env["PRESSWRENCH_ACCOUNT"] = opts.Account
	}
	if opts.BlockedOperations != nil {
		env["PRESSWRENCH_BLOCKED_OPERATIONS"] = *opts.BlockedOperations
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

// patchClients asks which AI tools to configure (detected ones
// pre-selected) and patches each. Patch failures are reported per client
// and don't stop the run. Returns the IDs that were configured.
func patchClients(u *ui.UI, opts Options, h *Hooks) ([]string, error) {
	all := h.Patchers(opts.Account)
	if len(opts.OnlyClients) > 0 {
		want := map[string]bool{}
		for _, id := range opts.OnlyClients {
			want[id] = true
		}
		filtered := make([]clients.Patcher, 0, len(all))
		for _, p := range all {
			if want[p.ID()] {
				filtered = append(filtered, p)
			}
		}
		all = filtered
	}

	type detectInfo struct {
		patcher   clients.Patcher
		installed bool
		path      string
	}
	infos := make([]detectInfo, 0, len(all))
	options := make([]ui.Option, 0, len(all))
	defaults := []string{}
	for _, p := range all {
		installed, path, _ := p.Detect()
		infos = append(infos, detectInfo{p, installed, path})
		opt := ui.Option{Label: p.DisplayName(), Value: p.ID()}
		if installed {
			defaults = append(defaults, p.ID())
		} else {
			opt.Hint = "(not detected)"
			opt.Dim = true
		}
		options = append(options, opt)
	}

	chosen := defaults
	if !opts.Unattended {
		var err error
		if chosen, err = opts.Prompter.MultiSelect("Configure which AI tools?", options, defaults); err != nil {
			return nil, err
		}
	}
	want := map[string]bool{}
	for _, id := range chosen {
		want[id] = true
	}

	patched := []string{}
	for _, i := range infos {
		if !want[i.patcher.ID()] {
			continue
		}
		changed, _, err := i.patcher.Patch(opts.BinaryPath, patchEnv(opts), false)
		if err != nil {
			u.Fail(i.patcher.DisplayName(), err.Error())
			continue
		}
		if changed {
			u.Step(i.patcher.DisplayName(), shortHome(i.path))
		} else {
			u.Step(i.patcher.DisplayName(), "already configured")
		}
		patched = append(patched, i.patcher.ID())
	}
	if len(chosen) == 0 {
		u.Step("AI tools", "none configured")
	}
	return patched, nil
}

// shortHome abbreviates the user's home directory to "~" for display.
func shortHome(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !strings.HasPrefix(p, home) {
		return p
	}
	return "~" + filepath.ToSlash(strings.TrimPrefix(p, home))
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
		u.NoteRaw(fmt.Sprintf("%s — %s  (%s)", e.Client, e.Name, e.Path))
	}
	u.Note("With both loaded the AI can bypass read-only mode and blocked operations. Remove that entry if you rely on them.")
	return true
}
