// Package wizard runs the interactive setup flow that the install scripts
// launch after dropping the binary in place: sign in to Pressable in the
// browser, create an SSH key and walk the user through adding it in
// MyPressable, then patch every detected MCP-client config.
//
// All prompts go through the Prompter interface so tests (and the
// --unattended path) can substitute scripted answers.
package wizard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/mcpserver"
	mcsh "github.com/februality/presswrench/internal/ssh"
)

// Options configure a wizard run.
type Options struct {
	Out         io.Writer
	Prompter    Prompter
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

// Run executes the setup flow. Returns the first fatal error or nil.
func Run(opts Options) error {
	ctx := context.Background()
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.Prompter == nil {
		opts.Prompter = NewPrompter()
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
	w := opts.Out

	printBanner(w)
	if opts.Account != "" {
		fmt.Fprintf(w, "  Setting up account %q — session, SSH key, and client entry suffixed -%s.\n\n", opts.Account, opts.Account)
	}

	store, err := creds.Open()
	if err != nil {
		return fmt.Errorf("open credentials store: %w", err)
	}

	// Step 1: sign in.
	if err := ensureSignedIn(ctx, w, opts, cfg, store); err != nil {
		return err
	}
	deps := mcpserver.Build(cfg, store)
	list, err := deps.Sites.List(ctx)
	if err != nil {
		return fmt.Errorf("verify session (list_sites): %w", err)
	}
	who := deps.Session.Identity()
	if who == "" {
		who = "your Pressable user"
	}
	fmt.Fprintf(w, "  ✓ Signed in as %s — %d sites accessible\n", who, len(list))
	fmt.Fprintf(w, "  ✓ Session stored in %s\n\n", backendLabel(store))

	// Step 2: SSH key.
	if !opts.SkipSSH {
		if err := setupSSH(ctx, w, opts, cfg, deps, len(list)); err != nil {
			return err
		}
	}

	// Step 3: read-only opt-in (baked into the client configs in step 4).
	if !opts.SkipClients && !opts.Unattended {
		ro, err := opts.Prompter.Confirm(
			"Run in read-only mode? Hides pressable_ssh_exec, pressable_wp_cli and pressable_sftp_write, and only lets "+
				"Pressable operations marked read-only through.",
			opts.ReadOnly,
		)
		if err != nil {
			return err
		}
		opts.ReadOnly = ro
	}
	if opts.ReadOnly {
		fmt.Fprintln(w, "  ✓ Read-only mode: ON")
		fmt.Fprintln(w)
	}

	// Step 4: patch clients.
	var patched []string
	if !opts.SkipClients {
		if patched, err = patchClients(w, opts); err != nil {
			return err
		}
	}

	WarnOfficial(w)
	printSummary(w, opts, cfg, patched)
	return nil
}

func backendLabel(store creds.Store) string {
	if fs, ok := store.(*creds.FileStore); ok {
		return fs.Path() + " (mode 0600)"
	}
	return "the OS keychain"
}

func ensureSignedIn(ctx context.Context, w io.Writer, opts Options, cfg *config.Config, store creds.Store) error {
	session := auth.NewSession(store, cfg.Account, cfg.AuthURL)
	_, tokErr := session.Token(ctx)
	if tokErr == nil {
		if opts.Unattended {
			return nil
		}
		again, err := opts.Prompter.Confirm(
			fmt.Sprintf("Already signed in as %s. Sign in again?", orDefault(session.Identity(), "a Pressable user")),
			false,
		)
		if err != nil || !again {
			return err
		}
	} else if opts.Unattended {
		return fmt.Errorf("--unattended needs an existing session (run `presswrench login`) or PRESSWRENCH_ACCESS_TOKEN: %w", tokErr)
	}

	fmt.Fprintln(w, "  Step 1 — Sign in to Pressable")
	fmt.Fprintln(w, "  You'll approve access in your browser as yourself; the AI tool gets exactly")
	fmt.Fprintln(w, "  the sites and permissions your Pressable account has.")
	fmt.Fprintln(w)
	reader := bufio.NewReader(os.Stdin)
	_, err := auth.SignIn(ctx, store, cfg.Account, auth.LoginOptions{
		AuthURL:     cfg.AuthURL,
		OpenBrowser: auth.OpenBrowser,
		Manual:      opts.ManualLogin,
		ReadLine:    func() (string, error) { return reader.ReadString('\n') },
		OnAuthorizeURL: func(u string, _ bool) {
			fmt.Fprintf(w, "  Open this URL if your browser didn't:\n\n    %s\n\n", u)
		},
	})
	return err
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func setupSSH(ctx context.Context, w io.Writer, opts Options, cfg *config.Config, deps *mcpserver.Deps, siteCount int) error {
	fmt.Fprintln(w, "  Step 2 — SSH key for shell, WP-CLI and file access")
	pair, err := mcsh.EnsureKeyPair(cfg.SSHKeyPath, cfg.SSHKeyLabel)
	if err != nil {
		return fmt.Errorf("ensure SSH key: %w", err)
	}
	fmt.Fprintf(w, "  ✓ SSH key at %s\n\n", cfg.SSHKeyPath)
	pub := strings.TrimSpace(pair.PublicKey)

	if opts.Unattended {
		fmt.Fprintln(w, "  Add this public key in MyPressable → Profile → Settings → SSH Keys")
		fmt.Fprintf(w, "  (name it %q):\n\n    %s\n\n", cfg.SSHKeyLabel, pub)
		return nil
	}

	copied := clipboard.WriteAll(pub) == nil
	fmt.Fprintln(w, "  Add this public key to your Pressable profile:")
	fmt.Fprintf(w, "\n    %s\n\n", pub)
	if copied {
		fmt.Fprintln(w, "  (Copied to your clipboard.)")
	}
	fmt.Fprintln(w, "    1. Open https://my.pressable.com → Profile → Settings → SSH Keys")
	fmt.Fprintf(w, "    2. Add key — name it %q and paste the key above\n", cfg.SSHKeyLabel)
	fmt.Fprintln(w, "  Pressable then creates an SSH login for you on every site you have SFTP access to.")
	fmt.Fprintln(w)
	if siteCount == 0 {
		fmt.Fprintln(w, "  · No sites to test against yet — skipping the SSH check.")
		fmt.Fprintln(w)
		return nil
	}

	for {
		test, err := opts.Prompter.Confirm("Added it? Test SSH access now (choose No to skip)", true)
		if err != nil {
			return err
		}
		if !test {
			fmt.Fprintln(w, "  · Skipped. Check later with `presswrench doctor`.")
			fmt.Fprintln(w)
			return nil
		}
		name, user, err := testSSH(ctx, w, deps)
		if err == nil {
			fmt.Fprintf(w, "  ✓ SSH works — logged in to %s as %s\n\n", name, user)
			return nil
		}
		fmt.Fprintf(w, "  ✗ %s\n\n", err)
	}
}

// testSSH tries the first few sites, polling briefly: Pressable can take a
// few seconds to create per-site logins after a key is added.
func testSSH(ctx context.Context, w io.Writer, deps *mcpserver.Deps) (string, string, error) {
	list, err := deps.Sites.List(ctx)
	if err != nil {
		return "", "", err
	}
	if len(list) > 3 {
		list = list[:3]
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			fmt.Fprintln(w, "  … waiting for Pressable to create the SSH logins")
			time.Sleep(10 * time.Second)
		}
		for _, s := range list {
			name, user, err := deps.CheckSSH(ctx, fmt.Sprint(s.ID))
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

func patchClients(w io.Writer, opts Options) ([]string, error) {
	all := clients.All(opts.Account)
	if len(opts.OnlyClients) > 0 {
		want := map[string]bool{}
		for _, id := range opts.OnlyClients {
			want[id] = true
		}
		filtered := all[:0]
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
	for _, p := range all {
		installed, path, _ := p.Detect()
		infos = append(infos, detectInfo{p, installed, path})
	}

	prompts := make([]SelectOption, 0, len(infos))
	defaults := []string{}
	for _, i := range infos {
		label := i.patcher.DisplayName()
		if !i.installed {
			label += " (not detected)"
		}
		prompts = append(prompts, SelectOption{Label: label, Value: i.patcher.ID()})
		if i.installed {
			defaults = append(defaults, i.patcher.ID())
		}
	}

	chosen := defaults
	if !opts.Unattended {
		var err error
		chosen, err = opts.Prompter.MultiSelect("Configure which AI tools?", prompts, defaults)
		if err != nil {
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
			fmt.Fprintf(w, "  ✗ %s: %s\n", i.patcher.DisplayName(), err)
			continue
		}
		if changed {
			fmt.Fprintf(w, "  ✓ %s — patched %s\n", i.patcher.DisplayName(), i.path)
		} else {
			fmt.Fprintf(w, "  · %s — already configured\n", i.patcher.DisplayName())
		}
		patched = append(patched, i.patcher.ID())
	}
	fmt.Fprintln(w)
	return patched, nil
}

func printSummary(w io.Writer, opts Options, cfg *config.Config, patched []string) {
	fmt.Fprintln(w, "  Setup complete.")
	fmt.Fprintln(w)
	if opts.Account != "" {
		fmt.Fprintf(w, "  Account:    %s\n", opts.Account)
	}
	fmt.Fprintf(w, "  Entry:      %s\n", clients.EntryName(opts.Account))
	fmt.Fprintf(w, "  Binary:     %s\n", opts.BinaryPath)
	if !opts.SkipSSH {
		fmt.Fprintf(w, "  SSH key:    %s (label %q)\n", cfg.SSHKeyPath, cfg.SSHKeyLabel)
	}
	fmt.Fprintf(w, "  MCP server: %s v%s\n", mcpserver.ServerName, mcpserver.ServerVersion)
	if len(patched) > 0 {
		fmt.Fprintf(w, "  Configured: %s\n", strings.Join(patched, ", "))
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Restart your AI tool to load the server.")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Verify with:  presswrench doctor")
	fmt.Fprintln(w)
}

// WarnOfficial prints a notice when an AI tool also has Pressable's hosted
// MCP server configured: with both loaded, the model can reach Pressable
// directly and skip read-only mode and the operation blocklist. Reports
// whether anything was found.
func WarnOfficial(w io.Writer) bool {
	found := clients.FindOfficial()
	if len(found) == 0 {
		return false
	}
	fmt.Fprintf(w, "  ! Pressable's official MCP server (%s) is also configured:\n", clients.OfficialHost)
	for _, e := range found {
		fmt.Fprintf(w, "      %s — %s  (%s)\n", e.Client, e.Name, e.Path)
	}
	fmt.Fprintln(w, "    With both loaded, the AI can call Pressable directly, bypassing presswrench's")
	fmt.Fprintln(w, "    read-only mode and blocked operations. Remove that entry if you rely on them.")
	fmt.Fprintln(w)
	return true
}
