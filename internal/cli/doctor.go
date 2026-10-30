package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/mcpserver"
	mcsh "github.com/februality/presswrench/internal/ssh"
	"github.com/februality/presswrench/internal/ui"
	"github.com/februality/presswrench/internal/wizard"
)

func NewDoctor() *cobra.Command {
	var site string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose the session, Pressable access, SSH, and per-client configs",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDoctor(site)
		},
	}
	cmd.Flags().StringVar(&site, "site", "", "site to test SSH against (default: the first accessible site)")
	return cmd
}

func runDoctor(site string) error {
	fmt.Println("Running diagnostics…")
	fmt.Println()

	accts := discoveredAccounts()
	if len(accts) == 0 && os.Getenv(auth.EnvAccessToken) == "" {
		fmt.Println("  ✗ No accounts configured. Run: presswrench setup")
		return errors.New("not signed in")
	}
	if len(accts) == 0 {
		accts = []string{creds.DefaultAccount}
	}

	var firstErr error
	for _, account := range accts {
		fmt.Printf("Account: %s\n", accountLabel(account))
		if err := doctorAccount(account, site); err != nil && firstErr == nil {
			firstErr = err
		}
		fmt.Println()
	}
	wizard.WarnOfficial(ui.New(os.Stdout, os.Stdin))
	if firstErr == nil {
		fmt.Println("All checks complete.")
	}
	return firstErr
}

func doctorAccount(account, site string) error {
	ctx := context.Background()
	cfg, err := loadConfigFor(account)
	if err != nil {
		return err
	}
	store, err := creds.Open()
	if err != nil {
		fmt.Printf("  ✗ Credentials store error: %s\n", err)
		return err
	}
	deps := mcpserver.Build(cfg, store)
	defer deps.SSHPool.Close()

	if _, err := deps.Session.Token(ctx); err != nil {
		if errors.Is(err, auth.ErrLoginRequired) {
			fmt.Printf("  ✗ Not signed in. Run: %s\n", loginCommand(account))
		} else {
			fmt.Printf("  ✗ Session refresh failed: %s\n", err)
		}
		return fmt.Errorf("no usable session for %s", accountLabel(account))
	}
	fmt.Printf("  ✓ Signed in as %s (source: %s)\n", orUnknown(deps.Session.Identity()), deps.Session.Source())

	list, err := deps.Sites.List(ctx)
	if err != nil {
		fmt.Printf("  ✗ Pressable MCP gateway: %s\n", err)
		return err
	}
	fmt.Printf("  ✓ Pressable MCP gateway reachable (%d sites accessible)\n", len(list))

	if mcsh.KeyPairExists(cfg.SSHKeyPath) {
		fmt.Printf("  ✓ SSH key at %s (label %q)\n", cfg.SSHKeyPath, cfg.SSHKeyLabel)
		target := site
		if target == "" && len(list) > 0 {
			target = fmt.Sprint(list[0].ID)
		}
		if target != "" {
			if name, user, err := deps.CheckSSH(ctx, target); err == nil {
				fmt.Printf("  ✓ SSH login to %s as %s\n", name, user)
			} else {
				fmt.Printf("  ✗ SSH: %s\n", err)
			}
		}
	} else {
		fmt.Printf("  ✗ SSH key missing at %s — run setup\n", cfg.SSHKeyPath)
	}
	if cfg.ReadOnly {
		fmt.Println("  · PRESSWRENCH_READ_ONLY is set in this shell")
	}

	fmt.Println("  AI-tool configs:")
	for _, p := range clients.All(account) {
		_, path, _ := p.Detect()
		entries, err := p.Entries()
		if err != nil {
			fmt.Printf("    ✗ %-16s %s\n", p.DisplayName(), err)
			continue
		}
		hasEntry := false
		for _, e := range entries {
			if e == account {
				hasEntry = true
				break
			}
		}
		if !hasEntry {
			if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
				fmt.Printf("    · %-16s no config file at %s\n", p.DisplayName(), path)
			} else {
				fmt.Printf("    · %-16s no entry for this account\n", p.DisplayName())
			}
			continue
		}
		roSuffix := ""
		if env, envErr := p.CurrentEnv(); envErr == nil && config.IsTrueEnv(env[readOnlyEnvVar]) {
			roSuffix = "  [read-only]"
		}
		fmt.Printf("    ✓ %-16s configured at %s%s\n", p.DisplayName(), path, roSuffix)
	}
	return nil
}
