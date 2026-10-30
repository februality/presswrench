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
			return runDoctor(ui.New(os.Stdout, os.Stdin), site)
		},
	}
	cmd.Flags().StringVar(&site, "site", "", "site to test SSH against (default: the first accessible site)")
	return cmd
}

func runDoctor(u *ui.UI, site string) error {
	fmt.Println("Running diagnostics…")
	fmt.Println()

	accts := discoveredAccounts()
	if len(accts) == 0 && os.Getenv(auth.EnvAccessToken) == "" {
		u.Fail("No accounts configured", "run presswrench setup")
		return errors.New("not signed in")
	}
	if len(accts) == 0 {
		accts = []string{creds.DefaultAccount}
	}

	var firstErr error
	for _, account := range accts {
		fmt.Printf("Account: %s\n", accountLabel(account))
		if err := doctorAccount(u, account, site); err != nil && firstErr == nil {
			firstErr = err
		}
		fmt.Println()
	}
	wizard.WarnOfficial(u)
	if firstErr == nil {
		fmt.Println("All checks complete.")
	}
	return firstErr
}

func doctorAccount(u *ui.UI, account, site string) error {
	ctx := context.Background()
	cfg, err := loadConfigFor(account)
	if err != nil {
		return err
	}
	store, err := creds.Open()
	if err != nil {
		u.Fail("Credentials store", err.Error())
		return err
	}
	deps := mcpserver.Build(cfg, store)
	defer deps.SSHPool.Close()

	if _, err := deps.Session.Token(ctx); err != nil {
		if errors.Is(err, auth.ErrLoginRequired) {
			u.Fail("Not signed in", "run "+loginCommand(account))
		} else {
			u.Fail("Session refresh failed", err.Error())
		}
		return fmt.Errorf("no usable session for %s", accountLabel(account))
	}
	u.Step("Signed in as "+orUnknown(deps.Session.Identity()), "source: "+string(deps.Session.Source()))

	var list []sitesList
	var listErr error
	if err := u.Spin("Checking Pressable access", "Listing sites…", nil, func(func(string)) ui.Outcome {
		l, err := deps.Sites.List(ctx)
		if err != nil {
			listErr = err
			return ui.Outcome{Level: ui.Fail, Text: "Pressable MCP gateway · " + err.Error()}
		}
		for _, s := range l {
			list = append(list, sitesList{id: fmt.Sprint(s.ID)})
		}
		return ui.Outcome{Level: ui.Done, Text: fmt.Sprintf("Pressable MCP gateway reachable · %d sites accessible", len(l))}
	}); err != nil {
		return err
	}
	if listErr != nil {
		return listErr
	}

	if mcsh.KeyPairExists(cfg.SSHKeyPath) {
		u.Step("SSH key", fmt.Sprintf("%s (label %q)", cfg.SSHKeyPath, cfg.SSHKeyLabel))
		target := site
		if target == "" && len(list) > 0 {
			target = list[0].id
		}
		if target != "" {
			if err := u.Spin("Checking SSH access", "Connecting…", nil, func(func(string)) ui.Outcome {
				name, user, err := deps.CheckSSH(ctx, target)
				if err != nil {
					return ui.Outcome{Level: ui.Fail, Text: "SSH · " + err.Error()}
				}
				return ui.Outcome{Level: ui.Done, Text: fmt.Sprintf("SSH login to %s as %s", name, user)}
			}); err != nil {
				return err
			}
		}
	} else {
		u.Fail("SSH key missing", cfg.SSHKeyPath+" — run setup")
	}
	if cfg.ReadOnly {
		u.Skip("PRESSWRENCH_READ_ONLY is set in this shell", "")
	}

	fmt.Println("  AI-tool configs:")
	for _, p := range clients.All(account) {
		_, path, _ := p.Detect()
		entries, err := p.Entries()
		if err != nil {
			fmt.Printf("    %s %-16s %s\n", u.Mark(ui.Fail), p.DisplayName(), err)
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
				fmt.Printf("    %s %-16s no config file at %s\n", u.Mark(ui.Skip), p.DisplayName(), path)
			} else {
				fmt.Printf("    %s %-16s no entry for this account\n", u.Mark(ui.Skip), p.DisplayName())
			}
			continue
		}
		roSuffix := ""
		if env, envErr := p.CurrentEnv(); envErr == nil && config.IsTrueEnv(env[readOnlyEnvVar]) {
			roSuffix = "  [read-only]"
		}
		fmt.Printf("    %s %-16s configured at %s%s\n", u.Mark(ui.Done), p.DisplayName(), path, roSuffix)
	}
	return nil
}

// sitesList is the subset of a site doctor needs.
type sitesList struct{ id string }
