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

	store, openErr := openStore()
	if openErr != nil {
		u.Fail("Credential store "+u.Sep()+" unavailable", auth.Explain(openErr))
		store = creds.Broken(openErr)
	} else {
		showStore(u, store)
	}
	fmt.Println()

	accts, listErr := discoveredAccounts(store)
	storeProblem := openErr
	if openErr == nil && listErr != nil {
		u.Warn("Could not list the stored accounts", auth.Explain(listErr))
		storeProblem = listErr
	}
	if len(accts) == 0 && os.Getenv(auth.EnvAccessToken) == "" {
		if storeProblem != nil {
			// The problem is already shown; don't claim there are no accounts.
			return ui.Reported(storeProblem)
		}
		u.Fail("No accounts configured", "run presswrench setup")
		return errors.New("not signed in")
	}
	if len(accts) == 0 {
		accts = []string{creds.DefaultAccount}
	}

	var firstErr error
	for _, account := range accts {
		fmt.Printf("Account: %s\n", auth.AccountLabel(account))
		if err := doctorAccount(u, store, account, site); err != nil && firstErr == nil {
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

// buildDeps is mcpserver.Build; tests replace it to inspect the deps.
var buildDeps = mcpserver.Build

func doctorAccount(u *ui.UI, store creds.Store, account, site string) error {
	ctx := context.Background()
	cfg, err := loadConfigFor(account)
	if err != nil {
		return err
	}
	deps := buildDeps(cfg, store)
	defer deps.SSHPool.Close()
	defer deps.Session.Close() // releases the lock of a session that couldn't save

	if _, err := deps.Session.Token(ctx); err != nil {
		u.Fail(auth.Explain(err), "")
		return fmt.Errorf("no usable session for %s", auth.AccountLabel(account))
	}
	src, _ := deps.Session.State()
	u.Step("Signed in as "+orUnknown(deps.Session.Identity()), "source: "+string(src))

	var list []sitesList
	var listErr error
	if err := u.Spin("Checking Pressable access", "Listing sites"+u.Ellipsis(), nil, func(func(string), func(...string)) ui.Outcome {
		l, err := deps.Sites.List(ctx)
		if err != nil {
			listErr = err
			return ui.Outcome{Level: ui.Fail, Text: "Pressable MCP gateway" + u.Dash() + " " + err.Error()}
		}
		for _, s := range l {
			list = append(list, sitesList{id: fmt.Sprint(s.ID)})
		}
		return ui.Outcome{Level: ui.Done, Text: fmt.Sprintf("Pressable MCP gateway reachable · %d sites accessible", len(l))}
	}); err != nil {
		return err
	}
	if listErr != nil {
		return ui.Reported(listErr)
	}

	if mcsh.KeyPairExists(cfg.SSHKeyPath) {
		u.Step("SSH key", fmt.Sprintf("%s (label %q)", cfg.SSHKeyPath, cfg.SSHKeyLabel))
		target := site
		if target == "" && len(list) > 0 {
			target = list[0].id
		}
		if target != "" {
			if err := u.Spin("Checking SSH access", "Connecting"+u.Ellipsis(), nil, func(func(string), func(...string)) ui.Outcome {
				name, user, err := deps.CheckSSH(ctx, target)
				if err != nil {
					return ui.Outcome{Level: ui.Fail, Text: "SSH" + u.Dash() + " " + err.Error()}
				}
				return ui.Outcome{Level: ui.Done, Text: fmt.Sprintf("SSH login to %s as %s", name, user)}
			}); err != nil {
				return err
			}
		}
	} else {
		u.Fail("SSH key missing", cfg.SSHKeyPath+" "+u.Dash()+" run setup")
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
