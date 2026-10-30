package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	mcsh "github.com/februality/presswrench/internal/ssh"
	"github.com/februality/presswrench/internal/ui"
)

func NewUninstall() *cobra.Command {
	var (
		account     string
		allAccounts bool
		clientIDs   []string
		all         bool
		removeCreds bool
		removeKey   bool
	)
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the presswrench entry from AI-tool configs",
		Long: "Removes the presswrench entry. Without --account, only the " +
			"default entry is touched — named accounts (presswrench-<name>) survive. " +
			"Use --account <name> to target one named account, or --all-accounts to " +
			"sweep every presswrench* entry from each targeted client.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := validateAccount(account); err != nil {
				return err
			}
			if allAccounts && account != "" {
				return fmt.Errorf("--account and --all-accounts are mutually exclusive")
			}
			if !all && len(clientIDs) == 0 && !removeCreds && !removeKey {
				return fmt.Errorf("must specify --all, --client, --remove-creds, or --remove-key")
			}

			// Resolve the set of patcher *instances* (one per client) we want
			// to operate on. When --all-accounts is set we expand each instance
			// into per-discovered-account instances below.
			var targets []clients.Patcher
			if all {
				targets = clients.All(account)
			} else {
				for _, id := range clientIDs {
					p := clients.ByID(id, account)
					if p == nil {
						return fmt.Errorf("unknown client %q", id)
					}
					targets = append(targets, p)
				}
			}

			u := ui.New(os.Stdout, os.Stdin)
			for _, p := range targets {
				if allAccounts {
					accts, err := p.Entries()
					if err != nil {
						u.Fail(p.DisplayName(), err.Error())
						continue
					}
					if len(accts) == 0 {
						u.Skip(p.DisplayName(), "no entries found")
						continue
					}
					for _, acct := range accts {
						unp := clients.ByID(p.ID(), acct)
						changed, err := unp.Unpatch()
						label := fmt.Sprintf("%s [%s]", p.DisplayName(), accountLabel(acct))
						if err != nil {
							u.Fail(label, err.Error())
							continue
						}
						if changed {
							u.Step(label, "removed entry")
						}
					}
					continue
				}
				changed, err := p.Unpatch()
				if err != nil {
					u.Fail(p.DisplayName(), err.Error())
					continue
				}
				if changed {
					u.Step(p.DisplayName(), "removed entry")
				} else {
					u.Skip(p.DisplayName(), "no entry found")
				}
			}

			if removeCreds {
				store, err := creds.Open()
				if err != nil {
					return err
				}
				cfg, err := loadConfigFor(account)
				if err != nil {
					return err
				}
				_ = auth.SignOut(context.Background(), store, account, cfg.AuthURL)
				_ = creds.DeleteSession(store, account)
				u.Step("Signed out and removed the stored session", "account "+accountLabel(account))
			}

			if removeKey {
				keyPath, _, _ := config.AccountDefaults(account)
				path, err := config.ExpandHome(keyPath)
				if err != nil {
					return err
				}
				if mcsh.KeyPairExists(path) {
					_ = os.Remove(path)
					_ = os.Remove(path + ".pub")
					u.Step("Removed SSH key files", path+"{,.pub}")
				} else {
					u.Skip("No SSH key files", path)
				}
				ar := u.Arrow()
				u.Warn(fmt.Sprintf("Also delete the public key from MyPressable %s Profile %s Settings %s SSH Keys", ar, ar, ar), "")
			}
			fmt.Println()
			u.Step("Uninstall complete", "")
			return nil
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "named account to unpatch; omit for the default")
	cmd.Flags().BoolVar(&allAccounts, "all-accounts", false, "for each targeted client, unpatch every discovered presswrench* entry")
	cmd.Flags().StringSliceVar(&clientIDs, "client", nil, "client ID to unpatch (repeatable)")
	cmd.Flags().BoolVar(&all, "all", false, "unpatch every MCP client we know about")
	cmd.Flags().BoolVar(&removeCreds, "remove-creds", false, "sign out and delete the stored Pressable session (scoped to --account)")
	cmd.Flags().BoolVar(&removeKey, "remove-key", false, "delete local SSH key files (scoped to --account)")
	return cmd
}

// accountLabel renders an account name for human output: "default" for the
// default account, the name itself otherwise.
func accountLabel(account string) string {
	if account == "" {
		return "default"
	}
	return account
}
