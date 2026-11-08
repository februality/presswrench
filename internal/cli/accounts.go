package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/ui"
)

// NewAccounts returns the `accounts` parent command (list, remove).
func NewAccounts() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "List or remove configured Pressable logins",
		Long: "Inspect or manage the named Pressable logins registered with " +
			"setup --account. The unnamed account is shown as \"default\".",
	}
	cmd.AddCommand(newAccountsList())
	cmd.AddCommand(newAccountsRemove())
	return cmd
}

type accountRow struct {
	Name           string   `json:"name"`
	HasCredentials bool     `json:"signedIn"`
	ClientEntries  []string `json:"clientEntries"`
}

func newAccountsList() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all configured accounts",
		RunE: func(_ *cobra.Command, _ []string) error {
			rows := listAccounts()
			if jsonOut {
				b, err := json.MarshalIndent(rows, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(b))
				return nil
			}
			u := ui.New(os.Stdout, os.Stdin)
			if len(rows) == 0 {
				u.Skip("No accounts configured", "run presswrench setup")
				return nil
			}
			fmt.Printf("%-20s  %-12s  %s\n", "ACCOUNT", "SIGNED IN", "CLIENT ENTRIES")
			for _, r := range rows {
				cred := u.Mark(ui.Fail)
				if r.HasCredentials {
					cred = u.Mark(ui.Done)
				}
				entries := "(none)"
				if len(r.ClientEntries) > 0 {
					entries = joinSorted(r.ClientEntries)
				}
				// The mark is one visible cell; pad by hand since it may
				// carry colour codes.
				fmt.Printf("%-20s  %s%s  %s\n", auth.AccountLabel(r.Name), cred, strings.Repeat(" ", 11), entries)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
	return cmd
}

func newAccountsRemove() *cobra.Command {
	var (
		account string
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a named account (session + every client entry)",
		Long: "Signs the named account out, deletes its stored session, and unpatches its " +
			"presswrench-<name> entry from every MCP client. Refuses to operate " +
			"on the default account — use `uninstall --remove-creds` for that.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if account == "" {
				return fmt.Errorf("--account is required")
			}
			if err := validateAccount(account); err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("destructive: pass --yes to confirm removing account %q", account)
			}
			store, err := creds.Open()
			if err != nil {
				return err
			}
			authURL := ""
			if cfg, err := loadConfigFor(account); err == nil {
				authURL = cfg.AuthURL
			}
			u := ui.New(os.Stdout, os.Stdin)
			if err := removeSession(u, store, account, authURL); err != nil {
				return err
			}
			for _, p := range clients.All(account) {
				changed, err := p.Unpatch()
				if err != nil {
					u.Fail(p.DisplayName(), err.Error())
					continue
				}
				if changed {
					u.Step(p.DisplayName(), "removed entry")
				}
			}
			ar := u.Arrow()
			u.Warn(fmt.Sprintf("The SSH key files on disk and the public key in MyPressable (Profile %s Settings %s SSH Keys) are not removed automatically", ar, ar), "")
			return nil
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "named account to remove (required; cannot be empty)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the destructive operation")
	return cmd
}

// removeSession revokes (best effort) and deletes an account's stored
// session, printing the outcome. A failed delete is shown with its fix and
// returned as a reported error, so the command exits non-zero.
func removeSession(u *ui.UI, store creds.Store, account, authURL string) error {
	if err := auth.RemoveAccount(context.Background(), store, account, authURL); err != nil {
		u.Fail("Could not remove the stored session", auth.Explain(err))
		return ui.Reported(err)
	}
	u.Step("Signed out and removed the stored session", "account "+auth.AccountLabel(account))
	return nil
}

// listAccounts returns one row per discovered account, unioning the
// credentials store with every client config's entries.
func listAccounts() []accountRow {
	rows := map[string]*accountRow{}
	credAccts, _ := creds.ListAccounts()
	for _, a := range credAccts {
		rows[a] = &accountRow{Name: a, HasCredentials: true}
	}
	for _, p := range clients.All("") {
		entries, err := p.Entries()
		if err != nil {
			continue
		}
		for _, e := range entries {
			row, ok := rows[e]
			if !ok {
				row = &accountRow{Name: e}
				rows[e] = row
			}
			row.ClientEntries = append(row.ClientEntries, p.ID())
		}
	}
	out := make([]accountRow, 0, len(rows))
	for _, r := range rows {
		sort.Strings(r.ClientEntries)
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func joinSorted(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
