package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	mcsh "github.com/februality/presswrench/internal/ssh"
	"github.com/februality/presswrench/internal/ui"
)

const readOnlyEnvVar = "PRESSWRENCH_READ_ONLY"

type statusOutput struct {
	Version    string `json:"version"`
	BinaryPath string `json:"binaryPath"`
	// Store describes the credential store in use; StoreWarning says why it
	// is degraded (for example the file fallback), when it is.
	Store        string `json:"store"`
	StoreWarning string `json:"storeWarning,omitempty"`
	// AccountsProblem is why the stored accounts couldn't be listed.
	AccountsProblem string          `json:"accountsProblem,omitempty"`
	Accounts        []accountStatus `json:"accounts"`
	// ReadOnlyEnv reflects PRESSWRENCH_READ_ONLY in the current shell — only useful
	// if the user happens to have it set when running `status`. The per-
	// client `readOnly` field is the authoritative signal.
	ReadOnlyEnv bool `json:"readOnlyEnv"`
}

type accountStatus struct {
	// Name is "" for the default account, otherwise the account slug.
	Name    string         `json:"name"`
	Session sessionStatus  `json:"session"`
	SSHKey  sshKeyStatus   `json:"sshKey"`
	Clients []clientStatus `json:"clients"`
}

type sessionStatus struct {
	SignedIn bool         `json:"signedIn"`
	Source   creds.Source `json:"source"`
	Identity string       `json:"identity,omitempty"`
	// Problem is why the session can't be read when that is not simply
	// "not signed in" (for example a locked keychain).
	Problem string `json:"problem,omitempty"`
}

type sshKeyStatus struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Label  string `json:"label"`
}

type clientStatus struct {
	ID         string `json:"id"`
	Name       string `json:"displayName"`
	ConfigPath string `json:"configPath"`
	Detected   bool   `json:"detected"`
	// HasEntry is true when the client's config has a presswrench entry
	// for this account.
	HasEntry bool `json:"hasEntry"`
	// ReadOnly is true when the client's config has PRESSWRENCH_READ_ONLY=1 in the
	// presswrench entry's env block — i.e. the MCP server will start up
	// in read-only mode.
	ReadOnly bool `json:"readOnly"`
}

func NewStatus() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what's configured and where",
		RunE: func(_ *cobra.Command, _ []string) error {
			out := buildStatus()
			if jsonOut {
				b, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(b))
				return nil
			}
			printStatusHuman(ui.New(os.Stdout, os.Stdin), out)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
	return cmd
}

// discoveredAccounts returns every account name with either a stored
// session or at least one client-config entry. Default ("") sorts first.
// A store that can't list its accounts is returned as the error; the
// accounts found in client configs are still returned.
func discoveredAccounts(store creds.Store) ([]string, error) {
	seen := map[string]struct{}{}
	accts, listErr := store.Accounts()
	for _, a := range accts {
		seen[a] = struct{}{}
	}
	for _, p := range clients.All("") {
		entries, err := p.Entries()
		if err != nil {
			continue
		}
		for _, e := range entries {
			seen[e] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, listErr
}

func buildStatus() statusOutput {
	exe, _ := os.Executable()
	out := statusOutput{
		Version:     Version,
		BinaryPath:  exe,
		ReadOnlyEnv: config.IsTrueEnv(os.Getenv(readOnlyEnvVar)),
	}
	store, err := openStore()
	if err != nil {
		store = creds.Broken(err)
	}
	info := store.Info()
	out.Store, out.StoreWarning = info.Description, info.Warning
	accts, listErr := discoveredAccounts(store)
	if err != nil {
		// The open failure is the problem; don't repeat it as a list failure.
		out.StoreWarning = auth.Explain(err)
	} else if listErr != nil {
		out.AccountsProblem = auth.Explain(listErr)
	}
	if len(accts) == 0 {
		// No state at all — surface the default account row so `status`
		// after a fresh install still has something to print.
		accts = []string{creds.DefaultAccount}
	}
	for _, name := range accts {
		out.Accounts = append(out.Accounts, buildAccountStatus(store, name))
	}
	return out
}

func buildAccountStatus(store creds.Store, account string) accountStatus {
	as := accountStatus{Name: account}
	sess := auth.NewSession(store, account, config.DefaultAuthURL)
	src, err := sess.State()
	as.Session = sessionStatus{SignedIn: err == nil, Source: src}
	if err == nil {
		as.Session.Identity = sess.Identity()
	} else if !errors.Is(err, auth.ErrLoginRequired) {
		as.Session.Problem = auth.Explain(err)
	}
	keyPath, keyLabel, _ := config.AccountDefaults(account)
	expanded, _ := config.ExpandHome(keyPath)
	as.SSHKey = sshKeyStatus{
		Path:   expanded,
		Label:  keyLabel,
		Exists: mcsh.KeyPairExists(expanded),
	}
	for _, p := range clients.All(account) {
		detected, path, _ := p.Detect()
		cs := clientStatus{
			ID: p.ID(), Name: p.DisplayName(), ConfigPath: path, Detected: detected,
		}
		// Check whether *this account's* entry exists in the config.
		if entries, err := p.Entries(); err == nil {
			for _, e := range entries {
				if e == account {
					cs.HasEntry = true
					break
				}
			}
		}
		if env, err := p.CurrentEnv(); err == nil {
			cs.ReadOnly = config.IsTrueEnv(env[readOnlyEnvVar])
		}
		as.Clients = append(as.Clients, cs)
	}
	return as
}

func printStatusHuman(u *ui.UI, s statusOutput) {
	fmt.Printf("presswrench %s\n", s.Version)
	fmt.Printf("Binary:      %s\n", s.BinaryPath)
	fmt.Printf("Credentials: %s\n", s.Store)
	if s.StoreWarning != "" {
		fmt.Printf("             %s %s\n", u.Mark(ui.Warn), s.StoreWarning)
	}
	if s.AccountsProblem != "" {
		fmt.Printf("             %s Could not list the stored accounts: %s\n", u.Mark(ui.Warn), s.AccountsProblem)
	}
	fmt.Println()

	for _, a := range s.Accounts {
		fmt.Printf("Account: %s\n", auth.AccountLabel(a.Name))

		if a.Session.SignedIn {
			fmt.Printf("  Session      %s %s (source: %s)\n", u.Mark(ui.Done), orUnknown(a.Session.Identity), a.Session.Source)
		} else if a.Session.Problem != "" {
			fmt.Printf("  Session      %s %s\n", u.Mark(ui.Fail), a.Session.Problem)
		} else {
			fmt.Printf("  Session      %s Not signed in. Run: %s\n", u.Mark(ui.Fail), auth.LoginCommand(a.Name))
		}

		if a.SSHKey.Exists {
			fmt.Printf("  SSH key      %s %s (label %q)\n", u.Mark(ui.Done), a.SSHKey.Path, a.SSHKey.Label)
		} else {
			fmt.Printf("  SSH key      %s Missing at %s\n", u.Mark(ui.Fail), a.SSHKey.Path)
		}

		fmt.Println("  AI tools:")
		for _, c := range a.Clients {
			mark := u.Mark(ui.Skip)
			if c.HasEntry {
				mark = u.Mark(ui.Done)
			}
			suffix := ""
			if c.ReadOnly {
				suffix = "  (read-only)"
			}
			extra := ""
			if !c.Detected && !c.HasEntry {
				extra = "  (not detected)"
			}
			fmt.Printf("    %s %-16s %s%s%s\n", mark, c.Name, c.ConfigPath, suffix, extra)
		}
		fmt.Println()
	}
}
