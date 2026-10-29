package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	mcsh "github.com/februality/presswrench/internal/ssh"
)

const readOnlyEnvVar = "PRESSWRENCH_READ_ONLY"

type statusOutput struct {
	Version    string          `json:"version"`
	BinaryPath string          `json:"binaryPath"`
	Accounts   []accountStatus `json:"accounts"`
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
			printStatusHuman(out)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
	return cmd
}

// discoveredAccounts returns every account name with either a stored
// session or at least one client-config entry. Default ("") sorts first.
func discoveredAccounts() []string {
	seen := map[string]struct{}{}
	if accts, err := creds.ListAccounts(); err == nil {
		for _, a := range accts {
			seen[a] = struct{}{}
		}
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
	return out
}

func buildStatus() statusOutput {
	exe, _ := os.Executable()
	out := statusOutput{
		Version:     Version,
		BinaryPath:  exe,
		ReadOnlyEnv: config.IsTrueEnv(os.Getenv(readOnlyEnvVar)),
	}
	accts := discoveredAccounts()
	if len(accts) == 0 {
		// No state at all — surface the default account row so `status`
		// after a fresh install still has something to print.
		accts = []string{creds.DefaultAccount}
	}
	for _, name := range accts {
		out.Accounts = append(out.Accounts, buildAccountStatus(name))
	}
	return out
}

func buildAccountStatus(account string) accountStatus {
	as := accountStatus{Name: account}
	if store, err := creds.Open(); err == nil {
		sess := auth.NewSession(store, account, config.DefaultAuthURL)
		src := sess.Source()
		as.Session = sessionStatus{SignedIn: src != creds.SourceNotFound, Source: src, Identity: sess.Identity()}
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

func printStatusHuman(s statusOutput) {
	fmt.Printf("presswrench %s\n", s.Version)
	fmt.Printf("Binary:      %s\n\n", s.BinaryPath)

	for _, a := range s.Accounts {
		fmt.Printf("Account: %s\n", accountLabel(a.Name))

		if a.Session.SignedIn {
			fmt.Printf("  Session      ✓ %s (source: %s)\n", orUnknown(a.Session.Identity), a.Session.Source)
		} else {
			fmt.Printf("  Session      ✗ Not signed in. Run: %s\n", loginCommand(a.Name))
		}

		if a.SSHKey.Exists {
			fmt.Printf("  SSH key      ✓ %s (label %q)\n", a.SSHKey.Path, a.SSHKey.Label)
		} else {
			fmt.Printf("  SSH key      ✗ Missing at %s\n", a.SSHKey.Path)
		}

		fmt.Println("  AI tools:")
		for _, c := range a.Clients {
			mark := "·"
			if c.HasEntry {
				mark = "✓"
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
