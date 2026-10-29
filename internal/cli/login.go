package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
)

func NewLogin() *cobra.Command {
	var (
		account string
		manual  bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to Pressable in your browser",
		Long: "Signs in as you via your browser and stores the session in the OS keychain. " +
			"The AI tool then acts with exactly your Pressable permissions.\n\n" +
			"Use --manual on a machine your browser can't reach (e.g. over SSH): open the " +
			"printed URL anywhere, approve, and paste back the URL you land on.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := validateAccount(account); err != nil {
				return err
			}
			cfg, err := loadConfigFor(account)
			if err != nil {
				return err
			}
			store, err := creds.Open()
			if err != nil {
				return fmt.Errorf("open credentials store: %w", err)
			}
			reader := bufio.NewReader(os.Stdin)
			tr, err := auth.SignIn(context.Background(), store, account, auth.LoginOptions{
				AuthURL:     cfg.AuthURL,
				OpenBrowser: auth.OpenBrowser,
				Manual:      manual,
				ReadLine:    func() (string, error) { return reader.ReadString('\n') },
				Out:         os.Stdout,
			})
			if err != nil {
				return err
			}
			fmt.Printf("  ✓ Signed in as %s (account: %s)\n", orUnknown(tr.Identity()), accountLabel(account))
			return nil
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "named account (lowercase slug); omit for the default")
	cmd.Flags().BoolVar(&manual, "manual", false, "paste the redirect URL instead of using a local callback listener")
	return cmd
}

func NewLogout() *cobra.Command {
	var account string
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Revoke and delete the stored Pressable session",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := validateAccount(account); err != nil {
				return err
			}
			cfg, err := loadConfigFor(account)
			if err != nil {
				return err
			}
			store, err := creds.Open()
			if err != nil {
				return err
			}
			if err := auth.SignOut(context.Background(), store, account, cfg.AuthURL); err != nil {
				return err
			}
			fmt.Printf("  ✓ Signed out (account: %s)\n", accountLabel(account))
			return nil
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "named account; omit for the default")
	return cmd
}

// loadConfigFor loads config as a serve process bound to account would.
func loadConfigFor(account string) (*config.Config, error) {
	if err := os.Setenv("PRESSWRENCH_ACCOUNT", account); err != nil {
		return nil, err
	}
	return config.Load()
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown user)"
	}
	return s
}
