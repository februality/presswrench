package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/ui"
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
			return runLogin(ui.New(os.Stdout, os.Stdin), store, cfg, account, manual)
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "named account (lowercase slug); omit for the default")
	cmd.Flags().BoolVar(&manual, "manual", false, "paste the redirect URL instead of using a local callback listener")
	return cmd
}

// runLogin signs in and prints one "Signed in as …" line. In a terminal
// the browser wait is a spinner; with --manual or without a terminal the
// URL is printed and the redirect URL is read from the prompt or stdin.
func runLogin(u *ui.UI, store creds.Store, cfg *config.Config, account string, manual bool) error {
	ctx := context.Background()
	lo := auth.LoginOptions{
		AuthURL:     cfg.AuthURL,
		OpenBrowser: auth.OpenBrowser,
		Manual:      manual,
	}
	detail := "account " + accountLabel(account)

	if manual || !u.Interactive() {
		lo.OnAuthorizeURL = func(url string, opened bool) {
			if opened {
				u.NoteRaw("Opened your browser to sign in. If nothing appeared, open:", url)
			} else {
				u.NoteRaw("Open this URL and sign in to Pressable:", url)
			}
		}
		if manual {
			u.Note("After approving, your browser lands on a 127.0.0.1 page that fails to load.")
			reader := bufio.NewReader(os.Stdin)
			lo.ReadLine = func() (string, error) { return reader.ReadString('\n') }
			if u.Interactive() {
				lo.ReadLine = func() (string, error) {
					return u.Text("Paste the URL your browser landed on", "http://127.0.0.1:53682/callback?"+u.Ellipsis(), func(s string) error {
						if s == "" {
							return errors.New("Paste the full URL")
						}
						return nil
					})
				}
			}
		}
		tr, err := auth.SignIn(ctx, store, account, lo)
		if err != nil {
			if errors.Is(err, ui.ErrCancelled) {
				return err
			}
			u.Fail(err.Error(), "")
			return ui.Reported(err)
		}
		u.Step("Signed in as "+orUnknown(tr.Identity()), detail)
		return nil
	}

	var signErr error
	err := u.Spin("Sign in to Pressable in your browser", "Opening the browser"+u.Ellipsis(), nil, func(set func(string), note func(...string)) ui.Outcome {
		lo.OnAuthorizeURL = func(url string, opened bool) {
			// note prints above the spinner untruncated; the status line
			// is cut to the terminal width, so the URL never goes there.
			if opened {
				note("If the browser didn't open, open this URL and sign in:", url)
			} else {
				note("Open this URL and sign in to Pressable:", url)
			}
			set("Waiting for you to approve access" + u.Ellipsis())
		}
		tr, err := auth.SignIn(ctx, store, account, lo)
		if err != nil {
			signErr = err
			return ui.Outcome{Level: ui.Fail, Text: err.Error()}
		}
		return ui.Outcome{Level: ui.Done, Text: "Signed in as " + orUnknown(tr.Identity()) + " · " + detail}
	})
	if err != nil {
		return err
	}
	if signErr != nil {
		return ui.Reported(signErr)
	}
	return nil
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
			ui.New(os.Stdout, os.Stdin).Step("Signed out", "account "+accountLabel(account))
			return nil
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "named account (lowercase slug); omit for the default")
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
