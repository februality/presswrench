package cli

import (
	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/wizard"
)

func NewSetup() *cobra.Command {
	var (
		account     string
		unattended  bool
		manualLogin bool
		skipSSH     bool
		skipClients bool
		onlyClients []string
		readOnly    bool
		blocked     string
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Run the interactive setup wizard",
		Long: "Signs you in to Pressable in your browser, creates an SSH key and walks you " +
			"through adding it in MyPressable, then configures your AI tools. Safe to re-run.\n\n" +
			"Use --account to set up a second Pressable login alongside the default. Each " +
			"named account gets its own client-config entry (presswrench-<name>), session, " +
			"and SSH key.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateAccount(account); err != nil {
				return err
			}
			opts := wizard.Options{
				Account:     account,
				Unattended:  unattended,
				ManualLogin: manualLogin,
				SkipSSH:     skipSSH,
				SkipClients: skipClients,
				OnlyClients: onlyClients,
				ReadOnly:    readOnly,
			}
			if cmd.Flags().Changed("blocked-operations") {
				opts.BlockedOperations = &blocked
			}
			return wizard.Run(opts)
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "named account (lowercase slug); omit for the default")
	cmd.Flags().BoolVar(&unattended, "unattended", false, "skip prompts (needs an existing session or PRESSWRENCH_ACCESS_TOKEN)")
	cmd.Flags().BoolVar(&manualLogin, "manual-login", false, "paste the browser redirect URL instead of using a local callback listener")
	cmd.Flags().BoolVar(&skipSSH, "skip-ssh", false, "skip SSH key creation and testing")
	cmd.Flags().BoolVar(&skipClients, "skip-clients", false, "skip AI-tool config patching")
	cmd.Flags().StringSliceVar(&onlyClients, "client", nil, "limit to specific client IDs (repeatable)")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "bake PRESSWRENCH_READ_ONLY=1 into client configs (also pre-selects the read-only prompt)")
	cmd.Flags().StringVar(&blocked, "blocked-operations", "", `comma-separated Pressable operations to refuse locally (default "delete_site"; "none" to block nothing)`)
	return cmd
}
