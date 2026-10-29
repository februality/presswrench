package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/mcpserver"
)

func NewServe() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP stdio server (invoked by MCP clients)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runServe()
		},
	}
}

func runServe() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	var store creds.Store
	if os.Getenv(auth.EnvAccessToken) == "" {
		if store, err = creds.Open(); err != nil {
			return fmt.Errorf("open credentials store: %w", err)
		}
		// Fail fast with instructions rather than registering tools that
		// can only ever error.
		if _, err := auth.NewSession(store, cfg.Account, cfg.AuthURL).Token(context.Background()); errors.Is(err, auth.ErrLoginRequired) {
			return fmt.Errorf("not signed in to Pressable.\n\nRun:\n  %s\n\nor set %s", loginCommand(cfg.Account), auth.EnvAccessToken)
		}
	}
	deps := mcpserver.Build(cfg, store)
	defer deps.SSHPool.Close()
	return server.ServeStdio(mcpserver.New(deps))
}

func loginCommand(account string) string {
	if account == "" {
		return "presswrench login"
	}
	return "presswrench login --account " + account
}
