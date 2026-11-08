package cli

import (
	"context"
	"fmt"
	"log/slog"
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
	// Cancelled when serve returns so the startup check never outlives it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps := startServeDeps(ctx, cfg, creds.Open)
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	return server.ServeStdio(mcpserver.New(deps))
}

// newServeDeps builds the server dependencies. It never fails: a credential
// store that cannot be opened becomes a broken store, so every tool explains
// the problem in its result instead of the server failing to start.
func newServeDeps(cfg *config.Config, open func() (creds.Store, error)) *mcpserver.Deps {
	return startServeDeps(context.Background(), cfg, open)
}

func startServeDeps(ctx context.Context, cfg *config.Config, open func() (creds.Store, error)) *mcpserver.Deps {
	var store creds.Store
	if os.Getenv(auth.EnvAccessToken) == "" {
		var err error
		if store, err = open(); err != nil {
			store = creds.Broken(err)
		}
	}
	deps := mcpserver.Build(cfg, store)
	// Fire-and-forget: log session problems to stderr so they show up in the
	// client's server log. Tools report them in-chat on their own.
	go func() {
		if _, err := deps.Session.Token(ctx); err != nil {
			if ctx.Err() == nil {
				slog.Warn("Pressable session problem", "detail", auth.Explain(err))
			}
			return
		}
		slog.Debug("session ok")
	}()
	return deps
}
