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
	// Deferred first so it runs last; the explicit cancel below runs before
	// Session.Close, which would otherwise wait on the check.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps, _ := startServeDeps(ctx, cfg, creds.Open)
	defer deps.SSHPool.Close()
	defer deps.Session.Close()
	defer cancel()
	return server.ServeStdio(mcpserver.New(deps))
}

// newServeDeps builds the server dependencies. It never fails: a credential
// store that cannot be opened becomes a broken store, so every tool explains
// the problem in its result instead of the server failing to start.
func newServeDeps(cfg *config.Config, open func() (creds.Store, error)) *mcpserver.Deps {
	deps, _ := startServeDeps(context.Background(), cfg, open)
	return deps
}

// startServeDeps also returns a channel closed when the background session
// check finishes. The check only inspects the store or env (State): no
// network, no account lock, no refresh.
func startServeDeps(ctx context.Context, cfg *config.Config, open func() (creds.Store, error)) (*mcpserver.Deps, <-chan struct{}) {
	var store creds.Store
	if os.Getenv(auth.EnvAccessToken) == "" {
		var err error
		if store, err = open(); err != nil {
			store = creds.Broken(err)
		}
	}
	deps := mcpserver.Build(cfg, store)
	done := make(chan struct{})
	// Background because State's Load can hit a slow keychain. Problems go to
	// stderr for the client's server log; tools report them in-chat themselves.
	go func() {
		defer close(done)
		if _, err := deps.Session.State(); err != nil {
			if ctx.Err() == nil {
				slog.Warn("Pressable session problem", "detail", auth.Explain(err))
			}
			return
		}
		slog.Debug("session ok")
	}()
	return deps, done
}
