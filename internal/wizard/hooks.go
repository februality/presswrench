package wizard

import (
	"context"
	"sync"
	"time"

	"github.com/atotto/clipboard"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/mcpserver"
	"github.com/februality/presswrench/internal/sites"
	mcsh "github.com/februality/presswrench/internal/ssh"
)

// Hooks are the wizard's side effects, as functions so tests can
// substitute fakes. DefaultHooks wires the real ones.
type Hooks struct {
	// Session returns the identity of an existing valid session, or the
	// error that stopped it from being used (auth.ErrLoginRequired when
	// there simply isn't one).
	Session func(ctx context.Context) (identity string, err error)
	// SignIn runs the browser/manual login and returns the identity.
	SignIn    func(ctx context.Context, o auth.LoginOptions) (identity string, err error)
	ListSites func(ctx context.Context) ([]sites.Site, error)
	CheckSSH  func(ctx context.Context, siteID string) (siteName, user string, err error)
	EnsureKey func(path, label string) (*mcsh.KeyPair, error)
	Clipboard func(text string) error
	Patchers  func(account string) []clients.Patcher
	Official  func() []clients.OfficialEntry
	// StoreLabel is "" for the OS keychain, else the path of the 0600
	// file fallback (mentioned once after sign-in).
	StoreLabel string
	// PollDelay separates SSH-login polling attempts: 10 s in production,
	// 0 in tests.
	PollDelay time.Duration
	// Close releases what the hooks built (sessions, SSH connections); Run
	// calls it when it returns. Optional.
	Close func()
}

// Seams for tests.
var (
	newSession = auth.NewSession
	buildDeps  = mcpserver.Build
)

// DefaultHooks builds the production hooks. The MCP dependencies (gateway,
// SSH) are created on first use so they see the session that sign-in
// stores.
func DefaultHooks(cfg *config.Config, store creds.Store) *Hooks {
	var (
		mu   sync.Mutex
		deps *mcpserver.Deps
	)
	build := func() *mcpserver.Deps {
		mu.Lock()
		defer mu.Unlock()
		if deps == nil {
			deps = buildDeps(cfg, store)
		}
		return deps
	}
	h := &Hooks{
		Session: func(ctx context.Context) (string, error) {
			s := newSession(store, cfg.Account, cfg.AuthURL)
			defer s.Close() // releases the lock of a session that couldn't save
			if _, err := s.Token(ctx); err != nil {
				return "", err
			}
			return s.Identity(), nil
		},
		SignIn: func(ctx context.Context, o auth.LoginOptions) (string, error) {
			tr, err := auth.SignIn(ctx, store, cfg.Account, o)
			if err != nil {
				return "", err
			}
			return tr.Identity(), nil
		},
		ListSites: func(ctx context.Context) ([]sites.Site, error) { return build().Sites.List(ctx) },
		CheckSSH: func(ctx context.Context, siteID string) (string, string, error) {
			return build().CheckSSH(ctx, siteID)
		},
		EnsureKey: mcsh.EnsureKeyPair,
		Clipboard: clipboard.WriteAll,
		Patchers:  clients.All,
		Official:  clients.FindOfficial,
		PollDelay: 10 * time.Second,
		Close: func() {
			mu.Lock()
			defer mu.Unlock()
			if deps != nil {
				deps.Session.Close()
				deps.SSHPool.Close()
				deps = nil
			}
		},
	}
	if store != nil {
		if info := store.Info(); info.Source == creds.SourceFile {
			h.StoreLabel = info.Description
		}
	}
	return h
}
