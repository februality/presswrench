package mcpserver

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/gateway"
	"github.com/februality/presswrench/internal/sites"
	mcsh "github.com/februality/presswrench/internal/ssh"
)

const (
	ServerName    = "presswrench"
	ServerVersion = "0.1.0"
)

// Gateway is the slice of *gateway.Client the tools use. An interface so
// tests can substitute a fake.
type Gateway interface {
	CallTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error)
	sites.Executor
}

type describer interface {
	Describe(ctx context.Context, name string) (*gateway.Operation, error)
}

type Deps struct {
	Cfg       *config.Config
	Session   *auth.Session
	Gateway   Gateway
	Describer describer
	Sites     *sites.Resolver
	SSHPool   *mcsh.Pool
	SSHOps    *mcsh.Ops
	Logins    *loginCache
}

// Build wires all dependencies from a loaded config. store may be nil when
// PRESSWRENCH_ACCESS_TOKEN is set.
func Build(cfg *config.Config, store creds.Store) *Deps {
	session := auth.NewSession(store, cfg.Account, cfg.AuthURL)
	gw := gateway.New(cfg.MCPURL, session, ServerVersion)
	verifier := mcsh.NewHostKeyVerifier(cfg.KnownHostsPath, cfg.InsecureHostKey)
	pool := mcsh.NewPool(cfg.SSHKeyPath, cfg.SSHTimeoutMs, verifier)
	ttl := time.Duration(cfg.CacheTTLSeconds) * time.Second
	return &Deps{
		Cfg:       cfg,
		Session:   session,
		Gateway:   gw,
		Describer: gateway.NewDescriber(gw),
		Sites:     sites.NewResolver(gw, ttl),
		SSHPool:   pool,
		SSHOps:    mcsh.NewOps(pool),
		Logins:    newLoginCache(ttl),
	}
}

const instructions = `Manage WordPress sites hosted on Pressable, acting as the signed-in Pressable user. Everything is scoped by Pressable itself: you can reach exactly the sites and actions this user's Pressable account and collaborator roles allow, and Pressable rejects the rest.

Two layers:

1. Platform operations (about 200: sites, domains/DNS/SSL, backups and restores, plugins/themes, logs, collaborators, caching, metrics, WordPress users, …) go through Pressable's own MCP gateway:
   pressable_discover (find an operation) → pressable_describe (get its parameters) → pressable_execute (run it).
   Operations take numeric site_id values; use the list_sites or search_sites operation to find them.

2. Direct site access over SSH with complete, synchronous output:
   pressable_ssh_exec (any shell command), pressable_wp_cli (WP-CLI), pressable_sftp_read / pressable_sftp_write / pressable_sftp_list (files).
   These accept a site name, domain, or numeric ID. Prefer them over the gateway's run_site_wpcli_commands / run_site_bash_commands operations, which run asynchronously and trim output to 500 characters.

Pressable layout: the web root is /srv/htdocs; WordPress core is a shared read-only symlink at /srv/htdocs/__wp__. Put Pressable wp wrapper global flags before the subcommand (wp --skip-plugins plugin list).`

// New returns an MCP server with tools registered. With deps.Cfg.ReadOnly,
// pressable_ssh_exec, pressable_wp_cli and pressable_sftp_write are not registered, and pressable_execute
// only runs operations Pressable annotates as read-only.
func New(deps *Deps) *server.MCPServer {
	s := server.NewMCPServer(ServerName, ServerVersion,
		server.WithToolCapabilities(false),
		server.WithInstructions(instructions),
	)
	RegisterGatewayTools(s, deps)
	RegisterSiteTools(s, deps)
	return s
}
