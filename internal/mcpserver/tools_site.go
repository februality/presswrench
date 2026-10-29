package mcpserver

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	xssh "golang.org/x/crypto/ssh"

	mcsh "github.com/februality/presswrench/internal/ssh"
)

// RegisterSiteTools registers the direct-access tools. pressable_ssh_exec, pressable_wp_cli and
// pressable_sftp_write are skipped in read-only mode — no command allowlist is safe
// enough to treat a shell as read-only.
func RegisterSiteTools(s *server.MCPServer, d *Deps) {
	s.AddTool(toolSFTPRead(), handleSFTPRead(d))
	s.AddTool(toolSFTPList(), handleSFTPList(d))
	s.AddTool(toolSSHStatus(), handleSSHStatus(d))
	if !d.Cfg.ReadOnly {
		s.AddTool(toolSSHExec(), handleSSHExec(d))
		s.AddTool(toolWPCLI(), handleWPCLI(d))
		s.AddTool(toolSFTPWrite(), handleSFTPWrite(d))
	}
}

const siteDesc = "Site: name, domain, or numeric Pressable site ID"

func toolSSHExec() mcp.Tool {
	return mcp.NewTool("pressable_ssh_exec",
		mcp.WithDescription("Run a shell command on a Pressable site over SSH and return its full stdout, stderr and exit code. Runs in the web root (/srv/htdocs) unless working_directory is given. Each call is a fresh shell (no state carries over)."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("command", mcp.Required(), mcp.Description("Shell command to execute")),
		mcp.WithString("working_directory", mcp.Description("Directory to run in: relative to /srv/htdocs, or absolute")),
		mcp.WithNumber("timeout", mcp.Description("Timeout in milliseconds. Defaults to PRESSWRENCH_EXEC_TIMEOUT_MS (120000). 0 disables the timeout.")),
	)
}

func toolWPCLI() mcp.Tool {
	return mcp.NewTool("pressable_wp_cli",
		mcp.WithDescription("Run a WP-CLI command on a Pressable site over SSH and return its full output. The leading \"wp\" is optional. Pressable's wp wrapper wants global flags before the subcommand: \"--skip-plugins plugin list\", not \"plugin list --skip-plugins\"."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("command", mcp.Required(), mcp.Description("WP-CLI command, e.g. \"plugin list --format=json\"")),
		mcp.WithNumber("timeout", mcp.Description("Timeout in milliseconds. Defaults to PRESSWRENCH_EXEC_TIMEOUT_MS (120000). 0 disables the timeout.")),
	)
}

func toolSFTPRead() mcp.Tool {
	return mcp.NewTool("pressable_sftp_read",
		mcp.WithDescription("Read a text file from a Pressable site over SFTP."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path: relative to the web root (wp-config.php), or absolute (/srv/htdocs/wp-config.php)")),
		mcp.WithNumber("max_lines", mcp.Description("Return at most this many lines")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func toolSFTPWrite() mcp.Tool {
	return mcp.NewTool("pressable_sftp_write",
		mcp.WithDescription("Write a text file on a Pressable site over SFTP. Overwrites the whole file — read, modify, then write."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path: relative to the web root, or absolute (/srv/htdocs/...)")),
		mcp.WithString("content", mcp.Required(), mcp.Description("Complete file content")),
		mcp.WithBoolean("create_dirs", mcp.Description("Create missing parent directories")),
	)
}

func toolSFTPList() mcp.Tool {
	return mcp.NewTool("pressable_sftp_list",
		mcp.WithDescription("List a directory on a Pressable site over SFTP (name, type, size, modified time, permissions)."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("path", mcp.Description("Directory: relative to the web root, or absolute. Defaults to the web root.")),
		mcp.WithBoolean("show_hidden", mcp.Description("Include dotfiles")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func toolSSHStatus() mcp.Tool {
	return mcp.NewTool("pressable_ssh_status",
		mcp.WithDescription("Show the local SSH key used for site access (path, label, fingerprint, public key). With `site`, also find and test the SSH login for that site — use this to troubleshoot pressable_ssh_exec / pressable_wp_cli / sftp_* failures."),
		mcp.WithString("site", mcp.Description(siteDesc)),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

// timeoutArg distinguishes an omitted timeout (-1 → configured default)
// from an explicit 0 (no timeout).
func timeoutArg(d *Deps, req mcp.CallToolRequest) int {
	t := int(req.GetFloat("timeout", -1))
	if t < 0 {
		return d.Cfg.ExecTimeoutMs
	}
	return t
}

func formatExec(res *mcsh.ExecResult) string {
	var parts []string
	if res.Stdout != "" {
		parts = append(parts, res.Stdout)
	}
	if res.Stderr != "" {
		parts = append(parts, "[stderr]\n"+res.Stderr)
	}
	if res.ExitCode != 0 {
		parts = append(parts, fmt.Sprintf("[exit code: %d]", res.ExitCode))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("(command completed with exit code %d)", res.ExitCode)
	}
	return strings.Join(parts, "\n")
}

func (d *Deps) exec(ctx context.Context, site, command, wd string, timeoutMs int) (*mcp.CallToolResult, error) {
	login, err := d.resolveLogin(ctx, site)
	if err != nil {
		return errResult(err)
	}
	res, err := d.SSHOps.Exec(d.Cfg.SSHHost, login.User, command, mcsh.ExecOptions{
		Cwd:       mcsh.ExecDir(wd),
		TimeoutMs: timeoutMs,
	})
	if err != nil {
		return errResult(err)
	}
	return mcp.NewToolResultText(formatExec(res)), nil
}

func handleSSHExec(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		site, err := req.RequireString("site")
		if err != nil {
			return errResult(err)
		}
		command, err := req.RequireString("command")
		if err != nil {
			return errResult(err)
		}
		return d.exec(ctx, site, command, req.GetString("working_directory", ""), timeoutArg(d, req))
	}
}

func handleWPCLI(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		site, err := req.RequireString("site")
		if err != nil {
			return errResult(err)
		}
		command, err := req.RequireString("command")
		if err != nil {
			return errResult(err)
		}
		return d.exec(ctx, site, wpCommand(command), "", timeoutArg(d, req))
	}
}

// wpCommand prefixes "wp " unless the caller already did.
func wpCommand(command string) string {
	c := strings.TrimSpace(command)
	if c == "wp" || strings.HasPrefix(c, "wp ") {
		return c
	}
	return "wp " + c
}

func handleSFTPRead(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		site, err := req.RequireString("site")
		if err != nil {
			return errResult(err)
		}
		path, err := req.RequireString("path")
		if err != nil {
			return errResult(err)
		}
		login, err := d.resolveLogin(ctx, site)
		if err != nil {
			return errResult(err)
		}
		content, err := d.SSHOps.ReadFile(d.Cfg.SSHHost, login.User, path, int(req.GetFloat("max_lines", 0)))
		if err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText(content), nil
	}
}

func handleSFTPWrite(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		site, err := req.RequireString("site")
		if err != nil {
			return errResult(err)
		}
		path, err := req.RequireString("path")
		if err != nil {
			return errResult(err)
		}
		content, err := req.RequireString("content")
		if err != nil {
			return errResult(err)
		}
		login, err := d.resolveLogin(ctx, site)
		if err != nil {
			return errResult(err)
		}
		written, err := d.SSHOps.WriteFile(d.Cfg.SSHHost, login.User, path, content, req.GetBool("create_dirs", false))
		if err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText(fmt.Sprintf("File written: %s (%d bytes)", written, len(content))), nil
	}
}

func handleSFTPList(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		site, err := req.RequireString("site")
		if err != nil {
			return errResult(err)
		}
		login, err := d.resolveLogin(ctx, site)
		if err != nil {
			return errResult(err)
		}
		entries, err := d.SSHOps.ListDir(d.Cfg.SSHHost, login.User, req.GetString("path", ""), req.GetBool("show_hidden", false))
		if err != nil {
			return errResult(err)
		}
		return jsonText(entries)
	}
}

type sshStatus struct {
	KeyPath     string         `json:"keyPath"`
	KeyExists   bool           `json:"keyExists"`
	KeyLabel    string         `json:"keyLabel"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	PublicKey   string         `json:"publicKey,omitempty"`
	Host        string         `json:"host"`
	AddKeyAt    string         `json:"addKeyAt"`
	Site        *siteSSHStatus `json:"site,omitempty"`
}

type siteSSHStatus struct {
	ID        int64  `json:"id"`
	Name      string `json:"name,omitempty"`
	Login     string `json:"login,omitempty"`
	Connected bool   `json:"connected"`
	Error     string `json:"error,omitempty"`
}

func handleSSHStatus(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		st := sshStatus{
			KeyPath:   d.Cfg.SSHKeyPath,
			KeyExists: mcsh.KeyPairExists(d.Cfg.SSHKeyPath),
			KeyLabel:  d.Cfg.SSHKeyLabel,
			Host:      d.Cfg.SSHHost,
			AddKeyAt:  "MyPressable → Profile → Settings → SSH Keys",
		}
		if pub, err := os.ReadFile(d.Cfg.SSHKeyPath + ".pub"); err == nil {
			st.PublicKey = strings.TrimSpace(string(pub))
			if pk, _, _, _, err := xssh.ParseAuthorizedKey(pub); err == nil {
				st.Fingerprint = xssh.FingerprintSHA256(pk)
			}
		}
		if site := req.GetString("site", ""); site != "" {
			ss := &siteSSHStatus{}
			login, err := d.resolveLogin(ctx, site)
			if err != nil {
				ss.Error = err.Error()
				if s, rerr := d.Sites.Resolve(ctx, site); rerr == nil {
					ss.ID, ss.Name = s.ID, s.Name
				}
			} else {
				ss.ID, ss.Name, ss.Login, ss.Connected = login.Site.ID, login.Site.Name, login.User, true
			}
			st.Site = ss
		}
		return jsonText(st)
	}
}
