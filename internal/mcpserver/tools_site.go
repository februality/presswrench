package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	xssh "golang.org/x/crypto/ssh"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/config"
	mcsh "github.com/februality/presswrench/internal/ssh"
)

// RegisterSiteTools registers the direct-access tools. pressable_ssh_exec,
// pressable_wp_cli, pressable_sftp_write and pressable_sftp_edit are skipped
// in read-only mode — no command allowlist is safe enough to treat a shell
// as read-only.
func RegisterSiteTools(s *server.MCPServer, d *Deps) {
	s.AddTool(toolSFTPRead(), handleSFTPRead(d))
	s.AddTool(toolSFTPList(), handleSFTPList(d))
	s.AddTool(toolSSHStatus(), handleSSHStatus(d))
	if !d.Cfg.ReadOnly {
		s.AddTool(toolSSHExec(), handleSSHExec(d))
		s.AddTool(toolWPCLI(), handleWPCLI(d))
		s.AddTool(toolSFTPWrite(), handleSFTPWrite(d))
		s.AddTool(toolSFTPEdit(), handleSFTPEdit(d))
	}
}

const (
	siteDesc    = "Site: name, domain, or numeric Pressable site ID"
	timeoutDesc = "Timeout in milliseconds. Defaults to PRESSWRENCH_EXEC_TIMEOUT_MS (120000). 0 disables the timeout."
	stdinDesc   = "Text to feed the command on standard input. Use it for multi-line PHP or SQL instead of shell quoting"
	sftpScope   = "Relative paths start at the web root (/srv/htdocs); a full path outside it (/tmp/…) is used as written, or refused when the login's SFTP is confined to the web root"
)

func toolSSHExec() mcp.Tool {
	return mcp.NewTool("pressable_ssh_exec",
		mcp.WithDescription("Run a shell command on a Pressable site over SSH and return its stdout, stderr and exit code. Runs in the web root (/srv/htdocs) unless working_directory is given. Each call is a fresh shell (no state carries over). Very long output keeps its start and end with the middle omitted, so filter it (grep, head, tail) or redirect it to a file. A command that hits the timeout is killed and returns what it printed so far. Nothing outlives the call: Pressable ends background jobs (nohup, &) when it returns."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("command", mcp.Required(), mcp.Description("Shell command to execute")),
		mcp.WithString("working_directory", mcp.Description("Directory to run in: relative to /srv/htdocs, or absolute")),
		mcp.WithString("stdin", mcp.Description(stdinDesc+" (e.g. command \"php\" or \"mysql\" style tools reading a script).")),
		mcp.WithNumber("timeout", mcp.Description(timeoutDesc)),
		writeTool("Run a shell command on a site"),
	)
}

func toolWPCLI() mcp.Tool {
	return mcp.NewTool("pressable_wp_cli",
		mcp.WithDescription("Run a WP-CLI command on a Pressable site over SSH and return its output. The leading \"wp\" is optional. Pressable's wp wrapper wants global flags before the subcommand: \"--skip-plugins plugin list\", not \"plugin list --skip-plugins\". Output is capped and timeouts behave as in pressable_ssh_exec."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("command", mcp.Required(), mcp.Description("WP-CLI command, e.g. \"plugin list --format=json\"")),
		mcp.WithString("stdin", mcp.Description(stdinDesc+": PHP (starting with <?php) for \"eval-file -\", SQL for \"db query\".")),
		mcp.WithNumber("timeout", mcp.Description(timeoutDesc)),
		writeTool("Run WP-CLI on a site"),
	)
}

func toolSFTPRead() mcp.Tool {
	return mcp.NewTool("pressable_sftp_read",
		mcp.WithDescription("Read a text file from a Pressable site over SFTP. Returns the file's exact text; a long file is returned in part, followed by a bracketed note saying which lines were shown and the offset to continue from. With local_path, downloads the file (text or binary) to this computer instead and returns only its size. "+sftpScope+"."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path: relative to the web root (wp-config.php), or absolute (/srv/htdocs/wp-config.php)")),
		mcp.WithNumber("offset", mcp.Description("First line to return, counting from 1. Defaults to 1.")),
		mcp.WithNumber("limit", mcp.Description("Return at most this many lines")),
		mcp.WithString("local_path", mcp.Description("Absolute path on this computer to save the file to, instead of returning its content")),
		mcp.WithBoolean("overwrite_local", mcp.Description("Replace local_path if it already exists")),
		readOnlyTool("Read a file on a site"),
	)
}

func toolSFTPWrite() mcp.Tool {
	return mcp.NewTool("pressable_sftp_write",
		mcp.WithDescription("Create or replace a whole file on a Pressable site over SFTP, atomically, from `content` or from a file on this computer (`local_path`, text or binary). To change part of an existing file use pressable_sftp_edit instead. "+sftpScope+"."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path: relative to the web root, or absolute (/srv/htdocs/...)")),
		mcp.WithString("content", mcp.Description("Complete file content. Give this or local_path.")),
		mcp.WithString("local_path", mcp.Description("Absolute path of a file on this computer to upload. Give this or content.")),
		mcp.WithBoolean("create_dirs", mcp.Description("Create missing parent directories")),
		writeTool("Write a file on a site"),
	)
}

func toolSFTPEdit() mcp.Tool {
	return mcp.NewTool("pressable_sftp_edit",
		mcp.WithDescription("Change part of a text file on a Pressable site: replace old_string with new_string and write the file back atomically. old_string must match the file exactly (whitespace and indentation included) and occur once; add surrounding lines to make it unique, or set replace_all. Read the file first with pressable_sftp_read. "+sftpScope+"."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path: relative to the web root, or absolute (/srv/htdocs/...)")),
		mcp.WithString("old_string", mcp.Required(), mcp.Description("Exact text to replace")),
		mcp.WithString("new_string", mcp.Required(), mcp.Description("Text to put in its place (may be empty to delete)")),
		mcp.WithBoolean("replace_all", mcp.Description("Replace every occurrence instead of requiring exactly one")),
		writeTool("Edit a file on a site"),
	)
}

func toolSFTPList() mcp.Tool {
	return mcp.NewTool("pressable_sftp_list",
		mcp.WithDescription("List a directory on a Pressable site over SFTP, one entry per line: type (dir, file, link), permissions, size in bytes, modified time (UTC), name. Directories come first. "+sftpScope+"."),
		mcp.WithString("site", mcp.Required(), mcp.Description(siteDesc)),
		mcp.WithString("path", mcp.Description("Directory: relative to the web root, or absolute. Defaults to the web root.")),
		mcp.WithBoolean("show_hidden", mcp.Description("Include dotfiles")),
		readOnlyTool("List a directory on a site"),
	)
}

func toolSSHStatus() mcp.Tool {
	return mcp.NewTool("pressable_ssh_status",
		mcp.WithDescription("Show the local SSH key used for site access (path, label, fingerprint, public key). With `site`, also find and test the SSH login for that site — use this to troubleshoot pressable_ssh_exec / pressable_wp_cli / sftp_* failures."),
		mcp.WithString("site", mcp.Description(siteDesc)),
		readOnlyTool("Check SSH access"),
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

// formatExec renders a command's result: stdout, then stderr, then a line
// for a non-zero exit code. Notes about a timeout or omitted output come
// last, in brackets.
func formatExec(res *mcsh.ExecResult, timeoutMs int) string {
	var parts []string
	if res.Stdout != "" {
		parts = append(parts, res.Stdout)
	}
	if res.Stderr != "" {
		parts = append(parts, "[stderr]\n"+res.Stderr)
	}
	switch {
	case res.TimedOut:
		note := fmt.Sprintf("[timed out after %dms and was killed", timeoutMs)
		if len(parts) > 0 {
			note += "; the output above is what it printed before that"
		} else {
			note += " before printing anything"
		}
		parts = append(parts, note+". Pass a longer timeout (milliseconds; 0 removes the limit) or do the work in smaller steps: Pressable ends background jobs when the call returns, so nohup or & won't keep it running]")
	case res.ExitCode != 0:
		parts = append(parts, fmt.Sprintf("[exit code: %d]", res.ExitCode))
	}
	if res.Truncated {
		parts = append(parts, "[output was too long and its middle was omitted. Narrow it with grep, head or tail, or redirect it to a file and read that in parts with pressable_sftp_read (offset, limit)]")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("(command completed with exit code %d)", res.ExitCode)
	}
	return strings.Join(parts, "\n")
}

func (d *Deps) exec(ctx context.Context, site, command, wd, stdin string, timeoutMs int) (*mcp.CallToolResult, error) {
	login, err := d.resolveLogin(ctx, site)
	if err != nil {
		return errResult(err)
	}
	res, err := d.SSHOps.Exec(ctx, d.Cfg.SSHHost, login.User, command, mcsh.ExecOptions{
		Cwd:            mcsh.ExecDir(wd),
		TimeoutMs:      timeoutMs,
		Stdin:          stdin,
		MaxOutputBytes: d.Cfg.MaxOutputBytes,
	})
	if err != nil {
		return errResult(err)
	}
	text := formatExec(res, timeoutMs)
	if res.TimedOut {
		return mcp.NewToolResultError(text), nil
	}
	return mcp.NewToolResultText(text), nil
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
		return d.exec(ctx, site, command, req.GetString("working_directory", ""), req.GetString("stdin", ""), timeoutArg(d, req))
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
		return d.exec(ctx, site, wpCommand(command), "", req.GetString("stdin", ""), timeoutArg(d, req))
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

// localPath validates a path on this computer. It must be absolute (or
// start with ~): the server's working directory is not the model's.
func localPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	expanded, err := config.ExpandHome(p)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(expanded) {
		return "", fmt.Errorf("local_path must be an absolute path on this computer, got %q", p)
	}
	return filepath.Clean(expanded), nil
}

// formatSlice renders a file read: the text itself, and a bracketed note
// when there is something to say about it: that it isn't the whole file
// (what was shown and how to continue), or that the file isn't UTF-8.
func formatSlice(s *mcsh.FileSlice, maxBytes int) string {
	var notes []string
	switch {
	case s.Whole():
	case s.FirstLine == 0 && s.TotalLines > 0:
		notes = append(notes, fmt.Sprintf("no lines at offset %d: %s has %d lines", s.Offset, s.Path, s.TotalLines))
	case s.FirstLine == 0:
		notes = append(notes, fmt.Sprintf("no lines at offset %d in %s", s.Offset, s.Path))
	default:
		note := fmt.Sprintf("lines %d-%d", s.FirstLine, s.LastLine)
		if s.FirstLine == s.LastLine {
			note = fmt.Sprintf("line %d", s.FirstLine)
		}
		if s.TotalLines > 0 {
			note += fmt.Sprintf(" of %d", s.TotalLines)
		}
		notes = append(notes, note+fmt.Sprintf(" of %s (%d bytes)", s.Path, s.Size))
		if s.LineCut {
			notes = append(notes, fmt.Sprintf("line %d is longer than the %d-byte limit and was cut, so download the file with local_path to get all of it", s.LastLine, maxBytes))
		}
		if s.More {
			notes = append(notes, fmt.Sprintf("continue with offset=%d", s.LastLine+1))
		}
	}
	if s.Encoding != "" {
		notes = append(notes, fmt.Sprintf("the file is %s, shown here as UTF-8; pressable_sftp_edit keeps its encoding, pressable_sftp_write would save UTF-8", s.Encoding))
	}
	if len(notes) == 0 {
		return s.Content
	}
	content := s.Content
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + "[" + strings.Join(notes, "; ") + "]"
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
		local := req.GetString("local_path", "")
		if local != "" {
			if local, err = localPath(local); err != nil {
				return errResult(err)
			}
			if _, err := os.Stat(local); err == nil && !req.GetBool("overwrite_local", false) {
				return errResult(fmt.Errorf("Local file %s already exists. Pass overwrite_local to replace it, or choose another local_path", local))
			}
		}
		login, err := d.resolveLogin(ctx, site)
		if err != nil {
			return errResult(err)
		}
		if local != "" {
			return d.download(ctx, login.User, path, local)
		}
		slice, err := d.SSHOps.ReadFile(ctx, d.Cfg.SSHHost, login.User, path, mcsh.ReadOptions{
			Offset:   int(req.GetFloat("offset", 0)),
			Limit:    int(req.GetFloat("limit", 0)),
			MaxBytes: d.Cfg.MaxOutputBytes,
		})
		if err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText(formatSlice(slice, d.Cfg.MaxOutputBytes)), nil
	}
}

// download saves a remote file to local through a temp file beside it, so
// a failed transfer never leaves a partial file under the final name.
func (d *Deps) download(ctx context.Context, user, path, local string) (*mcp.CallToolResult, error) {
	tmp, err := os.CreateTemp(filepath.Dir(local), ".presswrench-*.tmp")
	if err != nil {
		return errResult(fmt.Errorf("Failed to save to %s: %s", local, err.Error()))
	}
	remote, n, err := d.SSHOps.Download(ctx, d.Cfg.SSHHost, user, path, tmp)
	if cerr := tmp.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("Failed to save to %s: %s", local, cerr.Error())
	}
	if err == nil {
		if rerr := os.Rename(tmp.Name(), local); rerr != nil {
			err = fmt.Errorf("Failed to save to %s: %s", local, rerr.Error())
		}
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return errResult(err)
	}
	return mcp.NewToolResultText(fmt.Sprintf("Downloaded %s to %s (%d bytes)", remote, local, n)), nil
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
		_, hasContent := req.GetArguments()["content"].(string)
		local := req.GetString("local_path", "")
		if hasContent == (local != "") {
			return errResult(errors.New("Give exactly one of `content` (the file's text) or `local_path` (a file on this computer to upload)"))
		}
		var src io.Reader = strings.NewReader(req.GetString("content", ""))
		from := ""
		if local != "" {
			if local, err = localPath(local); err != nil {
				return errResult(err)
			}
			upload, err := os.Open(local)
			if err != nil {
				return errResult(fmt.Errorf("Failed to read local file %s: %s", local, err.Error()))
			}
			defer func() { _ = upload.Close() }()
			if st, err := upload.Stat(); err == nil && st.IsDir() {
				return errResult(fmt.Errorf("Local path %s is a directory. Upload one file at a time, or use pressable_ssh_exec to unpack an archive on the site", local))
			}
			src, from = upload, " from "+local
		}
		login, err := d.resolveLogin(ctx, site)
		if err != nil {
			return errResult(err)
		}
		written, n, err := d.SSHOps.WriteFile(ctx, d.Cfg.SSHHost, login.User, path, src, req.GetBool("create_dirs", false))
		if err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText(fmt.Sprintf("File written: %s (%d bytes)%s", written, n, from)), nil
	}
}

func handleSFTPEdit(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		site, err := req.RequireString("site")
		if err != nil {
			return errResult(err)
		}
		path, err := req.RequireString("path")
		if err != nil {
			return errResult(err)
		}
		oldText, err := req.RequireString("old_string")
		if err != nil {
			return errResult(err)
		}
		newText, err := req.RequireString("new_string")
		if err != nil {
			return errResult(err)
		}
		login, err := d.resolveLogin(ctx, site)
		if err != nil {
			return errResult(err)
		}
		res, err := d.SSHOps.EditFile(ctx, d.Cfg.SSHHost, login.User, path, oldText, newText, req.GetBool("replace_all", false))
		if err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText(formatEdit(res)), nil
	}
}

func formatEdit(res *mcsh.EditResult) string {
	where := fmt.Sprintf("1 replacement at line %d", res.Lines[0])
	if res.Replacements > 1 {
		lines := make([]string, 0, 10)
		for i, l := range res.Lines {
			if i == 10 {
				lines = append(lines, "…")
				break
			}
			lines = append(lines, fmt.Sprint(l))
		}
		where = fmt.Sprintf("%d replacements at lines %s", res.Replacements, strings.Join(lines, ", "))
	}
	return fmt.Sprintf("Edited %s: %s (file is now %d bytes)", res.Path, where, res.Size)
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
		dir, entries, err := d.SSHOps.ListDir(ctx, d.Cfg.SSHHost, login.User, req.GetString("path", ""), req.GetBool("show_hidden", false))
		if err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText(formatListing(dir, entries)), nil
	}
}

// formatListing renders a directory one entry per line:
// "file  644       26  2025-02-12 22:56  index.php".
func formatListing(dir string, entries []mcsh.FileEntry) string {
	if len(entries) == 0 {
		return dir + " is empty (dotfiles are hidden unless show_hidden is set)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s (type  permissions  bytes  modified UTC  name)\n", dir, count(len(entries), "entry", "entries"))
	for _, e := range entries {
		kind, name, size := "file", e.Name, fmt.Sprint(e.Size)
		switch e.Type {
		case mcsh.FileTypeDirectory:
			kind, name, size = "dir", e.Name+"/", "-"
		case mcsh.FileTypeSymlink:
			kind, size = "link", "-"
			if e.Target != "" {
				name += " -> " + e.Target
			}
		case mcsh.FileTypeOther:
			kind = "other"
		}
		modified := e.ModifiedAt
		if len(modified) >= 16 {
			modified = modified[:10] + " " + modified[11:16]
		}
		fmt.Fprintf(&b, "%-5s %s %10s  %s  %s\n", kind, e.Permissions, size, modified, name)
	}
	return b.String()
}

type sshStatus struct {
	KeyPath     string         `json:"keyPath"`
	KeyExists   bool           `json:"keyExists"`
	KeyLabel    string         `json:"keyLabel"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	PublicKey   string         `json:"publicKey,omitempty"`
	Host        string         `json:"host"`
	AddKeyAt    string         `json:"addKeyAt,omitempty"`
	Session     string         `json:"session,omitempty"`
	Site        *siteSSHStatus `json:"site,omitempty"`
}

type siteSSHStatus struct {
	ID        int64  `json:"id,omitempty"`
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
		if _, err := d.Session.State(); err != nil {
			st.Session = auth.Explain(err)
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
				ss.Error = auth.Explain(err)
				if s, rerr := d.Sites.Resolve(ctx, site); rerr == nil {
					ss.ID, ss.Name = s.ID, s.Name
				}
			} else {
				ss.ID, ss.Name, ss.Login, ss.Connected = login.Site.ID, login.Site.Name, login.User, true
				// The key works: how to add it is noise.
				st.PublicKey, st.AddKeyAt = "", ""
			}
			st.Site = ss
		}
		return jsonText(st)
	}
}
