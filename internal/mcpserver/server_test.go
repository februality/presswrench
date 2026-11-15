package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
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

// fakeGateway records calls and returns canned results: results by gateway
// tool name (or "execute_tool:<operation>"), else "upstream:<tool>".
type fakeGateway struct {
	calls   []string
	args    []map[string]any
	err     error
	results map[string]*mcp.CallToolResult
	// sites answers search_sites / list_sites for the resolver.
	sites string
}

func (f *fakeGateway) CallTool(_ context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	f.calls = append(f.calls, name)
	f.args = append(f.args, args)
	if f.err != nil {
		return nil, f.err
	}
	if op, _ := args["tool_name"].(string); op != "" {
		if res, ok := f.results[name+":"+op]; ok {
			return res, nil
		}
	}
	if res, ok := f.results[name]; ok {
		return res, nil
	}
	return mcp.NewToolResultText("upstream:" + name), nil
}

func (f *fakeGateway) ExecuteJSON(_ context.Context, _ string, _ map[string]any, out any) error {
	if f.sites == "" {
		return nil
	}
	return json.Unmarshal([]byte(f.sites), out)
}

type fakeDescriber map[string]bool // name -> readOnly

const siteIDSchema = `{"type":"object","required":["site_id"],"properties":{
	"site_id":{"type":"integer","description":"The numeric ID of the Pressable site. Find it with list_sites."},
	"page":{"type":"integer","description":"1-based page number"},
	"type":{"type":"string","enum":["filesystem","database"]}}}`

func (f fakeDescriber) Describe(_ context.Context, name string) (*gateway.Operation, error) {
	ro, ok := f[name]
	if !ok {
		return nil, errors.New("unknown operation")
	}
	return &gateway.Operation{Name: name, ReadOnly: ro, Destructive: !ro, InputSchema: json.RawMessage(siteIDSchema)}, nil
}

func newDeps(cfg *config.Config, gw *fakeGateway) *Deps {
	if cfg.SSHHost == "" {
		cfg.SSHHost = "ssh.example"
	}
	return &Deps{
		Cfg:       cfg,
		Session:   auth.NewSession(nil, "", ""),
		Gateway:   gw,
		Describer: fakeDescriber{"list_sites": true, "create_site": false, "delete_site": false},
		Sites:     sites.NewResolver(gw, time.Minute),
		Logins:    newLoginCache(time.Minute),
	}
}

func toolNames(s *server.MCPServer) []string {
	var out []string
	for name := range s.ListTools() {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func TestNew_ToolRegistration(t *testing.T) {
	full := toolNames(New(newDeps(&config.Config{}, &fakeGateway{})))
	want := []string{"pressable_describe", "pressable_discover", "pressable_execute", "pressable_sftp_edit", "pressable_sftp_list",
		"pressable_sftp_read", "pressable_sftp_write", "pressable_sites", "pressable_ssh_exec", "pressable_ssh_status", "pressable_wp_cli"}
	if strings.Join(full, ",") != strings.Join(want, ",") {
		t.Errorf("tools = %v, want %v", full, want)
	}

	ro := toolNames(New(newDeps(&config.Config{ReadOnly: true}, &fakeGateway{})))
	for _, hidden := range []string{"pressable_ssh_exec", "pressable_wp_cli", "pressable_sftp_write", "pressable_sftp_edit"} {
		for _, n := range ro {
			if n == hidden {
				t.Errorf("read-only mode registered %s", hidden)
			}
		}
	}
	if len(ro) != len(want)-4 {
		t.Errorf("read-only tools = %v", ro)
	}
}

func call(t *testing.T, h server.ToolHandlerFunc, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return res
}

func text(res *mcp.CallToolResult) string { return gateway.ResultText(res) }

func TestExecute_PassesThrough(t *testing.T) {
	gw := &fakeGateway{}
	d := newDeps(&config.Config{}, gw)
	res := call(t, handleExecute(d), map[string]any{"tool_name": "create_site", "parameters": map[string]any{"name": "x"}})
	if res.IsError || text(res) != "upstream:execute_tool" {
		t.Fatalf("result = %v %q", res.IsError, text(res))
	}
	if gw.args[0]["tool_name"] != "create_site" {
		t.Errorf("forwarded args = %v", gw.args[0])
	}
	params := gw.args[0]["parameters"].(map[string]any)
	if params["name"] != "x" {
		t.Errorf("parameters = %v", params)
	}
}

func TestExecute_ParametersAsJSONString(t *testing.T) {
	gw := &fakeGateway{}
	d := newDeps(&config.Config{}, gw)
	res := call(t, handleExecute(d), map[string]any{"tool_name": "create_site", "parameters": `{"name":"y"}`})
	if res.IsError {
		t.Fatalf("unexpected error: %s", text(res))
	}
	if gw.args[0]["parameters"].(map[string]any)["name"] != "y" {
		t.Errorf("parameters = %v", gw.args[0]["parameters"])
	}
}

func TestExecute_Blocklist(t *testing.T) {
	gw := &fakeGateway{}
	d := newDeps(&config.Config{BlockedOperations: []string{"delete_site"}}, gw)
	res := call(t, handleExecute(d), map[string]any{"tool_name": "DELETE_SITE"})
	if !res.IsError || !strings.Contains(text(res), "blocked by local policy") {
		t.Fatalf("want blocked error, got %v %q", res.IsError, text(res))
	}
	if len(gw.calls) != 0 {
		t.Errorf("blocked call reached the gateway: %v", gw.calls)
	}
}

func TestExecute_ReadOnly(t *testing.T) {
	gw := &fakeGateway{}
	d := newDeps(&config.Config{ReadOnly: true}, gw)

	res := call(t, handleExecute(d), map[string]any{"tool_name": "create_site"})
	if !res.IsError || !strings.Contains(text(res), "not read-only") {
		t.Fatalf("want read-only refusal, got %q", text(res))
	}
	res = call(t, handleExecute(d), map[string]any{"tool_name": "made_up_op"})
	if !res.IsError || !strings.Contains(text(res), "could not verify") {
		t.Fatalf("unknown op should be refused in read-only mode, got %q", text(res))
	}
	if len(gw.calls) != 0 {
		t.Fatalf("refused calls reached the gateway: %v", gw.calls)
	}

	res = call(t, handleExecute(d), map[string]any{"tool_name": "list_sites"})
	if res.IsError {
		t.Fatalf("read-only op refused: %q", text(res))
	}
}

// When the gateway's operation list isn't in a shape we parse, discover
// falls back to passing the query through.
func TestDiscoverAndDescribe_PassThrough(t *testing.T) {
	gw := &fakeGateway{}
	d := newDeps(&config.Config{}, gw)
	res := call(t, handleDiscover(d), map[string]any{"query": "backup"})
	if text(res) != "upstream:discover_tools" {
		t.Fatalf("discover = %q", text(res))
	}
	call(t, handleDescribe(d), map[string]any{"tool_name": "list_sites"})
	if strings.Join(gw.calls, ",") != "discover_tools,discover_tools,describe_tool" {
		t.Fatalf("calls = %v", gw.calls)
	}
	if gw.args[1]["query"] != "backup" || gw.args[2]["tool_name"] != "list_sites" {
		t.Errorf("args = %v", gw.args)
	}
}

const catalogDoc = `{"count": 5, "tools": [
  {"name": "list_site_backups", "title": "List Site Backups", "summary": "Lists scheduled backups for a site. Ordered by most recent first.", "category": "sites"},
  {"name": "restore_site_backup", "title": "Restore Site Backup", "summary": "Initiates a restore of a site from a backup.", "category": "sites"},
  {"name": "purge_site_edge_cache", "title": "Purge Edge Cache", "summary": "Purges the edge cache for a site.", "category": "sites"},
  {"name": "flush_site_object_cache", "title": "Flush Site Object Cache", "summary": "Flushes the WordPress object cache. Useful after restored backups.", "category": "sites"},
  {"name": "list_account_webhooks", "title": "List Account Webhooks", "summary": "Lists webhook URLs.", "category": "accounts"}]}`

func catalogGateway() *fakeGateway {
	return &fakeGateway{results: map[string]*mcp.CallToolResult{"discover_tools": mcp.NewToolResultText(catalogDoc)}}
}

func TestSearchCatalog(t *testing.T) {
	var doc struct{ Tools []catalogOp }
	if err := json.Unmarshal([]byte(catalogDoc), &doc); err != nil {
		t.Fatal(err)
	}
	names := func(query string) (string, bool) {
		ops, partial := searchCatalog(doc.Tools, query)
		var out []string
		for _, op := range ops {
			out = append(out, op.Name)
		}
		return strings.Join(out, ","), partial
	}
	cases := []struct {
		query, want string
		partial     bool
	}{
		{"purge cache", "purge_site_edge_cache,flush_site_object_cache", false},
		{"cache purge", "purge_site_edge_cache,flush_site_object_cache", false},
		{"the backups of a site", "list_site_backups,restore_site_backup,flush_site_object_cache", false},
		{"cache", "purge_site_edge_cache,flush_site_object_cache", false},
		{"restore_site_backup", "restore_site_backup", false},
		{"webhook delete", "list_account_webhooks", true},
		{"clear cache", "purge_site_edge_cache,flush_site_object_cache", false},
		{"show backups", "list_site_backups", false},
		{"zzz", "", false},
	}
	for _, c := range cases {
		if got, partial := names(c.query); got != c.want || partial != c.partial {
			t.Errorf("searchCatalog(%q) = %q partial=%v, want %q partial=%v", c.query, got, partial, c.want, c.partial)
		}
	}
}

func TestDiscover_SearchesLocallyAndInlinesParameters(t *testing.T) {
	gw := catalogGateway()
	d := newDeps(&config.Config{}, gw)
	d.Describer = fakeDescriber{"purge_site_edge_cache": false, "flush_site_object_cache": false}

	out := text(call(t, handleDiscover(d), map[string]any{"query": "purge cache"}))
	for _, want := range []string{`2 operations match "purge cache"`, "purge_site_edge_cache [destructive]", "Purges the edge cache for a site.",
		"Parameters: site_id* (integer), page (integer), type (filesystem|database)"} {
		if !strings.Contains(out, want) {
			t.Errorf("discover output lacks %q:\n%s", want, out)
		}
	}

	// No query: names by category, no summaries.
	out = text(call(t, handleDiscover(d), nil))
	if !strings.Contains(out, "5 Pressable operations") || !strings.Contains(out, "accounts: list_account_webhooks") || strings.Contains(out, "Lists webhook") {
		t.Errorf("catalogue:\n%s", out)
	}

	out = text(call(t, handleDiscover(d), map[string]any{"query": "zzz"}))
	if !strings.Contains(out, `No operations match "zzz"`) {
		t.Errorf("no match: %q", out)
	}
	if len(gw.calls) != 1 {
		t.Errorf("gateway calls = %v, want one catalogue fetch", gw.calls)
	}
}

func TestExecute_SiteFillsSiteID(t *testing.T) {
	gw := &fakeGateway{sites: `{"sites": [{"id": 42, "name": "acme", "domain_url": "acme.com"}]}`}
	d := newDeps(&config.Config{}, gw)
	res := call(t, handleExecute(d), map[string]any{"tool_name": "list_site_backups", "site": "acme.com"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", text(res))
	}
	params := gw.args[0]["parameters"].(map[string]any)
	if params["site_id"] != int64(42) {
		t.Errorf("parameters = %v", params)
	}

	res = call(t, handleExecute(d), map[string]any{"tool_name": "list_site_backups", "site": "acme", "parameters": map[string]any{"site_id": 7}})
	if !res.IsError || !strings.Contains(text(res), "not both") {
		t.Errorf("site + site_id: %q", text(res))
	}
	res = call(t, handleExecute(d), map[string]any{"tool_name": "list_site_backups", "site": "nope"})
	if !res.IsError || !strings.Contains(text(res), "Site not found: nope") || len(gw.calls) != 1 {
		t.Errorf("unknown site: %q, calls %v", text(res), gw.calls)
	}
}

func TestExecute_ParameterErrorCarriesTheSchema(t *testing.T) {
	gw := &fakeGateway{results: map[string]*mcp.CallToolResult{
		"execute_tool:list_sites":  mcp.NewToolResultError("Missing required parameter(s): site_id"),
		"execute_tool:create_site": mcp.NewToolResultError("You do not have permission to do that."),
	}}
	d := newDeps(&config.Config{}, gw)
	res := call(t, handleExecute(d), map[string]any{"tool_name": "list_sites"})
	out := text(res)
	if !res.IsError || !strings.HasPrefix(out, "Missing required parameter(s): site_id\n\nParameters of list_sites:") ||
		!strings.Contains(out, "site_id (integer, required): The numeric ID of the Pressable site.") {
		t.Errorf("got %q", out)
	}
	// An error that isn't about parameters stays as Pressable wrote it.
	res = call(t, handleExecute(d), map[string]any{"tool_name": "create_site"})
	if !res.IsError || text(res) != "You do not have permission to do that." {
		t.Errorf("got %q", text(res))
	}
}

func TestAboutParams(t *testing.T) {
	cases := map[string]bool{
		"Missing required parameter(s): site_id":                       true,
		"site_id must be a positive integer":                           true,
		"Invalid argument":                                             true,
		"You do not have permission to do that.":                       false,
		"This site is required to be live before it can be restored.":  false,
		"Invalid state: the site is deploying":                         false, // not about a parameter of this operation
		"The type of backup is not valid for this page of the listing": false, // "type" and "page" are parameters, but too common to trust
	}
	for msg, want := range cases {
		if got := aboutParams(strings.ToLower(msg), json.RawMessage(siteIDSchema)); got != want {
			t.Errorf("aboutParams(%q) = %v, want %v", msg, got, want)
		}
	}
}

// A broad search still gives parameters for its best matches.
func TestDiscover_ManyMatchesDescribeTheBest(t *testing.T) {
	var tools []map[string]string
	described := fakeDescriber{}
	for i := 0; i < 9; i++ {
		name := fmt.Sprintf("list_site_backup_kind%d", i)
		tools = append(tools, map[string]string{"name": name, "title": "Backups", "summary": "Lists backups. More detail here.", "category": "sites"})
		described[name] = true
	}
	doc, _ := json.Marshal(map[string]any{"count": len(tools), "tools": tools})
	d := newDeps(&config.Config{}, &fakeGateway{results: map[string]*mcp.CallToolResult{"discover_tools": mcp.NewToolResultText(string(doc))}})
	d.Describer = described
	out := text(call(t, handleDiscover(d), map[string]any{"query": "backup"}))
	if got := strings.Count(out, "Parameters: site_id* (integer)"); got != inlineSchemas {
		t.Errorf("%d operations got parameters, want %d:\n%s", got, inlineSchemas, out)
	}
	if !strings.Contains(out, "9 operations match") || !strings.Contains(out, "shown for the 5 best matches") || strings.Contains(out, "More detail here") {
		t.Errorf("output:\n%s", out)
	}
}

func TestUnknownOperation_NamesOurToolsAndSuggests(t *testing.T) {
	gw := catalogGateway()
	gw.results["describe_tool"] = mcp.NewToolResultError("Unknown tool 'site_backup_list'. Use discover_tools to list operations.")
	d := newDeps(&config.Config{}, gw)
	res := call(t, handleDescribe(d), map[string]any{"tool_name": "site_backup_list"})
	out := text(res)
	if !res.IsError || strings.Contains(out, "discover_tools") || !strings.Contains(out, "Use pressable_discover") ||
		!strings.Contains(out, "Similar operations: list_site_backups") {
		t.Errorf("got %q", out)
	}
}

func TestSites_CompactLines(t *testing.T) {
	gw := &fakeGateway{sites: `{"sites": [
	  {"id": 2, "name": "zeta", "display_name": "zeta.com", "state": "live", "wp_environment_type": "production"},
	  {"id": 1, "name": "acme-stg", "domain_url": "acme-stg.mystagingwebsite.com", "state": "live", "staging": true}]}`}
	d := newDeps(&config.Config{}, gw)
	out := text(call(t, handleSites(d), nil))
	want := "2 sites (ID  name  domain  state  environment):\n1  acme-stg  acme-stg.mystagingwebsite.com  live  staging\n2  zeta  zeta.com  live  production\n"
	if out != want {
		t.Errorf("got %q\nwant %q", out, want)
	}
	if out = formatSites(nil, "x", false); !strings.Contains(out, `No sites match "x"`) {
		t.Errorf("empty: %q", out)
	}
}

// Read-only tools must not carry mcp-go's default destructiveHint.
func TestAnnotations(t *testing.T) {
	for name, tool := range New(newDeps(&config.Config{}, &fakeGateway{})).ListTools() {
		a := tool.Tool.Annotations
		if a.Title == "" || a.ReadOnlyHint == nil || a.DestructiveHint == nil {
			t.Errorf("%s: incomplete annotations %+v", name, a)
			continue
		}
		if *a.ReadOnlyHint == *a.DestructiveHint {
			t.Errorf("%s: readOnlyHint=%v destructiveHint=%v", name, *a.ReadOnlyHint, *a.DestructiveHint)
		}
	}
}

func TestFormatExec(t *testing.T) {
	cases := []struct {
		res  mcsh.ExecResult
		want string
	}{
		{mcsh.ExecResult{Stdout: "out\n"}, "out\n"},
		{mcsh.ExecResult{}, "(command completed with exit code 0)"},
		{mcsh.ExecResult{Stdout: "out", Stderr: "bad", ExitCode: 3}, "out\n[stderr]\nbad\n[exit code: 3]"},
	}
	for _, c := range cases {
		if got := formatExec(&c.res, 1500); got != c.want {
			t.Errorf("formatExec(%+v) = %q, want %q", c.res, got, c.want)
		}
	}
	// A timeout keeps the partial output and says what happened.
	got := formatExec(&mcsh.ExecResult{Stdout: "started\n", ExitCode: -1, TimedOut: true}, 1500)
	if !strings.HasPrefix(got, "started\n\n[timed out after 1500ms and was killed; the output above") || strings.Contains(got, "exit code") {
		t.Errorf("timeout: %q", got)
	}
	if got = formatExec(&mcsh.ExecResult{ExitCode: -1, TimedOut: true}, 1500); !strings.Contains(got, "before printing anything") {
		t.Errorf("silent timeout: %q", got)
	}
	if got = formatExec(&mcsh.ExecResult{Stdout: "a\n[… 5 of 9 bytes omitted …]\nb", Truncated: true}, 0); !strings.Contains(got, "middle was omitted") {
		t.Errorf("truncated: %q", got)
	}
}

func TestFormatSlice(t *testing.T) {
	whole := &mcsh.FileSlice{Path: "/srv/htdocs/a", Content: "x\ny\n", Offset: 1, FirstLine: 1, LastLine: 2, TotalLines: 2}
	if got := formatSlice(whole, 100); got != "x\ny\n" {
		t.Errorf("whole file must come back untouched, got %q", got)
	}
	part := &mcsh.FileSlice{Path: "/srv/htdocs/a", Content: "x\ny\n", Size: 900, Offset: 1, FirstLine: 1, LastLine: 2, TotalLines: 40, More: true}
	if got := formatSlice(part, 100); got != "x\ny\n[lines 1-2 of 40 of /srv/htdocs/a (900 bytes); continue with offset=3]" {
		t.Errorf("part: %q", got)
	}
	last := &mcsh.FileSlice{Path: "/srv/htdocs/a", Content: "end", Size: 900, Offset: 40, FirstLine: 40, LastLine: 40, TotalLines: 40}
	if got := formatSlice(last, 100); got != "end\n[line 40 of 40 of /srv/htdocs/a (900 bytes)]" {
		t.Errorf("last: %q", got)
	}
	past := &mcsh.FileSlice{Path: "/srv/htdocs/a", Offset: 99, TotalLines: 40}
	if got := formatSlice(past, 100); got != "[no lines at offset 99: /srv/htdocs/a has 40 lines]" {
		t.Errorf("past the end: %q", got)
	}
	legacy := &mcsh.FileSlice{Path: "/srv/htdocs/a", Content: "café\n", Offset: 1, FirstLine: 1, LastLine: 1, TotalLines: 1, Encoding: mcsh.EncodingWindows1252}
	if got := formatSlice(legacy, 100); got != "café\n[the file is Windows-1252, shown here as UTF-8; pressable_sftp_edit keeps its encoding, pressable_sftp_write would save UTF-8]" {
		t.Errorf("legacy encoding: %q", got)
	}
	cut := &mcsh.FileSlice{Path: "/srv/htdocs/a.min.js", Content: "xxxx", Size: 5000, Offset: 1, FirstLine: 1, LastLine: 1, TotalLines: 1, More: true, LineCut: true}
	if got := formatSlice(cut, 4); !strings.Contains(got, "line 1 is longer than the 4-byte limit") || !strings.Contains(got, "local_path") {
		t.Errorf("cut: %q", got)
	}
}

func TestFormatListing(t *testing.T) {
	got := formatListing("/srv/htdocs/wp-content", []mcsh.FileEntry{
		{Name: "plugins", Type: mcsh.FileTypeDirectory, Size: 12, ModifiedAt: "2026-03-19T05:31:33.000Z", Permissions: "775"},
		{Name: "index.php", Type: mcsh.FileTypeFile, Size: 26, ModifiedAt: "2025-02-12T22:56:36.000Z", Permissions: "644"},
		{Name: "object-cache.php", Type: mcsh.FileTypeSymlink, Size: 41, ModifiedAt: "2025-02-12T22:56:36.000Z", Permissions: "777", Target: "/scripts/object-cache.php"},
	})
	want := "/srv/htdocs/wp-content — 3 entries (type  permissions  bytes  modified UTC  name)\n" +
		"dir   775          -  2026-03-19 05:31  plugins/\n" +
		"file  644         26  2025-02-12 22:56  index.php\n" +
		"link  777          -  2025-02-12 22:56  object-cache.php -> /scripts/object-cache.php\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if got = formatListing("/srv/htdocs/x", nil); !strings.Contains(got, "is empty") {
		t.Errorf("empty: %q", got)
	}
}

func TestLocalPath(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "a", "..", "dump.sql")
	if got, err := localPath(abs); err != nil || got != filepath.Clean(abs) {
		t.Errorf("localPath(%q) = %q, %v", abs, got, err)
	}
	if _, err := localPath("dump.sql"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("relative path accepted: %v", err)
	}
}

func TestSFTPWrite_NeedsExactlyOneSource(t *testing.T) {
	d := newDeps(&config.Config{}, &fakeGateway{})
	for _, args := range []map[string]any{
		{"site": "1", "path": "a.txt"},
		{"site": "1", "path": "a.txt", "content": "x", "local_path": "/tmp/a.txt"},
	} {
		res := call(t, handleSFTPWrite(d), args)
		if !res.IsError || !strings.Contains(text(res), "exactly one") {
			t.Errorf("args %v: %q", args, text(res))
		}
	}
}

func TestSFTPRead_RefusesToOverwriteLocalFile(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(existing, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newDeps(&config.Config{}, &fakeGateway{})
	res := call(t, handleSFTPRead(d), map[string]any{"site": "1", "path": "a.txt", "local_path": existing})
	if !res.IsError || !strings.Contains(text(res), "already exists") || !strings.Contains(text(res), "overwrite_local") {
		t.Errorf("got %q", text(res))
	}
}

func TestErrResult_LoginRequired(t *testing.T) {
	gw := &fakeGateway{err: auth.ErrLoginRequired}
	d := newDeps(&config.Config{}, gw)
	res := call(t, handleDiscover(d), nil)
	if !res.IsError || !strings.Contains(text(res), "presswrench login") {
		t.Fatalf("got %q", text(res))
	}
}

func TestErrResult_StorageErrorIsExplained(t *testing.T) {
	cerr := &creds.Error{Kind: creds.KindLocked}
	d := newDeps(&config.Config{}, &fakeGateway{err: cerr})
	res := call(t, handleDiscover(d), nil)
	if !res.IsError || text(res) != auth.Explain(cerr) {
		t.Fatalf("got %q", text(res))
	}
	if strings.Contains(text(res), "Not signed in") {
		t.Errorf("locked keychain reported as signed out: %q", text(res))
	}
}

func TestWPCommand(t *testing.T) {
	cases := map[string]string{
		"plugin list":           "wp plugin list",
		"wp plugin list":        "wp plugin list",
		"  wp core version ":    "wp core version",
		"wpml-cli thing":        "wp wpml-cli thing",
		"--skip-plugins option": "wp --skip-plugins option",
	}
	for in, want := range cases {
		if got := wpCommand(in); got != want {
			t.Errorf("wpCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdentityEmail(t *testing.T) {
	cases := map[string]string{
		"Jane Doe <jane@example.com>": "jane@example.com",
		"jane@example.com":            "jane@example.com",
		"Jane Doe":                    "",
		"":                            "",
	}
	for in, want := range cases {
		if got := identityEmail(in); got != want {
			t.Errorf("identityEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSSHStatus_NoSite(t *testing.T) {
	d := newDeps(&config.Config{SSHKeyPath: "/nonexistent/key", SSHKeyLabel: "presswrench"}, &fakeGateway{})
	res := call(t, handleSSHStatus(d), nil)
	var st sshStatus
	if err := json.Unmarshal([]byte(text(res)), &st); err != nil {
		t.Fatalf("parse: %v (%s)", err, text(res))
	}
	if st.KeyExists || st.KeyLabel != "presswrench" || st.Site != nil {
		t.Errorf("status = %+v", st)
	}
}

// sessionGateway fails the way the real gateway does: by asking the session for a token.
type sessionGateway struct {
	fakeGateway
	session *auth.Session
}

func (g *sessionGateway) CallTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	if _, err := g.session.Token(ctx); err != nil {
		return nil, err
	}
	return g.fakeGateway.CallTool(ctx, name, args)
}

func TestSSHStatus_ReportsSessionProblem(t *testing.T) {
	t.Setenv(auth.EnvAccessToken, "")
	cerr := &creds.Error{Kind: creds.KindUnavailable, Detail: "no dbus"}
	d := newDeps(&config.Config{SSHKeyPath: "/nonexistent/key", SSHKeyLabel: "presswrench"}, &fakeGateway{})
	d.Session = auth.NewSession(creds.Broken(cerr), "", "")
	res := call(t, handleSSHStatus(d), nil)
	if res.IsError {
		t.Fatalf("ssh_status must not fail: %q", text(res))
	}
	var st sshStatus
	if err := json.Unmarshal([]byte(text(res)), &st); err != nil {
		t.Fatalf("parse: %v (%s)", err, text(res))
	}
	if st.KeyPath != "/nonexistent/key" {
		t.Errorf("keyPath = %q", st.KeyPath)
	}
	if st.Session == "" || st.Session != auth.Explain(cerr) {
		t.Errorf("session = %q, want %q", st.Session, auth.Explain(cerr))
	}
}

func TestGatewayTool_NotSignedInExplains(t *testing.T) {
	t.Setenv(auth.EnvAccessToken, "")
	store := creds.NewFileStore(t.TempDir() + "/creds.json")
	sess := auth.NewSession(store, "", "http://127.0.0.1:1")
	d := newDeps(&config.Config{}, nil)
	d.Session = sess
	d.Gateway = &sessionGateway{session: sess}
	res := call(t, handleDiscover(d), nil)
	if !res.IsError || !strings.Contains(text(res), "presswrench login") {
		t.Fatalf("got %q", text(res))
	}
}

// warnStore reports a store warning (an override hiding the sign-in store).
type warnStore struct{ creds.Store }

const overrideWarning = "PRESSWRENCH_CREDENTIAL_STORE=file overrides the keyring store used at sign-in; sessions saved there aren't visible."

func (w warnStore) Info() creds.Info {
	i := w.Store.Info()
	i.Warning = overrideWarning
	return i
}

func TestNotSignedIn_ToolResultsCarryStoreWarning(t *testing.T) {
	store := warnStore{creds.NewFileStore(t.TempDir() + "/creds.json")}
	sess := auth.NewSession(store, "dev", "http://127.0.0.1:1")
	d := newDeps(&config.Config{SSHKeyPath: "/nonexistent/key"}, nil)
	d.Session = sess
	d.Gateway = &sessionGateway{session: sess}
	res := call(t, handleDiscover(d), nil)
	if !res.IsError || !strings.Contains(text(res), overrideWarning) {
		t.Errorf("discover = %q, want the store warning", text(res))
	}
	var st sshStatus
	if err := json.Unmarshal([]byte(text(call(t, handleSSHStatus(d), nil))), &st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(st.Session, overrideWarning) || !strings.Contains(st.Session, "presswrench login --account dev") {
		t.Errorf("ssh_status session = %q", st.Session)
	}
}

// noSiteID describes operations whose schema has no site_id.
type noSiteID struct{ schema string }

func (d noSiteID) Describe(_ context.Context, name string) (*gateway.Operation, error) {
	return &gateway.Operation{Name: name, InputSchema: json.RawMessage(d.schema)}, nil
}

func TestExecute_SiteNeedsASiteIDParameter(t *testing.T) {
	gw := &fakeGateway{sites: `{"sites": [{"id": 42, "name": "acme"}]}`}
	d := newDeps(&config.Config{}, gw)
	d.Describer = noSiteID{`{"type":"object","properties":{"zone_id":{"type":"integer","description":"The DNS zone."}},"required":["zone_id"]}`}
	res := call(t, handleExecute(d), map[string]any{"tool_name": "list_dns_zone_records", "site": "acme"})
	out := text(res)
	if !res.IsError || !strings.Contains(out, "has no site_id parameter") || !strings.Contains(out, "zone_id (integer, required): The DNS zone.") {
		t.Errorf("got %q", out)
	}
	if len(gw.calls) != 0 {
		t.Errorf("the call went out anyway: %v", gw.calls)
	}

	d.Describer = noSiteID{`{"type":"object","properties":{}}`}
	res = call(t, handleExecute(d), map[string]any{"tool_name": "list_dns_zones", "site": "acme"})
	if !res.IsError || !strings.Contains(text(res), "takes no parameters") {
		t.Errorf("got %q", text(res))
	}

	// An operation we can't describe is left for Pressable to judge.
	d.Describer = fakeDescriber{}
	res = call(t, handleExecute(d), map[string]any{"tool_name": "brand_new_op", "site": "acme"})
	if res.IsError || gw.args[0]["parameters"].(map[string]any)["site_id"] != int64(42) {
		t.Errorf("undescribable operation: %q %v", text(res), gw.args)
	}
}

// A remembered SSH login that the server now refuses is looked up again
// instead of failing until the cache expires.
func TestResolveLogin_ReplacesAStaleLogin(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id")
	if _, err := mcsh.EnsureKeyPair(keyPath, "presswrench"); err != nil {
		t.Fatal(err)
	}
	gw := &fakeGateway{sites: `{"ftp_accounts": [{"username": "knew", "ssh_key_label": "presswrench"}]}`}
	d := newDeps(&config.Config{SSHKeyPath: keyPath, SSHKeyLabel: "presswrench"}, gw)
	var tried []string
	d.dial = func(user string) error {
		tried = append(tried, user)
		if user == "kold" {
			return errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey]")
		}
		return nil
	}
	d.Logins.put(7, "kold")

	login, err := d.resolveLogin(context.Background(), "7")
	if err != nil || login.User != "knew" {
		t.Fatalf("got %+v, %v", login, err)
	}
	if strings.Join(tried, ",") != "kold,knew" {
		t.Errorf("tried %v", tried)
	}
	if user, _ := d.Logins.get(7); user != "knew" {
		t.Errorf("cache holds %q", user)
	}

	// A network failure is not a reason to forget a login.
	d.Logins.put(8, "kfine")
	d.dial = func(string) error { return errors.New("dial tcp: i/o timeout") }
	if login, err = d.resolveLogin(context.Background(), "8"); err != nil || login.User != "kfine" {
		t.Errorf("network error dropped the login: %+v, %v", login, err)
	}
}
