package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/config"
	"github.com/februality/presswrench/internal/gateway"
	"github.com/februality/presswrench/internal/sites"
)

// fakeGateway records calls and returns canned results.
type fakeGateway struct {
	calls []string
	args  []map[string]any
	err   error
}

func (f *fakeGateway) CallTool(_ context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	f.calls = append(f.calls, name)
	f.args = append(f.args, args)
	if f.err != nil {
		return nil, f.err
	}
	return mcp.NewToolResultText("upstream:" + name), nil
}

func (f *fakeGateway) ExecuteJSON(context.Context, string, map[string]any, any) error { return nil }

type fakeDescriber map[string]bool // name -> readOnly

func (f fakeDescriber) Describe(_ context.Context, name string) (*gateway.Operation, error) {
	ro, ok := f[name]
	if !ok {
		return nil, errors.New("unknown operation")
	}
	return &gateway.Operation{Name: name, ReadOnly: ro}, nil
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
	want := []string{"pressable_describe", "pressable_discover", "pressable_execute", "pressable_sftp_list",
		"pressable_sftp_read", "pressable_sftp_write", "pressable_ssh_exec", "pressable_ssh_status", "pressable_wp_cli"}
	if strings.Join(full, ",") != strings.Join(want, ",") {
		t.Errorf("tools = %v, want %v", full, want)
	}

	ro := toolNames(New(newDeps(&config.Config{ReadOnly: true}, &fakeGateway{})))
	for _, hidden := range []string{"pressable_ssh_exec", "pressable_wp_cli", "pressable_sftp_write"} {
		for _, n := range ro {
			if n == hidden {
				t.Errorf("read-only mode registered %s", hidden)
			}
		}
	}
	if len(ro) != len(want)-3 {
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

func TestDiscoverAndDescribe_PassThrough(t *testing.T) {
	gw := &fakeGateway{}
	d := newDeps(&config.Config{}, gw)
	call(t, handleDiscover(d), map[string]any{"query": "backup"})
	call(t, handleDescribe(d), map[string]any{"tool_name": "list_sites"})
	if strings.Join(gw.calls, ",") != "discover_tools,describe_tool" {
		t.Fatalf("calls = %v", gw.calls)
	}
	if gw.args[0]["query"] != "backup" || gw.args[1]["tool_name"] != "list_sites" {
		t.Errorf("args = %v", gw.args)
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
