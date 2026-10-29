package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeTokens struct {
	mu          sync.Mutex
	tok         string
	invalidated []string
}

func (f *fakeTokens) Token(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tok, nil
}

func (f *fakeTokens) Invalidate(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidated = append(f.invalidated, tok)
	f.tok = "fresh"
}

// fakeMCP is a Streamable-HTTP MCP server with a session id, optional SSE
// responses, a token it accepts, and a switch to expire the session.
type fakeMCP struct {
	mu        sync.Mutex
	sse       bool
	goodToken string
	session   int
	expire    bool
	inits     int
	calls     []string
}

func (f *fakeMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.goodToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct {
		ID     *int64         `json:"id"`
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	sid := fmt.Sprintf("s%d", f.session)
	if req.Method == "initialize" {
		f.inits++
		f.session++
		f.expire = false
		sid = fmt.Sprintf("s%d", f.session)
		w.Header().Set("Mcp-Session-Id", sid)
		f.reply(w, req.ID, map[string]any{"protocolVersion": protocolVersion})
		return
	}
	if r.Header.Get("Mcp-Session-Id") != sid || f.expire {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if req.ID == nil { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	name, _ := req.Params["name"].(string)
	f.calls = append(f.calls, name)
	args, _ := req.Params["arguments"].(map[string]any)
	switch name {
	case "describe_tool":
		def, _ := json.Marshal(map[string]any{"name": args["tool_name"], "annotations": map[string]any{"readOnlyHint": args["tool_name"] == "list_sites", "destructiveHint": false}})
		f.reply(w, req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": string(def)}}})
	case "execute_tool":
		if args["tool_name"] == "boom" {
			f.reply(w, req.ID, map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "Forbidden: missing role"}}})
			return
		}
		f.reply(w, req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": `{"sites":[{"id":7,"name":"seven"}]}`}}})
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32602, "message": "unknown tool"}})
	}
}

func (f *fakeMCP) reply(w http.ResponseWriter, id *int64, result any) {
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	if f.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		// A stray notification first, to prove id matching.
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n")
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(msg)
}

func setup(t *testing.T, sse bool) (*fakeMCP, *Client, *fakeTokens) {
	f := &fakeMCP{sse: sse, goodToken: "good"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	toks := &fakeTokens{tok: "good"}
	return f, New(srv.URL, toks, "test"), toks
}

func TestExecuteJSON(t *testing.T) {
	for _, sse := range []bool{false, true} {
		f, c, _ := setup(t, sse)
		var out struct {
			Sites []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"sites"`
		}
		if err := c.ExecuteJSON(context.Background(), "list_sites", nil, &out); err != nil {
			t.Fatalf("sse=%v: %v", sse, err)
		}
		if len(out.Sites) != 1 || out.Sites[0].ID != 7 {
			t.Errorf("sse=%v: out = %+v", sse, out)
		}
		if f.inits != 1 {
			t.Errorf("inits = %d", f.inits)
		}
	}
}

func TestExecuteJSON_ToolError(t *testing.T) {
	_, c, _ := setup(t, false)
	var out any
	err := c.ExecuteJSON(context.Background(), "boom", nil, &out)
	if err == nil || !strings.Contains(err.Error(), "Forbidden: missing role") {
		t.Fatalf("err = %v", err)
	}
}

func TestRPCError(t *testing.T) {
	_, c, _ := setup(t, false)
	_, err := c.CallTool(context.Background(), "nope", nil)
	if _, ok := err.(*RPCError); !ok {
		t.Fatalf("err = %T %v", err, err)
	}
}

func TestRetriesOn401WithFreshToken(t *testing.T) {
	f, c, toks := setup(t, false)
	f.goodToken = "fresh"
	if _, err := c.Execute(context.Background(), "list_sites", nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(toks.invalidated) != 1 || toks.invalidated[0] != "good" {
		t.Errorf("invalidated = %v", toks.invalidated)
	}
}

func TestReinitializesExpiredSession(t *testing.T) {
	f, c, _ := setup(t, false)
	if _, err := c.Execute(context.Background(), "list_sites", nil); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.expire = true
	f.mu.Unlock()
	if _, err := c.Execute(context.Background(), "list_sites", nil); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if f.inits != 2 {
		t.Errorf("inits = %d, want 2", f.inits)
	}
}

func TestDescriber_CachesAndParses(t *testing.T) {
	f, c, _ := setup(t, false)
	d := NewDescriber(c)
	for i := 0; i < 2; i++ {
		op, err := d.Describe(context.Background(), "list_sites")
		if err != nil || !op.ReadOnly {
			t.Fatalf("op = %+v, err = %v", op, err)
		}
	}
	op, _ := d.Describe(context.Background(), "create_site")
	if op.ReadOnly {
		t.Error("create_site should not be read-only")
	}
	describes := 0
	for _, c := range f.calls {
		if c == "describe_tool" {
			describes++
		}
	}
	if describes != 2 {
		t.Errorf("describe calls = %d, want 2 (cached)", describes)
	}
}

func TestParseOperation_MissingHintsAreConservative(t *testing.T) {
	op, err := parseOperation("x", `{"name":"x"}`)
	if err != nil {
		t.Fatal(err)
	}
	if op.ReadOnly || !op.Destructive {
		t.Errorf("op = %+v", op)
	}
}

func TestConcurrentCallsShareOneSession(t *testing.T) {
	f, c, _ := setup(t, true)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Execute(context.Background(), "list_sites", nil); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if f.inits != 1 {
		t.Errorf("inits = %d, want 1", f.inits)
	}
}

func TestServerRequestWithCollidingIDIsSkipped(t *testing.T) {
	msgs, err := readSSE(strings.NewReader("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"))
	if err != nil || len(msgs) != 2 {
		t.Fatalf("msgs = %d, err = %v", len(msgs), err)
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"))}
	raw, err := readResponse(resp, 1, true)
	if err != nil || string(raw) != `{"ok":true}` {
		t.Fatalf("raw = %s, err = %v", raw, err)
	}
}
