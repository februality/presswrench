// Package gateway is a minimal MCP client for Pressable's hosted MCP server
// (mcp.pressable.com). Pressable exposes its ~200 platform operations
// through three gateway tools — discover_tools, describe_tool, execute_tool
// — and enforces each user's site access and collaborator roles itself.
//
// Transport: MCP Streamable HTTP. Every request is a JSON-RPC POST; the
// response is either application/json or a short text/event-stream whose
// data lines carry the JSON-RPC response. The session id from initialize is
// echoed on later requests; a 404 means the session expired and is
// re-initialized once. A 401 invalidates the access token and retries once.
package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const protocolVersion = "2025-06-18"

// TokenSource supplies bearer tokens. Implemented by *auth.Session.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	Invalidate(token string)
}

// Client talks to the gateway. Safe for concurrent use: requests run in
// parallel on one MCP session; only session setup is serialized.
type Client struct {
	url     string
	tokens  TokenSource
	http    *http.Client
	version string

	initMu sync.Mutex // serializes session (re)initialization

	mu        sync.Mutex // guards the fields below
	sessionID string
	ready     bool
	gen       int // bumped on every new session

	nextID atomic.Int64
}

// New returns a client for the gateway at url. version is reported as the
// clientInfo version.
func New(url string, tokens TokenSource, version string) *Client {
	return &Client{
		url:    url,
		tokens: tokens,
		// Generous: some operations (clones, backups) take a while to
		// acknowledge. Tool-call contexts still cancel requests early.
		http:    &http.Client{Timeout: 10 * time.Minute},
		version: version,
	}
}

// HTTPError is a non-2xx gateway response.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Pressable MCP gateway returned HTTP %d: %s", e.Status, e.Body)
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("Pressable MCP gateway error %d: %s", e.Code, e.Message)
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	ID     *int64          `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

// CallTool invokes a gateway tool and returns its result unchanged.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	if args == nil {
		args = map[string]any{}
	}
	raw, err := c.request(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	return mcp.ParseCallToolResult(&raw)
}

// Execute runs a Pressable operation through execute_tool.
func (c *Client) Execute(ctx context.Context, operation string, params map[string]any) (*mcp.CallToolResult, error) {
	if params == nil {
		params = map[string]any{}
	}
	return c.CallTool(ctx, "execute_tool", map[string]any{"tool_name": operation, "parameters": params})
}

// ExecuteJSON runs an operation and decodes its text result as JSON into
// out. A tool-level error becomes a Go error carrying the gateway's text.
func (c *Client) ExecuteJSON(ctx context.Context, operation string, params map[string]any, out any) error {
	res, err := c.Execute(ctx, operation, params)
	if err != nil {
		return err
	}
	text := ResultText(res)
	if res.IsError {
		return fmt.Errorf("%s: %s", operation, strings.TrimSpace(text))
	}
	if err := json.Unmarshal([]byte(text), out); err != nil {
		return fmt.Errorf("%s: could not parse result as JSON: %w", operation, err)
	}
	return nil
}

// ResultText concatenates the text content items of a result.
func ResultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if t, ok := c.(mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func (c *Client) session() (string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID, c.gen
}

// request sends a JSON-RPC request on the current session, establishing one
// first if needed. A 404 means the server dropped the session: start a new
// one (once, however many requests noticed) and retry.
func (c *Client) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if err := c.ensureSession(ctx, -1); err != nil {
		return nil, err
	}
	sid, gen := c.session()
	raw, _, err := c.roundTrip(ctx, method, params, true, sid)
	var he *HTTPError
	if errors.As(err, &he) && he.Status == http.StatusNotFound {
		if err := c.ensureSession(ctx, gen); err != nil {
			return nil, err
		}
		sid, _ = c.session()
		raw, _, err = c.roundTrip(ctx, method, params, true, sid)
	}
	return raw, err
}

// ensureSession initializes a session if there is none, or — when stale is
// the generation a caller saw fail with 404 — replaces it, unless another
// goroutine already did.
func (c *Client) ensureSession(ctx context.Context, stale int) error {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	c.mu.Lock()
	if c.ready && c.gen != stale {
		c.mu.Unlock()
		return nil
	}
	c.sessionID, c.ready = "", false
	c.mu.Unlock()

	_, sid, err := c.roundTrip(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "presswrench", "version": c.version},
	}, true, "")
	if err != nil {
		return err
	}
	// Notification: no id, no response body expected.
	if _, _, err := c.roundTrip(ctx, "notifications/initialized", nil, false, sid); err != nil {
		return err
	}
	c.mu.Lock()
	c.sessionID, c.ready = sid, true
	c.gen++
	c.mu.Unlock()
	return nil
}

// roundTrip performs one POST on session sid (no locks held), retrying once
// on 401 with a fresh token. Returns the result and any session id the
// server assigned.
func (c *Client) roundTrip(ctx context.Context, method string, params any, expectResponse bool, sid string) (json.RawMessage, string, error) {
	req := rpcRequest{JSONRPC: "2.0", Method: method, Params: params}
	var id int64
	if expectResponse {
		id = c.nextID.Add(1)
		req.ID = &id
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, "", err
	}

	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.tokens.Token(ctx)
		if err != nil {
			return nil, "", err
		}
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
		if err != nil {
			return nil, "", err
		}
		hreq.Header.Set("Authorization", "Bearer "+token)
		hreq.Header.Set("Content-Type", "application/json")
		hreq.Header.Set("Accept", "application/json, text/event-stream")
		if method != "initialize" {
			hreq.Header.Set("MCP-Protocol-Version", protocolVersion)
		}
		if sid != "" {
			hreq.Header.Set("Mcp-Session-Id", sid)
		}
		resp, err := c.http.Do(hreq)
		if err != nil {
			return nil, "", fmt.Errorf("Pressable MCP gateway request failed: %w", err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			c.tokens.Invalidate(token)
			continue
		}
		newSID := resp.Header.Get("Mcp-Session-Id")
		raw, err := readResponse(resp, id, expectResponse)
		resp.Body.Close()
		return raw, newSID, err
	}
	return nil, "", &HTTPError{Status: http.StatusUnauthorized, Body: "token rejected after refresh — run `presswrench login`"}
}

func readResponse(resp *http.Response, id int64, expectResponse bool) (json.RawMessage, error) {
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if !expectResponse {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	}
	var msgs [][]byte
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		var err error
		msgs, err = readSSE(resp.Body)
		if err != nil {
			return nil, err
		}
	} else {
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, err
		}
		msgs = [][]byte{b}
	}
	for _, m := range msgs {
		var r rpcResponse
		// Skip notifications and server-initiated requests (which carry a
		// method and may reuse a numeric id).
		if json.Unmarshal(m, &r) != nil || r.Method != "" || r.ID == nil || *r.ID != id {
			continue
		}
		if r.Error != nil {
			return nil, r.Error
		}
		return r.Result, nil
	}
	return nil, fmt.Errorf("Pressable MCP gateway: no response for request %d", id)
}

// readSSE returns the data payload of each event in the stream.
func readSSE(r io.Reader) ([][]byte, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 64<<20)
	var out [][]byte
	var cur bytes.Buffer
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, append([]byte(nil), cur.Bytes()...))
			cur.Reset()
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			if cur.Len() > 0 {
				cur.WriteByte('\n')
			}
			cur.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	return out, sc.Err()
}
