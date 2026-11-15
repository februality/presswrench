package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/gateway"
	"github.com/februality/presswrench/internal/sites"
)

// RegisterGatewayTools registers the tools backed by Pressable's MCP
// gateway. Operation results come back as Pressable returned them; local
// logic is policy (blocklist, read-only) before pressable_execute forwards a
// call, a searchable copy of the operation catalogue, and errors that say
// what to do next.
func RegisterGatewayTools(s *server.MCPServer, d *Deps) {
	s.AddTool(toolSites(), handleSites(d))
	s.AddTool(toolDiscover(d), handleDiscover(d))
	s.AddTool(toolDescribe(), handleDescribe(d))
	s.AddTool(toolExecute(d), handleExecute(d))
}

// readOnlyTool and writeTool are the annotations every tool carries. mcp-go
// defaults destructiveHint to true, so read-only tools must say otherwise.
func readOnlyTool(title string) mcp.ToolOption {
	return func(t *mcp.Tool) {
		mcp.WithTitleAnnotation(title)(t)
		mcp.WithReadOnlyHintAnnotation(true)(t)
		mcp.WithDestructiveHintAnnotation(false)(t)
		mcp.WithIdempotentHintAnnotation(true)(t)
	}
}

func writeTool(title string) mcp.ToolOption {
	return func(t *mcp.Tool) {
		mcp.WithTitleAnnotation(title)(t)
		mcp.WithReadOnlyHintAnnotation(false)(t)
		mcp.WithDestructiveHintAnnotation(true)(t)
	}
}

func toolSites() mcp.Tool {
	return mcp.NewTool("pressable_sites",
		mcp.WithDescription("List the Pressable sites the signed-in user can access, one line each: numeric ID, name, primary domain, state, environment (production, staging, sandbox). Pass `query` to keep sites whose name or domain contains it. Start here to find a site; for one site's full details run the get_site_details operation with pressable_execute."),
		mcp.WithString("query", mcp.Description("Optional part of a site name or domain (e.g. \"acme\", \"acme.com\")")),
		readOnlyTool("List Pressable sites"),
	)
}

func toolDiscover(d *Deps) mcp.Tool {
	desc := "Find Pressable platform operations (about 200: sites, domains, DNS, SSL, backups, restores, plugins, themes, logs, collaborators, caching, metrics, WordPress users, and more). Pass `query` with one or more words (e.g. \"backup\", \"dns record\", \"php version\"): each match comes with its summary, and the 5 best also with their parameters, ready for pressable_execute. Without `query`, returns every operation name by category."
	if d.Cfg.ReadOnly {
		desc += " Read-only mode is on: only operations Pressable marks read-only can be executed."
	}
	return mcp.NewTool("pressable_discover",
		mcp.WithDescription(desc),
		mcp.WithString("query", mcp.Description("Words to look for in operation names, titles and summaries, in any order")),
		readOnlyTool("Find Pressable operations"),
	)
}

func toolDescribe() mcp.Tool {
	return mcp.NewTool("pressable_describe",
		mcp.WithDescription("Return one Pressable operation's full definition: description, input schema (parameters, types, required fields), and behavior annotations (readOnlyHint, destructiveHint). Use it when pressable_discover's parameter list isn't enough."),
		mcp.WithString("tool_name", mcp.Required(), mcp.Description("Exact operation name from pressable_discover (e.g. \"list_sites\")")),
		readOnlyTool("Describe a Pressable operation"),
	)
}

func toolExecute(d *Deps) mcp.Tool {
	desc := "Run a Pressable platform operation with the given parameters, as the signed-in user. Pressable enforces the user's site access and collaborator roles and logs the action. Find operations and their parameters with pressable_discover. For an operation that takes site_id, you can pass `site` (name or domain) instead and it is filled in."
	if d.Cfg.ReadOnly {
		desc += " Read-only mode is on: operations Pressable does not mark read-only are refused."
	}
	if len(d.Cfg.BlockedOperations) > 0 {
		desc += " Blocked locally: " + strings.Join(d.Cfg.BlockedOperations, ", ") + "."
	}
	return mcp.NewTool("pressable_execute",
		mcp.WithDescription(desc),
		mcp.WithString("tool_name", mcp.Required(), mcp.Description("Exact operation name from pressable_discover")),
		mcp.WithObject("parameters", mcp.Description("The operation's parameters, as listed by pressable_discover or pressable_describe")),
		mcp.WithString("site", mcp.Description("Site name, domain, or numeric ID. Sets parameters.site_id, so don't pass both.")),
		writeTool("Run a Pressable operation"),
	)
}

func handleSites(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query := strings.TrimSpace(req.GetString("query", ""))
		list, truncated, err := d.Sites.Search(ctx, query)
		if err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText(formatSites(list, query, truncated)), nil
	}
}

func formatSites(list []sites.Site, query string, truncated bool) string {
	if len(list) == 0 {
		if query == "" {
			return "This Pressable account has no sites you can access."
		}
		return fmt.Sprintf("No sites match %q. Call pressable_sites without a query to list them all.", query)
	}
	list = append([]sites.Site{}, list...)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	var b strings.Builder
	if query == "" {
		b.WriteString(count(len(list), "site", "sites"))
	} else {
		fmt.Fprintf(&b, "%s %q", count(len(list), "site matches", "sites match"), query)
	}
	b.WriteString(" (ID  name  domain  state  environment):\n")
	for _, s := range list {
		fmt.Fprintf(&b, "%d  %s  %s  %s  %s\n", s.ID, s.Name, dash(s.Host()), dash(s.State), dash(s.Env))
	}
	if truncated {
		b.WriteString("More sites match than Pressable returns for one search: use a longer query.\n")
	}
	return b.String()
}

// count renders "1 site" / "3 sites".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// catalogOp is one operation as discover_tools lists it.
type catalogOp struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
	Category string `json:"category"`
}

// catalogTTL is how long the operation catalogue is reused. Pressable adds
// operations rarely; an hour keeps a long-running server current.
const catalogTTL = time.Hour

// catalog caches the gateway's full operation list, so searching it costs
// no round trip and can match several words (the gateway's own filter is a
// single substring).
type catalog struct {
	mu  sync.Mutex
	ops []catalogOp
	at  time.Time
}

// errNoCatalog means the gateway's list wasn't in the shape we parse; the
// caller falls back to passing the request through.
var errNoCatalog = errors.New("operation catalogue unavailable")

func (d *Deps) operations(ctx context.Context) ([]catalogOp, error) {
	d.catalog.mu.Lock()
	defer d.catalog.mu.Unlock()
	if d.catalog.ops != nil && time.Since(d.catalog.at) < catalogTTL {
		return d.catalog.ops, nil
	}
	res, err := d.Gateway.CallTool(ctx, "discover_tools", map[string]any{})
	if err != nil {
		return nil, err
	}
	var doc struct {
		Tools []catalogOp `json:"tools"`
	}
	if res.IsError || json.Unmarshal([]byte(gateway.ResultText(res)), &doc) != nil || len(doc.Tools) == 0 {
		return nil, errNoCatalog
	}
	d.catalog.ops, d.catalog.at = doc.Tools, time.Now()
	return doc.Tools, nil
}

// inlineSchemas is how many of the best matches pressable_discover gives
// parameters for (one describe call each, cached).
const inlineSchemas = 5

// listedMatches caps a pressable_discover result.
const listedMatches = 25

func handleDiscover(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query := strings.TrimSpace(req.GetString("query", ""))
		ops, err := d.operations(ctx)
		if errors.Is(err, errNoCatalog) {
			args := map[string]any{}
			if query != "" {
				args["query"] = query
			}
			return passThrough(d.Gateway.CallTool(ctx, "discover_tools", args))
		}
		if err != nil {
			return errResult(err)
		}
		if query == "" {
			return mcp.NewToolResultText(formatCatalog(ops)), nil
		}
		matches, partial := searchCatalog(ops, query)
		if len(matches) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No operations match %q. Try other words, or call pressable_discover without a query for every operation name.", query)), nil
		}
		return mcp.NewToolResultText(d.formatMatches(ctx, query, matches, partial)), nil
	}
}

// formatCatalog lists every operation name under its category.
func formatCatalog(ops []catalogOp) string {
	byCat := map[string][]string{}
	var cats []string
	for _, op := range ops {
		if _, ok := byCat[op.Category]; !ok {
			cats = append(cats, op.Category)
		}
		byCat[op.Category] = append(byCat[op.Category], op.Name)
	}
	sort.Strings(cats)
	var b strings.Builder
	fmt.Fprintf(&b, "%d Pressable operations. Pass `query` (one or more words) for summaries and parameters.\n", len(ops))
	for _, c := range cats {
		fmt.Fprintf(&b, "\n%s: %s\n", dash(c), strings.Join(byCat[c], ", "))
	}
	return b.String()
}

var stopWords = map[string]bool{"a": true, "an": true, "the": true, "to": true, "of": true, "for": true, "on": true, "in": true, "my": true, "and": true}

func queryTokens(query string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(strings.ToLower(query), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if !stopWords[t] {
			out = append(out, t)
		}
	}
	return out
}

// synonymSets group the verbs people use interchangeably for what Pressable
// names one way ("add a DNS record" is create_dns_record).
var synonymSets = [][]string{
	{"add", "create", "new", "make"},
	{"delete", "remove", "destroy"},
	{"update", "change", "edit", "modify", "set"},
	{"list", "show", "get", "view"},
	{"purge", "flush", "clear"},
	{"enable", "activate"},
	{"disable", "deactivate"},
}

var synonyms = func() map[string][]string {
	m := map[string][]string{}
	for _, set := range synonymSets {
		for _, w := range set {
			m[w] = set
		}
	}
	return m
}()

// has reports whether hay contains token, its singular, or a synonym.
func has(hay, token string) bool {
	if strings.Contains(hay, token) {
		return true
	}
	if len(token) > 3 && strings.HasSuffix(token, "s") && strings.Contains(hay, strings.TrimSuffix(token, "s")) {
		return true
	}
	for _, alt := range synonyms[token] {
		if strings.Contains(hay, alt) {
			return true
		}
	}
	return false
}

// searchCatalog returns the operations matching every word of query, best
// first (a word in the name or title outranks one in the summary). When no
// operation has every word, it returns those with the most words and
// partial is true. An exact operation name returns just that operation.
func searchCatalog(ops []catalogOp, query string) (matches []catalogOp, partial bool) {
	tokens := queryTokens(query)
	if len(tokens) == 0 {
		return nil, false
	}
	for _, op := range ops {
		if strings.EqualFold(op.Name, strings.TrimSpace(query)) {
			return []catalogOp{op}, false
		}
	}
	type scored struct {
		op          catalogOp
		hits, score int
	}
	var all []scored
	best := 0
	for _, op := range ops {
		name := strings.ToLower(op.Name + " " + op.Title)
		rest := strings.ToLower(op.Summary + " " + op.Category)
		s := scored{op: op}
		for _, t := range tokens {
			switch {
			case strings.Contains(name, t):
				s.hits++
				s.score += 4
			case has(name, t):
				s.hits++
				s.score += 3
			case has(rest, t):
				s.hits++
				s.score++
			}
		}
		if s.hits > 0 {
			all = append(all, s)
			best = max(best, s.hits)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].score > all[j].score })
	for _, s := range all {
		if s.hits == best {
			matches = append(matches, s.op)
		}
	}
	return matches, len(matches) > 0 && best < len(tokens)
}

func (d *Deps) formatMatches(ctx context.Context, query string, matches []catalogOp, partial bool) string {
	var b strings.Builder
	total := len(matches)
	if partial {
		fmt.Fprintf(&b, "No operation matches every word of %q. Closest (%d):\n", query, total)
	} else {
		fmt.Fprintf(&b, "%s %q:\n", count(total, "operation matches", "operations match"), query)
	}
	if total > listedMatches {
		matches = matches[:listedMatches]
	}
	// The best matches come with their parameters, so the next call can
	// be pressable_execute. A long list keeps to first sentences.
	defs := make([]*gateway.Operation, min(len(matches), inlineSchemas))
	var wg sync.WaitGroup
	for i := range defs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defs[i], _ = d.Describer.Describe(ctx, matches[i].Name)
		}()
	}
	wg.Wait()
	described := 0
	for i, m := range matches {
		var def *gateway.Operation
		if i < len(defs) {
			def = defs[i]
		}
		fmt.Fprintf(&b, "\n%s", m.Name)
		if def != nil {
			fmt.Fprintf(&b, " [%s]", effect(def))
		}
		b.WriteString("\n")
		summary := m.Summary
		if total > inlineSchemas {
			summary = firstSentence(summary, 200)
		}
		if summary != "" {
			fmt.Fprintf(&b, "  %s\n", summary)
		}
		if def != nil {
			described++
			fmt.Fprintf(&b, "  Parameters: %s\n", paramSignature(def.InputSchema))
		}
	}
	if total > listedMatches {
		fmt.Fprintf(&b, "\n… and %d more. Add a word to narrow the search.\n", total-listedMatches)
	}
	switch {
	case described == 0:
		b.WriteString("\nCall pressable_describe for an operation's parameters.\n")
	case total > described:
		fmt.Fprintf(&b, "\n* = required. Parameters are shown for the %d best matches; for another operation call pressable_describe, which also has each parameter's meaning.\n", described)
	default:
		b.WriteString("\n* = required. Run with pressable_execute; pressable_describe has each parameter's meaning.\n")
	}
	return b.String()
}

func effect(op *gateway.Operation) string {
	switch {
	case op.ReadOnly:
		return "read-only"
	case op.Destructive:
		return "destructive"
	}
	return "write"
}

// firstSentence cuts s after its first sentence, or at limit bytes.
func firstSentence(s string, limit int) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i >= 0 {
		s = s[:i+1]
	}
	if len(s) > limit {
		s = strings.ToValidUTF8(s[:limit], "") + "…"
	}
	return s
}

type schemaProp struct {
	Type        any    `json:"type"`
	Description string `json:"description"`
	Enum        []any  `json:"enum"`
}

type inputSchema struct {
	Properties map[string]schemaProp `json:"properties"`
	Required   []string              `json:"required"`
}

// params returns a schema's parameters, required first, then by name.
func (s inputSchema) params() []string {
	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if required[names[i]] != required[names[j]] {
			return required[names[i]]
		}
		return names[i] < names[j]
	})
	return names
}

func (s inputSchema) required(name string) bool {
	for _, r := range s.Required {
		if r == name {
			return true
		}
	}
	return false
}

// typeLabel renders a property's type, or its allowed values.
func (p schemaProp) typeLabel() string {
	if len(p.Enum) > 0 && len(p.Enum) <= 8 {
		vals := make([]string, len(p.Enum))
		for i, v := range p.Enum {
			vals[i] = fmt.Sprint(v)
		}
		return strings.Join(vals, "|")
	}
	switch t := p.Type.(type) {
	case string:
		return t
	case []any:
		vals := make([]string, len(t))
		for i, v := range t {
			vals[i] = fmt.Sprint(v)
		}
		return strings.Join(vals, "|")
	}
	return "any"
}

// takesParam reports whether a schema declares the named parameter. A
// schema that can't be read counts as taking it.
func takesParam(raw json.RawMessage, name string) bool {
	var s inputSchema
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return true
	}
	_, ok := s.Properties[name]
	return ok
}

// paramSignature renders a schema on one line: "site_id* (integer), page (integer)".
func paramSignature(raw json.RawMessage) string {
	var s inputSchema
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil || len(s.Properties) == 0 {
		return "none"
	}
	var parts []string
	for _, n := range s.params() {
		star := ""
		if s.required(n) {
			star = "*"
		}
		parts = append(parts, fmt.Sprintf("%s%s (%s)", n, star, s.Properties[n].typeLabel()))
	}
	return strings.Join(parts, ", ")
}

// paramDetails renders a schema one parameter per line, with descriptions.
func paramDetails(raw json.RawMessage) string {
	var s inputSchema
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil || len(s.Properties) == 0 {
		return ""
	}
	var b strings.Builder
	for _, n := range s.params() {
		p := s.Properties[n]
		label := p.typeLabel()
		if s.required(n) {
			label += ", required"
		}
		fmt.Fprintf(&b, "\n  %s (%s)", n, label)
		if desc := firstSentence(p.Description, 200); desc != "" {
			fmt.Fprintf(&b, ": %s", desc)
		}
	}
	return b.String()
}

func handleDescribe(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, err := req.RequireString("tool_name")
		if err != nil {
			return errResult(err)
		}
		name = strings.TrimSpace(name)
		res, err := d.Gateway.CallTool(ctx, "describe_tool", map[string]any{"tool_name": name})
		if err != nil {
			return errResult(err)
		}
		if res.IsError {
			return d.gatewayError(ctx, name, res), nil
		}
		return res, nil
	}
}

func handleExecute(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, err := req.RequireString("tool_name")
		if err != nil {
			return errResult(err)
		}
		name = strings.TrimSpace(name)
		params := map[string]any{}
		if raw, ok := req.GetArguments()["parameters"]; ok && raw != nil {
			switch v := raw.(type) {
			case map[string]any:
				params = v
			case string:
				// Some clients send nested objects as JSON strings.
				if err := json.Unmarshal([]byte(v), &params); err != nil {
					return errResult(fmt.Errorf("parameters must be an object: %w", err))
				}
			default:
				return errResult(errors.New("parameters must be an object"))
			}
		}
		if err := checkPolicy(ctx, d, name); err != nil {
			return errResult(err)
		}
		if site := strings.TrimSpace(req.GetString("site", "")); site != "" {
			if _, both := params["site_id"]; both {
				return errResult(errors.New("Pass either `site` or parameters.site_id, not both"))
			}
			// Only an operation that takes site_id can use `site`. When
			// its definition can't be read, let Pressable judge the call.
			if op, err := d.Describer.Describe(ctx, name); err == nil && !takesParam(op.InputSchema, "site_id") {
				msg := fmt.Sprintf("Operation %q has no site_id parameter, so `site` can't be used with it. Put the site in the parameter it does take", name)
				if details := paramDetails(op.InputSchema); details != "" {
					msg += ":" + details
				} else {
					msg += " (it takes no parameters)"
				}
				return errResult(errors.New(msg))
			}
			s, err := d.Sites.Resolve(ctx, site)
			if err != nil {
				return errResult(err)
			}
			params["site_id"] = s.ID
		}
		res, err := d.Gateway.CallTool(ctx, "execute_tool", map[string]any{"tool_name": name, "parameters": params})
		if err != nil {
			return errResult(err)
		}
		if res.IsError {
			return d.gatewayError(ctx, name, res), nil
		}
		return res, nil
	}
}

// gatewayNames maps the gateway's own tool names, which its error messages
// mention, to the tools this server exposes.
var gatewayNames = strings.NewReplacer(
	"discover_tools", "pressable_discover",
	"describe_tool", "pressable_describe",
	"execute_tool", "pressable_execute",
)

// gatewayError rewrites a failed describe/execute result so the model can
// act on it in one step: our tool names instead of the gateway's, the
// operation's parameters when the complaint is about parameters, and the
// nearest operation names when the operation doesn't exist.
func (d *Deps) gatewayError(ctx context.Context, operation string, res *mcp.CallToolResult) *mcp.CallToolResult {
	text := gatewayNames.Replace(strings.TrimSpace(gateway.ResultText(res)))
	if text == "" {
		return res
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "unknown tool") || strings.Contains(lower, "unknown operation") || strings.Contains(lower, "not found: "+strings.ToLower(operation)):
		if ops, err := d.operations(ctx); err == nil {
			if near, _ := searchCatalog(ops, strings.NewReplacer("_", " ", "-", " ").Replace(operation)); len(near) > 0 {
				names := make([]string, 0, 8)
				for i, op := range near {
					if i == 8 {
						break
					}
					names = append(names, op.Name)
				}
				text += "\nSimilar operations: " + strings.Join(names, ", ")
			}
		}
	default:
		// The parameter list helps only when the complaint is about a
		// parameter: it says so, or it names one of the operation's own.
		if op, err := d.Describer.Describe(ctx, operation); err == nil && aboutParams(lower, op.InputSchema) {
			if details := paramDetails(op.InputSchema); details != "" {
				text += "\n\nParameters of " + operation + ":" + details
			}
		}
	}
	return mcp.NewToolResultError(text)
}

// aboutParams reports whether a (lowercased) error message is about the
// operation's parameters: it uses the word, or names one of them.
func aboutParams(lower string, raw json.RawMessage) bool {
	if strings.Contains(lower, "parameter") || strings.Contains(lower, "argument") {
		return true
	}
	var s inputSchema
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return false
	}
	words := strings.FieldsFunc(lower, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_'
	})
	for _, w := range words {
		// Short common names (id, name, type) appear in any sentence.
		if _, ok := s.Properties[w]; ok && (strings.Contains(w, "_") || len(w) > 5) {
			return true
		}
	}
	return false
}

// checkPolicy applies the local blocklist and read-only mode. Pressable's
// own permission checks still apply afterwards.
func checkPolicy(ctx context.Context, d *Deps, name string) error {
	for _, b := range d.Cfg.BlockedOperations {
		if strings.EqualFold(b, name) {
			return fmt.Errorf("Operation %q is blocked by local policy (PRESSWRENCH_BLOCKED_OPERATIONS). Do it in the MyPressable dashboard, or remove it from the blocklist with `presswrench install --blocked-operations ...`", name)
		}
	}
	if !d.Cfg.ReadOnly {
		return nil
	}
	op, err := d.Describer.Describe(ctx, name)
	if err != nil {
		return fmt.Errorf("Read-only mode: could not verify that %q is read-only: %s", name, gatewayNames.Replace(auth.Explain(err)))
	}
	if !op.ReadOnly {
		return fmt.Errorf("Operation %q is not read-only and read-only mode is on (PRESSWRENCH_READ_ONLY)", name)
	}
	return nil
}

// passThrough returns a gateway result unchanged, turning transport errors
// into tool errors.
func passThrough(res *mcp.CallToolResult, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return errResult(err)
	}
	return res, nil
}

func jsonText(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(b)), nil
}

// errResult reports err to the model as a tool error, as one actionable
// sentence (see auth.Explain).
func errResult(err error) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(auth.Explain(err)), nil
}
