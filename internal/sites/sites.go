// Package sites turns what the user typed ("example.com", "my-site",
// "1383590") into a Pressable site ID, and finds the SFTP/SSH logins on a
// site that belong to an SSH key — all via the Pressable MCP gateway, so
// only sites the signed-in user can access are ever visible.
//
// Gateway results are JSON text whose exact envelope isn't a published
// contract, so parsing is deliberately tolerant: it walks the document for
// objects with the fields we need rather than binding to one shape.
package sites

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Executor runs a gateway operation and decodes its JSON result.
// Implemented by *gateway.Client.
type Executor interface {
	ExecuteJSON(ctx context.Context, operation string, params map[string]any, out any) error
}

// Site is the subset of a Pressable site we use for resolution and listing.
type Site struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	CustomName  string   `json:"customName,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	URL         string   `json:"url,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	State       string   `json:"state,omitempty"`
	// Env is "production", "staging", "sandbox", … (empty when unknown).
	Env string `json:"env,omitempty"`
}

// Host is the site's primary host for display: its URL host, else its
// display name when that looks like a host, else its first domain.
func (s Site) Host() string {
	if h := normalizeHost(s.URL); h != "" {
		return h
	}
	if strings.Contains(s.DisplayName, ".") && !strings.ContainsAny(s.DisplayName, " \t") {
		return strings.ToLower(s.DisplayName)
	}
	if len(s.Domains) > 0 {
		return normalizeHost(s.Domains[0])
	}
	return ""
}

// FTPAccount is one SFTP/SSH login on a site.
type FTPAccount struct {
	Username    string `json:"username"`
	SSHKeyLabel string `json:"sshKeyLabel,omitempty"`
	Owner       bool   `json:"owner"`
	Email       string `json:"email,omitempty"`
}

// listPageSize is the gateway's maximum per_page for list_sites.
const listPageSize = 50

// maxListPages bounds the walk through list_sites (10,000 sites).
const maxListPages = 200

type resolvedSite struct {
	site Site
	at   time.Time
}

// Resolver finds sites through the gateway. list_sites is always paginated
// and carries no domains, so names and domains are resolved with
// search_sites (a server-side partial match on either) and an exact match
// here; the full list is only walked for List and as a fallback. Resolved
// inputs and the full list are cached for ttl.
type Resolver struct {
	exec Executor
	ttl  time.Duration
	now  func() time.Time

	mu       sync.Mutex
	sites    []Site
	loadedAt time.Time
	// hostsFilled: fillHosts has run for the loaded list.
	hostsFilled bool
	resolved    map[string]resolvedSite // lowercased input -> site
	byID        map[int64]Site          // every site seen, to name numeric IDs
}

func NewResolver(exec Executor, ttl time.Duration) *Resolver {
	return &Resolver{exec: exec, ttl: ttl, now: time.Now, resolved: map[string]resolvedSite{}, byID: map[int64]Site{}}
}

// List returns every site the user can access (cached), walking all pages
// of list_sites.
func (r *Resolver) List(ctx context.Context) ([]Site, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listLocked(ctx)
}

func (r *Resolver) listLocked(ctx context.Context) ([]Site, error) {
	if r.sites != nil && r.now().Sub(r.loadedAt) < r.ttl {
		return r.sites, nil
	}
	all := []Site{}
	seen := map[int64]bool{}
	for page := 1; page <= maxListPages; page++ {
		var doc any
		if err := r.exec.ExecuteJSON(ctx, "list_sites", map[string]any{"page": page, "per_page": listPageSize}, &doc); err != nil {
			return nil, err
		}
		added := 0
		for _, s := range extractSites(doc) {
			if !seen[s.ID] {
				seen[s.ID] = true
				all = append(all, s)
				added++
			}
		}
		if added == 0 || !hasNextPage(doc, page) {
			break
		}
	}
	r.remember(all)
	r.sites = all
	r.hostsFilled = false
	r.loadedAt = r.now()
	return all, nil
}

// hasNextPage reads the pagination fields of a list_sites result. An
// envelope without them is taken as unpaginated.
func hasNextPage(doc any, page int) bool {
	m, ok := doc.(map[string]any)
	if !ok {
		return false
	}
	if out, _ := m["page_out_of_range"].(bool); out {
		return false
	}
	if next, ok := num(m["next_page"]); ok {
		return next > int64(page)
	}
	if last, ok := num(m["last_page"]); ok {
		return last > int64(page)
	}
	return false
}

func (r *Resolver) remember(list []Site) {
	for _, s := range list {
		r.byID[s.ID] = s
	}
}

// searchBy runs search_sites with one filter ("name" or "domain", both
// partial matches on Pressable's side). truncated reports that more sites
// matched than were returned.
func (r *Resolver) searchBy(ctx context.Context, field, value string) (list []Site, truncated bool, err error) {
	list, truncated, err = r.search(ctx, field, value)
	r.remember(list)
	return list, truncated, err
}

// search is searchBy without touching the resolver's state, so several can
// run at once.
func (r *Resolver) search(ctx context.Context, field, value string) (list []Site, truncated bool, err error) {
	var doc any
	if err := r.exec.ExecuteJSON(ctx, "search_sites", map[string]any{field: value}, &doc); err != nil {
		return nil, false, err
	}
	list = extractSites(doc)
	if m, ok := doc.(map[string]any); ok {
		if total, ok := num(m["total_matches"]); ok && total > int64(len(list)) {
			truncated = true
		}
	}
	return list, truncated, nil
}

// lookups bounds how many gateway calls a fan-out runs at once.
const lookups = 6

// each runs fn(0..n-1) with at most `lookups` at a time and waits.
func each(n int, fn func(i int)) {
	sem := make(chan struct{}, lookups)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			fn(i)
		}()
	}
	wg.Wait()
}

// maxHostLookups bounds how many sites fillHosts looks up.
const maxHostLookups = 30

// fillHosts gives the listed sites that have no known host their primary
// domain. list_sites carries none; a site whose display name is a custom
// label instead of its domain would otherwise be listed without one.
// search_sites does return it, one name at a time, so only the sites that
// need it are asked for, a bounded number, and once per loaded list.
func (r *Resolver) fillHosts(ctx context.Context) {
	if r.hostsFilled {
		return
	}
	r.hostsFilled = true
	var missing []int
	for i, s := range r.sites {
		if s.Host() == "" && s.Name != "" && len(missing) < maxHostLookups {
			missing = append(missing, i)
		}
	}
	urls := make([]string, len(missing))
	each(len(missing), func(k int) {
		site := r.sites[missing[k]]
		found, _, err := r.search(ctx, "name", site.Name)
		if err != nil {
			return
		}
		for _, f := range found {
			if f.ID == site.ID {
				urls[k] = f.URL
			}
		}
	})
	for k, i := range missing {
		if urls[k] != "" {
			r.sites[i].URL = urls[k]
			r.byID[r.sites[i].ID] = r.sites[i]
		}
	}
}

// Search returns the sites whose name or domain contains query, as matched
// by Pressable (at most 50 per field); truncated reports that there were
// more. An empty query lists every site.
func (r *Resolver) Search(ctx context.Context, query string) (list []Site, truncated bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := strings.TrimSpace(query)
	if q == "" {
		if list, err = r.listLocked(ctx); err != nil {
			return nil, false, err
		}
		r.fillHosts(ctx)
		return r.sites, false, nil
	}
	byName, t1, err := r.searchBy(ctx, "name", q)
	if err != nil {
		return nil, false, err
	}
	list = byName
	if host := normalizeHost(q); host != "" {
		byDomain, t2, err := r.searchBy(ctx, "domain", host)
		if err != nil {
			return nil, false, err
		}
		list, truncated = merge(list, byDomain), t2
	}
	return list, truncated || t1, nil
}

func merge(a, b []Site) []Site {
	seen := make(map[int64]bool, len(a))
	out := make([]Site, 0, len(a)+len(b))
	for _, s := range append(append([]Site{}, a...), b...) {
		if !seen[s.ID] {
			seen[s.ID] = true
			out = append(out, s)
		}
	}
	return out
}

// Resolve maps a site ID, name, or domain to a site. A purely numeric input
// is taken as an ID without a lookup — Pressable rejects IDs the user can't
// access when they're used.
func (r *Resolver) Resolve(ctx context.Context, input string) (*Site, error) {
	in := strings.TrimSpace(input)
	if in == "" {
		return nil, fmt.Errorf("site is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, err := strconv.ParseInt(in, 10, 64); err == nil {
		if s, ok := r.byID[id]; ok {
			return &s, nil
		}
		return &Site{ID: id}, nil
	}

	key := strings.ToLower(in)
	if c, ok := r.resolved[key]; ok && r.now().Sub(c.at) < r.ttl {
		s := c.site
		return &s, nil
	}

	// Ask for the likelier field first: one gateway call on a hit.
	host := normalizeHost(in)
	fields := []string{"name", "domain"}
	if strings.Contains(in, ".") || strings.Contains(in, "/") {
		fields = []string{"domain", "name"}
	}
	var pool []Site
	truncated := false
	found := func() (*Site, error) {
		site, err := match(pool, in)
		if err == nil {
			r.resolved[key] = resolvedSite{site: *site, at: r.now()}
		}
		return site, err
	}
	for _, field := range fields {
		value := in
		if field == "domain" {
			if value = host; value == "" {
				continue
			}
		}
		list, trunc, err := r.searchBy(ctx, field, value)
		if err != nil {
			return nil, err
		}
		truncated = truncated || trunc
		pool = merge(pool, list)
		if site, err := found(); err != errNotFound {
			return site, err
		}
	}
	if truncated {
		// More than a page of partial matches hid the exact one.
		list, err := r.listLocked(ctx)
		if err != nil {
			return nil, err
		}
		pool = merge(pool, list)
		if site, err := found(); err != errNotFound {
			return site, err
		}
	}
	if strings.Contains(host, ".") {
		// Not a name or a primary domain: maybe another domain of a site.
		site, err := r.byAttachedDomain(ctx, host, pool)
		if err == nil {
			r.resolved[key] = resolvedSite{site: *site, at: r.now()}
		}
		if err != errNotFound {
			return site, err
		}
	}
	if sug := suggestions(pool, in); len(sug) > 0 {
		return nil, fmt.Errorf("Site not found: %s. Did you mean one of these (use the exact name, domain or ID):%s", in, siteLines(sug))
	}
	if strings.Contains(host, ".") {
		return nil, fmt.Errorf("Site not found: %s. No site you can access has that as its primary domain, and none of the likely ones has it attached. Find the site with pressable_sites and use its name or ID", in)
	}
	return nil, fmt.Errorf("Site not found: %s. Use pressable_sites to list the sites you can access", in)
}

// maxDomainCandidates bounds how many sites byAttachedDomain asks for
// their domains (one gateway call each).
const maxDomainCandidates = 6

// byAttachedDomain resolves a host that is attached to a site without
// being its primary domain: the staging URL, or an alias. search_sites
// only knows primary domains (verified 2026-11-14) and nothing searches
// domains account-wide, so this guesses likely sites — the partial matches
// so far, sites named like the host's first label or like the host without
// its dots (Pressable's default naming: "acme.com" is "acmecom"), and sites
// whose primary domain is a parent of the host — and confirms a guess with
// list_site_domains. Only an exact domain match counts.
func (r *Resolver) byAttachedDomain(ctx context.Context, host string, pool []Site) (*Site, error) {
	labels := strings.Split(host, ".")
	// The guesses are independent gateway calls: run them together, and
	// keep their order (likeliest first) when merging.
	type query struct{ field, value string }
	queries := []query{{"name", labels[0]}, {"name", strings.Join(labels, "")}}
	for i := 1; i < len(labels)-1; i++ {
		queries = append(queries, query{"domain", strings.Join(labels[i:], ".")})
	}
	found := make([][]Site, len(queries))
	each(len(queries), func(i int) {
		// Best effort: a search that fails just contributes no guesses.
		found[i], _, _ = r.search(ctx, queries[i].field, queries[i].value)
	})
	candidates := suggestions(pool, host)
	for _, list := range found {
		candidates = merge(candidates, list)
	}
	if len(candidates) > maxDomainCandidates {
		candidates = candidates[:maxDomainCandidates]
	}
	domains := make([][]string, len(candidates))
	each(len(candidates), func(i int) {
		var doc any
		if err := r.exec.ExecuteJSON(ctx, "list_site_domains", map[string]any{"site_id": candidates[i].ID}, &doc); err == nil {
			domains[i] = extractDomains(doc)
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var hits []Site
	for i, c := range candidates {
		for _, d := range domains[i] {
			if normalizeHost(d) == host {
				c.Domains = domains[i]
				hits = append(hits, c)
				break
			}
		}
	}
	switch len(hits) {
	case 0:
		return nil, errNotFound
	case 1:
		r.remember(hits)
		return &hits[0], nil
	}
	return nil, ambiguous(host, hits)
}

// extractDomains reads the domain names out of a list_site_domains result.
func extractDomains(doc any) []string {
	name := func(m map[string]any) string {
		if n := str(m["domain_name"]); n != "" {
			return n
		}
		return str(m["name"])
	}
	var out []string
	for _, m := range preferredArray(doc, []string{"domains", "data", "results", "items"}, func(m map[string]any) bool { return name(m) != "" }) {
		out = append(out, name(m))
	}
	return out
}

type notFound struct{}

func (notFound) Error() string { return "not found" }

var errNotFound error = notFound{}

func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimPrefix(s, "www.")
}

// aliases returns everything a site answers to exactly: its names
// (lowercased) and its hosts (normalized).
func aliases(s Site) (names, hosts []string) {
	for _, n := range []string{s.Name, s.CustomName, s.DisplayName} {
		if n != "" {
			names = append(names, strings.ToLower(n))
		}
	}
	for _, h := range append([]string{s.URL, s.DisplayName}, s.Domains...) {
		if h = normalizeHost(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return names, hosts
}

// match accepts exact matches only (name, custom name, URL host, or any
// domain). Tools that write or execute must never guess, so near-misses
// come back as a "did you mean" error instead of being picked.
func match(list []Site, in string) (*Site, error) {
	lower := strings.ToLower(in)
	host := normalizeHost(in)
	var exact []Site
	for _, s := range list {
		names, hosts := aliases(s)
		if contains(names, lower) || (host != "" && contains(hosts, host)) {
			exact = append(exact, s)
		}
	}
	if len(exact) == 1 {
		return &exact[0], nil
	}
	if len(exact) > 1 {
		return nil, ambiguous(in, exact)
	}
	return nil, errNotFound
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// suggestions lists sites with a name or host containing the input.
func suggestions(list []Site, in string) []Site {
	lower := strings.ToLower(in)
	host := normalizeHost(in)
	if lower == "" || host == "" {
		return nil
	}
	var out []Site
	for _, s := range list {
		names, hosts := aliases(s)
		hit := false
		for _, n := range names {
			hit = hit || strings.Contains(n, lower)
		}
		for _, h := range hosts {
			hit = hit || strings.Contains(h, host)
		}
		if hit {
			out = append(out, s)
		}
	}
	return out
}

func ambiguous(in string, list []Site) error {
	return fmt.Errorf("Multiple sites match %q — use one of these names or IDs:%s", in, siteLines(list))
}

// siteLines renders up to 10 sites as "\n  - name (ID n, host)" lines.
func siteLines(list []Site) string {
	list = append([]Site{}, list...)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	var b strings.Builder
	for i, s := range list {
		if i == 10 {
			fmt.Fprintf(&b, "\n  … and %d more", len(list)-10)
			break
		}
		fmt.Fprintf(&b, "\n  - %s (ID %d", s.Name, s.ID)
		if h := s.Host(); h != "" {
			fmt.Fprintf(&b, ", %s", h)
		}
		b.WriteString(")")
	}
	return b.String()
}

// FTPAccounts lists the SFTP/SSH logins on a site.
func FTPAccounts(ctx context.Context, exec Executor, siteID int64) ([]FTPAccount, error) {
	var doc any
	if err := exec.ExecuteJSON(ctx, "list_site_ftp_accounts", map[string]any{"site_id": siteID}, &doc); err != nil {
		return nil, err
	}
	return extractFTPAccounts(doc), nil
}

// KeyCandidates orders the logins worth trying with our SSH key: those
// carrying our key label first (several collaborators may each have used
// the same label), then any other key-backed login. Password-only logins
// can never accept a key and are dropped. Within a group, a login whose
// email matches the signed-in user sorts first.
func KeyCandidates(accounts []FTPAccount, label, email string) []string {
	var mine, others []FTPAccount
	for _, a := range accounts {
		switch a.SSHKeyLabel {
		case "":
			continue
		case label:
			mine = append(mine, a)
		default:
			others = append(others, a)
		}
	}
	byEmail := func(list []FTPAccount) {
		if email == "" {
			return
		}
		sort.SliceStable(list, func(i, j int) bool {
			return strings.EqualFold(list[i].Email, email) && !strings.EqualFold(list[j].Email, email)
		})
	}
	byEmail(mine)
	byEmail(others)
	out := make([]string, 0, len(mine)+len(others))
	for _, a := range append(mine, others...) {
		out = append(out, a.Username)
	}
	return out
}

// ---- tolerant extraction ----

// recordArray finds the array in doc whose elements best look like records
// (objects for which isRecord is true) and returns those elements. Picking a
// whole array — rather than every matching object anywhere — keeps nested
// objects (an "account" block, a site's collaborators) from being mistaken
// for records.
func recordArray(doc any, isRecord func(map[string]any) bool) []map[string]any {
	var best []map[string]any
	var visit func(any)
	visit = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				visit(v[k])
			}
		case []any:
			var recs []map[string]any
			for _, e := range v {
				if m, ok := e.(map[string]any); ok && isRecord(m) {
					recs = append(recs, m)
				}
			}
			if len(recs) > len(best) {
				best = recs
			}
			for _, e := range v {
				visit(e)
			}
		}
	}
	visit(doc)
	return best
}

func siteID(m map[string]any) (int64, bool) {
	if id, ok := num(m["id"]); ok {
		return id, true
	}
	return num(m["site_id"])
}

// preferredArray returns the records under a conventional top-level key
// ("sites", "data", …) when present, so the site list wins over any
// incidental array elsewhere in the document (a site's domain objects also
// carry id and name).
func preferredArray(doc any, keys []string, isRecord func(map[string]any) bool) []map[string]any {
	var arr []any
	switch v := doc.(type) {
	case []any:
		arr = v
	case map[string]any:
		for _, k := range keys {
			if a, ok := v[k].([]any); ok {
				arr = a
				break
			}
		}
	}
	var recs []map[string]any
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok && isRecord(m) {
			recs = append(recs, m)
		}
	}
	if len(recs) > 0 {
		return recs
	}
	return recordArray(doc, isRecord)
}

func extractSites(doc any) []Site {
	isSite := func(m map[string]any) bool {
		_, ok := siteID(m)
		return ok && (str(m["name"]) != "" || str(m["site_name"]) != "" || str(m["url"]) != "")
	}
	var out []Site
	for _, m := range preferredArray(doc, []string{"sites", "data", "results", "items"}, isSite) {
		id, _ := siteID(m)
		name := str(m["name"])
		if name == "" {
			name = str(m["site_name"])
		}
		s := Site{ID: id, Name: name, URL: str(m["url"]), CustomName: str(m["custom_name"]),
			DisplayName: str(m["display_name"]), State: str(m["state"]), Env: str(m["wp_environment_type"])}
		if s.URL == "" {
			s.URL = str(m["domain_url"])
		}
		if sandbox, _ := m["sandbox"].(bool); sandbox {
			s.Env = "sandbox"
		} else if staging, _ := m["staging"].(bool); staging {
			s.Env = "staging"
		}
		for _, k := range []string{"domains", "domain_names"} {
			if arr, ok := m[k].([]any); ok {
				for _, d := range arr {
					switch v := d.(type) {
					case string:
						s.Domains = append(s.Domains, v)
					case map[string]any:
						if n := str(v["name"]); n != "" {
							s.Domains = append(s.Domains, n)
						} else if n := str(v["domain"]); n != "" {
							s.Domains = append(s.Domains, n)
						}
					}
				}
			}
		}
		for _, k := range []string{"primary_domain", "primaryDomain", "domain"} {
			if d := str(m[k]); d != "" {
				s.Domains = append(s.Domains, d)
			}
		}
		out = append(out, s)
	}
	return out
}

func extractFTPAccounts(doc any) []FTPAccount {
	isAccount := func(m map[string]any) bool { return str(m["username"]) != "" }
	var out []FTPAccount
	for _, m := range preferredArray(doc, []string{"ftp_accounts", "accounts", "data", "results", "items"}, isAccount) {
		label := str(m["ssh_key_label"])
		if label == "" {
			label = str(m["sshKeyLabel"])
		}
		owner, _ := m["owner"].(bool)
		out = append(out, FTPAccount{Username: str(m["username"]), SSHKeyLabel: label, Owner: owner, Email: str(m["email"])})
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), n == float64(int64(n)) && n > 0
	case json.Number:
		i, err := n.Int64()
		return i, err == nil && i > 0
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil && i > 0
	}
	return 0, false
}
