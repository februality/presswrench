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

// Site is the subset of a Pressable site we use for resolution.
type Site struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

// FTPAccount is one SFTP/SSH login on a site.
type FTPAccount struct {
	Username    string `json:"username"`
	SSHKeyLabel string `json:"sshKeyLabel,omitempty"`
	Owner       bool   `json:"owner"`
	Email       string `json:"email,omitempty"`
}

// Resolver caches the site list for ttl.
type Resolver struct {
	exec Executor
	ttl  time.Duration
	now  func() time.Time

	mu       sync.Mutex
	sites    []Site
	loadedAt time.Time
}

func NewResolver(exec Executor, ttl time.Duration) *Resolver {
	return &Resolver{exec: exec, ttl: ttl, now: time.Now}
}

// List returns every site the user can access (cached).
func (r *Resolver) List(ctx context.Context) ([]Site, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listLocked(ctx, false)
}

func (r *Resolver) listLocked(ctx context.Context, force bool) ([]Site, error) {
	if !force && r.sites != nil && r.now().Sub(r.loadedAt) < r.ttl {
		return r.sites, nil
	}
	var doc any
	if err := r.exec.ExecuteJSON(ctx, "list_sites", nil, &doc); err != nil {
		return nil, err
	}
	r.sites = extractSites(doc)
	r.loadedAt = r.now()
	return r.sites, nil
}

// Resolve maps a site ID, name, or domain to a site. A purely numeric input
// is taken as an ID without a lookup — Pressable rejects IDs the user can't
// access when they're used.
func (r *Resolver) Resolve(ctx context.Context, input string) (*Site, error) {
	in := strings.TrimSpace(input)
	if in == "" {
		return nil, fmt.Errorf("site is required")
	}
	if id, err := strconv.ParseInt(in, 10, 64); err == nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, s := range r.sites {
			if s.ID == id {
				s := s
				return &s, nil
			}
		}
		return &Site{ID: id}, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	list, err := r.listLocked(ctx, false)
	if err != nil {
		return nil, err
	}
	site, err := match(list, in)
	if err == errNotFound {
		// The cache may predate a newly created site: refetch once.
		if list, err = r.listLocked(ctx, true); err != nil {
			return nil, err
		}
		site, err = match(list, in)
	}
	if err == errNotFound {
		if sug := suggestions(list, in); len(sug) > 0 {
			return nil, fmt.Errorf("Site not found: %s. Did you mean one of these (use the exact name or ID):%s", in, siteLines(sug))
		}
		return nil, fmt.Errorf("Site not found: %s", in)
	}
	return site, err
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

// match accepts exact matches only (name, URL host, or any domain). Tools
// that write or execute must never guess, so near-misses come back as a
// "did you mean" error instead of being picked.
func match(list []Site, in string) (*Site, error) {
	lower := strings.ToLower(in)
	host := normalizeHost(in)
	var exact []Site
	for _, s := range list {
		if strings.ToLower(s.Name) == lower || (host != "" && s.URL != "" && normalizeHost(s.URL) == host) {
			exact = append(exact, s)
			continue
		}
		for _, d := range s.Domains {
			if host != "" && normalizeHost(d) == host {
				exact = append(exact, s)
				break
			}
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

// suggestions lists sites whose name or host contains the input.
func suggestions(list []Site, in string) []Site {
	lower := strings.ToLower(in)
	host := normalizeHost(in)
	if lower == "" || host == "" {
		return nil
	}
	var out []Site
	for _, s := range list {
		if strings.Contains(strings.ToLower(s.Name), lower) || strings.Contains(normalizeHost(s.URL), host) {
			out = append(out, s)
		}
	}
	return out
}

func ambiguous(in string, list []Site) error {
	return fmt.Errorf("Multiple sites match %q — use one of these names or IDs:%s", in, siteLines(list))
}

// siteLines renders up to 10 sites as "\n  - name (ID n, url)" lines.
func siteLines(list []Site) string {
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	var b strings.Builder
	for i, s := range list {
		if i == 10 {
			fmt.Fprintf(&b, "\n  … and %d more", len(list)-10)
			break
		}
		fmt.Fprintf(&b, "\n  - %s (ID %d, %s)", s.Name, s.ID, s.URL)
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
		s := Site{ID: id, Name: name, URL: str(m["url"])}
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
