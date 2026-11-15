package sites

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExec answers list_sites and list_site_ftp_accounts from canned docs
// and search_sites the way Pressable does: a partial match of one filter
// against the sites in the list_sites doc, at most searchCap per request.
type fakeExec struct {
	mu sync.Mutex // the resolver fans some lookups out
	// domains answers list_site_domains, by site ID.
	domains   map[int64][]string
	docs      map[string]string
	pages     []string // list_sites pages, when paginated
	searchCap int
	calls     int
	ops       []string
}

func (f *fakeExec) ExecuteJSON(_ context.Context, op string, params map[string]any, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.ops = append(f.ops, op)
	switch {
	case op == "list_site_domains":
		id, _ := params["site_id"].(int64)
		var list []map[string]any
		for i, d := range f.domains[id] {
			list = append(list, map[string]any{"id": i, "domain_name": d, "primary": i == 0})
		}
		b, _ := json.Marshal(map[string]any{"site_id": id, "site_name": "x", "domains": list})
		return json.Unmarshal(b, out)
	case op == "list_sites" && f.pages != nil:
		page, _ := params["page"].(int)
		if page < 1 || page > len(f.pages) {
			return json.Unmarshal([]byte(`{"page_out_of_range": true, "sites": []}`), out)
		}
		return json.Unmarshal([]byte(f.pages[page-1]), out)
	case op == "search_sites":
		var doc struct {
			Sites []map[string]any `json:"sites"`
		}
		if err := json.Unmarshal([]byte(f.docs["list_sites"]), &doc); err != nil {
			return err
		}
		var hits []map[string]any
		for _, m := range doc.Sites {
			name, _ := m["name"].(string)
			url, _ := m["url"].(string)
			custom, _ := m["custom_name"].(string)
			if v, ok := params["name"].(string); ok && strings.Contains(name+"\n"+strings.ToLower(custom), strings.ToLower(v)) {
				hits = append(hits, m)
			}
			if v, ok := params["domain"].(string); ok && strings.Contains(url, v) {
				m["domain_url"] = url
				hits = append(hits, m)
			}
		}
		total := len(hits)
		if f.searchCap > 0 && len(hits) > f.searchCap {
			hits = hits[:f.searchCap]
		}
		b, _ := json.Marshal(map[string]any{"sites": hits, "total_matches": total, "returned": len(hits)})
		return json.Unmarshal(b, out)
	}
	return json.Unmarshal([]byte(f.docs[op]), out)
}

const sitesDoc = `{
  "account": {"id": 99, "name": "Agency Inc"},
  "count": 3,
  "sites": [
    {"id": 101, "name": "acme-live", "url": "https://acme.com", "domains": [{"name": "www.acme.com"}, {"name": "acme.net"}],
     "collaborators": [{"id": 5, "name": "bob"}]},
    {"id": 102, "name": "acme-staging", "url": "acme-staging.mystagingwebsite.com"},
    {"id": 103, "name": "globex", "url": "https://globex.example"}
  ]
}`

func newResolver(doc string) (*Resolver, *fakeExec) {
	f := &fakeExec{docs: map[string]string{"list_sites": doc}}
	return NewResolver(f, time.Minute), f
}

func TestExtractSites_PicksSiteArray(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(sitesDoc), &doc)
	got := extractSites(doc)
	if len(got) != 3 {
		t.Fatalf("got %d sites: %+v", len(got), got)
	}
	if got[0].ID != 101 || len(got[0].Domains) != 2 {
		t.Errorf("site 0 = %+v", got[0])
	}
	for _, s := range got {
		if s.ID == 99 || s.ID == 5 {
			t.Errorf("non-site object extracted: %+v", s)
		}
	}
}

func TestExtractSites_BareArray(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`[{"site_id": "7", "site_name": "seven"}]`), &doc)
	got := extractSites(doc)
	if len(got) != 1 || got[0].ID != 7 || got[0].Name != "seven" {
		t.Fatalf("got %+v", got)
	}
}

func TestResolve(t *testing.T) {
	r, f := newResolver(sitesDoc)
	ctx := context.Background()
	cases := map[string]int64{
		"acme-live":                 101,
		"ACME-LIVE":                 101,
		"acme.com":                  101,
		"https://www.acme.com/path": 101,
		"globex":                    103,
		"globex.example":            103,
		"103":                       103,
	}
	for in, want := range cases {
		s, err := r.Resolve(ctx, in)
		if err != nil {
			t.Errorf("Resolve(%q): %v", in, err)
			continue
		}
		if s.ID != want {
			t.Errorf("Resolve(%q) = %d, want %d", in, s.ID, want)
		}
	}
	for _, op := range f.ops {
		if op != "search_sites" {
			t.Errorf("Resolve called %s; it should only search", op)
		}
	}
	before := f.calls
	if _, err := r.Resolve(ctx, "Acme-Live"); err != nil || f.calls != before {
		t.Errorf("repeat resolve: err %v, %d extra calls (want cached)", err, f.calls-before)
	}
}

// A name hits on the first search; a domain asks the domain filter first.
func TestResolve_OneCallOnAHit(t *testing.T) {
	for _, in := range []string{"acme-live", "acme.com"} {
		r, f := newResolver(sitesDoc)
		if _, err := r.Resolve(context.Background(), in); err != nil {
			t.Fatalf("Resolve(%q): %v", in, err)
		}
		if f.calls != 1 {
			t.Errorf("Resolve(%q) made %d gateway calls, want 1", in, f.calls)
		}
	}
}

func TestResolve_DisplayAndCustomName(t *testing.T) {
	r, _ := newResolver(`{"sites": [
	  {"id": 7, "name": "gkdmetal", "display_name": "gkdmetal.com", "custom_name": null},
	  {"id": 8, "name": "gkdmetal-old", "display_name": "GKD Old", "custom_name": "GKD Old"}]}`)
	for in, want := range map[string]int64{"gkdmetal": 7, "gkd old": 8} {
		s, err := r.Resolve(context.Background(), in)
		if err != nil || s.ID != want {
			t.Errorf("Resolve(%q) = %+v, %v; want %d", in, s, err, want)
		}
	}
}

func TestResolve_NumericIDWithoutLookup(t *testing.T) {
	r, f := newResolver(sitesDoc)
	s, err := r.Resolve(context.Background(), "555")
	if err != nil || s.ID != 555 {
		t.Fatalf("got %+v, %v", s, err)
	}
	if f.calls != 0 {
		t.Errorf("numeric ID triggered a lookup")
	}
}

func TestResolve_PartialIsNeverPicked(t *testing.T) {
	r, _ := newResolver(sitesDoc)
	for _, in := range []string{"acme", "staging"} {
		_, err := r.Resolve(context.Background(), in)
		if err == nil || !strings.HasPrefix(err.Error(), "Site not found: "+in) || !strings.Contains(err.Error(), "acme-staging (ID 102, acme-staging.mystagingwebsite.com)") {
			t.Fatalf("Resolve(%q) err = %v", in, err)
		}
	}
	if _, err := r.Resolve(context.Background(), "/"); err == nil || strings.Contains(err.Error(), "acme") {
		t.Fatalf("empty host matched sites: %v", err)
	}
}

// When more sites match partially than one search returns, the exact one
// is still found by walking the full list.
func TestResolve_TruncatedSearchFallsBackToList(t *testing.T) {
	r, f := newResolver(`{"sites": [{"id": 1, "name": "shop-eu"}, {"id": 2, "name": "shop-us"}, {"id": 3, "name": "shop"}]}`)
	f.searchCap = 2
	s, err := r.Resolve(context.Background(), "shop")
	if err != nil || s.ID != 3 {
		t.Fatalf("got %+v, %v", s, err)
	}
}

func TestResolve_NotFound(t *testing.T) {
	r, _ := newResolver(sitesDoc)
	_, err := r.Resolve(context.Background(), "nope")
	if err == nil || !strings.HasPrefix(err.Error(), "Site not found: nope") || !strings.Contains(err.Error(), "pressable_sites") {
		t.Fatalf("err = %v", err)
	}
}

func TestList_WalksEveryPage(t *testing.T) {
	f := &fakeExec{pages: []string{
		`{"current_page": 1, "next_page": 2, "last_page": 3, "sites": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]}`,
		`{"current_page": 2, "next_page": 3, "last_page": 3, "sites": [{"id": 3, "name": "c", "staging": true}]}`,
		`{"current_page": 3, "next_page": null, "last_page": 3, "sites": [{"id": 4, "name": "d", "display_name": "d.com"}]}`,
	}}
	r := NewResolver(f, time.Minute)
	list, err := r.List(context.Background())
	if err != nil || len(list) != 4 {
		t.Fatalf("got %d sites, %v", len(list), err)
	}
	if f.calls != 3 {
		t.Errorf("calls = %d, want 3", f.calls)
	}
	if list[2].Env != "staging" || list[3].Host() != "d.com" {
		t.Errorf("fields: %+v %+v", list[2], list[3])
	}
	if _, err := r.List(context.Background()); err != nil || f.calls != 3 {
		t.Errorf("second List: %v, calls %d (want cached)", err, f.calls)
	}
	// A numeric ID seen in a listing carries its name.
	if s, _ := r.Resolve(context.Background(), "4"); s.Name != "d" {
		t.Errorf("Resolve(4) = %+v", s)
	}
}

func TestSearch(t *testing.T) {
	r, _ := newResolver(sitesDoc)
	list, _, err := r.Search(context.Background(), "acme")
	if err != nil || len(list) != 2 {
		t.Fatalf("Search(acme) = %+v, %v", list, err)
	}
	if list, _, _ = r.Search(context.Background(), ""); len(list) != 3 {
		t.Fatalf("Search(\"\") = %+v", list)
	}
}

func TestExtractSites_SingleSiteWithDomainObjects(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`{"sites":[{"id":1,"name":"only","domains":[{"id":10,"name":"a.com"},{"id":11,"name":"b.com"}]}]}`), &doc)
	got := extractSites(doc)
	if len(got) != 1 || got[0].ID != 1 || len(got[0].Domains) != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestFTPAccountsAndCandidates(t *testing.T) {
	f := &fakeExec{docs: map[string]string{"list_site_ftp_accounts": `{
	  "site": {"id": 101, "name": "acme-live"},
	  "ftp_accounts": [
	    {"username": "owner1", "owner": true, "ssh_key_label": null},
	    {"username": "kbob", "ssh_key_label": "presswrench", "email": "bob@x.com"},
	    {"username": "kjane", "ssh_key_label": "presswrench", "email": "jane@x.com"},
	    {"username": "klaptop", "ssh_key_label": "laptop", "email": "jane@x.com"}
	  ]}`}}
	accts, err := FTPAccounts(context.Background(), f, 101)
	if err != nil {
		t.Fatal(err)
	}
	if len(accts) != 4 {
		t.Fatalf("accounts = %+v", accts)
	}
	got := KeyCandidates(accts, "presswrench", "jane@x.com")
	want := "kjane,kbob,klaptop"
	if strings.Join(got, ",") != want {
		t.Errorf("candidates = %v, want %s", got, want)
	}
	if c := KeyCandidates(accts[:1], "presswrench", ""); len(c) != 0 {
		t.Errorf("password-only login offered as candidate: %v", c)
	}
}

// search_sites only knows primary domains. A staging URL or an alias is
// found by guessing the site and confirming with its domain list.
func TestResolve_AttachedDomain(t *testing.T) {
	doc := `{"sites": [
	  {"id": 1, "name": "gkdmetalcom", "url": "gkdmetal.com"},
	  {"id": 2, "name": "gkdmetal-old", "url": "old.example.org"},
	  {"id": 3, "name": "shop", "url": "shop.example.com"}]}`
	domains := map[int64][]string{
		1: {"gkdmetal.com", "www.gkdmetal.com", "gkdmetalcom.mystagingwebsite.com", "gkdmetal.net"},
		2: {"old.example.org", "gkdmetal-old.mystagingwebsite.com"},
		3: {"shop.example.com", "store.example.com"},
	}
	cases := map[string]int64{
		"gkdmetalcom.mystagingwebsite.com":           1, // staging URL: first label is the site name
		"https://gkdmetal-old.mystagingwebsite.com/": 2,
		"gkdmetal.net": 1, // alias: a site named like its first label
	}
	for in, want := range cases {
		r, f := newResolver(doc)
		f.domains = domains
		s, err := r.Resolve(context.Background(), in)
		if err != nil || s.ID != want {
			t.Errorf("Resolve(%q) = %+v, %v; want %d", in, s, err, want)
			continue
		}
		before := f.calls
		if _, err := r.Resolve(context.Background(), in); err != nil || f.calls != before {
			t.Errorf("Resolve(%q) again: %v, %d more calls (want cached)", in, err, f.calls-before)
		}
	}

	// A host no candidate carries is still not found, and nothing is guessed.
	r, f := newResolver(doc)
	f.domains = domains
	if _, err := r.Resolve(context.Background(), "gkdmetal.org"); err == nil || !strings.HasPrefix(err.Error(), "Site not found: gkdmetal.org") {
		t.Errorf("unattached domain: %v", err)
	}
	listed := 0
	for _, op := range f.ops {
		if op == "list_site_domains" {
			listed++
		}
	}
	if listed == 0 || listed > maxDomainCandidates {
		t.Errorf("asked %d sites for their domains, want 1..%d", listed, maxDomainCandidates)
	}

	// A plain name never triggers the domain lookups.
	r, f = newResolver(doc)
	f.domains = domains
	_, _ = r.Resolve(context.Background(), "nope")
	for _, op := range f.ops {
		if op == "list_site_domains" {
			t.Error("a name without a dot looked up domains")
		}
	}
}

// The full listing fills in the primary domain of sites list_sites gives
// none for, once per loaded list.
func TestSearch_FullListFillsMissingHosts(t *testing.T) {
	f := &fakeExec{
		pages: []string{`{"sites": [
		  {"id": 1, "name": "acme", "display_name": "acme.com"},
		  {"id": 2, "name": "partners", "display_name": "Partners portal"},
		  {"id": 3, "name": "partners-staging", "display_name": "Partners (staging)"}]}`},
		// search_sites answers from this doc, with domains.
		docs: map[string]string{"list_sites": `{"sites": [
		  {"id": 2, "name": "partners", "url": "partners.example.com"},
		  {"id": 3, "name": "partners-staging", "url": "partners-staging.mystagingwebsite.com"}]}`},
	}
	r := NewResolver(f, time.Minute)
	list, _, err := r.Search(context.Background(), "")
	if err != nil || len(list) != 3 {
		t.Fatalf("got %+v, %v", list, err)
	}
	hosts := map[int64]string{}
	for _, s := range list {
		hosts[s.ID] = s.Host()
	}
	if hosts[1] != "acme.com" || hosts[2] != "partners.example.com" || hosts[3] != "partners-staging.mystagingwebsite.com" {
		t.Errorf("hosts = %v", hosts)
	}
	if f.calls != 3 { // one page, two lookups: the site with a host isn't asked for
		t.Errorf("calls = %d (%v), want 3", f.calls, f.ops)
	}
	if _, _, err = r.Search(context.Background(), ""); err != nil || f.calls != 3 {
		t.Errorf("second listing: %v, calls %d (want cached)", err, f.calls)
	}
}
