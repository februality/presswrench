package sites

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type fakeExec struct {
	docs  map[string]string
	calls int
}

func (f *fakeExec) ExecuteJSON(_ context.Context, op string, _ map[string]any, out any) error {
	f.calls++
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
		"acme.net":                  101,
		"globex":                    103,
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
	if f.calls != 1 {
		t.Errorf("list_sites calls = %d, want 1 (cached)", f.calls)
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
		if err == nil || !strings.HasPrefix(err.Error(), "Site not found: "+in) || !strings.Contains(err.Error(), "acme-staging") {
			t.Fatalf("Resolve(%q) err = %v", in, err)
		}
	}
	if _, err := r.Resolve(context.Background(), "/"); err == nil || strings.Contains(err.Error(), "acme") {
		t.Fatalf("empty host matched sites: %v", err)
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

func TestResolve_NotFoundRefetches(t *testing.T) {
	r, f := newResolver(sitesDoc)
	_, err := r.Resolve(context.Background(), "nope")
	if err == nil || !strings.HasPrefix(err.Error(), "Site not found: nope") {
		t.Fatalf("err = %v", err)
	}
	if f.calls != 2 {
		t.Errorf("calls = %d, want 2 (refetch on miss)", f.calls)
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
