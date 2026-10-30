package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/februality/presswrench/internal/creds"
)

// fakeAS is a minimal OAuth authorization server: dynamic registration,
// an authorize endpoint that immediately redirects back with a code, and a
// token endpoint that checks PKCE and supports refresh.
type fakeAS struct {
	t  *testing.T
	mu sync.Mutex

	clients    map[string]bool
	challenges map[string]string // code -> challenge
	refresh    map[string]bool   // valid refresh tokens
	rotate     bool              // issue a new refresh token on refresh
	issued     int
	refreshes  int
}

func newFakeAS(t *testing.T) (*fakeAS, *httptest.Server) {
	f := &fakeAS{t: t, clients: map[string]bool{}, challenges: map[string]string{}, refresh: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/register", f.register)
	mux.HandleFunc("/auth/authorize", f.authorize)
	mux.HandleFunc("/auth/token", f.token)
	mux.HandleFunc("/auth/revoke", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAS) register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RedirectURIs []string `json:"redirect_uris"`
		Auth         string   `json:"token_endpoint_auth_method"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if len(body.RedirectURIs) != len(RedirectPorts) || body.Auth != "none" {
		http.Error(w, "bad registration", 400)
		return
	}
	f.mu.Lock()
	id := "client-" + strconv.Itoa(len(f.clients)+1)
	f.clients[id] = true
	f.mu.Unlock()
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(map[string]string{"client_id": id})
}

func (f *fakeAS) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	known := f.clients[q.Get("client_id")]
	f.mu.Unlock()
	redirect := q.Get("redirect_uri")
	if !known {
		http.Redirect(w, r, redirect+"?error=invalid_client&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("scope") != Scope {
		http.Error(w, "bad authorize request", 400)
		return
	}
	code := "code-" + q.Get("state")
	f.mu.Lock()
	f.challenges[code] = q.Get("code_challenge")
	f.mu.Unlock()
	http.Redirect(w, r, redirect+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
}

func (f *fakeAS) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(code string) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	if !f.clients[r.Form.Get("client_id")] {
		fail("invalid_client")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		ch, ok := f.challenges[r.Form.Get("code")]
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != ch {
			fail("invalid_grant")
			return
		}
		delete(f.challenges, r.Form.Get("code"))
	case "refresh_token":
		rt := r.Form.Get("refresh_token")
		if !f.refresh[rt] {
			fail("invalid_grant")
			return
		}
		f.refreshes++
		if f.rotate {
			delete(f.refresh, rt)
		} else {
			f.issued++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-" + strconv.Itoa(f.issued), "expires_in": 3600, "scope": Scope,
			})
			return
		}
	default:
		fail("unsupported_grant_type")
		return
	}
	f.issued++
	rt := "refresh-" + strconv.Itoa(f.issued)
	f.refresh[rt] = true
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "access-" + strconv.Itoa(f.issued), "refresh_token": rt,
		"expires_in": 3600, "scope": Scope, "name": "Jane Doe", "email": "jane@example.com",
	})
}

// browserFollow plays the browser: GET the authorize URL and follow the
// redirect to the loopback callback.
func browserFollow(u string) error {
	go func() {
		resp, err := http.Get(u)
		if err == nil {
			resp.Body.Close()
		}
	}()
	return nil
}

func newStore(t *testing.T) *creds.FileStore {
	dir := t.TempDir()
	lockDir = func() (string, error) { return dir, nil }
	return creds.NewFileStore(filepath.Join(dir, "credentials.json"))
}

func TestSignIn_RegistersAndStoresSession(t *testing.T) {
	_, srv := newFakeAS(t)
	store := newStore(t)
	tr, err := SignIn(context.Background(), store, "", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if tr.Identity() != "Jane Doe <jane@example.com>" {
		t.Errorf("identity = %q", tr.Identity())
	}
	for _, k := range []string{creds.KeyOAuthClientID, creds.KeyRefreshToken, creds.KeyAccessToken, creds.KeyAccessExpiry, creds.KeyIdentity} {
		if v, err := store.GetFor("", k); err != nil || v == "" {
			t.Errorf("stored %s missing: %v", k, err)
		}
	}
	accts, _ := store.Accounts()
	if len(accts) != 1 || accts[0] != "" {
		t.Errorf("accounts = %v", accts)
	}
}

func TestSignIn_ReRegistersWhenClientDeleted(t *testing.T) {
	_, srv := newFakeAS(t)
	store := newStore(t)
	_ = store.SetFor("acme", creds.KeyOAuthClientID, "deleted-client")
	if _, err := SignIn(context.Background(), store, "acme", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if id, _ := store.GetFor("acme", creds.KeyOAuthClientID); id == "deleted-client" {
		t.Error("client was not re-registered")
	}
}

func TestLogin_ManualPaste(t *testing.T) {
	_, srv := newFakeAS(t)
	clientID, err := Register(context.Background(), nil, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Capture the authorize URL from the callback, follow it without a
	// listener, and paste the final redirect URL back.
	var authURL string
	readLine := func() (string, error) {
		if !strings.HasPrefix(authURL, srv.URL+"/auth/authorize") {
			return "", fmt.Errorf("OnAuthorizeURL not called before ReadLine (got %q)", authURL)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(authURL)
		if err != nil {
			return "", err
		}
		resp.Body.Close()
		return resp.Header.Get("Location") + "\n", nil
	}
	tr, err := Login(context.Background(), LoginOptions{
		AuthURL: srv.URL, ClientID: clientID, Manual: true, ReadLine: readLine,
		OnAuthorizeURL: func(u string, _ bool) { authURL = u },
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tr.AccessToken == "" {
		t.Error("no access token")
	}
}

func TestLogin_StateMismatch(t *testing.T) {
	_, srv := newFakeAS(t)
	clientID, _ := Register(context.Background(), nil, srv.URL)
	_, err := Login(context.Background(), LoginOptions{
		AuthURL: srv.URL, ClientID: clientID, Manual: true,
		ReadLine: func() (string, error) { return "http://127.0.0.1:53682/callback?code=x&state=forged", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("err = %v", err)
	}
}

func signedInSession(t *testing.T, f *fakeAS, srv *httptest.Server) (*Session, *creds.FileStore) {
	t.Helper()
	store := newStore(t)
	if _, err := SignIn(context.Background(), store, "", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvAccessToken, "")
	return NewSession(store, "", srv.URL), store
}

func TestSession_UsesStoredTokenThenRefreshes(t *testing.T) {
	f, srv := newFakeAS(t)
	s, store := signedInSession(t, f, srv)

	tok, err := s.Token(context.Background())
	if err != nil || tok != "access-1" {
		t.Fatalf("Token = %q, %v", tok, err)
	}
	if f.refreshes != 0 {
		t.Fatal("refreshed while stored token was valid")
	}

	// Jump past expiry: must refresh and persist.
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	tok, err = s.Token(context.Background())
	if err != nil || tok == "access-1" {
		t.Fatalf("Token after expiry = %q, %v", tok, err)
	}
	if stored, _ := store.GetFor("", creds.KeyAccessToken); stored != tok {
		t.Errorf("refreshed token not persisted: %q vs %q", stored, tok)
	}
}

func TestSession_InvalidateForcesRefresh(t *testing.T) {
	f, srv := newFakeAS(t)
	s, _ := signedInSession(t, f, srv)
	tok, _ := s.Token(context.Background())
	s.Invalidate(tok)
	again, err := s.Token(context.Background())
	if err != nil || again == tok || f.refreshes != 1 {
		t.Fatalf("Token after Invalidate = %q (was %q), refreshes=%d, err=%v", again, tok, f.refreshes, err)
	}
}

func TestSession_RotatedRefreshTokenFromSibling(t *testing.T) {
	f, srv := newFakeAS(t)
	f.rotate = true
	s, store := signedInSession(t, f, srv)
	sibling := NewSession(store, "", srv.URL)
	later := func() time.Time { return time.Now().Add(2 * time.Hour) }
	s.now, sibling.now = later, later

	// Sibling refreshes first and rotates the refresh token in the store.
	if _, err := sibling.Token(context.Background()); err != nil {
		t.Fatalf("sibling: %v", err)
	}
	// Make our process see an expired cached token and a stale refresh
	// token, as if it had read the store before the sibling rotated it.
	_ = store.SetFor("", creds.KeyAccessExpiry, "0")
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatalf("Token after sibling rotation: %v", err)
	}
}

func TestSession_LoginRequired(t *testing.T) {
	t.Setenv(EnvAccessToken, "")
	s := NewSession(newStore(t), "", "http://unused")
	if _, err := s.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v", err)
	}
	if s.Source() != creds.SourceNotFound {
		t.Errorf("source = %v", s.Source())
	}
}

func TestSession_EnvToken(t *testing.T) {
	t.Setenv(EnvAccessToken, "env-token")
	s := NewSession(nil, "", "http://unused")
	if tok, err := s.Token(context.Background()); err != nil || tok != "env-token" {
		t.Fatalf("Token = %q, %v", tok, err)
	}
	if s.Source() != creds.SourceEnv {
		t.Errorf("source = %v", s.Source())
	}
}

func TestSignOut_KeepsClientRegistration(t *testing.T) {
	f, srv := newFakeAS(t)
	_, store := signedInSession(t, f, srv)
	if err := SignOut(context.Background(), store, "", srv.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetFor("", creds.KeyRefreshToken); err == nil {
		t.Error("refresh token survived sign-out")
	}
	if id, _ := store.GetFor("", creds.KeyOAuthClientID); id == "" {
		t.Error("client registration was deleted")
	}
}

func TestRefreshLock_SerializesAndBreaksStale(t *testing.T) {
	dir := t.TempDir()
	lockDir = func() (string, error) { return dir, nil }
	unlock, err := acquireRefreshLock(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := acquireRefreshLock(ctx, "x"); err == nil {
		t.Fatal("second acquire should block while held")
	}
	unlock()
	unlock2, err := acquireRefreshLock(context.Background(), "x")
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	unlock2()

	// A stale lock (crashed holder) is broken.
	stale := filepath.Join(dir, "refresh-x.lock")
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * lockStaleAfter)
	_ = os.Chtimes(stale, old, old)
	unlock3, err := acquireRefreshLock(context.Background(), "x")
	if err != nil {
		t.Fatalf("stale lock not broken: %v", err)
	}
	unlock3()
}

func TestCallback_IgnoresForeignState(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String() + "/callback"
	go func() {
		time.Sleep(100 * time.Millisecond)
		if resp, err := http.Get(base + "?error=access_denied&state=evil"); err == nil {
			resp.Body.Close()
		}
		if resp, err := http.Get(base + "?code=c&state=good"); err == nil {
			resp.Body.Close()
		}
	}()
	q, err := waitForCallback(context.Background(), ln, "good", 5*time.Second)
	if err != nil || q.Get("code") != "c" {
		t.Fatalf("q = %v, err = %v", q, err)
	}
}

func TestLogin_ReportsBrowserOpened(t *testing.T) {
	_, srv := newFakeAS(t)
	clientID, err := Register(context.Background(), nil, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		open func(string) error
		want bool
	}{
		{"opened", browserFollow, true},
		{"failed", func(u string) error { _ = browserFollow(u); return errors.New("no browser") }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var gotURL string
			var gotOpened bool
			_, err := Login(context.Background(), LoginOptions{
				AuthURL: srv.URL, ClientID: clientID, OpenBrowser: c.open, Timeout: 10 * time.Second,
				OnAuthorizeURL: func(u string, opened bool) { gotURL, gotOpened = u, opened },
			})
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			if !strings.HasPrefix(gotURL, srv.URL+"/auth/authorize") || gotOpened != c.want {
				t.Fatalf("url=%q opened=%v want %v", gotURL, gotOpened, c.want)
			}
		})
	}
}
