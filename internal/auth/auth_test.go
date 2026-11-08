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

	delay           time.Duration // sleep before answering /auth/token
	registrations   int
	revokes         int
	refreshAttempts int // refresh grants received, valid or not
	refreshRejected int // refresh grants answered with invalid_grant
}

func newFakeAS(t *testing.T) (*fakeAS, *httptest.Server) {
	f := &fakeAS{t: t, clients: map[string]bool{}, challenges: map[string]string{}, refresh: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/register", f.register)
	mux.HandleFunc("/auth/authorize", f.authorize)
	mux.HandleFunc("/auth/token", f.token)
	mux.HandleFunc("/auth/revoke", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.revokes++
		f.mu.Unlock()
		w.WriteHeader(200)
	})
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
	f.registrations++
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
	delay := f.delay
	f.mu.Unlock()
	time.Sleep(delay)
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
		f.refreshAttempts++
		if !f.refresh[rt] {
			f.refreshRejected++
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

func newStore(t *testing.T) creds.Store {
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
	r, err := store.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.V != creds.RecordVersion || r.ClientID == "" || r.RefreshToken == "" || r.AccessToken == "" || r.AccessExpiry == 0 {
		t.Errorf("stored record incomplete: %+v", r)
	}
	if r.Identity != "Jane Doe <jane@example.com>" {
		t.Errorf("stored identity = %q", r.Identity)
	}
	accts, _ := store.Accounts()
	if len(accts) != 1 || accts[0] != "" {
		t.Errorf("accounts = %v", accts)
	}
}

func TestSignIn_ReRegistersWhenClientDeleted(t *testing.T) {
	_, srv := newFakeAS(t)
	store := newStore(t)
	if err := store.Save("acme", creds.Record{ClientID: "deleted-client"}); err != nil {
		t.Fatal(err)
	}
	if _, err := SignIn(context.Background(), store, "acme", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if r, _ := store.Load("acme"); r.ClientID == "deleted-client" || r.ClientID == "" {
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

func signedInSession(t *testing.T, f *fakeAS, srv *httptest.Server) (*Session, creds.Store) {
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
	if stored, _ := store.Load(""); stored.AccessToken != tok {
		t.Errorf("refreshed token not persisted: %q vs %q", stored.AccessToken, tok)
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
	expire(t, store, "")
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatalf("Token after sibling rotation: %v", err)
	}
}

// expire zeroes the stored access expiry, as if the cached access token
// were missing its expiry.
func expire(t *testing.T, store creds.Store, account string) {
	t.Helper()
	r, err := store.Load(account)
	if err != nil {
		t.Fatal(err)
	}
	r.AccessExpiry = 0
	if err := store.Save(account, r); err != nil {
		t.Fatal(err)
	}
}

func TestSession_ZeroExpiryRefreshes(t *testing.T) {
	f, srv := newFakeAS(t)
	s, store := signedInSession(t, f, srv)
	expire(t, store, "")
	tok, err := s.Token(context.Background())
	if err != nil || tok == "" {
		t.Fatalf("Token = %q, %v", tok, err)
	}
	if f.refreshes != 1 {
		t.Errorf("refreshes = %d, want 1", f.refreshes)
	}
	if r, _ := store.Load(""); r.AccessToken != tok || r.AccessExpiry == 0 {
		t.Errorf("refreshed session not persisted: %+v", r)
	}
}

func TestSession_LoginRequired(t *testing.T) {
	t.Setenv(EnvAccessToken, "")
	s := NewSession(newStore(t), "", "http://unused")
	if _, err := s.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v", err)
	}
	if src, err := s.State(); src != creds.SourceNotFound || !errors.Is(err, ErrLoginRequired) {
		t.Errorf("State = %v, %v", src, err)
	}
}

func TestSession_EnvToken(t *testing.T) {
	t.Setenv(EnvAccessToken, "env-token")
	s := NewSession(nil, "", "http://unused")
	if tok, err := s.Token(context.Background()); err != nil || tok != "env-token" {
		t.Fatalf("Token = %q, %v", tok, err)
	}
	if src, err := s.State(); src != creds.SourceEnv || err != nil {
		t.Errorf("State = %v, %v", src, err)
	}
}

func TestSignOut_KeepsClientRegistration(t *testing.T) {
	f, srv := newFakeAS(t)
	_, store := signedInSession(t, f, srv)
	if err := SignOut(context.Background(), store, "", srv.URL); err != nil {
		t.Fatal(err)
	}
	r, err := store.Load("")
	if err != nil {
		t.Fatalf("Load after sign-out: %v", err)
	}
	if r.RefreshToken != "" || r.AccessToken != "" || r.Identity != "" {
		t.Errorf("session survived sign-out: %+v", r)
	}
	if r.ClientID == "" {
		t.Error("client registration was deleted")
	}
	if accts, _ := store.Accounts(); len(accts) != 0 {
		t.Errorf("signed-out account still listed: %q", accts)
	}
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

// faultyStore wraps a real store with injectable failures. loadErr fails
// every Load; saveErrs are consumed one per Save call (nil entry = succeed).
type faultyStore struct {
	creds.Store
	loadErr   error
	saveErrs  []error
	saves     int
	deleteErr error
}

func (f *faultyStore) Delete(account string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.Store.Delete(account)
}

func (f *faultyStore) Load(account string) (creds.Record, error) {
	if f.loadErr != nil {
		return creds.Record{}, f.loadErr
	}
	return f.Store.Load(account)
}

func (f *faultyStore) Save(account string, r creds.Record) error {
	f.saves++
	if len(f.saveErrs) > 0 {
		err := f.saveErrs[0]
		f.saveErrs = f.saveErrs[1:]
		if err != nil {
			return err
		}
	}
	return f.Store.Save(account, r)
}

func TestSession_LockedKeychainIsNotLoginRequired(t *testing.T) {
	t.Setenv(EnvAccessToken, "")
	locked := &creds.Error{Kind: creds.KindLocked, Account: "acme"}
	fs := &faultyStore{Store: newStore(t), loadErr: locked}
	s := NewSession(fs, "acme", "http://unused")
	_, err := s.Token(context.Background())
	if creds.KindOf(err) != creds.KindLocked || errors.Is(err, ErrLoginRequired) {
		t.Fatalf("Token err = %v", err)
	}
	if _, serr := s.State(); creds.KindOf(serr) != creds.KindLocked || errors.Is(serr, ErrLoginRequired) {
		t.Fatalf("State err = %v", serr)
	}
}

func TestSession_InvalidGrantIsExpired(t *testing.T) {
	f, srv := newFakeAS(t)
	s, store := signedInSession(t, f, srv)
	expire(t, store, "")
	f.mu.Lock()
	f.refresh = map[string]bool{}
	f.mu.Unlock()
	_, err := s.Token(context.Background())
	var lr *LoginRequiredError
	if !errors.As(err, &lr) || !lr.Expired || !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v", err)
	}
}
