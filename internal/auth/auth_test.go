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
	"github.com/februality/presswrench/internal/lockfile"
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
// Write to the embedded Store directly to bypass the faults (as another
// process would). Save is safe from a background goroutine; read the count
// with saveCount there.
type faultyStore struct {
	creds.Store
	loadErr   error
	saveErrs  []error
	saves     int
	deleteErr error
	saveDelay time.Duration // a slow keychain
	saveBlock chan struct{} // when set, Save waits until it's closed (a hung keychain)

	mu sync.Mutex // guards loadErr (via setLoadErr), saveErrs, saves, saveDelay
}

func (f *faultyStore) setLoadErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadErr = err
}

func (f *faultyStore) saveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saves
}

func (f *faultyStore) Delete(account string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.Store.Delete(account)
}

func (f *faultyStore) Load(account string) (creds.Record, error) {
	f.mu.Lock()
	err := f.loadErr
	f.mu.Unlock()
	if err != nil {
		return creds.Record{}, err
	}
	return f.Store.Load(account)
}

func (f *faultyStore) Save(account string, r creds.Record) error {
	f.mu.Lock()
	f.saves++
	var err error
	if len(f.saveErrs) > 0 {
		err = f.saveErrs[0]
		f.saveErrs = f.saveErrs[1:]
	}
	delay, block := f.saveDelay, f.saveBlock
	f.mu.Unlock()
	time.Sleep(delay)
	if block != nil {
		<-block
	}
	if err != nil {
		return err
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

// failSaves returns n save errors of kind k.
func failSaves(n int, k creds.Kind) []error {
	errs := make([]error, n)
	for i := range errs {
		errs[i] = &creds.Error{Kind: k, Op: "save", Detail: "test failure"}
	}
	return errs
}

// pendingSession signs in (rotating refresh tokens), wraps the store with
// the given save failures and returns a Session whose clock is past the
// stored access token's expiry, so its first Token call refreshes. Save
// backoff is zeroed; the session is closed at cleanup.
func pendingSession(t *testing.T, saveErrs []error) (*Session, *faultyStore, *fakeAS, *httptest.Server) {
	t.Helper()
	oldBackoff := saveBackoff
	saveBackoff = []time.Duration{0, 0}
	t.Cleanup(func() { saveBackoff = oldBackoff })
	f, srv := newFakeAS(t)
	f.rotate = true
	_, store := signedInSession(t, f, srv)
	fs := &faultyStore{Store: store, saveErrs: saveErrs}
	s := NewSession(fs, "", srv.URL)
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	t.Cleanup(func() { closeAndSettle(t, s) })
	return s, fs, f, srv
}

// closeAndSettle closes s and waits for a background flush still in flight
// (Close leaves the lock to it) so it can't write into a removed temp dir.
func closeAndSettle(t *testing.T, s *Session) {
	s.Close()
	settled := eventually(func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return !s.flushing
	})
	if !settled {
		t.Error("background flush still running 5 s after Close")
	}
}

// advance moves the session's clock forward by d.
func advance(s *Session, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.now
	s.now = func() time.Time { return old().Add(d) }
}

// runRetry runs the pending session's background retry now, as its timer
// would, and returns when that attempt has settled. pendingRetry stays long
// in the tests that use it, so the real timer never fires alongside.
func runRetry(s *Session) {
	s.mu.Lock()
	t := s.retry
	s.mu.Unlock()
	if t != nil {
		s.retryTick(func() *time.Timer { return t })
	}
}

// isPending reports whether s holds an unsaved session.
func isPending(s *Session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending != nil
}

// lockFree reports whether the default account's lock can be taken now.
func lockFree(t *testing.T) bool {
	t.Helper()
	shortLockWait(t, 100*time.Millisecond)
	l, err := lockAccount(context.Background(), "")
	if err != nil {
		return false
	}
	l.Release()
	return true
}

// eventually polls cond for up to 5 s.
func eventually(cond func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

func TestSession_SaveFailureKeepsWorking(t *testing.T) {
	s, fs, f, _ := pendingSession(t, failSaves(100, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil || tok != "access-2" {
		t.Fatalf("Token = %q, %v; want the refreshed token despite the failed save", tok, err)
	}
	if n := fs.saveCount(); n != 3 {
		t.Errorf("saves = %d, want 3 (1 + len(saveBackoff))", n)
	}
	again, err := s.Token(context.Background())
	if err != nil || again != tok {
		t.Fatalf("second Token = %q, %v; want %q from memory", again, err, tok)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refreshes != 1 {
		t.Errorf("refreshes = %d, want 1", f.refreshes)
	}
}

func TestSession_SaveFailureHoldsLock(t *testing.T) {
	s, fs, f, srv := pendingSession(t, failSaves(100, creds.KindOther))
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	shortLockWait(t, 100*time.Millisecond)
	sibling := NewSession(fs.Store, "", srv.URL)
	sibling.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, err := sibling.Token(context.Background())
	var held *lockfile.HeldError
	if !errors.As(err, &held) {
		t.Fatalf("sibling err = %v, want *lockfile.HeldError", err)
	}
	if !strings.Contains(held.Reason, "account default") {
		t.Errorf("Reason = %q, want it to name the account", held.Reason)
	}
	msg := Explain(err)
	if !strings.Contains(msg, "newer session it couldn't save") ||
		!strings.Contains(msg, "Sign in again with `presswrench login` to replace it.") ||
		strings.Contains(msg, unsavedPrefix) || strings.Contains(msg, "\n") {
		t.Errorf("Explain = %q", msg)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refreshes != 1 || f.refreshRejected != 0 {
		t.Errorf("refreshes = %d, rejected = %d; want 1, 0 (the sibling spent the stale token)", f.refreshes, f.refreshRejected)
	}
}

func TestSession_PendingFlushedWhenStoreRecovers(t *testing.T) {
	s, fs, _, _ := pendingSession(t, failSaves(3, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := fs.Store.Load(""); r.RefreshToken == "refresh-2" {
		t.Fatal("saved although every attempt failed")
	}
	runRetry(s)
	again, err := s.Token(context.Background())
	if err != nil || again != tok {
		t.Fatalf("Token = %q, %v; want %q", again, err, tok)
	}
	r, err := fs.Store.Load("")
	if err != nil || r.RefreshToken != "refresh-2" || r.AccessToken != tok {
		t.Fatalf("stored = %+v, %v; want the rotated session", r, err)
	}
	if !lockFree(t) {
		t.Error("account lock still held after the session was saved")
	}
}

func TestSession_PendingDiscardedWhenSuperseded(t *testing.T) {
	s, fs, _, _ := pendingSession(t, failSaves(3, creds.KindOther))
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := fs.Store.Load("")
	if err != nil {
		t.Fatal(err)
	}
	r.RefreshToken, r.AccessToken = "from-login", "access-from-login"
	r.AccessExpiry = time.Now().Add(4 * time.Hour).Unix()
	if err := fs.Store.Save("", r); err != nil { // another writer, bypassing the lock
		t.Fatal(err)
	}
	runRetry(s)
	tok, err := s.Token(context.Background())
	if err != nil || tok != "access-from-login" {
		t.Fatalf("Token = %q, %v; want the newer stored session", tok, err)
	}
	if r, _ := fs.Store.Load(""); r.RefreshToken != "from-login" {
		t.Errorf("stored refresh token = %q; the newer session was overwritten", r.RefreshToken)
	}
	if !lockFree(t) {
		t.Error("account lock still held after the pending session was discarded")
	}
}

func TestSession_PartialSaveCountsAsFlushed(t *testing.T) {
	s, fs, _, _ := pendingSession(t, failSaves(100, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A save that wrote the record and then failed (e.g. on the index).
	r, _ := fs.Store.Load("")
	r.RefreshToken, r.AccessToken = "refresh-2", tok
	if err := fs.Store.Save("", r); err != nil {
		t.Fatal(err)
	}
	saves := fs.saveCount()
	runRetry(s)
	if again, err := s.Token(context.Background()); err != nil || again != tok {
		t.Fatalf("Token = %q, %v; want %q", again, err, tok)
	}
	if isPending(s) || fs.saveCount() != saves {
		t.Errorf("pending = %v, saves %d -> %d; want settled without saving", isPending(s), saves, fs.saveCount())
	}
	if !lockFree(t) {
		t.Error("lock still held")
	}
}

func TestSession_DeniedNotRetried(t *testing.T) {
	s, fs, _, _ := pendingSession(t, failSaves(100, creds.KindDenied))
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := fs.saveCount(); n != 1 {
		t.Errorf("saves = %d, want 1 (Denied is permanent)", n)
	}
}

func TestSession_SlowKindsSavedOnce(t *testing.T) {
	for _, k := range []creds.Kind{creds.KindTimeout, creds.KindLocked} {
		t.Run(fmt.Sprint(k), func(t *testing.T) {
			s, fs, _, _ := pendingSession(t, failSaves(100, k))
			tok, err := s.Token(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if n := fs.saveCount(); n != 1 {
				t.Errorf("saves = %d, want 1 (the call already waited)", n)
			}
			advance(s, pendingRetry)
			if again, err := s.Token(context.Background()); err != nil || again != tok {
				t.Fatalf("Token = %q, %v", again, err)
			}
			if n := fs.saveCount(); n != 1 {
				t.Errorf("saves = %d; Token tried to save in the foreground", n)
			}
			runRetry(s)
			if n := fs.saveCount(); n != 2 {
				t.Errorf("saves = %d after a background retry, want 2", n)
			}
		})
	}
}

// A save that hangs for longer than pendingRetry (an unanswered keychain
// prompt) must not hold up Token: the background retry makes it without
// the session mutex.
func TestSession_HungSaveDoesNotBlockToken(t *testing.T) {
	old := pendingRetry
	pendingRetry = 20 * time.Millisecond
	t.Cleanup(func() { pendingRetry = old })
	s, fs, _, _ := pendingSession(t, failSaves(3, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	var unblock sync.Once
	release := func() { unblock.Do(func() { close(block) }) }
	t.Cleanup(release)
	fs.mu.Lock()
	fs.saveBlock = block
	fs.mu.Unlock()
	if !eventually(func() bool { return fs.saveCount() > 3 }) {
		t.Fatal("background retry never started a save")
	}
	deadline := time.Now().Add(5 * pendingRetry) // well past pendingRetry, save still hung
	for time.Now().Before(deadline) {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				got, err := s.Token(context.Background())
				if d := time.Since(start); d > 200*time.Millisecond {
					t.Errorf("Token took %v while the save hung", d)
				}
				if err != nil || got != tok {
					t.Errorf("Token = %q, %v; want %q", got, err, tok)
				}
			}()
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			release()
			t.Fatal("Token blocked behind the hung save")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !isPending(s) {
		t.Fatal("settled while the save was still hung")
	}
	release()
	if !eventually(func() bool { return !isPending(s) }) {
		t.Fatal("pending session not saved after the keychain answered")
	}
	if r, _ := fs.Store.Load(""); r.RefreshToken != "refresh-2" {
		t.Errorf("stored refresh token = %q, want refresh-2", r.RefreshToken)
	}
	if !lockFree(t) {
		t.Error("lock still held after the save")
	}
}

func TestSession_CloseReleasesLock(t *testing.T) {
	s, _, _, _ := pendingSession(t, failSaves(100, creds.KindOther))
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lockFree(t) {
		t.Fatal("lock not held while the session is unsaved")
	}
	s.Close()
	if !lockFree(t) {
		t.Error("lock still held after Close")
	}
	s.Close()
}

func TestSession_CloseWithoutToken(t *testing.T) {
	f, srv := newFakeAS(t)
	s, _ := signedInSession(t, f, srv)
	s.Close()
	s.Close()
	NewSession(nil, "", srv.URL).Close()
}

func TestSession_TokenAfterCloseSpendsNothing(t *testing.T) {
	s, _, f, _ := pendingSession(t, failSaves(100, creds.KindOther))
	s.Close()
	if _, err := s.Token(context.Background()); !errors.Is(err, errSessionClosed) {
		t.Fatalf("err = %v, want errSessionClosed", err)
	}
	f.mu.Lock()
	attempts := f.refreshAttempts
	f.mu.Unlock()
	if attempts != 0 {
		t.Errorf("refresh attempts = %d after Close, want 0", attempts)
	}
	if !lockFree(t) {
		t.Error("a closed session holds the account lock")
	}
}

func TestSession_PendingRetriedInBackground(t *testing.T) {
	old := pendingRetry
	pendingRetry = 20 * time.Millisecond
	t.Cleanup(func() { pendingRetry = old })
	s, fs, _, _ := pendingSession(t, failSaves(5, creds.KindOther)) // 3 on refresh, 2 on ticks
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Poll the session, not the store: the timer may be mid-write.
	if !eventually(func() bool { return !isPending(s) }) {
		t.Fatalf("background retry never saved the session (saves = %d)", fs.saveCount())
	}
	if r, _ := fs.Store.Load(""); r.RefreshToken != "refresh-2" {
		t.Errorf("stored refresh token = %q, want refresh-2", r.RefreshToken)
	}
	if !lockFree(t) {
		t.Error("lock still held after the background save")
	}
	n := fs.saveCount()
	time.Sleep(100 * time.Millisecond)
	if fs.saveCount() != n {
		t.Error("background retry kept running after the session was saved")
	}
}

func TestSession_InvalidateWhilePendingUsesPendingRefreshToken(t *testing.T) {
	s, fs, f, _ := pendingSession(t, failSaves(100, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.Invalidate(tok)
	again, err := s.Token(context.Background())
	if err != nil || again == tok {
		t.Fatalf("Token after Invalidate = %q, %v", again, err)
	}
	f.mu.Lock()
	attempts, rejected := f.refreshAttempts, f.refreshRejected
	f.mu.Unlock()
	if attempts != 2 || rejected != 0 {
		t.Errorf("refresh attempts = %d, rejected = %d; want 2, 0 (the stale stored token was spent)", attempts, rejected)
	}
	// The store recovers: the latest rotation is what gets saved.
	fs.mu.Lock()
	fs.saveErrs = nil
	fs.mu.Unlock()
	runRetry(s) // the pending refresh also brought the timer forward; either saves
	if !eventually(func() bool { return !isPending(s) }) {
		t.Fatal("not saved after the store recovered")
	}
	if r, _ := fs.Store.Load(""); r.RefreshToken != "refresh-3" || r.AccessToken != again {
		t.Errorf("stored = %q/%q, want refresh-3/%q", r.RefreshToken, r.AccessToken, again)
	}
	if !lockFree(t) {
		t.Error("lock still held after the save")
	}
}

func TestSession_NetworkErrorWhilePendingKeepsLock(t *testing.T) {
	s, _, _, srv := pendingSession(t, failSaves(100, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.Invalidate(tok)
	s.mu.Lock()
	s.authURL = "http://127.0.0.1:1" // nothing listens
	s.mu.Unlock()
	_, err = s.Token(context.Background())
	if err == nil || errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want a network error", err)
	}
	if !isPending(s) || lockFree(t) {
		t.Fatalf("pending = %v; the unsaved session or its lock was dropped on a network error", isPending(s))
	}
	s.mu.Lock()
	s.authURL = srv.URL
	s.mu.Unlock()
	if again, err := s.Token(context.Background()); err != nil || again == tok {
		t.Fatalf("Token after recovery = %q, %v", again, err)
	}
}

func TestSession_PendingRevokedReleasesLock(t *testing.T) {
	s, _, f, _ := pendingSession(t, failSaves(100, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.Invalidate(tok)
	f.mu.Lock()
	f.refresh = map[string]bool{} // Pressable revoked the session
	f.mu.Unlock()
	_, err = s.Token(context.Background())
	var lr *LoginRequiredError
	if !errors.As(err, &lr) || !lr.Expired {
		t.Fatalf("err = %v, want expired sign-in", err)
	}
	if !lockFree(t) {
		t.Error("lock still held after the unsaved session was revoked")
	}
}

func TestSession_FlushStoredRecordStates(t *testing.T) {
	t.Run("corrupt is overwritten", func(t *testing.T) {
		s, fs, _, _ := pendingSession(t, failSaves(3, creds.KindOther))
		tok, err := s.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		fs.setLoadErr(&creds.Error{Kind: creds.KindCorrupt, Op: "load"})
		runRetry(s)
		if again, err := s.Token(context.Background()); err != nil || again != tok {
			t.Fatalf("Token = %q, %v", again, err)
		}
		fs.setLoadErr(nil)
		if r, _ := fs.Store.Load(""); r.RefreshToken != "refresh-2" {
			t.Errorf("stored refresh token = %q, want refresh-2", r.RefreshToken)
		}
		if isPending(s) || !lockFree(t) {
			t.Error("not settled after overwriting a corrupt record")
		}
	})
	t.Run("newer format is kept", func(t *testing.T) {
		s, fs, _, _ := pendingSession(t, failSaves(3, creds.KindOther))
		if _, err := s.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
		fs.setLoadErr(&creds.Error{Kind: creds.KindNewerFormat, Op: "load"})
		saves := fs.saveCount()
		runRetry(s)
		if _, err := s.Token(context.Background()); creds.KindOf(err) != creds.KindNewerFormat {
			t.Fatalf("err = %v, want the newer-format error", err)
		}
		if isPending(s) || fs.saveCount() != saves || !lockFree(t) {
			t.Errorf("pending = %v, saves %d -> %d; want discarded without saving", isPending(s), saves, fs.saveCount())
		}
	})
	t.Run("deleted is kept deleted", func(t *testing.T) {
		s, fs, _, _ := pendingSession(t, failSaves(3, creds.KindOther))
		if _, err := s.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := fs.Store.Delete(""); err != nil {
			t.Fatal(err)
		}
		runRetry(s)
		if _, err := s.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
			t.Fatalf("err = %v, want login required", err)
		}
		if _, err := fs.Store.Load(""); creds.KindOf(err) != creds.KindNotFound {
			t.Errorf("deleted record came back: %v", err)
		}
		if isPending(s) || !lockFree(t) {
			t.Error("not settled after the record was deleted")
		}
	})
}

func TestSession_LoginTakesOverPendingLock(t *testing.T) {
	s, fs, _, srv := pendingSession(t, failSaves(100, creds.KindOther))
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := SignIn(context.Background(), fs.Store, "", LoginOptions{AuthURL: srv.URL, OpenBrowser: browserFollow, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("login: %v", err)
	}
	if d := time.Since(start); d > lockWait/4 {
		t.Errorf("login took %v; it waited for the unsaved session's lock", d)
	}
	login, err := fs.Store.Load("")
	if err != nil || login.RefreshToken == "" || login.RefreshToken == "refresh-1" || login.RefreshToken == "refresh-2" {
		t.Fatalf("stored after login = %+v, %v", login, err)
	}
	saves := fs.saveCount()
	// Real clock: the login's access token is fresh.
	s.mu.Lock()
	s.now = time.Now
	s.mu.Unlock()
	runRetry(s)
	tok, err := s.Token(context.Background())
	if err != nil || tok != login.AccessToken {
		t.Fatalf("Token = %q, %v; want the login's %q", tok, err, login.AccessToken)
	}
	if r, _ := fs.Store.Load(""); r.RefreshToken != login.RefreshToken {
		t.Errorf("stored refresh token = %q; the login's session was overwritten", r.RefreshToken)
	}
	if isPending(s) || fs.saveCount() != saves {
		t.Errorf("pending = %v, saves %d -> %d; want discarded without saving", isPending(s), saves, fs.saveCount())
	}
	if !lockFree(t) {
		t.Error("lock still held")
	}
}

func TestSession_LogoutTakesOverPendingLock(t *testing.T) {
	s, fs, _, srv := pendingSession(t, failSaves(100, creds.KindOther))
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := SignOut(context.Background(), fs.Store, "", srv.URL); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if d := time.Since(start); d > lockWait/4 {
		t.Errorf("logout took %v", d)
	}
	runRetry(s)
	if _, err := s.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want login required after logout", err)
	}
	if r, _ := fs.Store.Load(""); r.SignedIn() {
		t.Error("the unsaved session was written back after logout")
	}
	if !lockFree(t) {
		t.Error("lock still held")
	}
}

func TestSession_CloseConcurrentWithTokenAndFlush(t *testing.T) {
	old := pendingRetry
	pendingRetry = 5 * time.Millisecond
	t.Cleanup(func() { pendingRetry = old })
	s, fs, _, _ := pendingSession(t, failSaves(100000, creds.KindOther))
	fs.mu.Lock()
	fs.saveDelay = 15 * time.Millisecond // a slow keychain: flushes overlap Token calls
	fs.mu.Unlock()
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				tok, err := s.Token(context.Background())
				if errors.Is(err, errSessionClosed) {
					return
				}
				if err != nil {
					t.Errorf("Token: %v", err)
					return
				}
				if i%2 == 0 {
					s.Invalidate(tok) // force refreshes alongside the background flush
				}
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	s.Close()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Token calls still running 10 s after Close (deadlock?)")
	}
	if !eventually(func() bool { return lockFree(t) }) {
		t.Error("lock never released after Close")
	}
}

// A user command that takes the lock over without changing the stored
// session (login's client step) must stop the former holder from saving
// while it holds the lock.
func TestSession_TakenOverLockNotWrittenUnder(t *testing.T) {
	old := relockWait
	relockWait = 100 * time.Millisecond
	t.Cleanup(func() { relockWait = old })
	s, fs, _, _ := pendingSession(t, failSaves(3, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	taker, err := lockAccountForUser(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	saves := fs.saveCount()
	runRetry(s)
	if again, err := s.Token(context.Background()); err != nil || again != tok {
		t.Errorf("Token = %q, %v; want the in-memory %q while the taker holds the lock", again, err, tok)
	}
	if fs.saveCount() != saves || isPending(s) {
		t.Errorf("saves %d -> %d, pending = %v; want discarded without writing under the taker's lock", saves, fs.saveCount(), isPending(s))
	}
	if !taker.Held() {
		t.Error("the former holder broke the taker's lock")
	}
	taker.Release()
}

// Once the user command is done, the former holder takes the lock back and
// saves its session.
func TestSession_TakenOverLockRegainedAndSaved(t *testing.T) {
	s, fs, _, _ := pendingSession(t, failSaves(3, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	taker, err := lockAccountForUser(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	taker.Release()
	runRetry(s)
	if again, err := s.Token(context.Background()); err != nil || again != tok {
		t.Fatalf("Token = %q, %v", again, err)
	}
	if r, _ := fs.Store.Load(""); r.RefreshToken != "refresh-2" {
		t.Errorf("stored refresh token = %q, want refresh-2", r.RefreshToken)
	}
	if isPending(s) || !lockFree(t) {
		t.Error("not settled after regaining the lock")
	}
}

// A pending session that must refresh after a user command took its lock
// settles first and never spends its refresh token without the lock.
func TestSession_TakenOverLockNotRefreshedWithout(t *testing.T) {
	old := relockWait
	relockWait = 100 * time.Millisecond
	t.Cleanup(func() { relockWait = old })
	s, fs, f, _ := pendingSession(t, failSaves(100, creds.KindOther))
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	taker, err := lockAccountForUser(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer taker.Release()
	saves := fs.saveCount()
	s.Invalidate(tok)
	shortLockWait(t, 100*time.Millisecond)
	_, err = s.Token(context.Background())
	var held *lockfile.HeldError
	if !errors.As(err, &held) {
		t.Fatalf("err = %v, want *lockfile.HeldError (the taker holds the account)", err)
	}
	f.mu.Lock()
	attempts := f.refreshAttempts
	f.mu.Unlock()
	if attempts != 1 || fs.saveCount() != saves || isPending(s) {
		t.Errorf("refresh attempts = %d, saves %d -> %d, pending = %v; want 1, unchanged, false",
			attempts, saves, fs.saveCount(), isPending(s))
	}
	if !taker.Held() {
		t.Error("the taker lost its lock")
	}
}
