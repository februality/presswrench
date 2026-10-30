// Package auth signs a developer in to Pressable as themselves and keeps
// the session alive.
//
// Flow: the first login dynamically registers a public OAuth client for
// this install (POST /auth/register, RFC 7591), then runs an
// authorization-code + PKCE flow (RFC 7636) against a loopback redirect
// (RFC 8252). The resulting token carries the user's own Pressable
// permissions — site access and collaborator roles are enforced by Pressable,
// not by us. Tokens are scoped "mcp": they work against Pressable's hosted
// MCP gateway, not the /v1 REST API.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Scope requested for every token.
const Scope = "mcp"

// RedirectPorts are the loopback ports registered as redirect URIs. Login
// uses the first free one. Pressable matches redirect URIs exactly, so the
// set is fixed at registration time.
var RedirectPorts = []int{53682, 53683, 53684}

// ErrLoginRequired means there is no usable session: the user must run
// `presswrench login`.
var ErrLoginRequired = errors.New("not signed in to Pressable")

// TokenResponse is the subset of /auth/token's response we use. Pressable
// also returns the signed-in user's name and email.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	Name         string `json:"name"`
	Email        string `json:"email"`
}

// Identity renders "Name <email>" (or whichever half is present).
func (t *TokenResponse) Identity() string {
	switch {
	case t.Name != "" && t.Email != "":
		return t.Name + " <" + t.Email + ">"
	case t.Email != "":
		return t.Email
	default:
		return t.Name
	}
}

// OAuthError is an RFC 6749 error response from the token endpoint.
type OAuthError struct {
	Status      int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("Pressable OAuth error %d %s: %s", e.Status, e.Code, e.Description)
	}
	return fmt.Sprintf("Pressable OAuth error %d %s", e.Status, e.Code)
}

func redirectURI(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/callback", port)
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// Register creates a public OAuth client for this install and returns its
// client_id.
func Register(ctx context.Context, hc *http.Client, authURL string) (string, error) {
	if hc == nil {
		hc = defaultHTTPClient()
	}
	host, _ := os.Hostname()
	name := "presswrench"
	if host != "" {
		name += " (" + host + ")"
	}
	uris := make([]string, len(RedirectPorts))
	for i, p := range RedirectPorts {
		uris[i] = redirectURI(p)
	}
	body, _ := json.Marshal(map[string]any{
		"client_name":                name,
		"redirect_uris":              uris,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      Scope,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL+"/auth/register", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("register OAuth client: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("register OAuth client: HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.ClientID == "" {
		return "", fmt.Errorf("register OAuth client: unexpected response: %s", truncate(string(raw), 300))
	}
	return out.ClientID, nil
}

// LoginOptions configure an interactive login.
type LoginOptions struct {
	AuthURL  string
	ClientID string
	// OpenBrowser opens the authorize URL. When nil, or when it fails, the
	// URL is printed for the user to open themselves.
	OpenBrowser func(string) error
	// Manual skips the loopback listener: the user pastes the URL their
	// browser was redirected to. For machines the browser can't reach.
	Manual bool
	// ReadLine reads the pasted redirect URL in Manual mode. The caller
	// prompts; Login prints nothing.
	ReadLine func() (string, error)
	// OnAuthorizeURL, when set, receives the authorize URL right after the
	// browser was (or wasn't) opened, before Login waits for the callback.
	OnAuthorizeURL func(url string, browserOpened bool)
	Timeout        time.Duration
	HTTP           *http.Client
}

// Login runs the authorization-code + PKCE flow and returns the tokens.
func Login(ctx context.Context, o LoginOptions) (*TokenResponse, error) {
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Minute
	}
	verifier, challenge, err := newPKCE()
	if err != nil {
		return nil, err
	}
	state, err := randomString(16)
	if err != nil {
		return nil, err
	}

	var ln net.Listener
	port := RedirectPorts[0]
	if !o.Manual {
		ln, port, err = listenLoopback()
		if err != nil {
			return nil, err
		}
		defer ln.Close()
	}
	redirect := redirectURI(port)

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {Scope},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authorizeURL := o.AuthURL + "/auth/authorize?" + q.Encode()

	opened := false
	if o.OpenBrowser != nil && !o.Manual {
		opened = o.OpenBrowser(authorizeURL) == nil
	}
	if o.OnAuthorizeURL != nil {
		o.OnAuthorizeURL(authorizeURL, opened)
	}

	var params url.Values
	if o.Manual {
		if o.ReadLine == nil {
			return nil, errors.New("manual login needs a line reader")
		}
		line, err := o.ReadLine()
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(strings.TrimSpace(line))
		if err != nil {
			return nil, fmt.Errorf("parse pasted URL: %w", err)
		}
		params = u.Query()
	} else {
		params, err = waitForCallback(ctx, ln, state, o.Timeout)
		if err != nil {
			return nil, err
		}
	}

	if e := params.Get("error"); e != "" {
		return nil, fmt.Errorf("authorization denied: %s %s", e, params.Get("error_description"))
	}
	if params.Get("state") != state {
		return nil, errors.New("authorization failed: state mismatch (possible CSRF); try again")
	}
	code := params.Get("code")
	if code == "" {
		return nil, errors.New("authorization failed: no code in callback")
	}
	return exchange(ctx, o.HTTP, o.AuthURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {o.ClientID},
		"code_verifier": {verifier},
	})
}

// Refresh trades a refresh token for a new access token.
func Refresh(ctx context.Context, hc *http.Client, authURL, clientID, refreshToken string) (*TokenResponse, error) {
	return exchange(ctx, hc, authURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
}

// Revoke invalidates a token server-side. Best effort.
func Revoke(ctx context.Context, hc *http.Client, authURL, clientID, token string) error {
	if hc == nil {
		hc = defaultHTTPClient()
	}
	form := url.Values{"token": {token}, "client_id": {clientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL+"/auth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("revoke: HTTP %d", resp.StatusCode)
	}
	return nil
}

func exchange(ctx context.Context, hc *http.Client, authURL string, form url.Values) (*TokenResponse, error) {
	if hc == nil {
		hc = defaultHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL+"/auth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		oe := &OAuthError{Status: resp.StatusCode}
		if json.Unmarshal(raw, oe) != nil || oe.Code == "" {
			oe.Code = "http_error"
			oe.Description = truncate(string(raw), 300)
		}
		return nil, oe
	}
	var tr TokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil || tr.AccessToken == "" {
		return nil, fmt.Errorf("token request: unexpected response: %s", truncate(string(raw), 300))
	}
	return &tr, nil
}

func listenLoopback() (net.Listener, int, error) {
	var lastErr error
	for _, p := range RedirectPorts {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			return ln, p, nil
		}
		lastErr = err
	}
	return nil, 0, fmt.Errorf("no free loopback port for the login callback (tried %v): %w — or use `presswrench login --manual`", RedirectPorts, lastErr)
}

const callbackPage = `<!doctype html><meta charset="utf-8"><title>presswrench</title>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">
<h2>%s</h2><p>%s</p></body>`

// waitForCallback serves the loopback redirect. Requests without our state
// are rejected and ignored, so a stray or hostile local request can't abort
// or hijack the login.
func waitForCallback(ctx context.Context, ln net.Listener, state string, timeout time.Duration) (url.Values, error) {
	got := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if q.Get("state") != state {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, callbackPage, "Unexpected request", "This page doesn't match the sign-in in progress.")
			return
		}
		if q.Get("error") != "" {
			fmt.Fprintf(w, callbackPage, "Sign-in was not completed", "You can close this tab and return to your terminal.")
		} else {
			fmt.Fprintf(w, callbackPage, "Signed in to Pressable", "You can close this tab and return to your terminal.")
		}
		select {
		case got <- q:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case q := <-got:
		return q, nil
	case <-timer.C:
		return nil, fmt.Errorf("timed out after %s waiting for the browser sign-in", timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newPKCE() (verifier, challenge string, err error) {
	verifier, err = randomString(48)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
