package auth

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/februality/presswrench/internal/creds"
)

// refreshMargin: treat a token as expired this long before it actually is,
// so a request never races the expiry.
const refreshMargin = 2 * time.Minute

// EnvAccessToken, when set, is used verbatim as the bearer token and the
// stored session is ignored. No refresh happens.
const EnvAccessToken = "PRESSWRENCH_ACCESS_TOKEN"

// Session hands out valid access tokens for one account, refreshing and
// persisting them as needed.
//
// Several `serve` processes (one per open MCP client) share one stored
// session. The access token is cached in the store so they don't all
// refresh; and if Pressable rotates refresh tokens, a refresh that fails
// with invalid_grant re-reads the store once in case a sibling process
// already rotated it.
type Session struct {
	store   creds.Store
	account string
	authURL string
	http    *http.Client
	now     func() time.Time

	mu       sync.Mutex
	envToken string
	access   string
	expiry   time.Time
	bad      string // token the gateway rejected; never hand it out again
}

// NewSession binds a session to an account. store may be nil when
// PRESSWRENCH_ACCESS_TOKEN is set.
func NewSession(store creds.Store, account, authURL string) *Session {
	return &Session{
		store:    store,
		account:  account,
		authURL:  authURL,
		http:     defaultHTTPClient(),
		now:      time.Now,
		envToken: os.Getenv(EnvAccessToken),
	}
}

// Source reports where tokens come from.
func (s *Session) Source() creds.Source {
	if s.envToken != "" {
		return creds.SourceEnv
	}
	if s.store == nil {
		return creds.SourceNotFound
	}
	if _, err := s.store.GetFor(s.account, creds.KeyRefreshToken); err != nil {
		return creds.SourceNotFound
	}
	return s.store.Backend()
}

// Identity returns the stored "Name <email>" of the signed-in user, or "".
func (s *Session) Identity() string {
	if s.store == nil {
		return ""
	}
	v, _ := s.store.GetFor(s.account, creds.KeyIdentity)
	return v
}

// Token returns a valid access token, refreshing if necessary.
func (s *Session) Token(ctx context.Context) (string, error) {
	if s.envToken != "" {
		return s.envToken, nil
	}
	if s.store == nil {
		return "", ErrLoginRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.access != "" && s.access != s.bad && now.Before(s.expiry.Add(-refreshMargin)) {
		return s.access, nil
	}

	// Another process may have refreshed already.
	if tok, exp, ok := s.loadStoredAccess(); ok && tok != s.bad && now.Before(exp.Add(-refreshMargin)) {
		s.access, s.expiry = tok, exp
		return tok, nil
	}

	// Serialize refreshes across processes so two servers never spend the
	// same refresh token (a rotating server would reject the second, or
	// revoke the whole token family on reuse).
	unlock, err := acquireRefreshLock(ctx, s.account)
	if err != nil {
		return "", err
	}
	defer unlock()

	// A sibling may have refreshed while we waited for the lock.
	if tok, exp, ok := s.loadStoredAccess(); ok && tok != s.bad && now.Before(exp.Add(-refreshMargin)) {
		s.access, s.expiry = tok, exp
		return tok, nil
	}

	clientID, err := s.store.GetFor(s.account, creds.KeyOAuthClientID)
	if err != nil {
		return "", ErrLoginRequired
	}
	refresh, err := s.store.GetFor(s.account, creds.KeyRefreshToken)
	if err != nil {
		return "", ErrLoginRequired
	}
	tr, err := Refresh(ctx, s.http, s.authURL, clientID, refresh)
	var oe *OAuthError
	if errors.As(err, &oe) && oe.Code == "invalid_grant" {
		// Belt and braces for a process that refreshed without the lock
		// (an older binary): use whatever it stored.
		if tok, exp, ok := s.loadStoredAccess(); ok && tok != s.bad && now.Before(exp.Add(-refreshMargin)) {
			s.access, s.expiry = tok, exp
			return tok, nil
		}
		if again, gerr := s.store.GetFor(s.account, creds.KeyRefreshToken); gerr == nil && again != refresh {
			tr, err = Refresh(ctx, s.http, s.authURL, clientID, again)
		}
		if errors.As(err, &oe) && oe.Code == "invalid_grant" {
			return "", ErrLoginRequired
		}
	}
	if err != nil {
		return "", err
	}
	if err := SaveTokens(s.store, s.account, tr, now); err != nil {
		return "", err
	}
	s.access = tr.AccessToken
	s.expiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	s.bad = ""
	return s.access, nil
}

// Invalidate marks a token as rejected (HTTP 401) so the next Token call
// refreshes instead of returning it.
func (s *Session) Invalidate(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bad = token
	if s.access == token {
		s.access = ""
	}
}

func (s *Session) loadStoredAccess() (string, time.Time, bool) {
	tok, err := s.store.GetFor(s.account, creds.KeyAccessToken)
	if err != nil || tok == "" {
		return "", time.Time{}, false
	}
	raw, err := s.store.GetFor(s.account, creds.KeyAccessExpiry)
	if err != nil {
		return "", time.Time{}, false
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	return tok, time.Unix(secs, 0), true
}

// SaveTokens persists a token response. The refresh token is only
// overwritten when Pressable issued a new one.
func SaveTokens(store creds.Store, account string, tr *TokenResponse, now time.Time) error {
	if tr.RefreshToken != "" {
		if err := store.SetFor(account, creds.KeyRefreshToken, tr.RefreshToken); err != nil {
			return err
		}
	}
	if err := store.SetFor(account, creds.KeyAccessToken, tr.AccessToken); err != nil {
		return err
	}
	exp := now.Add(time.Duration(tr.ExpiresIn) * time.Second).Unix()
	if err := store.SetFor(account, creds.KeyAccessExpiry, strconv.FormatInt(exp, 10)); err != nil {
		return err
	}
	if id := tr.Identity(); id != "" {
		if err := store.SetFor(account, creds.KeyIdentity, id); err != nil {
			return err
		}
	}
	return nil
}
