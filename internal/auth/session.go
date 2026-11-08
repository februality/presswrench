package auth

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/februality/presswrench/internal/creds"
)

// refreshMargin: treat a token as expired this long before it actually is,
// so a request never races the expiry.
const refreshMargin = 2 * time.Minute

// EnvAccessToken names the env var whose value, when set, is used verbatim
// as the bearer token and the stored session is ignored. No refresh happens.
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
// State reports where the session comes from, or why there is none. It
// only inspects the environment and the store; it never refreshes.
func (s *Session) State() (creds.Source, error) {
	if s.envToken != "" {
		return creds.SourceEnv, nil
	}
	if s.store == nil {
		return creds.SourceNotFound, &LoginRequiredError{Account: s.account}
	}
	r, err := s.store.Load(s.account)
	if err != nil {
		if creds.KindOf(err) == creds.KindNotFound {
			err = &LoginRequiredError{Account: s.account}
		}
		return creds.SourceNotFound, err
	}
	if !r.SignedIn() {
		return creds.SourceNotFound, &LoginRequiredError{Account: s.account}
	}
	return s.store.Info().Source, nil
}

func (s *Session) Identity() string {
	if s.store == nil {
		return ""
	}
	r, _ := s.store.Load(s.account)
	return r.Identity
}

// Token returns a valid access token, refreshing if necessary.
func (s *Session) Token(ctx context.Context) (string, error) {
	if s.envToken != "" {
		return s.envToken, nil
	}
	if s.store == nil {
		return "", &LoginRequiredError{Account: s.account}
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
	lock, err := lockAccount(ctx, s.account)
	if err != nil {
		return "", err
	}
	defer lock.Release()

	// A sibling may have refreshed while we waited for the lock.
	if tok, exp, ok := s.loadStoredAccess(); ok && tok != s.bad && now.Before(exp.Add(-refreshMargin)) {
		s.access, s.expiry = tok, exp
		return tok, nil
	}

	stored, err := s.store.Load(s.account)
	if err != nil && creds.KindOf(err) != creds.KindNotFound {
		return "", err
	}
	if err != nil || stored.ClientID == "" || stored.RefreshToken == "" {
		return "", &LoginRequiredError{Account: s.account}
	}
	clientID, refresh := stored.ClientID, stored.RefreshToken
	tr, err := Refresh(ctx, s.http, s.authURL, clientID, refresh)
	var oe *OAuthError
	if errors.As(err, &oe) && oe.Code == "invalid_grant" {
		// Belt and braces for a process that refreshed without the lock
		// (an older binary): use whatever it stored.
		if tok, exp, ok := s.loadStoredAccess(); ok && tok != s.bad && now.Before(exp.Add(-refreshMargin)) {
			s.access, s.expiry = tok, exp
			return tok, nil
		}
		if again, gerr := s.store.Load(s.account); gerr == nil && again.RefreshToken != "" && again.RefreshToken != refresh {
			tr, err = Refresh(ctx, s.http, s.authURL, clientID, again.RefreshToken)
		}
		if errors.As(err, &oe) && oe.Code == "invalid_grant" {
			return "", &LoginRequiredError{Account: s.account, Expired: true}
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

// loadStoredAccess returns the stored access token and its expiry. A
// missing expiry reads as the Unix epoch, i.e. expired, so it refreshes.
func (s *Session) loadStoredAccess() (string, time.Time, bool) {
	r, err := s.store.Load(s.account)
	if err != nil || r.AccessToken == "" {
		return "", time.Time{}, false
	}
	return r.AccessToken, time.Unix(r.AccessExpiry, 0), true
}

// SaveTokens persists a token response in one write: it loads the record,
// replaces the token fields (the refresh token only when Pressable issued a
// new one) and the identity (when the response carries one), and saves it.
// The caller holds the account lock.
func SaveTokens(store creds.Store, account string, tr *TokenResponse, now time.Time) error {
	r, err := loadForUpdate(store, account)
	if err != nil {
		return err
	}
	applyTokens(&r, tr, now, false)
	return store.Save(account, r)
}

// applyTokens copies a token response into r: the refresh token only when
// Pressable issued a new one, the identity when the response carries one.
// replace (a new login) drops the previous identity first.
func applyTokens(r *creds.Record, tr *TokenResponse, now time.Time, replace bool) {
	if tr.RefreshToken != "" {
		r.RefreshToken = tr.RefreshToken
	}
	r.AccessToken = tr.AccessToken
	r.AccessExpiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second).Unix()
	if replace {
		r.Identity = ""
	}
	if id := tr.Identity(); id != "" {
		r.Identity = id
	}
}

// loadForUpdate loads the record a write will modify. A missing, corrupt or
// newer-format record starts from empty (the write replaces it); any other
// error (store unreachable) is returned.
func loadForUpdate(store creds.Store, account string) (creds.Record, error) {
	r, err := store.Load(account)
	switch creds.KindOf(err) {
	case creds.KindNotFound, creds.KindCorrupt, creds.KindNewerFormat:
		return creds.Record{}, nil
	}
	if err != nil {
		return creds.Record{}, err
	}
	return r, nil
}
