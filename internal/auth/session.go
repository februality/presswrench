package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/februality/presswrench/internal/creds"
	"github.com/februality/presswrench/internal/lockfile"
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

	// A refreshed session that couldn't be saved (see persist). While
	// pending != nil this process holds the account lock in held, and
	// spent is the refresh token it exchanged (what the store still holds).
	pending *creds.Record
	spent   string
	held    *lockfile.Lock
	retry   *time.Timer // background save retry
	closed  bool
}

// saveBackoff is the wait before each retry of a save after a refresh
// (len+1 attempts in all); tests zero it.
var saveBackoff = []time.Duration{200 * time.Millisecond, time.Second}

// pendingRetry is how often an unsaved session retries its save in the
// background; tests shrink it.
var pendingRetry = 30 * time.Second

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
//
// While a rotated session is unsaved (see persist), Token first retries the
// save, serves the in-memory access token, and refreshes with the in-memory
// refresh token under the account lock it still holds.
func (s *Session) Token(ctx context.Context) (string, error) {
	if s.envToken != "" {
		return s.envToken, nil
	}
	if s.store == nil {
		return "", &LoginRequiredError{Account: s.account}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pending != nil {
		s.flushLocked()
	}
	now := s.now()
	if s.access != "" && s.access != s.bad && now.Before(s.expiry.Add(-refreshMargin)) {
		return s.access, nil
	}
	if s.pending != nil {
		return s.refreshPendingLocked(ctx, now)
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
	// From here on every return releases the lock, except persist keeping
	// it for a session it couldn't save.
	tok, keep, err := s.refreshLocked(ctx, now, lock)
	if !keep {
		lock.Release()
	}
	return tok, err
}

// refreshLocked refreshes from the stored refresh token. The caller holds
// lock; keep reports that persist took ownership of it.
func (s *Session) refreshLocked(ctx context.Context, now time.Time, lock *lockfile.Lock) (tok string, keep bool, err error) {
	// A sibling may have refreshed while we waited for the lock.
	if tok, exp, ok := s.loadStoredAccess(); ok && tok != s.bad && now.Before(exp.Add(-refreshMargin)) {
		s.access, s.expiry = tok, exp
		return tok, false, nil
	}

	stored, err := s.store.Load(s.account)
	if err != nil && creds.KindOf(err) != creds.KindNotFound {
		return "", false, err
	}
	if err != nil || stored.ClientID == "" || stored.RefreshToken == "" {
		return "", false, &LoginRequiredError{Account: s.account}
	}
	clientID, refresh := stored.ClientID, stored.RefreshToken
	tr, err := Refresh(ctx, s.http, s.authURL, clientID, refresh)
	var oe *OAuthError
	if errors.As(err, &oe) && oe.Code == "invalid_grant" {
		// Belt and braces for a process that refreshed without the lock
		// (an older binary): use whatever it stored.
		if tok, exp, ok := s.loadStoredAccess(); ok && tok != s.bad && now.Before(exp.Add(-refreshMargin)) {
			s.access, s.expiry = tok, exp
			return tok, false, nil
		}
		if again, gerr := s.store.Load(s.account); gerr == nil && again.RefreshToken != "" && again.RefreshToken != refresh {
			stored = again
			tr, err = Refresh(ctx, s.http, s.authURL, clientID, again.RefreshToken)
		}
		if errors.As(err, &oe) && oe.Code == "invalid_grant" {
			return "", false, &LoginRequiredError{Account: s.account, Expired: true}
		}
	}
	if err != nil {
		return "", false, err
	}
	keep = s.persist(ctx, stored, tr, now, lock)
	return s.access, keep, nil
}

// refreshPendingLocked refreshes an unsaved session with its in-memory
// refresh token; the store's one is already spent. The account lock is
// still held (s.held) from the refresh that produced it.
func (s *Session) refreshPendingLocked(ctx context.Context, now time.Time) (string, error) {
	p := *s.pending
	tr, err := Refresh(ctx, s.http, s.authURL, p.ClientID, p.RefreshToken)
	var oe *OAuthError
	if errors.As(err, &oe) && oe.Code == "invalid_grant" {
		// Pressable revoked the session we couldn't save; nothing is left
		// to protect, so let others at the store (and its sign-in prompt).
		slog.Error("Pressable rejected the unsaved session's refresh token; discarding it",
			"account", AccountLabel(s.account))
		s.dropPendingLocked()
		return "", &LoginRequiredError{Account: s.account, Expired: true}
	}
	if err != nil {
		return "", err
	}
	s.persist(ctx, p, tr, now, s.held)
	return s.access, nil
}

// persist applies a token response to base (the record the refresh started
// from), adopts the new tokens in memory, and saves them, retrying with
// saveBackoff unless the error is permanent. lock is the held account lock.
//
// A failed save leaves this process the only holder of a rotated session:
// the record is kept in s.pending, the lock in s.held (with a reason for
// waiters) so no sibling spends the stale stored refresh token, and the save
// is retried on later Token calls and every pendingRetry. It reports whether
// it kept the lock; when it didn't, the caller releases it (or, for a
// pending session, it was released here).
func (s *Session) persist(ctx context.Context, base creds.Record, tr *TokenResponse, now time.Time, lock *lockfile.Lock) (keep bool) {
	r := base
	applyTokens(&r, tr, now, false)
	s.access = tr.AccessToken
	s.expiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	s.bad = ""

	err := s.saveWithRetry(ctx, r)
	if err == nil {
		if s.pending != nil {
			s.dropPendingLocked()
		}
		return false
	}
	slog.Error("Could not save the refreshed Pressable session; keeping it in memory and holding the account lock until it saves",
		"account", AccountLabel(s.account), "error", Explain(err))
	if s.closed {
		// Token after Close: nobody will retry, so don't strand the lock.
		// (Close dropped any pending session, so the caller owns lock.)
		return false
	}
	if s.pending == nil {
		s.spent = base.RefreshToken // still what the store holds
		s.held = lock
	}
	s.pending = &r
	if serr := s.held.SetReason(fmt.Sprintf("account %s: %s", AccountLabel(s.account), Explain(err))); serr != nil {
		slog.Debug("could not annotate the account lock", "error", serr)
	}
	s.scheduleRetryLocked()
	return true
}

// saveWithRetry saves r, retrying after each saveBackoff delay unless the
// error is permanent or ctx ends.
func (s *Session) saveWithRetry(ctx context.Context, r creds.Record) error {
	err := s.store.Save(s.account, r)
	for _, d := range saveBackoff {
		if err == nil || creds.Permanent(err) {
			break
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
		err = s.store.Save(s.account, r)
	}
	return err
}

// flushLocked tries once to save the pending session. It first re-reads the
// store: if the stored refresh token is no longer the one this process
// spent, someone (a login) wrote a newer session, so the pending one is
// discarded rather than overwriting it. Either way a settled session
// releases the lock. The caller holds s.mu and s.pending != nil.
func (s *Session) flushLocked() {
	stored, err := s.store.Load(s.account)
	switch kind := creds.KindOf(err); {
	case err == nil && stored.RefreshToken == s.spent, kind == creds.KindCorrupt:
		// Still ours (a damaged record is no one's): save over it.
	case err == nil, kind == creds.KindNotFound, kind == creds.KindNewerFormat:
		slog.Warn("The stored Pressable session changed while ours was unsaved; discarding ours",
			"account", AccountLabel(s.account))
		s.dropPendingLocked()
		s.access, s.expiry = "", time.Time{}
		return
	default:
		slog.Debug("still can't read the session store", "account", AccountLabel(s.account), "error", Explain(err))
		return
	}
	if err := s.store.Save(s.account, *s.pending); err != nil {
		slog.Debug("still can't save the refreshed session", "account", AccountLabel(s.account), "error", Explain(err))
		return
	}
	slog.Info("Saved the refreshed Pressable session", "account", AccountLabel(s.account))
	s.dropPendingLocked()
}

// dropPendingLocked forgets the pending record, stops the retry timer and
// releases the account lock. In-memory access tokens are left to the
// caller.
func (s *Session) dropPendingLocked() {
	s.pending, s.spent = nil, ""
	if s.retry != nil {
		s.retry.Stop()
		s.retry = nil
	}
	if s.held != nil {
		s.held.Release()
		s.held = nil
	}
}

// scheduleRetryLocked arms the background save retry if it isn't already.
func (s *Session) scheduleRetryLocked() {
	if s.retry != nil || s.closed {
		return
	}
	var t *time.Timer
	t = time.AfterFunc(pendingRetry, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.retry != t { // stopped or replaced after this tick fired
			return
		}
		s.flushLocked()
		if s.pending != nil && s.retry == t {
			t.Reset(pendingRetry)
		}
	})
	s.retry = t
}

// Close stops the background save retry and releases the account lock a
// pending session holds; unsaved tokens are lost. Idempotent, safe when
// nothing is pending or Token was never called; it waits for an in-flight
// Token call.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.pending != nil {
		slog.Error("Exiting with a refreshed Pressable session that was never saved; you may need to sign in again",
			"account", AccountLabel(s.account), "command", LoginCommand(s.account))
	}
	s.dropPendingLocked()
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
