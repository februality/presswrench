package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
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
	// pending != nil this process holds the account lock in held (unless a
	// user command took it over; see flushOnce), and spent is the refresh
	// token it exchanged (what the store still holds).
	pending  *creds.Record
	spent    string
	held     *lockfile.Lock
	reason   string      // held's lock reason
	retry    *time.Timer // background save retry
	flushing bool        // a flush is running without s.mu (see flushUnlocked)
	idle     *sync.Cond  // on s.mu; broadcast when flushing ends
	closed   bool
}

// errSessionClosed is returned by Token after Close.
var errSessionClosed = errors.New("PressWrench is shutting down. Retry once your MCP client has restarted it.")

// relockWait bounds how long a session whose lock a user command took over
// waits to take it back before discarding its unsaved tokens.
var relockWait = 2 * time.Second

// saveBackoff is the wait before each retry of a save after a refresh
// (len+1 attempts in all); tests zero it.
var saveBackoff = []time.Duration{200 * time.Millisecond, time.Second}

// pendingRetry is how often an unsaved session retries its save in the
// background; tests shrink it.
var pendingRetry = 30 * time.Second

// NewSession binds a session to an account. store may be nil when
// PRESSWRENCH_ACCESS_TOKEN is set.
func NewSession(store creds.Store, account, authURL string) *Session {
	s := &Session{
		store:    store,
		account:  account,
		authURL:  authURL,
		http:     defaultHTTPClient(),
		now:      time.Now,
		envToken: os.Getenv(EnvAccessToken),
	}
	s.idle = sync.NewCond(&s.mu)
	return s
}

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

// Identity returns the stored "Name <email>" of the signed-in user, or ""
// when it isn't known or the store can't be read.
func (s *Session) Identity() string {
	if s.store == nil {
		return ""
	}
	r, _ := s.store.Load(s.account)
	return r.Identity
}

// Token returns a valid access token, refreshing if necessary.
//
// While a rotated session is unsaved (see persist), Token never touches
// the store: it serves the in-memory access token, or refreshes with the
// in-memory refresh token under the account lock it still holds. Saving is
// left to the background retry, so a hung keychain never stalls it.
func (s *Session) Token(ctx context.Context) (string, error) {
	if s.envToken != "" {
		return s.envToken, nil
	}
	if s.store == nil {
		return "", &LoginRequiredError{Account: s.account}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", errSessionClosed
	}

	now := s.now()
	if s.validLocked(now) {
		return s.access, nil
	}
	if s.pending != nil {
		for s.flushing { // never refresh alongside a save in flight
			s.idle.Wait()
		}
		if s.closed {
			return "", errSessionClosed
		}
		if s.pending != nil && !s.held.Held() {
			// A user command took the lock: settle before spending a
			// refresh token (which a partial save may have stored).
			s.flushUnlocked(ctx)
			if s.closed {
				return "", errSessionClosed
			}
		}
		now = s.now() // we may have waited
		if s.validLocked(now) {
			return s.access, nil // another caller refreshed, or the store is newer
		}
		if s.pending != nil {
			return s.refreshPendingLocked(ctx, now)
		}
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

func (s *Session) validLocked(now time.Time) bool {
	return s.access != "" && s.access != s.bad && now.Before(s.expiry.Add(-refreshMargin))
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

// persist applies a token response to base (the stored record the refresh
// started from), adopts the new tokens in memory, and saves them, retrying
// with saveBackoff. lock is the account lock, just taken.
//
// A failed save leaves this process the only holder of a rotated session:
// the record is kept in s.pending and the lock in s.held, with a reason for
// waiters, so no sibling spends the stale stored refresh token. The save is
// retried by Token and every pendingRetry. It reports whether it kept the
// lock; when it didn't, the caller releases it.
func (s *Session) persist(ctx context.Context, base creds.Record, tr *TokenResponse, now time.Time, lock *lockfile.Lock) (keep bool) {
	r := base
	applyTokens(&r, tr, now, false)
	s.access = tr.AccessToken
	s.expiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	s.bad = ""

	err := s.saveWithRetry(ctx, r)
	if err == nil {
		return false
	}
	slog.Error("Could not save the refreshed Pressable session; keeping it in memory and holding the account lock until it saves",
		"account", AccountLabel(s.account), "error", Explain(err))
	s.pending, s.spent, s.held = &r, base.RefreshToken, lock
	s.reason = fmt.Sprintf("%saccount %s: %s Sign in again with `%s` to replace it.",
		unsavedPrefix, AccountLabel(s.account), sentence(Explain(err)), LoginCommand(s.account))
	if serr := s.held.SetReason(s.reason); serr != nil {
		slog.Debug("could not annotate the account lock", "error", serr)
	}
	s.scheduleRetryLocked()
	return true
}

// sentence ends msg with a full stop if it has no final punctuation.
func sentence(msg string) string {
	if msg == "" || strings.ContainsAny(msg[len(msg)-1:], ".!?") {
		return msg
	}
	return msg + "."
}

// saveWithRetry saves r, retrying after each saveBackoff delay. It stops
// early on permanent errors, and on Locked/Timeout: those already waited
// (up to the keychain timeout) and a retry would only stall the server.
func (s *Session) saveWithRetry(ctx context.Context, r creds.Record) error {
	err := s.store.Save(s.account, r)
	for _, d := range saveBackoff {
		if k := creds.KindOf(err); err == nil || creds.Permanent(err) || k == creds.KindTimeout || k == creds.KindLocked {
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

// refreshPendingLocked refreshes an unsaved session with its in-memory
// refresh token (the store's one is already spent) under the lock still in
// s.held. The result replaces pending and the background retry is brought
// forward to save it.
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
		s.access, s.expiry = "", time.Time{}
		return "", &LoginRequiredError{Account: s.account, Expired: true}
	}
	if err != nil {
		return "", err // still pending, lock still held
	}
	applyTokens(&p, tr, now, false)
	s.pending = &p
	s.access = tr.AccessToken
	s.expiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	s.bad = ""
	if s.retry != nil {
		s.retry.Reset(0)
	}
	return s.access, nil
}

// flushResult is the outcome of one attempt to save a pending session.
type flushResult int

const (
	flushPending    flushResult = iota // still unsaved; keep retrying
	flushSaved                         // the store holds it
	flushSuperseded                    // the store holds a newer session
	flushLost                          // the lock was taken over and not regained
)

// flushOnce tries once to save p. It touches the store and the lock but no
// Session state, so the background retry can run it without s.mu.
//
// If a user command (login, logout, remove) took the lock over, it takes
// the lock back (relockWait) or gives up. It then re-reads the store: the
// store already holding p counts as saved (a save that wrote the record but
// then failed); a refresh token other than spent means someone wrote a
// newer session, which is never overwritten; a damaged record is no one's
// and is overwritten. It returns the lock now held for p.
func (s *Session) flushOnce(ctx context.Context, p *creds.Record, spent string, held *lockfile.Lock, reason string) (flushResult, *lockfile.Lock) {
	if !held.Held() {
		held.Release() // stops its heartbeat; never touches the new holder's file
		l, err := lockAccountWait(ctx, s.account, relockWait, nil)
		if err != nil {
			return flushLost, nil
		}
		held = l
		if serr := held.SetReason(reason); serr != nil {
			slog.Debug("could not annotate the account lock", "error", serr)
		}
	}
	stored, err := s.store.Load(s.account)
	kind := creds.KindOf(err)
	switch {
	case err == nil && stored.RefreshToken == p.RefreshToken:
		return flushSaved, held
	case err == nil && stored.RefreshToken == spent, err != nil && kind == creds.KindCorrupt:
		// Still ours: save over it.
	case err == nil, kind == creds.KindNotFound, kind == creds.KindNewerFormat:
		return flushSuperseded, held
	default:
		slog.Debug("still can't read the session store", "account", AccountLabel(s.account), "error", Explain(err))
		return flushPending, held
	}
	if err := s.store.Save(s.account, *p); err != nil {
		slog.Debug("still can't save the refreshed session", "account", AccountLabel(s.account), "error", Explain(err))
		return flushPending, held
	}
	return flushSaved, held
}

// flushUnlocked runs one flushOnce of the pending session without s.mu, so
// slow keychain calls never block Token serving the in-memory token, and
// applies its outcome. The caller holds s.mu (released meanwhile and held
// again on return), s.pending != nil and !s.flushing. While flushing, Token
// doesn't refresh and Close leaves the lock to the settle step, so nothing
// replaces pending underneath it.
func (s *Session) flushUnlocked(ctx context.Context) {
	p, spent, held, reason := s.pending, s.spent, s.held, s.reason
	s.flushing = true
	s.mu.Unlock()
	res, lock := s.flushOnce(ctx, p, spent, held, reason)
	s.mu.Lock()
	s.flushing = false
	s.idle.Broadcast()
	s.settleFlushLocked(p, res, lock)
}

// settleFlushLocked applies a flush of p that returned res holding lock.
func (s *Session) settleFlushLocked(p *creds.Record, res flushResult, lock *lockfile.Lock) {
	if s.pending != p { // settled while the flush ran
		if lock != nil && lock != s.held {
			lock.Release()
		}
		return
	}
	if lock != s.held {
		s.held.Release() // lost; Release leaves the new holder's file alone
		s.held = lock
	}
	if s.closed { // Close left the release to us
		s.dropPendingLocked()
		return
	}
	switch res {
	case flushSaved:
		slog.Info("Saved the refreshed Pressable session", "account", AccountLabel(s.account))
		s.dropPendingLocked()
	case flushSuperseded:
		slog.Warn("A newer Pressable session was stored while ours was unsaved; discarding ours",
			"account", AccountLabel(s.account))
		s.dropPendingLocked()
		s.access, s.expiry = "", time.Time{}
	case flushLost:
		// A sign-in, sign-out or remove holds the account; it decides
		// what's stored. The access token stays usable until it expires;
		// the next refresh goes through the store.
		slog.Warn("Another PressWrench command took over the account while our refreshed session was unsaved; discarding it",
			"account", AccountLabel(s.account))
		s.dropPendingLocked()
	}
}

// dropPendingLocked forgets the pending record, stops the retry timer and
// releases the account lock. In-memory access tokens are left to the
// caller.
func (s *Session) dropPendingLocked() {
	s.pending, s.spent, s.reason = nil, "", ""
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
	// The tick reads t only under s.mu, which we hold until t is set.
	t = time.AfterFunc(pendingRetry, func() { s.retryTick(func() *time.Timer { return t }) })
	s.retry = t
}

// retryTick is one background save attempt, the only retry path while a
// session is unsaved.
func (s *Session) retryTick(timer func() *time.Timer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := timer()
	if s.retry != t || s.pending == nil || s.closed {
		return
	}
	if !s.flushing { // else Token is settling a lost lock; try again later
		s.flushUnlocked(context.Background())
	}
	if s.pending != nil && s.retry == t {
		t.Reset(pendingRetry)
	}
}

// Close stops the background save retry and releases the account lock a
// pending session holds; unsaved tokens are lost. If a background save is
// in flight, the lock is released when it ends (never while a write may
// still land); if the process exits first, the lock goes stale. Idempotent,
// safe when nothing is pending or Token was never called; it waits for an
// in-flight Token call. Token fails after Close.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil && !s.closed {
		slog.Error("Exiting with a refreshed Pressable session that was never saved; you may need to sign in again",
			"account", AccountLabel(s.account), "command", LoginCommand(s.account))
	}
	s.closed = true
	if s.flushing {
		if s.retry != nil {
			s.retry.Stop()
			s.retry = nil
		}
		return
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
