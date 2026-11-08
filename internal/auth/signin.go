package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/februality/presswrench/internal/creds"
)

// SignIn runs the full interactive login for an account and persists the
// session: it registers this install's OAuth client on first use, runs the
// browser flow, and stores the tokens. If the stored client was deleted
// server-side, it registers a fresh one and retries once.
//
// The account lock is held only for the two short store steps (client id,
// then the final save), never while the user is in the browser: holding it
// for minutes would fail every sibling refresh. A login interrupted in the
// browser leaves a record with only the client id, which the next login
// reuses.
func SignIn(ctx context.Context, store creds.Store, account string, o LoginOptions) (*TokenResponse, error) {
	clientID, fresh, err := ensureClient(ctx, store, account, o, "")
	if err != nil {
		return nil, err
	}
	o.ClientID = clientID
	tr, err := Login(ctx, o)
	if !fresh && isInvalidClient(err) {
		if clientID, _, err = ensureClient(ctx, store, account, o, clientID); err != nil {
			return nil, err
		}
		o.ClientID = clientID
		tr, err = Login(ctx, o)
	}
	if err != nil {
		return nil, err
	}
	if err := storeLogin(ctx, store, account, clientID, tr); err != nil {
		return nil, err
	}
	if err := creds.RememberBackend(store); err != nil {
		slog.Warn("could not remember the credential store", "error", err)
	}
	return tr, nil
}

// isInvalidClient matches both a token-endpoint invalid_client error and an
// authorize redirect carrying error=invalid_client.
func isInvalidClient(err error) bool {
	var oe *OAuthError
	if errors.As(err, &oe) {
		return oe.Code == "invalid_client"
	}
	return err != nil && strings.Contains(err.Error(), "invalid_client")
}

// ensureClient returns the OAuth client id to log in with, under the
// account lock. It registers (and saves) a new client only when there is no
// usable record: none stored, no client id in it, or one that is corrupt or
// from a newer PressWrench (Explain tells those users to sign in again, so
// login must be able to replace it). Any other store error (locked, denied,
// timed out, unavailable) is returned as is: registering would leave an
// orphan client on Pressable and could overwrite a session we can't read.
//
// rejected is a client id Pressable just refused; it is replaced unless
// another process already stored a different one meanwhile.
func ensureClient(ctx context.Context, store creds.Store, account string, o LoginOptions, rejected string) (clientID string, fresh bool, err error) {
	lock, err := lockAccountForUser(ctx, account)
	if err != nil {
		return "", false, err
	}
	defer lock.Release()

	r, err := store.Load(account)
	switch creds.KindOf(err) {
	case creds.KindNotFound, creds.KindCorrupt, creds.KindNewerFormat:
		r = creds.Record{}
	default:
		if err != nil {
			return "", false, err
		}
	}
	if r.ClientID != "" && r.ClientID != rejected {
		return r.ClientID, false, nil
	}
	clientID, err = Register(ctx, o.HTTP, o.AuthURL)
	if err != nil {
		return "", false, err
	}
	// Any tokens in the old record belong to no client or to the rejected
	// one, so they're useless: keep only the new client id. A login
	// interrupted after this leaves a client-only, unlisted record.
	if err := store.Save(account, creds.Record{ClientID: clientID}); err != nil {
		return "", false, err
	}
	return clientID, true, nil
}

// storeLogin saves a completed login under the account lock: it re-reads
// the record (another process may have written it while the user was in the
// browser) and replaces the session wholesale. The client id is set to the
// one the tokens were issued to, since a refresh only works with that one.
func storeLogin(ctx context.Context, store creds.Store, account, clientID string, tr *TokenResponse) error {
	lock, err := lockAccountForUser(ctx, account)
	if err != nil {
		return err
	}
	defer lock.Release()

	r, err := loadForUpdate(store, account)
	if err != nil {
		return err
	}
	r.ClientID = clientID
	applyTokens(&r, tr, time.Now(), true)
	return store.Save(account, r)
}

// SignOut revokes the stored tokens (best effort) and clears the session,
// saving a record with only the OAuth client id so a later login reuses
// the registration. It holds the account lock throughout.
func SignOut(ctx context.Context, store creds.Store, account, authURL string) error {
	lock, err := lockAccountForUser(ctx, account)
	if err != nil {
		return err
	}
	defer lock.Release()

	r, err := store.Load(account)
	if errors.Is(err, creds.ErrNotFound) {
		return nil
	}
	if err != nil {
		if r, err = loadForUpdate(store, account); err != nil {
			return err
		}
	}
	revokeAll(ctx, authURL, r)
	if r.ClientID == "" {
		return store.Delete(account)
	}
	return store.Save(account, creds.Record{ClientID: r.ClientID})
}

// RemoveAccount deletes an account's stored record entirely (client id
// included), under the account lock. Revoking its tokens is best effort and
// skipped when authURL is empty or the record can't be read; a failed
// delete is returned. A missing record is not an error.
func RemoveAccount(ctx context.Context, store creds.Store, account, authURL string) error {
	lock, err := lockAccountForUser(ctx, account)
	if err != nil {
		return err
	}
	defer lock.Release()

	if r, err := store.Load(account); err == nil {
		revokeAll(ctx, authURL, r)
	}
	return store.Delete(account)
}

// revokeAll revokes the record's tokens server-side, best effort.
func revokeAll(ctx context.Context, authURL string, r creds.Record) {
	if authURL == "" || r.ClientID == "" {
		return
	}
	for _, tok := range []string{r.RefreshToken, r.AccessToken} {
		if tok != "" {
			_ = Revoke(ctx, nil, authURL, r.ClientID, tok)
		}
	}
}
