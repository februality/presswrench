package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/februality/presswrench/internal/creds"
)

// SignIn runs the full interactive login for an account and persists the
// session: it registers this install's OAuth client on first use, runs the
// browser flow, and stores the tokens. If the stored client was deleted
// server-side, it registers a fresh one and retries once.
func SignIn(ctx context.Context, store creds.Store, account string, o LoginOptions) (*TokenResponse, error) {
	stored, err := store.Load(account)
	clientID := stored.ClientID
	fresh := false
	if err != nil || clientID == "" {
		if clientID, err = registerAndStore(ctx, store, account, o); err != nil {
			return nil, err
		}
		fresh = true
	}
	o.ClientID = clientID
	tr, err := Login(ctx, o)
	if !fresh && isInvalidClient(err) {
		if clientID, err = registerAndStore(ctx, store, account, o); err != nil {
			return nil, err
		}
		o.ClientID = clientID
		tr, err = Login(ctx, o)
	}
	if err != nil {
		return nil, err
	}
	// A new login replaces any previous session wholesale.
	if err := saveTokens(store, account, tr, time.Now(), true); err != nil {
		return nil, err
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

func registerAndStore(ctx context.Context, store creds.Store, account string, o LoginOptions) (string, error) {
	clientID, err := Register(ctx, o.HTTP, o.AuthURL)
	if err != nil {
		return "", err
	}
	r, err := loadForUpdate(store, account)
	if err != nil {
		return "", err
	}
	r.ClientID = clientID
	if err := store.Save(account, r); err != nil {
		return "", err
	}
	return clientID, nil
}

// SignOut revokes the stored tokens (best effort) and clears the session,
// saving a record with only the OAuth client id so a later login reuses
// the registration.
func SignOut(ctx context.Context, store creds.Store, account, authURL string) error {
	r, err := store.Load(account)
	if errors.Is(err, creds.ErrNotFound) {
		return nil
	}
	if err != nil {
		if r, err = loadForUpdate(store, account); err != nil {
			return err
		}
	}
	if r.ClientID != "" {
		for _, tok := range []string{r.RefreshToken, r.AccessToken} {
			if tok != "" {
				_ = Revoke(ctx, nil, authURL, r.ClientID, tok)
			}
		}
	}
	if r.ClientID == "" {
		return store.Delete(account)
	}
	return store.Save(account, creds.Record{ClientID: r.ClientID})
}
