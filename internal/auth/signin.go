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
	clientID, err := store.GetFor(account, creds.KeyOAuthClientID)
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
	_ = store.DeleteFor(account, creds.KeyIdentity)
	if err := SaveTokens(store, account, tr, time.Now()); err != nil {
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
	if err := store.SetFor(account, creds.KeyOAuthClientID, clientID); err != nil {
		return "", err
	}
	return clientID, nil
}

// SignOut revokes the stored tokens (best effort) and deletes the session.
// The OAuth client registration is kept so a later login reuses it.
func SignOut(ctx context.Context, store creds.Store, account, authURL string) error {
	clientID, _ := store.GetFor(account, creds.KeyOAuthClientID)
	if clientID != "" {
		for _, k := range []string{creds.KeyRefreshToken, creds.KeyAccessToken} {
			if tok, err := store.GetFor(account, k); err == nil && tok != "" {
				_ = Revoke(ctx, nil, authURL, clientID, tok)
			}
		}
	}
	var firstErr error
	for _, k := range []string{creds.KeyAccessToken, creds.KeyAccessExpiry, creds.KeyRefreshToken, creds.KeyIdentity} {
		if err := store.DeleteFor(account, k); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
