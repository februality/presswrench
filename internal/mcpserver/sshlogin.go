package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/februality/presswrench/internal/sites"
	mcsh "github.com/februality/presswrench/internal/ssh"
)

// loginCache remembers which SFTP username on a site accepted our key.
type loginCache struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[int64]loginEntry
}

type loginEntry struct {
	user string
	at   time.Time
}

func newLoginCache(ttl time.Duration) *loginCache {
	return &loginCache{ttl: ttl, m: map[int64]loginEntry{}}
}

func (c *loginCache) get(siteID int64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[siteID]
	if !ok || time.Since(e.at) > c.ttl {
		return "", false
	}
	return e.user, true
}

func (c *loginCache) drop(siteID int64) {
	c.mu.Lock()
	delete(c.m, siteID)
	c.mu.Unlock()
}

func (c *loginCache) put(siteID int64, user string) {
	c.mu.Lock()
	c.m[siteID] = loginEntry{user: user, at: time.Now()}
	c.mu.Unlock()
}

// siteLogin is a resolved site plus the SSH username that accepts our key.
type siteLogin struct {
	Site *sites.Site
	User string
}

// resolveLogin finds the SFTP/SSH login on a site that belongs to the
// user's key. Pressable creates one login per (SSH key, site) pair, but
// only on sites the key's owner can reach with SFTP access — so this is
// where Pressable's scoping applies to the SSH layer.
//
// Candidate logins come from list_site_ftp_accounts (key-backed logins,
// ours by label first) and are tried in order; the first that accepts the
// key wins and is cached. Several collaborators can use the same label, so
// a refused key just moves on to the next candidate.
func (d *Deps) resolveLogin(ctx context.Context, siteInput string) (*siteLogin, error) {
	// The first call to a site pays for three things in a row; the debug
	// log says how long each took.
	started := time.Now()
	site, err := d.Sites.Resolve(ctx, siteInput)
	if err != nil {
		return nil, err
	}
	slog.Debug("site resolved", "site", siteInput, "id", site.ID, "took", time.Since(started).Round(time.Millisecond))
	if user, ok := d.Logins.get(site.ID); ok {
		// A remembered login can stop working (removed in MyPressable, key
		// replaced). Connecting is free while the connection is pooled, so
		// check, and look the login up again if the key is now refused.
		if err := d.connect(user); err == nil || !mcsh.IsAuthError(err) {
			return &siteLogin{Site: site, User: user}, nil
		}
		d.Logins.drop(site.ID)
	}
	if !mcsh.KeyPairExists(d.Cfg.SSHKeyPath) {
		return nil, fmt.Errorf("SSH key not found at %s. Run `presswrench setup` to create it and add it to Pressable", d.Cfg.SSHKeyPath)
	}
	started = time.Now()
	accounts, err := sites.FTPAccounts(ctx, d.Gateway, site.ID)
	if err != nil {
		return nil, err
	}
	slog.Debug("site logins listed", "id", site.ID, "logins", len(accounts), "took", time.Since(started).Round(time.Millisecond))
	candidates := sites.KeyCandidates(accounts, d.Cfg.SSHKeyLabel, identityEmail(d.Session.Identity()))
	if len(candidates) == 0 {
		return nil, fmt.Errorf("No SSH-key login exists on site %s for your key. Either the public key %s.pub hasn't been added in MyPressable (Profile → Settings → SSH Keys, label %q), or your Pressable account lacks SFTP access to this site", siteLabel(site), d.Cfg.SSHKeyPath, d.Cfg.SSHKeyLabel)
	}
	var lastErr error
	for _, user := range candidates {
		started = time.Now()
		err := d.connect(user)
		slog.Debug("ssh login tried", "id", site.ID, "login", user, "ok", err == nil, "took", time.Since(started).Round(time.Millisecond))
		if err == nil {
			d.Logins.put(site.ID, user)
			return &siteLogin{Site: site, User: user}, nil
		}
		if !mcsh.IsAuthError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("None of the %d key-based logins on site %s accepted %s (last error: %v). Check that this key's public half is the one added in MyPressable under label %q", len(candidates), siteLabel(site), d.Cfg.SSHKeyPath, lastErr, d.Cfg.SSHKeyLabel)
}

// connect opens (or reuses) the SSH connection for a login.
func (d *Deps) connect(user string) error {
	if d.dial != nil {
		return d.dial(user)
	}
	_, err := d.SSHPool.Get(d.Cfg.SSHHost, user)
	return err
}

// CheckSSH resolves a site and confirms our key logs in to it. Used by the
// setup wizard and doctor.
func (d *Deps) CheckSSH(ctx context.Context, site string) (siteName, user string, err error) {
	login, err := d.resolveLogin(ctx, site)
	if err != nil {
		return "", "", err
	}
	return siteLabel(login.Site), login.User, nil
}

func siteLabel(s *sites.Site) string {
	if s.Name == "" {
		return fmt.Sprintf("%d", s.ID)
	}
	return fmt.Sprintf("%s (ID %d)", s.Name, s.ID)
}

// identityEmail extracts the email from "Name <email>" (or a bare email).
func identityEmail(id string) string {
	if i := strings.LastIndex(id, "<"); i >= 0 {
		return strings.TrimSuffix(id[i+1:], ">")
	}
	if strings.Contains(id, "@") {
		return id
	}
	return ""
}
