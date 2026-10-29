// Package config resolves environment-variable settings (PRESSWRENCH_*) into
// a Config. Credentials are not part of Config — the OAuth session lives in
// internal/creds and is driven by internal/auth.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	// Account is the named Pressable login this process is bound to, or ""
	// for the default one. Driven by PRESSWRENCH_ACCOUNT, which setup/install
	// bake into the patched MCP-client config for named accounts.
	Account string

	// AuthURL is the OAuth authorization server (MyPressable).
	AuthURL string
	// MCPURL is Pressable's hosted MCP gateway.
	MCPURL string

	SSHHost        string
	SSHKeyPath     string
	SSHKeyLabel    string
	KnownHostsPath string
	SSHTimeoutMs   int
	ExecTimeoutMs  int
	// CacheTTLSeconds bounds how long site lookups and SFTP-user matches
	// are reused before being re-fetched from Pressable.
	CacheTTLSeconds int
	InsecureHostKey bool

	// ReadOnly hides pressable_ssh_exec, pressable_wp_cli and pressable_sftp_write, and restricts
	// pressable_execute to operations Pressable marks read-only.
	// Driven by PRESSWRENCH_READ_ONLY (1/true/yes/on). Off by default.
	ReadOnly bool
	// BlockedOperations are Pressable operation names pressable_execute
	// refuses regardless of the user's Pressable permissions.
	BlockedOperations []string
}

const (
	DefaultAuthURL           = "https://my.pressable.com"
	DefaultMCPURL            = "https://mcp.pressable.com"
	DefaultSSHHost           = "ssh.pressable.com"
	DefaultSSHKeyPath        = "~/.ssh/presswrench"
	DefaultSSHKeyLabel       = "presswrench"
	DefaultKnownHostsPath    = "~/.ssh/presswrench_known_hosts"
	DefaultSSHTimeoutMs      = 30000
	DefaultExecTimeoutMs     = 120000
	DefaultCacheTTLSec       = 300
	DefaultBlockedOperations = "delete_site"
)

// AccountDefaults returns the per-account SSH key path, key label, and
// known_hosts path. Named accounts get suffixed paths so two Pressable
// logins never share a key.
func AccountDefaults(account string) (sshKeyPath, sshKeyLabel, knownHostsPath string) {
	if account == "" {
		return DefaultSSHKeyPath, DefaultSSHKeyLabel, DefaultKnownHostsPath
	}
	suffix := "-" + account
	return DefaultSSHKeyPath + suffix,
		DefaultSSHKeyLabel + suffix,
		"~/.ssh/presswrench" + suffix + "_known_hosts"
}

// Load resolves every setting from the environment, falling back to
// defaults.
func Load() (*Config, error) {
	account := os.Getenv("PRESSWRENCH_ACCOUNT")
	defKeyPath, defKeyLabel, defKnownHosts := AccountDefaults(account)

	keyPath, err := ExpandHome(stringEnv("PRESSWRENCH_SSH_KEY_PATH", defKeyPath))
	if err != nil {
		return nil, err
	}
	knownHosts, err := ExpandHome(stringEnv("PRESSWRENCH_KNOWN_HOSTS_PATH", defKnownHosts))
	if err != nil {
		return nil, err
	}

	return &Config{
		Account:           account,
		AuthURL:           strings.TrimRight(stringEnv("PRESSWRENCH_AUTH_URL", DefaultAuthURL), "/"),
		MCPURL:            strings.TrimRight(stringEnv("PRESSWRENCH_GATEWAY_URL", DefaultMCPURL), "/"),
		SSHHost:           stringEnv("PRESSWRENCH_SSH_HOST", DefaultSSHHost),
		SSHKeyPath:        keyPath,
		SSHKeyLabel:       stringEnv("PRESSWRENCH_SSH_KEY_LABEL", defKeyLabel),
		KnownHostsPath:    knownHosts,
		SSHTimeoutMs:      intEnv("PRESSWRENCH_SSH_TIMEOUT_MS", DefaultSSHTimeoutMs),
		ExecTimeoutMs:     intEnv("PRESSWRENCH_EXEC_TIMEOUT_MS", DefaultExecTimeoutMs),
		CacheTTLSeconds:   intEnv("PRESSWRENCH_CACHE_TTL_SECONDS", DefaultCacheTTLSec),
		InsecureHostKey:   os.Getenv("PRESSWRENCH_INSECURE_DISABLE_HOST_KEY_CHECK") == "1",
		ReadOnly:          IsTrueEnv(os.Getenv("PRESSWRENCH_READ_ONLY")),
		BlockedOperations: ParseList(stringEnv("PRESSWRENCH_BLOCKED_OPERATIONS", DefaultBlockedOperations)),
	}, nil
}

// ParseList splits a comma-separated list, trimming blanks. The single
// value "none" yields an empty list (how a user clears the default
// blocklist).
func ParseList(v string) []string {
	if strings.EqualFold(strings.TrimSpace(v), "none") {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IsTrueEnv parses 1/true/yes/on (case-insensitive, trimmed) as true.
// Anything else, including unset and empty, is false.
func IsTrueEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func ExpandHome(p string) (string, error) {
	if !strings.HasPrefix(p, "~") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, p[1:]), nil
}

func stringEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func intEnv(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
