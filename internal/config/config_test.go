package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIsTrueEnv(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"off", false},
		{"  ", false},
		{"anything", false},

		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"on", true},
		{"  1  ", true},
	}
	for _, c := range cases {
		if got := IsTrueEnv(c.in); got != c.want {
			t.Errorf("IsTrueEnv(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"none", nil},
		{" NONE ", nil},
		{"delete_site", []string{"delete_site"}},
		{"delete_site, delete_site_plugins ,,", []string{"delete_site", "delete_site_plugins"}},
	}
	for _, c := range cases {
		if got := ParseList(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseList(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func clearEnv(t *testing.T) {
	for _, k := range []string{
		"PRESSWRENCH_ACCOUNT", "PRESSWRENCH_SSH_KEY_PATH", "PRESSWRENCH_SSH_KEY_LABEL",
		"PRESSWRENCH_KNOWN_HOSTS_PATH", "PRESSWRENCH_READ_ONLY", "PRESSWRENCH_BLOCKED_OPERATIONS",
		"PRESSWRENCH_GATEWAY_URL", "PRESSWRENCH_AUTH_URL",
	} {
		t.Setenv(k, "")
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	home, _ := os.UserHomeDir()
	if cfg.SSHKeyPath != filepath.Join(home, ".ssh/presswrench") {
		t.Errorf("SSHKeyPath = %q", cfg.SSHKeyPath)
	}
	if cfg.SSHKeyLabel != "presswrench" {
		t.Errorf("SSHKeyLabel = %q", cfg.SSHKeyLabel)
	}
	if cfg.MCPURL != DefaultMCPURL || cfg.AuthURL != DefaultAuthURL {
		t.Errorf("URLs = %q %q", cfg.MCPURL, cfg.AuthURL)
	}
	if cfg.ReadOnly {
		t.Error("ReadOnly should default to false")
	}
	if !reflect.DeepEqual(cfg.BlockedOperations, []string{"delete_site"}) {
		t.Errorf("BlockedOperations = %v, want [delete_site]", cfg.BlockedOperations)
	}
}

func TestLoad_ReadOnlyAndBlocklist(t *testing.T) {
	clearEnv(t)
	t.Setenv("PRESSWRENCH_READ_ONLY", "yes")
	t.Setenv("PRESSWRENCH_BLOCKED_OPERATIONS", "none")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ReadOnly {
		t.Error("ReadOnly should be true")
	}
	if len(cfg.BlockedOperations) != 0 {
		t.Errorf("BlockedOperations = %v, want empty", cfg.BlockedOperations)
	}
}

func TestLoad_NamedAccountDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("PRESSWRENCH_ACCOUNT", "acme")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	home, _ := os.UserHomeDir()
	if cfg.Account != "acme" {
		t.Errorf("Account = %q", cfg.Account)
	}
	if cfg.SSHKeyPath != filepath.Join(home, ".ssh/presswrench-acme") {
		t.Errorf("SSHKeyPath = %q", cfg.SSHKeyPath)
	}
	if cfg.SSHKeyLabel != "presswrench-acme" {
		t.Errorf("SSHKeyLabel = %q", cfg.SSHKeyLabel)
	}
	if cfg.KnownHostsPath != filepath.Join(home, ".ssh/presswrench-acme_known_hosts") {
		t.Errorf("KnownHostsPath = %q", cfg.KnownHostsPath)
	}
}
