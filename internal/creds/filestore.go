package creds

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// FileStore persists credentials as JSON at mode 0600 in the user's config
// directory. Used as a fallback when the OS keychain isn't available.
// Writes are atomic (unique temp file + rename). Concurrent writers from
// different processes are last-writer-wins per file; the one write path
// that races in practice — token refresh — is serialized by the refresh
// lock in internal/auth.
//
// On-disk shape: {"accounts": {"": {...attrs}, "acme": {...attrs}}}. The
// default account is stored under the empty-string key.
type FileStore struct {
	path string
	mu   sync.Mutex
}

type fileEnvelope struct {
	Accounts map[string]map[string]string `json:"accounts"`
}

// DefaultFilePath returns the canonical credentials-file path for this OS.
// Honors XDG_CONFIG_HOME on Unix.
func DefaultFilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ServiceName, "credentials.json"), nil
}

// OpenFile returns a FileStore at the default path.
func OpenFile() (Store, error) {
	p, err := DefaultFilePath()
	if err != nil {
		return nil, err
	}
	return &FileStore{path: p}, nil
}

// NewFileStore returns a FileStore at an explicit path (tests).
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

func (f *FileStore) load() (*fileEnvelope, error) {
	env := &fileEnvelope{Accounts: map[string]map[string]string{}}
	b, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return env, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return env, nil
	}
	if err := json.Unmarshal(b, env); err != nil {
		return nil, fmt.Errorf("parse credentials file %s: %w", f.path, err)
	}
	if env.Accounts == nil {
		env.Accounts = map[string]map[string]string{}
	}
	return env, nil
}

func (f *FileStore) save(env *fileEnvelope) error {
	if len(env.Accounts) == 0 {
		if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	// Unique temp name: concurrent processes must not share one.
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".credentials-*.tmp")
	if err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), f.path)
}

func (f *FileStore) GetFor(account, attr string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	env, err := f.load()
	if err != nil {
		return "", err
	}
	v := env.Accounts[account][attr]
	if v == "" {
		return "", ErrNotFound
	}
	return v, nil
}

func (f *FileStore) SetFor(account, attr, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	env, err := f.load()
	if err != nil {
		return err
	}
	if env.Accounts[account] == nil {
		env.Accounts[account] = map[string]string{}
	}
	env.Accounts[account][attr] = value
	return f.save(env)
}

func (f *FileStore) DeleteFor(account, attr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	env, err := f.load()
	if err != nil {
		return err
	}
	m, ok := env.Accounts[account]
	if !ok {
		return nil
	}
	if _, ok := m[attr]; !ok {
		return nil
	}
	delete(m, attr)
	if len(m) == 0 {
		delete(env.Accounts, account)
	}
	return f.save(env)
}

func (f *FileStore) Accounts() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	env, err := f.load()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for name, m := range env.Accounts {
		if m[KeyRefreshToken] != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *FileStore) Backend() Source { return SourceFile }

// Path returns the on-disk path for diagnostics.
func (f *FileStore) Path() string { return f.path }
