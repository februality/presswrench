package creds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/februality/presswrench/internal/lockfile"
)

// fileVersion is the format of the credentials file envelope.
const fileVersion = 1

const fileLockWait = 30 * time.Second

// fileBackend stores raw values in one JSON file at mode 0600:
// {"v":1,"items":{"<key>":"<value>"}}. Values are the record/index JSON,
// kept as strings so the file stays readable. Writes are atomic (unique
// temp file + rename) and every access, reads included, is serialized
// across processes by a lockfile next to the file, so two processes saving
// different accounts can't lose each other's write. Files from earlier builds (no "v") are ignored and
// replaced on the next write.
type fileBackend struct {
	path string
	mu   sync.Mutex // in-process; the lockfile covers other processes
}

type fileEnvelope struct {
	V     int               `json:"v"`
	Items map[string]string `json:"items"`
}

// NewFileStore returns a Store backed by the file at path. Its index lock
// lives in the same directory.
func NewFileStore(path string) Store {
	return newRecordStore(&fileBackend{path: path}, Info{Source: SourceFile, Description: path}, filepath.Dir(path))
}

func (f *fileBackend) fileError(err error, what string) error {
	kind := KindOther
	if errors.Is(err, os.ErrPermission) {
		kind = KindDenied
	}
	return &Error{Kind: kind, Detail: fmt.Sprintf("%s credentials file %s: %v", what, f.path, err), Err: err}
}

func (f *fileBackend) load() (*fileEnvelope, error) {
	env := &fileEnvelope{V: fileVersion, Items: map[string]string{}}
	b, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return env, nil
		}
		return nil, f.fileError(err, "reading")
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return env, nil
	}
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, &Error{Kind: KindCorrupt, Detail: "credentials file " + f.path + " is not valid JSON", Err: err}
	}
	if probe.V > fileVersion {
		return nil, &Error{Kind: KindNewerFormat, Detail: fmt.Sprintf("credentials file %s has format %d, this build reads %d", f.path, probe.V, fileVersion)}
	}
	if probe.V < 1 {
		return env, nil // earlier development builds: ignored
	}
	if err := json.Unmarshal(b, env); err != nil {
		return nil, &Error{Kind: KindCorrupt, Detail: "credentials file " + f.path + " has unexpected contents", Err: err}
	}
	if env.Items == nil {
		env.Items = map[string]string{}
	}
	return env, nil
}

func (f *fileBackend) save(env *fileEnvelope) error {
	if len(env.Items) == 0 {
		if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return f.fileError(err, "removing")
		}
		return nil
	}
	env.V = fileVersion
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return f.fileError(err, "creating the directory for")
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	// Unique temp name: concurrent processes must not share one.
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".credentials-*.tmp")
	if err != nil {
		return f.fileError(err, "writing")
	}
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return f.fileError(err, "writing")
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return f.fileError(err, "writing")
	}
	if err := os.Rename(tmp.Name(), f.path); err != nil {
		_ = os.Remove(tmp.Name())
		return f.fileError(err, "writing")
	}
	return nil
}

// locked runs fn under the in-process mutex and the cross-process file
// lock. Reads take it too: on Windows a rename can't replace a file another
// handle has open, so an unlocked read would make a concurrent write fail.
// fn must not call get/set/del (the file lock isn't reentrant).
func (f *fileBackend) locked(fn func() error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	lock, err := lockfile.Acquire(context.Background(), f.path+".lock", fileLockWait)
	if err != nil {
		return &Error{Kind: KindOther, Err: err}
	}
	defer lock.Release()
	return fn()
}

// update runs a read-modify-write of the file under the locks. change
// reports whether it modified env.
func (f *fileBackend) update(change func(env *fileEnvelope) bool) error {
	return f.locked(func() error {
		env, err := f.load()
		if err != nil {
			return err
		}
		if !change(env) {
			return nil
		}
		return f.save(env)
	})
}

func (f *fileBackend) get(key string) ([]byte, error) {
	var out []byte
	err := f.locked(func() error {
		env, err := f.load()
		if err != nil {
			return err
		}
		v, ok := env.Items[key]
		if !ok {
			return &Error{Kind: KindNotFound}
		}
		out = []byte(v)
		return nil
	})
	return out, err
}

func (f *fileBackend) set(key, _ string, value []byte) error {
	return f.update(func(env *fileEnvelope) bool {
		env.Items[key] = string(value)
		return true
	})
}

func (f *fileBackend) del(key string) error {
	return f.update(func(env *fileEnvelope) bool {
		if _, ok := env.Items[key]; !ok {
			return false
		}
		delete(env.Items, key)
		return true
	})
}

func (f *fileBackend) maxValue() int { return 0 }
