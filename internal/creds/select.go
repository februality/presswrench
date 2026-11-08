package creds

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnvCredentialStore forces the backend: "keyring" or "file".
const EnvCredentialStore = "PRESSWRENCH_CREDENTIAL_STORE"

type selectOpts struct {
	env         string // value of EnvCredentialStore
	markerPath  string // <config dir>/store
	filePath    string
	lockDir     string
	openKeyring func() (rawBackend, Info, error)
}

func markerFile() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "store"), nil
}

// Open returns the credential store: the one forced by
// PRESSWRENCH_CREDENTIAL_STORE, else the one remembered at sign-in, else the
// keyring with a file fallback.
func Open() (Store, error) {
	path, err := DefaultFilePath()
	if err != nil {
		return nil, err
	}
	marker, err := markerFile()
	if err != nil {
		return nil, err
	}
	return openWith(selectOpts{
		env:         os.Getenv(EnvCredentialStore),
		markerPath:  marker,
		filePath:    path,
		lockDir:     filepath.Dir(path),
		openKeyring: openKeyring,
	})
}

func readMarker(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	switch v := strings.TrimSpace(string(b)); v {
	case "keyring", "file":
		return v
	}
	return ""
}

func openWith(o selectOpts) (Store, error) {
	env := strings.ToLower(strings.TrimSpace(o.env))
	if env != "" && env != "keyring" && env != "file" {
		return nil, &Error{Kind: KindOther, Op: "open", Detail: EnvCredentialStore + " must be keyring or file"}
	}
	marker := readMarker(o.markerPath)

	want, reason := env, ""
	switch {
	case env != "":
		reason = " (" + EnvCredentialStore + "=" + env + ")"
	case marker != "":
		want, reason = marker, " (chosen at first sign-in)"
	}
	warning := ""
	if env != "" && marker != "" && env != marker {
		warning = fmt.Sprintf("%s=%s overrides the %s store used at sign-in; sessions saved there aren't visible.", EnvCredentialStore, env, marker)
	}

	fileStore := func(desc string) Store {
		return newRecordStore(&fileBackend{path: o.filePath},
			Info{Source: SourceFile, Description: "file " + o.filePath + desc, Warning: warning}, o.lockDir)
	}
	if want == "file" {
		return fileStore(reason), nil
	}

	raw, info, err := o.openKeyring()
	if err == nil {
		info.Warning = warning
		return newRecordStore(raw, info, o.lockDir), nil
	}
	if want == "keyring" {
		var e *Error
		if errors.As(err, &e) && e.Kind == KindUnavailable {
			return nil, err
		}
		return nil, &Error{Kind: KindUnavailable, Op: "open", Backend: SourceKeyring, Detail: err.Error(), Err: err}
	}
	return fileStore(" (keyring unavailable: " + err.Error() + ")"), nil
}

// RememberBackend records which backend holds the sessions so later runs
// don't silently switch to another one. It does nothing for a broken or
// env-token store and when the marker is already right.
func RememberBackend(s Store) error {
	var val string
	switch s.Info().Source {
	case SourceKeyring:
		val = "keyring"
	case SourceFile:
		val = "file"
	default:
		return nil
	}
	path, err := markerFile()
	if err != nil {
		return err
	}
	if readMarker(path) == val {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "store-*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.WriteString(val + "\n")
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr, os.Chmod(tmp.Name(), 0o600)); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}
