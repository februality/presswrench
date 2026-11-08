package creds

import (
	"fmt"
	"time"
)

type callResult[T any] struct {
	v   T
	err error
}

// callWithin runs fn, a keyring library call that can't be cancelled (a
// locked Secret Service collection blocks on its unlock prompt), and waits
// at most keychainTimeout for it, counting the wait for an earlier call
// still holding sem. On expiry it returns a KindTimeout *Error; fn keeps
// running on its goroutine (leaked until the library returns) and holds sem
// until then, so later calls wait or time out instead of piling up behind
// it, and a write that timed out can never land after a newer one.
func callWithin[T any](sem chan struct{}, what string, fn func() (T, error)) (T, error) {
	var zero T
	timer := time.NewTimer(keychainTimeout)
	defer timer.Stop()
	select {
	case sem <- struct{}{}:
	case <-timer.C:
		return zero, keyringTimeout(what)
	}
	done := make(chan callResult[T], 1)
	go func() {
		defer func() { <-sem }()
		v, err := fn()
		done <- callResult[T]{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-timer.C:
		return zero, keyringTimeout(what)
	}
}

func keyringTimeout(what string) error {
	return &Error{Kind: KindTimeout, Backend: SourceKeyring, Detail: fmt.Sprintf("%s the system keyring timed out after %s; unlock it or approve its prompt and try again", what, keychainTimeout)}
}
