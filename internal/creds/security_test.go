package creds

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type secCall struct {
	args  []string
	stdin string
}

type fakeSec struct {
	calls  []secCall
	stdout string
	stderr string
	exit   int
	err    error
	block  bool
}

func (f *fakeSec) run(ctx context.Context, stdin string, args ...string) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, secCall{args: args, stdin: stdin})
	if f.block {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	return []byte(f.stdout), []byte(f.stderr), f.exit, f.err
}

func TestSecurity_GetDecodes(t *testing.T) {
	f := &fakeSec{stdout: "eyJ2IjoxfQ==\n"}
	b := newSecurityBackend("presswrench", f.run)
	got, err := b.get("session:acme")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"v":1}` {
		t.Errorf("got %q", got)
	}
	want := []string{"find-generic-password", "-s", "presswrench", "-a", "session:acme", "-w"}
	if !reflect.DeepEqual(f.calls[0].args, want) {
		t.Errorf("argv = %q", f.calls[0].args)
	}
}

func TestSecurity_SetKeepsSecretOffArgv(t *testing.T) {
	f := &fakeSec{}
	b := newSecurityBackend("presswrench", f.run)
	if err := b.set("session:my-site-2", "PressWrench session (my-site-2)", []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	c := f.calls[0]
	if !reflect.DeepEqual(c.args, []string{"-i"}) {
		t.Errorf("argv = %q", c.args)
	}
	want := `add-generic-password -U -s "presswrench" -a "session:my-site-2" -l "PressWrench session (my-site-2)" -w eyJ2IjoxfQ==` + "\n"
	if c.stdin != want {
		t.Errorf("stdin = %q\nwant    %q", c.stdin, want)
	}
	for _, a := range c.args {
		if strings.Contains(a, "eyJ2") {
			t.Errorf("secret in argv: %q", a)
		}
	}
}

func TestSecurity_ExitCodes(t *testing.T) {
	cases := map[int]Kind{44: KindNotFound, 36: KindLocked, 128: KindDenied, 51: KindDenied, 2: KindOther}
	for exit, kind := range cases {
		f := &fakeSec{exit: exit, stderr: "  boom \n", err: errors.New("exit status")}
		b := newSecurityBackend("presswrench", f.run)
		_, err := b.get("session:x")
		if KindOf(err) != kind {
			t.Errorf("exit %d: kind = %v, want %v", exit, KindOf(err), kind)
		}
		var e *Error
		if kind != KindNotFound && (!errors.As(err, &e) || !strings.Contains(e.Detail, "boom")) {
			t.Errorf("exit %d: detail missing stderr: %v", exit, err)
		}
		if kind != KindNotFound && e != nil && strings.Contains(e.Detail, "boom \n") {
			t.Errorf("exit %d: stderr not trimmed: %q", exit, e.Detail)
		}
	}
}

func TestSecurity_Timeout(t *testing.T) {
	old := keychainTimeout
	keychainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { keychainTimeout = old })
	f := &fakeSec{block: true}
	b := newSecurityBackend("presswrench", f.run)
	start := time.Now()
	_, err := b.get("session:x")
	if KindOf(err) != KindTimeout {
		t.Fatalf("kind = %v (%v)", KindOf(err), err)
	}
	if time.Since(start) > time.Second {
		t.Error("took too long")
	}
}

func TestSecurity_DeleteMissingIsNil(t *testing.T) {
	f := &fakeSec{exit: 44, err: errors.New("exit status 44")}
	b := newSecurityBackend("presswrench", f.run)
	if err := b.del("session:x"); err != nil {
		t.Fatal(err)
	}
	if f.calls[0].args[0] != "delete-generic-password" {
		t.Errorf("argv = %q", f.calls[0].args)
	}
}

func TestSecurity_GarbledValueIsCorrupt(t *testing.T) {
	f := &fakeSec{stdout: "%%%\n"}
	b := newSecurityBackend("presswrench", f.run)
	if _, err := b.get("session:x"); KindOf(err) != KindCorrupt {
		t.Fatalf("kind = %v", KindOf(err))
	}
}

func TestSecurity_SetQuotesAndRejectsNewlines(t *testing.T) {
	f := &fakeSec{}
	b := newSecurityBackend("presswrench", f.run)
	if err := b.set(`session:a"b\c`, "L", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.calls[0].stdin, `-a "session:a\"b\\c"`) {
		t.Errorf("stdin = %q", f.calls[0].stdin)
	}
	if err := b.set("session:a\nb", "L", []byte("x")); err == nil {
		t.Error("newline in key accepted")
	}
}
