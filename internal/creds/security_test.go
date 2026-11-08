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

func TestSecurity_SignalDeathIsOther(t *testing.T) {
	f := &fakeSec{exit: -1, err: errors.New("signal: killed")}
	b := newSecurityBackend("presswrench", f.run)
	_, err := b.get("session:x")
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindOther || !strings.Contains(e.Detail, "killed by a signal") {
		t.Fatalf("err = %#v", err)
	}
}

func TestSecurity_TimeoutWinsOverSignal(t *testing.T) {
	old := keychainTimeout
	keychainTimeout = 30 * time.Millisecond
	t.Cleanup(func() { keychainTimeout = old })
	f := &fakeSec{block: true} // returns exit -1 once the deadline kills it
	b := newSecurityBackend("presswrench", f.run)
	if err := b.set("session:x", "L", []byte("x")); KindOf(err) != KindTimeout {
		t.Fatalf("kind = %v (%v), want KindTimeout", KindOf(err), err)
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

// security -i splits lines at ~4096 bytes and runs the rest as a separate
// command, so the size cap must keep the whole add line under the limit for
// the longest account name.
func TestSecurity_MaxValueKeepsLineUnderLimit(t *testing.T) {
	f := &fakeSec{}
	b := newSecurityBackend("presswrench", f.run)
	maxV := b.maxValue()
	if maxV < 2500 || maxV > 3000 {
		t.Fatalf("maxValue = %d, want about 2900", maxV)
	}
	worst := strings.Repeat("a", maxAccountName)
	if err := b.set(sessionKey(worst), itemLabel(worst), make([]byte, maxV)); err != nil {
		t.Fatalf("set at maxValue: %v", err)
	}
	if n := len(f.calls[0].stdin); n > securityLineLimit {
		t.Errorf("line at maxValue is %d bytes, limit %d", n, securityLineLimit)
	}
	if err := b.set(sessionKey(worst), itemLabel(worst), make([]byte, maxV+3)); KindOf(err) != KindTooLarge {
		t.Errorf("set past maxValue: kind = %v (%v), want KindTooLarge", KindOf(err), err)
	}
}

func TestSecurity_SetRefusesOverlongLine(t *testing.T) {
	f := &fakeSec{}
	b := newSecurityBackend("presswrench", f.run)
	long := strings.Repeat("x", 600) // an account name past the usual limit
	err := b.set(sessionKey(long), itemLabel(long), make([]byte, b.maxValue()))
	if KindOf(err) != KindTooLarge {
		t.Fatalf("kind = %v (%v), want KindTooLarge", KindOf(err), err)
	}
	if len(f.calls) != 0 {
		t.Error("an overlong line was sent to security")
	}
}

func TestSecurity_RecordStoreRefusesLargeRecord(t *testing.T) {
	f := &fakeSec{}
	s := newRecordStore(newSecurityBackend("presswrench", f.run), Info{Source: SourceKeyring}, t.TempDir())
	err := s.Save("acme", Record{RefreshToken: "r", AccessToken: strings.Repeat("a", 3000)})
	if KindOf(err) != KindTooLarge {
		t.Fatalf("kind = %v (%v), want KindTooLarge", KindOf(err), err)
	}
	if len(f.calls) != 0 {
		t.Error("an oversized record was sent to security")
	}
}
