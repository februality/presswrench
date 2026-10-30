package wizard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/februality/presswrench/internal/auth"
	"github.com/februality/presswrench/internal/clients"
	"github.com/februality/presswrench/internal/sites"
	mcsh "github.com/februality/presswrench/internal/ssh"
	"github.com/februality/presswrench/internal/ui"
)

// scriptedPrompter answers prompts from queues and records every call.
type scriptedPrompter struct {
	confirms []bool
	selects  []string
	multis   [][]string
	texts    []string
	err      error // returned by every prompt when set (e.g. ui.ErrCancelled)
	multiErr error // returned by MultiSelect only

	calls         []string
	confirmDefs   []bool
	selectOpts    [][]ui.Option
	multiOpts     [][]ui.Option
	multiDefaults [][]string
}

func (p *scriptedPrompter) Text(title, _ string, _ func(string) error) (string, error) {
	p.calls = append(p.calls, "text:"+title)
	if p.err != nil {
		return "", p.err
	}
	v := p.texts[0]
	p.texts = p.texts[1:]
	return v, nil
}

func (p *scriptedPrompter) Confirm(title string, def bool) (bool, error) {
	p.calls = append(p.calls, "confirm:"+title)
	p.confirmDefs = append(p.confirmDefs, def)
	if p.err != nil {
		return false, p.err
	}
	v := p.confirms[0]
	p.confirms = p.confirms[1:]
	return v, nil
}

func (p *scriptedPrompter) Select(title string, options []ui.Option, _ string) (string, error) {
	p.calls = append(p.calls, "select:"+title)
	p.selectOpts = append(p.selectOpts, options)
	if p.err != nil {
		return "", p.err
	}
	v := p.selects[0]
	p.selects = p.selects[1:]
	return v, nil
}

func (p *scriptedPrompter) MultiSelect(title string, options []ui.Option, defaults []string) ([]string, error) {
	p.calls = append(p.calls, "multi:"+title)
	p.multiOpts = append(p.multiOpts, options)
	p.multiDefaults = append(p.multiDefaults, defaults)
	if p.err != nil {
		return nil, p.err
	}
	if p.multiErr != nil {
		return nil, p.multiErr
	}
	v := p.multis[0]
	p.multis = p.multis[1:]
	return v, nil
}

func fakeSites(n int) []sites.Site {
	out := make([]sites.Site, n)
	for i := range out {
		out[i] = sites.Site{ID: int64(i + 1), Name: fmt.Sprintf("site%d", i+1)}
	}
	return out
}

// fakeHooks returns hooks for a signed-in user with 12 sites, a working
// key, a working clipboard, no clients and no official server.
func fakeHooks() *Hooks {
	return &Hooks{
		Session: func(context.Context) (string, bool) { return "andrew@example.com", true },
		SignIn: func(context.Context, auth.LoginOptions) (string, error) {
			return "", errors.New("SignIn should not be called")
		},
		ListSites: func(context.Context) ([]sites.Site, error) { return fakeSites(12), nil },
		CheckSSH: func(context.Context, string) (string, string, error) {
			return "", "", errors.New("CheckSSH should not be called")
		},
		EnsureKey: func(string, string) (*mcsh.KeyPair, error) {
			return &mcsh.KeyPair{PublicKey: "ssh-ed25519 AAAA test\n"}, nil
		},
		Clipboard: func(string) error { return nil },
		Patchers:  func(string) []clients.Patcher { return nil },
		Official:  func() []clients.OfficialEntry { return nil },
	}
}

type runResult struct {
	out string
	err error
	p   *scriptedPrompter
}

func run(t *testing.T, interactive bool, opts Options, h *Hooks, p *scriptedPrompter) runResult {
	t.Helper()
	t.Setenv("PRESSWRENCH_ACCOUNT", "")
	var buf bytes.Buffer
	opts.Out = &buf
	opts.UI = ui.NewTest(&buf, interactive, true, 80)
	opts.Hooks = h
	opts.Prompter = p
	opts.BinaryPath = "/bin/presswrench"
	err := Run(opts)
	return runResult{out: buf.String(), err: err, p: p}
}

func TestRun_AlreadySignedIn(t *testing.T) {
	r := run(t, true, Options{SkipSSH: true, SkipClients: true}, fakeHooks(), &scriptedPrompter{})
	if r.err != nil {
		t.Fatalf("err: %v", r.err)
	}
	want := "┌  PressWrench setup  v0.1.0\n│\n" +
		"◆  Checking Pressable access\n" +
		"◇  Signed in as andrew@example.com · 12 sites\n" +
		"│\n└  Done. Run `presswrench doctor` to verify.\n"
	if r.out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", r.out, want)
	}
	if len(r.p.calls) != 0 {
		t.Fatalf("unexpected prompts: %v", r.p.calls)
	}
}

func TestRun_SignInFails(t *testing.T) {
	h := fakeHooks()
	h.Session = func(context.Context) (string, bool) { return "", false }
	h.SignIn = func(context.Context, auth.LoginOptions) (string, error) { return "", errors.New("boom") }
	r := run(t, true, Options{SkipSSH: true, SkipClients: true}, h, &scriptedPrompter{})
	if !strings.Contains(r.out, "■  boom\n") {
		t.Fatalf("output lacks failure line:\n%s", r.out)
	}
	if !ui.IsReported(r.err) || r.err.Error() != "boom" {
		t.Fatalf("err %v", r.err)
	}
}

func TestRun_BrowserSignIn(t *testing.T) {
	h := fakeHooks()
	h.Session = func(context.Context) (string, bool) { return "", false }
	h.SignIn = func(_ context.Context, o auth.LoginOptions) (string, error) {
		o.OnAuthorizeURL("https://auth.example/authorize?x=1", true)
		return "jane@example.com", nil
	}
	r := run(t, true, Options{SkipSSH: true, SkipClients: true}, h, &scriptedPrompter{})
	if r.err != nil {
		t.Fatalf("err: %v", r.err)
	}
	if !strings.Contains(r.out, "◆  Sign in to Pressable in your browser\n◇  Signed in as jane@example.com · 12 sites\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

func TestRun_ManualSignIn(t *testing.T) {
	h := fakeHooks()
	h.Session = func(context.Context) (string, bool) { return "", false }
	var pasted string
	h.SignIn = func(_ context.Context, o auth.LoginOptions) (string, error) {
		o.OnAuthorizeURL("https://auth.example/authorize?x=1", false)
		line, err := o.ReadLine()
		pasted = line
		return "jane@example.com", err
	}
	p := &scriptedPrompter{texts: []string{"http://127.0.0.1:53682/callback?code=abc"}}
	r := run(t, true, Options{SkipSSH: true, SkipClients: true, ManualLogin: true}, h, p)
	if r.err != nil {
		t.Fatalf("err: %v", r.err)
	}
	if pasted != "http://127.0.0.1:53682/callback?code=abc" {
		t.Fatalf("pasted %q", pasted)
	}
	if !strings.Contains(r.out, "│  https://auth.example/authorize?x=1\n") {
		t.Fatalf("URL not shown raw:\n%s", r.out)
	}
	if !strings.Contains(r.out, "◇  Signed in as jane@example.com · 12 sites\n") {
		t.Fatalf("output:\n%s", r.out)
	}
	if len(p.calls) != 1 || !strings.HasPrefix(p.calls[0], "text:Paste the URL") {
		t.Fatalf("calls %v", p.calls)
	}
}

func TestRun_NoTerminalNeedsUnattended(t *testing.T) {
	r := run(t, false, Options{}, fakeHooks(), &scriptedPrompter{})
	if !errors.Is(r.err, ui.ErrNoTerminal) {
		t.Fatalf("err %v", r.err)
	}
	if r.out != "" {
		t.Fatalf("wrote %q", r.out)
	}
}

func TestRun_UnattendedNeedsSession(t *testing.T) {
	h := fakeHooks()
	h.Session = func(context.Context) (string, bool) { return "", false }
	r := run(t, false, Options{Unattended: true}, h, &scriptedPrompter{})
	if r.err == nil || !strings.Contains(r.err.Error(), "presswrench login") {
		t.Fatalf("err %v", r.err)
	}
}

func TestRun_FileStoreNote(t *testing.T) {
	h := fakeHooks()
	h.StoreLabel = "/x/credentials.json"
	r := run(t, true, Options{SkipSSH: true, SkipClients: true}, h, &scriptedPrompter{})
	if !strings.Contains(r.out, "◇  Signed in as andrew@example.com · 12 sites · session in /x/credentials.json (0600)\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

func TestRun_AccountNote(t *testing.T) {
	r := run(t, true, Options{Account: "dev", SkipSSH: true, SkipClients: true}, fakeHooks(), &scriptedPrompter{})
	if !strings.HasPrefix(r.out, "┌  PressWrench setup  v0.1.0\n│\n│  Account \"dev\" · entry presswrench-dev\n│\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

// --- SSH step ---

func sshHooks(check func(context.Context, string) (string, string, error)) *Hooks {
	h := fakeHooks()
	h.CheckSSH = check
	return h
}

func optionValues(opts []ui.Option) []string {
	out := []string{}
	for _, o := range opts {
		out = append(out, o.Value)
	}
	return out
}

func TestSSHStep_ClipboardWorks(t *testing.T) {
	p := &scriptedPrompter{selects: []string{"skip"}}
	r := run(t, true, Options{SkipClients: true}, fakeHooks(), p)
	if r.err != nil {
		t.Fatalf("err %v", r.err)
	}
	if !strings.Contains(r.out, "◇  SSH key · ~/.ssh/presswrench · copied to clipboard\n") {
		t.Fatalf("output:\n%s", r.out)
	}
	if strings.Contains(r.out, "ssh-ed25519 AAAA") {
		t.Fatalf("key must not be printed when copied:\n%s", r.out)
	}
	if got := strings.Join(optionValues(p.selectOpts[0]), ","); got != "test,show,skip" {
		t.Fatalf("options %s", got)
	}
	if !strings.Contains(r.out, "◇  SSH test · skipped, check later with presswrench doctor\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

func TestSSHStep_ClipboardFails(t *testing.T) {
	h := fakeHooks()
	h.Clipboard = func(string) error { return errors.New("no clipboard") }
	p := &scriptedPrompter{selects: []string{"skip"}}
	r := run(t, true, Options{SkipClients: true}, h, p)
	if !strings.Contains(r.out, "◇  SSH key · ~/.ssh/presswrench\n") || !strings.Contains(r.out, "│  ssh-ed25519 AAAA test\n") {
		t.Fatalf("output:\n%s", r.out)
	}
	if got := strings.Join(optionValues(p.selectOpts[0]), ","); got != "test,skip" {
		t.Fatalf("options %s", got)
	}
}

func TestSSHStep_ShowKeyThenTest(t *testing.T) {
	h := sshHooks(func(context.Context, string) (string, string, error) { return "mysite", "u1", nil })
	p := &scriptedPrompter{selects: []string{"show", "test"}}
	r := run(t, true, Options{SkipClients: true}, h, p)
	if r.err != nil {
		t.Fatalf("err %v", r.err)
	}
	if strings.Count(r.out, "│  ssh-ed25519 AAAA test\n") != 1 {
		t.Fatalf("key should be shown exactly once:\n%s", r.out)
	}
	if !strings.Contains(r.out, "◆  Checking SSH access\n◇  SSH works · mysite as u1\n") {
		t.Fatalf("output:\n%s", r.out)
	}
	if len(p.selectOpts) != 2 {
		t.Fatalf("select calls %d", len(p.selectOpts))
	}
}

func TestSSHStep_TestFailsThenSkip(t *testing.T) {
	calls := 0
	h := sshHooks(func(context.Context, string) (string, string, error) { calls++; return "", "", errors.New("denied") })
	p := &scriptedPrompter{selects: []string{"test", "skip"}}
	r := run(t, true, Options{SkipClients: true}, h, p)
	if r.err != nil {
		t.Fatalf("err %v", r.err)
	}
	if !strings.Contains(r.out, "▲  SSH not working yet · denied\n") {
		t.Fatalf("output:\n%s", r.out)
	}
	if !strings.Contains(r.out, "◇  SSH test · skipped, check later with presswrench doctor\n") {
		t.Fatalf("output:\n%s", r.out)
	}
	if calls != 12 {
		t.Fatalf("CheckSSH called %d times, want 12 (3 sites x 4 attempts)", calls)
	}
}

func TestSSHStep_NoSites(t *testing.T) {
	h := fakeHooks()
	h.ListSites = func(context.Context) ([]sites.Site, error) { return nil, nil }
	p := &scriptedPrompter{}
	r := run(t, true, Options{SkipClients: true}, h, p)
	if !strings.Contains(r.out, "◇  SSH test · no sites to test against yet\n") || len(p.calls) != 0 {
		t.Fatalf("output:\n%s\ncalls %v", r.out, p.calls)
	}
}

func TestSSHStep_Unattended(t *testing.T) {
	p := &scriptedPrompter{}
	r := run(t, false, Options{SkipClients: true, Unattended: true}, fakeHooks(), p)
	if r.err != nil {
		t.Fatalf("err %v", r.err)
	}
	if !strings.Contains(r.out, "│  ssh-ed25519 AAAA test\n") || len(p.calls) != 0 {
		t.Fatalf("output:\n%s\ncalls %v", r.out, p.calls)
	}
}

func TestSSHStep_Cancel(t *testing.T) {
	p := &scriptedPrompter{err: ui.ErrCancelled}
	r := run(t, true, Options{SkipClients: true}, fakeHooks(), p)
	if !ui.IsReported(r.err) || !errors.Is(r.err, ui.ErrCancelled) {
		t.Fatalf("err %v", r.err)
	}
	if !strings.HasSuffix(r.out, "└\n") {
		t.Fatalf("output should end with the bare outro:\n%s", r.out)
	}
}

// --- read-only, AI tools, official warning ---

type fakePatcher struct {
	id, name, path string
	detected       bool
	changed        bool
	err            error
	patched        bool
	env            map[string]string
}

func (p *fakePatcher) ID() string          { return p.id }
func (p *fakePatcher) DisplayName() string { return p.name }
func (p *fakePatcher) Detect() (bool, string, error) {
	return p.detected, p.path, nil
}
func (p *fakePatcher) Patch(_ string, env map[string]string, _ bool) (bool, string, error) {
	p.patched = true
	p.env = env
	return p.changed, "", p.err
}
func (p *fakePatcher) Unpatch() (bool, error)                 { return false, nil }
func (p *fakePatcher) CurrentEnv() (map[string]string, error) { return nil, nil }
func (p *fakePatcher) Entries() ([]string, error)             { return nil, nil }
func (p *fakePatcher) OfficialEntries() ([]string, error)     { return nil, nil }

func threePatchers() (a, b, c *fakePatcher, h *Hooks) {
	a = &fakePatcher{id: "a", name: "A", path: "/a", detected: true, changed: true}
	b = &fakePatcher{id: "b", name: "B", path: "/b", detected: true, changed: false}
	c = &fakePatcher{id: "c", name: "C", path: "/c", detected: false}
	h = fakeHooks()
	h.Patchers = func(string) []clients.Patcher { return []clients.Patcher{a, b, c} }
	return
}

func TestRun_ReadOnlyDefaultFromFlag(t *testing.T) {
	a, _, _, h := threePatchers()
	p := &scriptedPrompter{confirms: []bool{true}, multis: [][]string{{"a"}}}
	r := run(t, true, Options{SkipSSH: true, ReadOnly: true}, h, p)
	if r.err != nil {
		t.Fatalf("err %v", r.err)
	}
	if len(p.confirmDefs) != 1 || !p.confirmDefs[0] {
		t.Fatalf("confirm defaults %v", p.confirmDefs)
	}
	if a.env["PRESSWRENCH_READ_ONLY"] != "1" {
		t.Fatalf("env %v", a.env)
	}
	if !strings.Contains(r.out, "│  Hides shell, WP-CLI and file writes; allows only read-only Pressable calls.\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

func TestRun_ClientsPatched(t *testing.T) {
	a, b, c, h := threePatchers()
	p := &scriptedPrompter{confirms: []bool{false}, multis: [][]string{{"a", "b"}}}
	r := run(t, true, Options{SkipSSH: true}, h, p)
	if r.err != nil {
		t.Fatalf("err %v", r.err)
	}
	if !strings.Contains(r.out, "◇  A · /a\n◇  B · already configured\n") {
		t.Fatalf("output:\n%s", r.out)
	}
	if !a.patched || !b.patched || c.patched {
		t.Fatalf("patched a=%v b=%v c=%v", a.patched, b.patched, c.patched)
	}
	if a.env != nil {
		t.Fatalf("plain install must have no env block, got %v", a.env)
	}
	opts := p.multiOpts[0]
	if len(opts) != 3 || opts[2].Hint != "(not detected)" || !opts[2].Dim || opts[0].Hint != "" {
		t.Fatalf("options %+v", opts)
	}
	if got := strings.Join(p.multiDefaults[0], ","); got != "a,b" {
		t.Fatalf("defaults %s", got)
	}
	if !strings.HasSuffix(r.out, "│\n└  Done. Restart your AI tool, then run `presswrench doctor`.\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

func TestRun_ClientPatchErrorNonFatal(t *testing.T) {
	a, _, _, h := threePatchers()
	a.err = errors.New("boom")
	p := &scriptedPrompter{confirms: []bool{false}, multis: [][]string{{"a"}}}
	r := run(t, true, Options{SkipSSH: true}, h, p)
	if r.err != nil {
		t.Fatalf("err %v", r.err)
	}
	if !strings.Contains(r.out, "■  A · boom\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

func TestRun_NoClientsChosen(t *testing.T) {
	_, _, _, h := threePatchers()
	p := &scriptedPrompter{confirms: []bool{false}, multis: [][]string{{}}}
	r := run(t, true, Options{SkipSSH: true}, h, p)
	if !strings.Contains(r.out, "◇  AI tools · none configured\n") || !strings.Contains(r.out, "└  Done. Run `presswrench doctor` to verify.\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

func TestRun_UnattendedPatchesDetected(t *testing.T) {
	a, b, c, h := threePatchers()
	p := &scriptedPrompter{}
	r := run(t, false, Options{SkipSSH: true, Unattended: true}, h, p)
	if r.err != nil || len(p.calls) != 0 {
		t.Fatalf("err %v calls %v", r.err, p.calls)
	}
	if !a.patched || !b.patched || c.patched {
		t.Fatalf("patched a=%v b=%v c=%v", a.patched, b.patched, c.patched)
	}
}

func TestRun_OnlyClients(t *testing.T) {
	a, b, _, h := threePatchers()
	p := &scriptedPrompter{confirms: []bool{false}, multis: [][]string{{"b"}}}
	r := run(t, true, Options{SkipSSH: true, OnlyClients: []string{"b"}}, h, p)
	if r.err != nil {
		t.Fatalf("err %v", r.err)
	}
	if len(p.multiOpts[0]) != 1 || p.multiOpts[0][0].Value != "b" || a.patched || !b.patched {
		t.Fatalf("opts %+v a=%v b=%v", p.multiOpts[0], a.patched, b.patched)
	}
}

func TestRun_OfficialWarning(t *testing.T) {
	h := fakeHooks()
	h.Official = func() []clients.OfficialEntry {
		return []clients.OfficialEntry{{Client: "Claude Code", Name: "pressable", Path: "/c.json"}}
	}
	r := run(t, true, Options{SkipSSH: true, SkipClients: true}, h, &scriptedPrompter{})
	if !strings.Contains(r.out, "▲  Pressable's official MCP server (mcp.pressable.com) is also configured\n│  Claude Code — pressable  (/c.json)\n") {
		t.Fatalf("output:\n%s", r.out)
	}
}

func TestRun_CancelDuringClients(t *testing.T) {
	a, _, _, h := threePatchers()
	// Confirm answers, then the multi-select cancels.
	p := &scriptedPrompter{confirms: []bool{false}, multiErr: ui.ErrCancelled}
	r := run(t, true, Options{SkipSSH: true}, h, p)
	if !ui.IsReported(r.err) || !errors.Is(r.err, ui.ErrCancelled) {
		t.Fatalf("err %v", r.err)
	}
	if !strings.HasSuffix(r.out, "└\n") || a.patched {
		t.Fatalf("output:\n%s\npatched=%v", r.out, a.patched)
	}
}
