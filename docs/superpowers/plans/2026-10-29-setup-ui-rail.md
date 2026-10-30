# Setup UI "Rail" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the setup wizard's scrolling prose and `huh` prompts with a compact clack-style "rail" presentation built on a new `internal/ui` package.

**Architecture:** `internal/ui` owns every line the wizard prints: static rail lines written with `fmt`, plus four inline Bubble Tea programs (select, multi-select, text, spinner) whose final `View()` is the collapsed one-line result. `internal/wizard` keeps its step logic but talks only to `ui` and to a small `Hooks` struct of injectable functions. `internal/auth` stops printing; it reports the authorize URL through a callback.

**Tech Stack:** Go 1.25, Bubble Tea v1.3.6, lipgloss v1.1.0, bubbles (spinner, textinput), charmbracelet/x/term, termenv. `huh` is removed.

**Spec:** `docs/superpowers/specs/2026-10-29-setup-ui-design.md`

## Global Constraints

- Go 1.25+, no CGO; CI builds and tests on ubuntu, macOS and Windows. All paths `filepath`-based.
- No new direct dependencies beyond promoting Bubble Tea, lipgloss, bubbles, x/term, termenv (all already indirect). Remove `huh`.
- Colours: ANSI 16 only (`lipgloss.Color("2")` green, `"6"` cyan, `"3"` yellow, `"1"` red, `"8"` dim). `NO_COLOR` honoured by lipgloss.
- Error strings are capitalised sentences that say how to fix the problem (ST1005 is off).
- Logs go to stderr; the wizard writes to stdout. `serve` is untouched.
- `wizard.Options.Out` and `wizard.Prompter` remain the test seams; no test needs a TTY or real Pressable.
- Non-TTY without `--unattended` fails with `ui.ErrNoTerminal`; prompts are never reached in a pipe.
- The public key and the authorize URL are printed with `NoteRaw` (never hard-wrapped).

## Review Focus

1. A terminal narrower than 44 columns: notes wrap at a 40-column floor and never panic (Task 1 test `TestWrap_NarrowFloor`).
2. `LANG=C` on Linux or a legacy `cmd.exe` on Windows: the whole run renders in ASCII glyphs with no `?` boxes (Task 1 test `TestUnicodeDetection`).
3. Ctrl+C in the middle of the AI-tools multi-select: the run ends with `■  Cancelled.` and `└`, exit status 130, nothing half-written (Task 9 test `TestRun_CancelDuringClients`, Task 1 test `TestExitCode`).
4. Clipboard write fails (SSH session, bare Linux): the key is printed in full, and the "Show the key" option is absent (Task 8 test `TestSSHStep_ClipboardFails`).
5. Every SSH attempt fails: the warning line shows the last error and the prompt is re-asked, never looping without the user (Task 8 test `TestSSHStep_TestFailsThenSkip`).

## File structure

```
internal/ui/
  ui.go          UI struct, New/NewTest, Option, Level, Outcome, errors, ExitCode
  glyphs.go      unicode + ascii glyph tables, lipgloss styles
  lines.go       Intro, Step, Warn, Fail, Note, NoteRaw, Outro, wrap
  run.go         runProgram: inline tea.Program runner, cancel mapping
  selectm.go     select model (Confirm + Select)
  multiselect.go multi-select model
  text.go        text model (bubbles/textinput)
  spin.go        Spin (bubbles/spinner)
  *_test.go      one per file
internal/wizard/
  hooks.go       Hooks + DefaultHooks
  prompts.go     Prompter interface (Text, Confirm, Select, MultiSelect)
  wizard.go      Run, steps
  wizard_test.go scripted-prompter tests
  banner.go      DELETED
internal/auth/oauth.go      LoginOptions: -Out, +OnAuthorizeURL
cmd/presswrench/main.go     exit code + reported errors
internal/cli/{setup,login,doctor,status,install,uninstall,accounts}.go
```

---

### Task 1: `internal/ui` core — detection, glyphs, static lines, errors

**Files:**
- Create: `internal/ui/ui.go`, `internal/ui/glyphs.go`, `internal/ui/lines.go`, `internal/ui/ui_test.go`, `internal/ui/lines_test.go`
- Modify: `cmd/presswrench/main.go`

**Interfaces:**
- Produces:
  ```go
  package ui
  type UI struct{ /* out io.Writer; in *os.File; interactive, unicode bool; width int; r *lipgloss.Renderer; g glyphs */ }
  func New(out io.Writer, in *os.File) *UI          // detects TTY (both in and out), unicode, width
  func NewTest(out io.Writer, interactive, unicode bool, width int) *UI  // colour profile Ascii
  func (u *UI) Interactive() bool
  type Option struct{ Label, Value, Hint string; Dim bool }
  type Level int; const ( Done Level = iota; Warn; Fail )
  type Outcome struct{ Level Level; Text string }
  var ErrCancelled = errors.New("Cancelled")
  var ErrNoTerminal = errors.New("Setup needs a terminal. Use --unattended for scripted installs.")
  func Reported(err error) error     // wraps: "already printed by the UI"
  func IsReported(err error) bool
  func ExitCode(err error) int       // 0 nil, 130 if errors.Is(err, ErrCancelled), else 1
  func (u *UI) Intro(title, detail string)   // "┌  title  detail\n" then "│\n"; detail may be ""
  func (u *UI) Step(title, detail string)    // "◇  title · detail\n" (no " · " when detail == "")
  func (u *UI) Warn(title, detail string)    // "▲  …"
  func (u *UI) Fail(title, detail string)    // "■  …"
  func (u *UI) Note(lines ...string)         // each line wrapped at width-4 (floor 40), prefixed "│  "
  func (u *UI) NoteRaw(lines ...string)      // prefixed "│  ", no wrapping
  func (u *UI) Blank()                       // "│\n"
  func (u *UI) Outro(msg string)             // "└  msg\n"
  func (u *UI) Line(level Level, title, detail string) // used by Spin/prompts for final lines
  ```
- Unicode detection (`detectUnicode(goos string, env func(string) string) bool`): on windows → any of `WT_SESSION`, `TERM_PROGRAM`, `ConEmuTask` non-empty; else → `TERM != "linux"` and one of `LC_ALL`, `LC_CTYPE`, `LANG` (first non-empty) contains `UTF-8` or `utf8` case-insensitively. `PRESSWRENCH_ASCII` truthy (via `config.IsTrueEnv`) forces ASCII on both.
- Glyph tables:

  | name | unicode | ascii |
  |------|---------|-------|
  | intro | `┌` | `+` |
  | rail | `│` | `\|` |
  | done | `◇` | `o` |
  | active | `◆` | `*` |
  | warn | `▲` | `!` |
  | fail | `■` | `x` |
  | outro | `└` | `+` |
  | radioOn / radioOff | `●` / `○` | `(*)` / `( )` |
  | checkOn / checkOff | `◼` / `◻` | `[x]` / `[ ]` |
  | cursor | `▸` | `>` |
  | spinner frames | `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` | `-\|/` (as `spinner.Spinner{Frames, FPS}`) |

- Width: if `out` is an `*os.File` and a TTY, `term.GetSize(fd)`; else 80.

- [ ] **Step 1: Write failing tests in `ui_test.go` and `lines_test.go`**

```go
func TestUnicodeDetection(t *testing.T) {
    cases := []struct{ goos string; env map[string]string; want bool }{
        {"linux", map[string]string{"LANG": "en_US.UTF-8"}, true},
        {"linux", map[string]string{"LANG": "C"}, false},
        {"linux", map[string]string{"TERM": "linux", "LANG": "en_US.UTF-8"}, false},
        {"darwin", map[string]string{"LC_ALL": "en_US.utf8"}, true},
        {"windows", map[string]string{"WT_SESSION": "x"}, true},
        {"windows", map[string]string{}, false},
        {"linux", map[string]string{"LANG": "en_US.UTF-8", "PRESSWRENCH_ASCII": "1"}, false},
    }
    // detectUnicode(c.goos, func(k string) string { return c.env[k] }) == c.want
}

func TestExitCode(t *testing.T) {
    // nil → 0; ErrCancelled → 130; Reported(ErrCancelled) → 130; errors.New("x") → 1
    // IsReported(Reported(err)) true; IsReported(err) false; errors.Is(Reported(ErrCancelled), ErrCancelled) true
}

func TestLines_Unicode(t *testing.T) {
    var b bytes.Buffer
    u := NewTest(&b, false, true, 80)
    u.Intro("PressWrench setup", "v0.1.0"); u.Step("SSH key", "~/k"); u.Step("Done", "")
    u.Warn("W", "d"); u.Fail("F", ""); u.Blank(); u.Outro("Done.")
    want := "┌  PressWrench setup  v0.1.0\n│\n◇  SSH key · ~/k\n◇  Done\n▲  W · d\n■  F\n│\n└  Done.\n"
}

func TestLines_ASCII(t *testing.T) { /* same calls, NewTest(&b,false,false,80), want "+  …\n|\no  SSH key · ~/k\no  Done\n!  W · d\nx  F\n|\n+  Done.\n" */ }

func TestNote_Wraps(t *testing.T) {
    // width 50 → wrap at 46: Note("aaaa bbbb … ") 60 chars of words produces two "│  " lines, no line > 49 runes
}
func TestWrap_NarrowFloor(t *testing.T) { /* NewTest(width 20): wrap width is 40, not 16; a 30-char word line is one line */ }
func TestNoteRaw_NoWrap(t *testing.T) { /* 200-char string → exactly one line "│  " + s */ }
```

- [ ] **Step 2: Run `go test ./internal/ui/ -v`** — expected: FAIL (package does not exist / undefined).

- [ ] **Step 3: Implement `ui.go`, `glyphs.go`, `lines.go`**

`New` sets `interactive = isatty(in) && isatty(out)` using `mattn/go-isatty`. Renderer: `lipgloss.NewRenderer(out)`; `NewTest` calls `r.SetColorProfile(termenv.Ascii)`. Styles: dim for rail/intro/outro/detail, green done, cyan active, yellow warn, red fail. `wrap(s string, width int) []string` splits on spaces, greedy; never splits a single word.

- [ ] **Step 4: Wire `main.go`**

```go
if err := cli.Execute(); err != nil {
    if !ui.IsReported(err) && !errors.Is(err, ui.ErrCancelled) {
        fmt.Fprintln(os.Stderr, "error:", err)
    }
    os.Exit(ui.ExitCode(err))
}
```

- [ ] **Step 5: Run `go test ./internal/ui/ -v && go build ./... `** — expected: PASS.

- [ ] **Step 6: Commit** `feat(ui): rail glyphs, static lines, exit codes`

---

### Task 2: Inline program runner + Select/Confirm

**Files:**
- Create: `internal/ui/run.go`, `internal/ui/selectm.go`, `internal/ui/select_test.go`

**Interfaces:**
- Consumes: Task 1 (`UI`, `Option`, glyphs, `Line`).
- Produces:
  ```go
  func (u *UI) runProgram(m tea.Model) (tea.Model, error)   // tea.NewProgram(m, tea.WithInput(u.in), tea.WithOutput(u.out)); returns ErrCancelled when the final model reports cancel
  func (u *UI) Select(title string, options []Option, def string) (string, error)
  func (u *UI) Confirm(title string, def bool) (bool, error)  // Select with Yes/No; returns value "yes"/"no"
  type selectModel struct{ u *UI; title string; opts []Option; cursor int; done, cancelled bool }
  func newSelectModel(u *UI, title string, opts []Option, def string) selectModel
  func (m selectModel) Update(tea.Msg) (tea.Model, tea.Cmd)
  func (m selectModel) View() string
  ```
- Keys: `left`/`h`/`shift+tab` previous, `right`/`l`/`tab` next (wrapping), `1`–`9` jump, `y`/`n` select the option whose label starts with Y/N (case-insensitive) and confirm immediately, `enter` confirm, `esc`/`ctrl+c` cancel.
- Active view (unicode, width irrelevant):
  ```
  ◆  Title
  │  ● Yes  ○ Not yet
  └
  ```
  Focused radio is `radioOn` styled with cyan background + black foreground; others `radioOff` dim. Final view when done: `◇  Title · <label>\n`; when cancelled: `■  Cancelled.\n`. **Final views end with `\n`** (Bubble Tea erases the line the cursor rests on at exit).
- Non-interactive: `Select`/`Confirm` return `ErrNoTerminal` without printing.

- [ ] **Step 1: Write failing tests**

```go
func TestSelect_View(t *testing.T) {
    u := NewTest(io.Discard, true, true, 80)
    m := newSelectModel(u, "Added the key?", []Option{{Label:"Test SSH now",Value:"test"},{Label:"Show the key",Value:"show"},{Label:"Skip",Value:"skip"}}, "test")
    // View() == "◆  Added the key?\n│  ● Test SSH now  ○ Show the key  ○ Skip\n└\n"
}
func TestSelect_Keys(t *testing.T) {
    // right → cursor 1; right,right → wraps to 0 from 2; "3" → cursor 2; enter → done, value "skip"
    // View() after enter == "◇  Added the key?  · Skip\n" -- exact: "◇  Added the key? · Skip\n"
}
func TestSelect_YN(t *testing.T) {
    // Confirm model (labels "Yes","No", def false): View shows "○ Yes  ● No"; key "y" → done, value "yes"
}
func TestSelect_Cancel(t *testing.T) { /* esc → cancelled, View()=="■  Cancelled.\n"; ctrl+c same */ }
func TestSelect_ASCII(t *testing.T) { /* NewTest(unicode=false): "*  T\n|  (*) Yes  ( ) No\n+\n" */ }
func TestSelect_NonInteractive(t *testing.T) { /* NewTest(interactive=false).Select(...) returns ErrNoTerminal, writes nothing */ }
```

- [ ] **Step 2: Run `go test ./internal/ui/ -run 'TestSelect' -v`** — expected: FAIL undefined.
- [ ] **Step 3: Implement `run.go` and `selectm.go`.** `runProgram` uses `tea.NewProgram(m, tea.WithInput(u.in), tea.WithOutput(u.out))`; after `Run`, if the model's `cancelled` is true return `ErrCancelled`.
- [ ] **Step 4: Run tests** — expected: PASS.
- [ ] **Step 5: Manual check** — add a temporary `main` under the scratchpad (not the repo) or run `go run` of a throwaway file that calls `Confirm` twice then `fmt.Println("after")`; confirm the two finished lines stay and "after" is on its own line. Remove the throwaway.
- [ ] **Step 6: Commit** `feat(ui): inline select and confirm prompts`

---

### Task 3: MultiSelect

**Files:**
- Create: `internal/ui/multiselect.go`, `internal/ui/multiselect_test.go`

**Interfaces:**
- Consumes: Task 2 (`runProgram`).
- Produces:
  ```go
  func (u *UI) MultiSelect(title string, options []Option, defaults []string) ([]string, error)  // returns chosen values in option order
  type multiSelectModel struct{ u *UI; title string; opts []Option; checked []bool; cursor int; done, cancelled bool }
  func newMultiSelectModel(u *UI, title string, opts []Option, defaults []string) multiSelectModel
  ```
- Keys: `up`/`k`, `down`/`j` move (wrapping); `space`/`x` toggle; `a` toggle all; `enter` confirm; `esc`/`ctrl+c` cancel.
- Active view:
  ```
  ◆  Configure which AI tools?
  │  ▸ ◼ Claude Code
  │    ◼ Cursor
  │    ◻ Windsurf  (not detected)
  │  space toggle · enter confirm · esc cancel
  └
  ```
  Hint rendered dim after two spaces; `Dim` options render label dim. Focused checkbox gets cyan background. Final: `◇  Title · Claude Code, Cursor\n`; none chosen: `◇  Title · none\n`.
- Non-interactive: `ErrNoTerminal`.

- [ ] **Step 1: Write failing tests** — `TestMultiSelect_View` (exact string above with Windsurf `Hint:"(not detected)", Dim:true`), `TestMultiSelect_Toggle` (down, space → Cursor unchecked; enter → `[]string{"claude"}`), `TestMultiSelect_None` (uncheck all → final view `· none`), `TestMultiSelect_Cancel`, `TestMultiSelect_ASCII` (`|  > [x] Claude Code`).
- [ ] **Step 2: Run** `go test ./internal/ui/ -run TestMultiSelect -v` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(ui): multi-select prompt`

---

### Task 4: Text prompt

**Files:**
- Create: `internal/ui/text.go`, `internal/ui/text_test.go`

**Interfaces:**
- Produces:
  ```go
  func (u *UI) Text(title, placeholder string, validate func(string) error) (string, error)
  type textModel struct{ u *UI; title string; input textinput.Model; validate func(string) error; err error; done, cancelled bool }
  func newTextModel(u *UI, title, placeholder string, validate func(string) error) textModel
  ```
- Enter runs `validate` on the trimmed value; on error keeps the prompt open and shows `│  ▲ <err>` under the input in yellow; on success done. Final: `◇  Title · <value>\n`. Non-interactive: `ErrNoTerminal`.
- Active view:
  ```
  ◆  Paste the URL your browser landed on
  │  <textinput view>
  └
  ```

- [ ] **Step 1: Write failing tests** — `TestText_View` (title + placeholder present), `TestText_ValidateBlocks` (validate returns error for "" → after enter not done, View contains `▲ Required`), `TestText_Done` (type "abc" via `tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("abc")}`, enter → value "abc", final view `◇  T · abc\n`), `TestText_Cancel`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(ui): text prompt`

---

### Task 5: Spin

**Files:**
- Create: `internal/ui/spin.go`, `internal/ui/spin_test.go`

**Interfaces:**
- Produces:
  ```go
  // Spin shows title as the active step with a spinner and status beneath, and
  // optional raw detail lines (never wrapped). fn runs in a goroutine; set()
  // replaces status. The outcome becomes the step's final line.
  func (u *UI) Spin(title, status string, detail []string, fn func(set func(status string)) Outcome) error
  type spinModel struct{ u *UI; title, status string; detail []string; sp spinner.Model; outcome *Outcome; cancelled bool }
  type spinStatusMsg string; type spinDoneMsg Outcome
  ```
- Active view:
  ```
  ◆  Sign in to Pressable in your browser
  │  ⠋ Waiting for you to approve access…
  │  If the browser didn't open: https://…
  └
  ```
- Final: `Line(outcome.Level, outcome.Text, "")` + `\n`. Ctrl+C → `■  Cancelled.\n`, `ErrCancelled` (fn's goroutine is abandoned).
- Non-interactive: prints `◆  title\n` (ASCII/unicode per detection) and the detail lines via `NoteRaw`, runs fn synchronously, then prints the outcome line. Returns nil.

- [ ] **Step 1: Write failing tests** — `TestSpin_View` (unicode: exact string above with status/detail), `TestSpin_StatusAndDone` (Update with `spinStatusMsg("attempt 2 of 4")` → status shown; `spinDoneMsg{Done,"Signed in as a · 3 sites"}` → View `◇  Signed in as a · 3 sites\n`), `TestSpin_WarnOutcome` (`▲  …`), `TestSpin_NonInteractive` (buffer gets `◆  T\n│  d\n◇  ok\n` and fn ran once).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(ui): spinner step`

---

### Task 6: `auth.LoginOptions` stops printing

**Files:**
- Modify: `internal/auth/oauth.go:134-150,190-207`, `internal/auth/auth_test.go:190-215`

**Interfaces:**
- Produces: `LoginOptions.OnAuthorizeURL func(url string, browserOpened bool)` replaces `Out`. `Login` calls it (when non-nil) right after attempting `OpenBrowser`, before waiting. In `Manual` mode `Login` no longer prints the paste instructions; it just calls `ReadLine`.

- [ ] **Step 1: Update `TestLogin_ManualPaste`** to capture the URL via `OnAuthorizeURL: func(u string, _ bool) { authURL = u }` instead of scraping `out`. Add `TestLogin_ReportsBrowserOpened` (fake `OpenBrowser` returning nil → `browserOpened == true`; returning an error → false).
- [ ] **Step 2: Run `go test ./internal/auth/ -run 'TestLogin' -v`** — FAIL (field undefined).
- [ ] **Step 3: Implement**; delete the three `Fprint*` calls and the `Out` field; drop the `io` import if unused.
- [ ] **Step 4: Run `go test ./internal/auth/ && go build ./...`** — auth PASS; build fails in `cli/login.go` and `wizard` (expected; fixed in Tasks 7 and 10). Fix `cli/login.go` minimally now: pass `OnAuthorizeURL` that prints the URL with `fmt.Println` so the build is green (Task 10 replaces it).
- [ ] **Step 5: Commit** `refactor(auth): report authorize URL via callback`

---

### Task 7: Wizard skeleton — Hooks, Prompter, intro, sign-in, outro, errors

**Files:**
- Create: `internal/wizard/hooks.go`, `internal/wizard/wizard_test.go`
- Modify: `internal/wizard/prompts.go` (rewrite), `internal/wizard/wizard.go` (rewrite `Run`, `ensureSignedIn`, `printSummary` removed)
- Delete: `internal/wizard/banner.go`

**Interfaces:**
- Consumes: `ui.UI` (Tasks 1–5), `auth.LoginOptions.OnAuthorizeURL` (Task 6).
- Produces:
  ```go
  // prompts.go
  type Prompter interface {
      Text(title, placeholder string, validate func(string) error) (string, error)
      Confirm(title string, def bool) (bool, error)
      Select(title string, options []ui.Option, def string) (string, error)
      MultiSelect(title string, options []ui.Option, defaults []string) ([]string, error)
  }
  type SelectOption = ui.Option
  // hooks.go
  type Hooks struct {
      SignIn    func(ctx context.Context, o auth.LoginOptions) (identity string, err error)  // default: auth.SignIn + Identity()
      Session   func(ctx context.Context) (identity string, ok bool)   // existing valid session? default: auth.NewSession(...).Token
      ListSites func(ctx context.Context) ([]sites.Site, error)
      CheckSSH  func(ctx context.Context, siteID string) (name, user string, err error)
      EnsureKey func(path, label string) (*mcsh.KeyPair, error)
      Clipboard func(text string) error
      Patchers  func(account string) []clients.Patcher
      Official  func() []clients.OfficialEntry
      StoreLabel string          // "" for keychain, else file path for the 0600 fallback note
      PollDelay time.Duration    // 10s prod, 0 tests
  }
  func DefaultHooks(cfg *config.Config, store creds.Store) (*Hooks, error)  // builds mcpserver deps lazily after sign-in: see note
  // Options gains:
  UI    *ui.UI   // nil → ui.New(Out, os.Stdin)
  Hooks *Hooks   // nil → DefaultHooks
  ```
  Note: `ListSites`/`CheckSSH` need a session; `DefaultHooks` wraps `mcpserver.Build(cfg, store)` created once on first call (closure with `sync.Once`).
- `Run` sequence:
  1. `u := opts.UI` (or `ui.New`). If `!u.Interactive() && !opts.Unattended` → return `ui.ErrNoTerminal` (not reported; main prints it).
  2. `u.Intro("PressWrench setup", "v"+mcpserver.ServerVersion)`; with account: `u.Note(fmt.Sprintf("Account %q · entry %s", acct, clients.EntryName(acct)))` then `u.Blank()`.
  3. Sign-in (`signIn(ctx, u, opts, hooks)`):
     - If `hooks.Session` ok: skip to site listing under `Spin("Checking Pressable access", "Listing sites…", nil, …)` → `Done "Signed in as <id> · N sites"`.
     - Else unattended → error `--unattended needs an existing session (run presswrench login) or PRESSWRENCH_ACCESS_TOKEN`.
     - Else manual: `OnAuthorizeURL` → `u.NoteRaw("Open this URL and sign in:", url)`; `ReadLine` = `opts.Prompter.Text("Paste the URL your browser landed on", "", requireNonEmpty)`; then `ListSites`; print `u.Step("Signed in as …", "N sites")`.
     - Else: `Spin("Sign in to Pressable in your browser", "Waiting for you to approve access…", detail, fn)` where `fn` calls `hooks.SignIn` then `hooks.ListSites`; detail is `[]string{"If the browser didn't open: " + url}` — since the URL is known only inside `fn`, `Spin`'s `set` is used for status and the URL goes through a second callback: extend `Spin`'s `set` contract? **Decision:** `Spin` gets `detail []string` at call time; the sign-in step calls `hooks.SignIn` with `OnAuthorizeURL` that sends the URL via `set("Waiting for you to approve access… " )`… no. Keep it simple: run the authorize-URL discovery first is impossible, so the sign-in `Spin` uses `set` with the full line `"Waiting in the browser · if it didn't open: <url>"`. One status line, raw (status is never wrapped).
     - Store note: if `hooks.StoreLabel != ""` append ` · session in <path> (0600)` to the Done text.
     - Any error → `u.Fail(err.Error(), "")`? No: `Spin` already rendered the Fail outcome; return `ui.Reported(err)`. Outside `Spin`, call `u.Fail` then return `ui.Reported(err)`.
  4. Steps 2–5 are Tasks 8–9; for this task `Run` goes straight from sign-in to the outro.
  5. `WarnOfficial(u)` (signature change: takes `*ui.UI`, returns bool; uses `hooks.Official` — make it a method-free func `warnOfficial(u *ui.UI, found []clients.OfficialEntry) bool` and keep exported `WarnOfficial(u *ui.UI) bool` calling `clients.FindOfficial()` for `doctor`).
  6. `u.Blank(); u.Outro("Done. Restart your AI tool, then run `presswrench doctor`.")` — when no client was patched, outro is `Done. Run `presswrench doctor` to verify.`
  - Cancellation: any `ui.ErrCancelled` from a prompt → `u.Outro("")`? No: the prompt already printed `■  Cancelled.`; `Run` prints `└` via `u.Outro("")` rendered as just `└\n` and returns `ui.Reported(ui.ErrCancelled)`.

- [ ] **Step 1: Write failing tests** (scripted prompter + fake hooks, `u := ui.NewTest(&buf, false, true, 80)` — non-interactive UI but `Options.Unattended=false` must be allowed in tests: add `Options.allowNonInteractive bool` unexported, set by tests via `testOptions()` helper in the test file; or simpler: tests use `Unattended: false` with a `ui.NewTest(&buf, true, …)` whose prompts are never called because `Prompter` is the scripted one. **Use the latter**; `Spin` on an interactive test UI would start a tea.Program — so `NewTest(interactive=true)` must still make `Spin` run synchronously: add `UI.syncSpin bool` set by `NewTest`.)

```go
type scriptedPrompter struct{ confirms []bool; selects []string; multis [][]string; texts []string; calls []string }
func TestRun_AlreadySignedIn(t *testing.T) {
    // hooks.Session ok "andrew@example.com"; ListSites → 12 sites; SkipSSH, SkipClients
    // output == "┌  PressWrench setup  v0.1.0\n│\n◆  Checking Pressable access\n◇  Signed in as andrew@example.com · 12 sites\n│\n└  Done. Run `presswrench doctor` to verify.\n"
}
func TestRun_SignInFails(t *testing.T) { /* hooks.SignIn err "boom" → output contains "■  boom\n", err IsReported */ }
func TestRun_NoTerminalNeedsUnattended(t *testing.T) { /* NewTest(interactive=false), Unattended=false → ErrNoTerminal, buffer empty */ }
func TestRun_UnattendedNeedsSession(t *testing.T) { /* Session not ok, Unattended → error mentions "presswrench login" */ }
func TestRun_FileStoreNote(t *testing.T) { /* StoreLabel "/x/credentials.json" → line ends "· session in /x/credentials.json (0600)" */ }
```

- [ ] **Step 2: Run `go test ./internal/wizard/ -v`** — FAIL.
- [ ] **Step 3: Implement** `hooks.go`, `prompts.go`, `wizard.go` (sign-in + outro only; leave `setupSSH`, read-only and `patchClients` compiled but unreachable for now, or delete and re-add in Tasks 8–9 — delete). Delete `banner.go`. Update `cli/setup.go` and `cli/doctor.go` for the new `WarnOfficial(*ui.UI)` signature (doctor: `wizard.WarnOfficial(ui.New(os.Stdout, os.Stdin))`).
- [ ] **Step 4: Run `go test ./... && go build ./...`** — PASS.
- [ ] **Step 5: Commit** `feat(wizard): rail skeleton with hooks and sign-in step`

---

### Task 8: Wizard SSH key + add/test step

**Files:**
- Modify: `internal/wizard/wizard.go`, `internal/wizard/wizard_test.go`

**Interfaces:**
- Consumes: Task 7 (`Hooks`, `Prompter.Select`), `ui.Spin`, `ui.Warn`, `ui.NoteRaw`.
- Produces: `func setupSSH(ctx, u *ui.UI, opts Options, cfg *config.Config, h *Hooks, siteCount int) error`.
- Behaviour (spec §3):
  - `h.EnsureKey(cfg.SSHKeyPath, cfg.SSHKeyLabel)`; error → `u.Fail("SSH key", err)`, `Reported`.
  - `copied := h.Clipboard(pub) == nil`; `u.Step("SSH key", path + (" · copied to clipboard" if copied))`.
  - Unattended: `u.NoteRaw(pub)`, `u.Note("Add it in MyPressable → Profile → Settings → SSH Keys, named \"<label>\".")`, return.
  - `u.Note("Add it in MyPressable → Profile → Settings → SSH Keys, named \"<label>\".")`; if `!copied` → `u.NoteRaw(pub)`; `u.Blank()`.
  - `siteCount == 0` → `u.Step("SSH test", "no sites to test against yet")`, return.
  - Loop: options `[{Test SSH now,test},{Show the key,show}?,{Skip,skip}]` ("show" only when copied); `Select("Added the key?", opts, "test")`:
    - `show` → `u.NoteRaw(pub)`, continue.
    - `skip` → `u.Step("SSH test", "skipped, check later with presswrench doctor")`, return.
    - `test` → `Spin("Checking SSH access", "attempt 1 of 4", nil, fn)` where fn polls first 3 sites × 4 attempts, `set(fmt.Sprintf("attempt %d of 4", n))`, sleeping `h.PollDelay` between attempts; success → `Outcome{Done, "SSH works · <site> as <user>"}`; all fail → `Outcome{Warn, "SSH not working yet · <lastErr>"}` and loop continues.
  - `ErrCancelled` from `Select` → return it (Run handles).

- [ ] **Step 1: Write failing tests**

```go
func TestSSHStep_ClipboardWorks(t *testing.T) { /* select "skip": output has "◇  SSH key · /k · copied to clipboard", no raw key line, Select options were [test show skip] */ }
func TestSSHStep_ClipboardFails(t *testing.T) { /* Clipboard returns err: output has "│  ssh-ed25519 AAAA test" line; options [test skip] */ }
func TestSSHStep_ShowKeyThenTest(t *testing.T) { /* selects ["show","test"]; CheckSSH ok ("mysite","u1") → key printed once more, then "◇  SSH works · mysite as u1" */ }
func TestSSHStep_TestFailsThenSkip(t *testing.T) { /* CheckSSH always err "denied"; PollDelay 0; selects ["test","skip"] → "▲  SSH not working yet · denied" then "◇  SSH test · skipped, check later with presswrench doctor"; CheckSSH called 12 times (3 sites × 4) */ }
func TestSSHStep_NoSites(t *testing.T) { /* "◇  SSH test · no sites to test against yet", Select never called */ }
func TestSSHStep_Unattended(t *testing.T) { /* raw key printed, no Select */ }
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run `go test ./internal/wizard/ -v`** — PASS.
- [ ] **Step 5: Commit** `feat(wizard): SSH key step on the rail`

---

### Task 9: Wizard read-only, AI tools, official warning, cancel

**Files:**
- Modify: `internal/wizard/wizard.go`, `internal/wizard/wizard_test.go`

**Interfaces:**
- Consumes: Task 7–8.
- Produces: `func readOnlyStep(u, opts, p Prompter) (bool, error)`, `func patchClients(u, opts, h *Hooks, p Prompter) ([]string, error)`, `func warnOfficial(u *ui.UI, found []clients.OfficialEntry) bool`.
- Behaviour (spec §4–5, warning, outro):
  - Read-only: skipped when `SkipClients || Unattended`; `u.Note("Hides shell, WP-CLI and file writes; lets only read-only Pressable operations through.")`; `Confirm("Run in read-only mode?", opts.ReadOnly)`; then `u.Step("Read-only mode", "on"/"off")`. (The `Confirm` prompt's own final line is `◇  Run in read-only mode? · Yes`; **do not** also print `Step` — in interactive mode the prompt line is the record. In the scripted tests the prompter prints nothing, so tests assert on the prompter's call log, not on a read-only line.)
  - Clients: detect as today; `MultiSelect("Configure which AI tools?", opts, defaults)` with `Hint:"(not detected)", Dim:true` for undetected; unattended → defaults. Then `Spin("Writing configs", "…", nil, fn)` is **not** used (patching is fast); instead per client `u.Step(name, path)` / `u.Step(name, "already configured")` / `u.Fail(name, err)` (non-fatal). No selection → `u.Step("AI tools", "none configured")`.
  - `warnOfficial`: `u.Warn("Pressable's official MCP server is also configured", "")`, one `u.Note("<Client> — <Name>  (<Path>)")` per entry, then `u.Note("With both loaded the AI can bypass read-only mode and blocked operations.")`.
  - Outro text depends on `len(patched) > 0` (Task 7).
  - Cancel: `Run` maps `ui.ErrCancelled` from any step to `u.Outro("")` + `ui.Reported(ui.ErrCancelled)`.

- [ ] **Step 1: Write failing tests**

```go
func TestRun_ReadOnlyDefaultFromFlag(t *testing.T) { /* ReadOnly:true → Confirm called with def true */ }
func TestRun_ClientsPatched(t *testing.T) { /* fake patchers: A detected→patched path "/a", B detected→unchanged, C undetected; multi returns [a b]; output has "◇  A · /a", "◇  B · already configured"; MultiSelect options: C has Hint "(not detected)" and Dim; defaults [a b] */ }
func TestRun_ClientPatchErrorNonFatal(t *testing.T) { /* "■  A · boom" and Run returns nil */ }
func TestRun_OfficialWarning(t *testing.T) { /* Official returns one entry → "▲  Pressable's official MCP server is also configured\n│  Claude Code — pressable  (/c.json)\n" */ }
func TestRun_CancelDuringClients(t *testing.T) { /* MultiSelect returns ui.ErrCancelled → output ends "└\n", err: IsReported && errors.Is ErrCancelled, no patcher called */ }
func TestRun_OutroWithClients(t *testing.T) { /* "└  Done. Restart your AI tool, then run `presswrench doctor`.\n" */ }
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run `go test ./... `** — PASS.
- [ ] **Step 5: Commit** `feat(wizard): read-only, AI tools and warning on the rail`

---

### Task 10: `login` and `setup` commands on `ui`

**Files:**
- Modify: `internal/cli/login.go`, `internal/cli/setup.go`

**Interfaces:**
- Consumes: `ui.New`, `ui.Spin`, `ui.Text`, `auth.LoginOptions.OnAuthorizeURL`.
- `login`: `u := ui.New(os.Stdout, os.Stdin)`. Interactive non-manual: `u.Spin("Sign in to Pressable in your browser", "Opening the browser…", nil, fn)` where `OnAuthorizeURL` calls `set("Waiting in the browser · if it didn't open: " + url)`; outcome `Done "Signed in as <id> · account <label>"`, or `Fail err`. Manual or non-interactive: `fmt`-free path using `u.NoteRaw` for the URL and `u.Text` (manual, interactive) or `ReadLine` from stdin (manual, non-interactive); then `u.Step("Signed in as <id>", "account <label>")`.
- `logout` line → `u.Step("Signed out", "account <label>")`.
- `setup`: unchanged apart from passing nothing new (wizard builds its own `ui`).

- [ ] **Step 1: Build and run manually**: `go build -o presswrench ./cmd/presswrench && ./presswrench login --account dev` (real browser; `dev` is a throwaway slot per CLAUDE.md). Expected: spinner line, then `◇  Signed in as … · account dev`. Then `./presswrench setup --account dev --skip-clients` end to end and screenshot/paste the output into the task notes.
- [ ] **Step 2: `go vet ./... && go test ./...`** — PASS.
- [ ] **Step 3: Commit** `feat(cli): login and setup use the rail UI`

---

### Task 11: Other commands adopt the glyphs

**Files:**
- Modify: `internal/cli/doctor.go`, `internal/cli/status.go`, `internal/cli/install.go`, `internal/cli/uninstall.go`, `internal/cli/accounts.go`

**Interfaces:**
- Consumes: `ui.Step/Warn/Fail/Note`, `ui.Spin`.
- Rules: every `✓ X` → `u.Step`, `✗ X` → `u.Fail`, `· X` → `u.Note` (dim), `~ X` (install dry-run) → `u.Warn`. Keep each command's section headers (`Account: …`, `AI-tool configs:`) as plain `fmt` lines. `doctor` wraps the gateway and SSH checks in `Spin` ("Checking Pressable access" / "Checking SSH access"). `status` keeps its column layout; only the leading glyphs change (use `u.Glyph(ui.Done)`-style accessor: add `func (u *UI) Mark(level Level) string` to `lines.go`, returning the styled glyph). `status --json` and `accounts --json` output must not change.
- [ ] **Step 1: Add `Mark` with a test** (`TestMark`: unicode `◇`, ascii `o`).
- [ ] **Step 2: Convert the five files.** Run each command: `./presswrench status`, `./presswrench doctor`, `./presswrench install --dry-run`, `./presswrench accounts list`. Confirm `./presswrench status --json | jq .version` still works.
- [ ] **Step 3: `go test ./... && go vet ./...`** — PASS.
- [ ] **Step 4: Commit** `refactor(cli): shared rail glyphs in status, doctor, install, uninstall, accounts`

---

### Task 12: Dependencies, lint, docs

**Files:**
- Modify: `go.mod`, `go.sum`, `.env.example`, `CLAUDE.md`, `README.md` (if it shows wizard output)

- [ ] **Step 1: `go mod tidy`** — `huh` and `catppuccin/go` disappear; bubbletea, lipgloss, bubbles, x/term, termenv become direct. Confirm `grep -c huh go.mod` → 0.
- [ ] **Step 2: `golangci-lint run`** — fix anything it reports. Verify on Windows paths: `GOOS=windows go build ./...`.
- [ ] **Step 3: Docs**: `.env.example` gains `# PRESSWRENCH_ASCII=1  # force ASCII glyphs in setup/status output`. `CLAUDE.md` architecture tree gains `ui/  rail-style terminal output (static lines + inline Bubble Tea prompts); every command's glyphs come from here` and the `wizard/` line becomes `setup flow on internal/ui; Hooks struct is the test seam`. Add a Gotcha: "**Prompt final views end with `\n`.** Bubble Tea erases the line the cursor rests on when a program exits, so a view without a trailing newline loses its last line." README: replace any pasted wizard transcript with the new shape.
- [ ] **Step 4: Full verification** — `go build -o presswrench ./cmd/presswrench && go test ./... && go vet ./... && golangci-lint run && sh -n install.sh`. Run `./presswrench setup --account dev` once more end to end with Ctrl+C at the AI-tools prompt: expect `■  Cancelled.`, `└`, `echo $?` → 130.
- [ ] **Step 5: Commit** `chore: drop huh, document the rail UI`

---

## Self-review notes

- Spec coverage: intro/sign-in/outro (T7), SSH (T8), read-only/clients/warning/cancel (T9), prompts (T2–4), spinner (T5), auth callback (T6), other commands (T11), ASCII/env/docs (T1, T12), test seams/Hooks (T7), no-TTY error (T7), NoteRaw for key/URL (T1, T7, T8), `login` single step (T10), manual login without spinner (T7, T10).
- Open decision resolved in T7: the authorize URL reaches the sign-in spinner through `set()` as part of the status line, so `Spin` keeps a fixed `detail` parameter and no second callback.
- Name consistency: `ui.Option{Label,Value,Hint,Dim}`, `ui.Outcome{Level,Text}`, `Hooks` field names, `WarnOfficial(*ui.UI) bool` used in T7 and T11.
