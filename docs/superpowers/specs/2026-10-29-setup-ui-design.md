# Setup wizard UI redesign — "rail" style

Date: 2026-10-29. Status: approved in conversation, awaiting plan.

## Intent

`presswrench setup` works well but reads badly. It prints prose for every
step, each `huh` prompt scrolls the previous text away, and the Yes/No
confirm relies on the theme's accent colour to show which button is
focused. Redo the presentation so a run reads as one compact block in
which the current state is obvious at a glance.

The chosen look is the "rail" style used by `npm create vite` / clack:
a vertical `│` rail ties the run together, finished steps collapse to a
single `◇` line, the active prompt is `◆`, and focus is always shown with
a glyph plus a filled background, never colour alone.

## Goals

- A complete run leaves roughly ten lines in the scrollback, one per step.
- At any moment the user can tell what the installer is doing or waiting
  for by looking at the last two lines.
- Yes/No and list prompts show focus unambiguously (glyph + fill),
  and `y`/`n` keystrokes work in Yes/No prompts.
- Long waits (browser sign-in, Pressable creating SSH logins) show a
  spinner that updates in place instead of appending lines.
- Same behaviour on macOS, Linux and Windows (Windows Terminal), with an
  ASCII fallback when the terminal can't show the glyphs.
- Non-interactive paths (`--unattended`, no TTY) still work, printing the
  same vocabulary without prompts.

## Non-goals

- No full-screen (alternate screen) interface. The rail lives in normal
  scrollback.
- No change to what setup does: the same steps, same files written, same
  flags. Only the presentation and the prompt widgets change, plus the
  behaviour changes listed under "Decisions".
- `install.sh` / `install.ps1` output is untouched.
- `status`, `doctor`, `login` keep their structure; they only adopt the
  glyph/colour helpers (see "Other commands").

## Anti-goals (would make this a failure even if it works)

- The run becomes *less* informative: errors must still say what to do.
- The wizard breaks in `--unattended` mode, in CI, or when stdout is a pipe.
- Hard-coded truecolour palettes that are unreadable on light terminals.
- A new dependency tree beyond what the module already pulls in.

## Constraints

- Go 1.25+, no CGO, builds on ubuntu/macOS/Windows in CI. Paths are
  `filepath`-based.
- Bubble Tea v1.3, lipgloss v1.1 and bubbles are already indirect
  dependencies via `huh`; promote them to direct and drop `huh`.
- `wizard.Options.Out io.Writer` and the `Prompter` interface remain the
  test seams. Tests never need a real TTY.
- Logs go to stderr; the wizard writes to stdout (not the MCP channel,
  since `serve` is a different command).
- Error strings stay capitalised sentences that say how to fix the problem.

## Visual vocabulary

ANSI 16-colour only (adapts to the user's theme). `NO_COLOR` is honoured
(lipgloss does this).

| Glyph | ASCII | Colour | Meaning |
|-------|-------|--------|---------|
| `┌`   | `+`   | dim    | intro line: `┌  PressWrench setup  v0.1.0` |
| `│`   | `\|`  | dim    | rail; notes are indented under it as `│  text` |
| `◇`   | `o`   | green  | finished step |
| `◆`   | `*`   | cyan   | active prompt (rail segment below it also cyan) |
| `▲`   | `!`   | yellow | warning |
| `■`   | `x`   | red    | failure / cancelled |
| `└`   | `+`   | dim    | outro line |
| spinner frames `⠋⠙⠹…` | `-\|/` | cyan | step in progress |

Step lines are `GLYPH  Title · detail`, with the detail dimmed. Notes
(instructions, URLs, the public key) sit under the rail as `│  …` and are
wrapped at terminal width minus 4, minimum 40 columns.

Prompt widgets, while active:

```
◆  Added it? Test SSH access now
│  ● Yes / ○ Not yet
└
```

```
◆  Configure which AI tools?
│  ▸ ◼ Claude Code
│    ◼ Cursor
│    ◻ Windsurf            (not detected)
│    ◻ Codex CLI           (not detected)
│  space toggle · enter confirm · esc cancel
└
```

The focused item carries a `▸` cursor and the focused radio/checkbox
glyph is rendered with a cyan background. Key hints appear only in the
multi-select, dimmed, as the last line of the widget.

When a prompt is answered it is redrawn as one finished line and the
cursor moves on:

```
◇  Test SSH access · Yes
◇  AI tools · Claude Code, Cursor
```

Unicode detection: non-Windows → `TERM != "linux"` and
`LANG`/`LC_ALL`/`LC_CTYPE` contains `UTF-8`; Windows → `WT_SESSION`,
`TERM_PROGRAM`, or `ConEmuTask` set, else ASCII. `PRESSWRENCH_ASCII=1`
forces ASCII (document in `.env.example`).

## The flow, line by line

Below, "while" is what's on screen during the step and "after" is the
single line it collapses to.

**Intro**

```
┌  PressWrench setup  v0.1.0
│  Account "dev" · entry presswrench-dev           (only with --account)
│
```

**1. Sign in**

- Already signed in: no prompt. After: `◇  Signed in as andrew@example.com · 12 sites`.
- Otherwise, while:
  ```
  ◆  Sign in to Pressable in your browser
  │  ⠋ Waiting for you to approve access…
  │  If the browser didn't open: https://auth.pressable.com/…
  └
  ```
  `--manual-login` replaces the spinner with a text prompt: `Paste the URL your browser landed on`.
- The spinner covers both the token exchange and the `list_sites` check.
  After: `◇  Signed in as andrew@example.com · 12 sites`. When the
  credentials store is the file fallback, a second dimmed detail is
  appended: `· session in ~/.config/presswrench/credentials.json (0600)`.

**2. SSH key**

- After: `◇  SSH key · ~/.presswrench/id_ed25519` with `· copied to clipboard`
  appended when the clipboard write succeeded.
- `--skip-ssh`: the step is omitted entirely.

**3. Add the key and test**

- While (clipboard worked):
  ```
  │  Add it in MyPressable → Profile → Settings → SSH Keys, named "presswrench".
  │
  ◆  Added the key?
  │  ● Test SSH now  ○ Show the key  ○ Skip
  └
  ```
- Clipboard failed: the key is printed as a note before the prompt and
  the "Show the key" option is omitted. "Show the key" prints the key as
  a note and re-asks.
- "Test SSH now": spinner `⠋ Checking SSH access… (attempt 2 of 4)`,
  polling as today (first three sites, four attempts, 10 s apart).
  Success after: `◇  SSH works · example-site as presswrench-abc1`.
  Failure: `▲  SSH not working yet · <error>` as a warning line, then the
  prompt is re-asked.
- "Skip": after `◇  SSH test · skipped, check later with presswrench doctor`.
- No sites: no prompt; after `◇  SSH test · no sites to test against yet`.
- `--unattended`: the key is printed as a note with the MyPressable
  instructions, no prompt, no test (as today).

**4. Read-only**

- While: `◆  Run in read-only mode?` with `○ No  ● Yes` when `--read-only`
  was passed, `● No  ○ Yes` otherwise. The explanation moves to a one-line
  note above the prompt: `│  Hides shell, WP-CLI and file writes; lets only read-only Pressable operations through.`
- After: `◇  Read-only mode · off` / `· on`.

**5. AI tools**

- Multi-select as drawn above; detected clients pre-checked, undetected
  ones dimmed with `(not detected)` but still selectable.
- Patching happens under a spinner `⠋ Writing configs…`; after, one line
  per chosen client:
  `◇  Claude Code · ~/.claude.json` or `◇  Cursor · already configured`
  or `■  Windsurf · <error>` (non-fatal, continues).
- Nothing selected: `◇  AI tools · none configured`.

**Official-server warning** (unchanged logic, new shape):

```
▲  Pressable's official MCP server is also configured
│  Claude Code — pressable  (~/.claude.json)
│  With both loaded the AI can bypass read-only mode and blocked operations.
```

**Outro**

```
│
└  Done. Restart your AI tool, then run `presswrench doctor`.
```

The old summary block (Entry, Binary, SSH key, MCP server version) is
dropped from setup; `presswrench status` already prints it.

**Errors and cancellation**

- A fatal error prints `■  <error>` under the rail and `└` then returns
  the error; `main` still prints `error: …` to stderr, so the wizard's
  line and main's line must not duplicate: the wizard prints the line and
  returns a sentinel-wrapped error that `main`/cobra does not re-print
  (builder decides the mechanism, e.g. an `ErrReported` type checked in
  `main`).
- Ctrl+C or Esc in any prompt prints `■  Cancelled.`, `└`, and exits with
  status 130.

## Package design

New package `internal/ui`:

```go
type UI struct { /* out, interactive, unicode, width */ }
func New(out io.Writer, in *os.File) *UI   // detects TTY, unicode, width

// static lines
func (u *UI) Intro(title, detail string)
func (u *UI) Step(title, detail string)      // ◇
func (u *UI) Warn(title, detail string)      // ▲
func (u *UI) Fail(title, detail string)      // ■
func (u *UI) Note(lines ...string)           // │  text (wrapped)
func (u *UI) Outro(msg string)               // └

// in-progress
func (u *UI) Spin(title string, fn func(update func(string)) (detail string, err error)) error

// prompts (each implements part of wizard.Prompter)
func (u *UI) Confirm(title string, def bool) (bool, error)
func (u *UI) Select(title string, options []Option, def string) (string, error)
func (u *UI) MultiSelect(title string, options []Option, defaults []string) ([]string, error)
func (u *UI) Text(title, placeholder string, validate func(string) error) (string, error)

var ErrCancelled = errors.New("Cancelled")
```

- Each prompt and the spinner is a small Bubble Tea program run inline
  (no alt screen). Its final `View()` is the collapsed `◇` line, so
  quitting leaves exactly that line behind.
- Models are pure (`Update` on `tea.KeyMsg`), so tests drive them without
  a terminal and compare `View()` output in ASCII mode.
- `Spin` runs `fn` in a goroutine; `update` replaces the spinner's detail
  text (used for "attempt 2 of 4").
- Non-interactive `UI` (no TTY): `Spin` prints the title once and then
  the result line; every prompt returns `ErrNoTerminal` ("Setup needs a
  terminal. Use --unattended for scripted installs."). `wizard.Run`
  checks `UI.Interactive()` up front and fails with that error unless
  `--unattended` was passed, so the wizard never reaches a prompt in a
  pipe and the existing `opts.Unattended` branches stay the single
  non-interactive path.
- `Note` has a no-wrap form (`NoteRaw`) used for the public key and the
  authorize URL, so copy-by-hand strings and clickable URLs are never
  broken across lines; the terminal soft-wraps them.
- `--manual-login` runs with no spinner: the text prompt collects the
  pasted URL, then the exchange and `list_sites` run silently and the
  `◇ Signed in …` line is printed. `auth.Login` keeps its single-call
  shape.
- `presswrench login` does not call `list_sites`; its line is
  `◇  Signed in as andrew@example.com · account default`.

`wizard.Prompter` grows `Select`, loses `Password` (unused). `ui.UI`
implements it. `wizard.Options` gains `UI *ui.UI` (nil → `ui.New(Out, os.Stdin)`).

`auth.LoginOptions` stops printing. It gains
`OnAuthorizeURL func(url string, browserOpened bool)` and the manual-paste
prompt moves to the caller via `ReadLine` as today. `login` and `setup`
both render through `ui`.

## Other commands

- `login`: same spinner and `◇ Signed in as …` line as setup step 1.
- `logout`, `install`, `uninstall`, `accounts`: replace `✓/✗/·` with
  `ui.Step/Fail` glyphs. No prompts change.
- `status`, `doctor`: swap glyphs via `ui`, keep layout. `doctor`'s
  running checks may use `Spin` for the gateway and SSH checks.
- `wizard.WarnOfficial(w)` becomes `ui`-based and keeps its boolean result.

## Decisions made in conversation

- Rail style (option B) over a gh-style prompt log or a full-screen
  Bubble Tea wizard.
- The public key is hidden when the clipboard copy succeeds, shown in
  full when it fails, and available on demand via "Show the key".
  Rationale: public keys are not secret; hiding is for brevity and to
  prevent partial mouse-copies.
- Finished steps remain in the scrollback as a record (one line each).

## Calls made by the author (flag if you disagree)

- Drop `huh`; build widgets directly on Bubble Tea/lipgloss/bubbles.
- An existing valid session skips the "sign in again?" prompt. Users who
  want to switch run `presswrench logout` / `login` or use `--account`.
- "Added the key?" is a three-way select, not a Yes/No, to make "Show the
  key" and "Skip" explicit.
- Setup's closing summary block is removed in favour of `status`.
- ANSI 16 colours only; cyan for active, green done, yellow warn, red fail.
- No TTY without `--unattended` is an error, not a run with defaults.
- The public key and authorize URL are never hard-wrapped.
- `login` stays a single network step (no site count on its line).
- Manual login has no spinner.
- The wizard gets a small `Hooks` struct for tests (above); no broader
  refactor.

## Test seams in the wizard

`wizard.Run` today calls the keychain, config, gateway, SSH, clipboard
and client patchers directly, so the step-level tests listed below need
light injection. `Options` gains an unexported-by-default `hooks` value
(exported constructor for tests) with function fields:

```go
type Hooks struct {
    ListSites  func(ctx) ([]sites.Site, error)
    CheckSSH   func(ctx, siteID string) (name, user string, err error)
    EnsureKey  func(path, label string) (*ssh.KeyPair, error)
    Clipboard  func(text string) error
    Patchers   func(account string) []clients.Patcher
    PollDelay  time.Duration   // 10 s in production, 0 in tests
}
```

Production fills these from `mcpserver.Build` and friends exactly as
today; tests pass fakes. This is the only structural change to the
wizard beyond the presentation layer.

## Left to the builder

- Exact spinner frame set and tick rate.
- How `ErrReported`/exit 130 are plumbed through cobra and `main`.
- Terminal width detection library (`x/term` is already indirect).
- Golden-test format for `View()` output.
- Whether `Confirm` is implemented as a two-option horizontal `Select`.

## Testing

- `internal/ui`: model-level tests for Confirm/Select/MultiSelect/Text
  (key handling, defaults, cancel, `y`/`n`), rendering tests in ASCII and
  Unicode modes, non-interactive fallbacks, note wrapping.
- `internal/wizard`: scripted `Prompter` tests for the step-3 loop
  (test → fail → show key → skip), read-only default, client selection,
  and unattended output. No test touches real Pressable or a real TTY.
- CI unchanged: vet, test, build on three OSes; golangci-lint.
