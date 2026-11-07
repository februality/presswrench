# Reliable Credential Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-attribute credential store with one versioned record per account, classified errors, bounded keychain calls, sticky backend choice, heartbeat locks, loss-proof refresh persistence, and a `serve` that always starts and explains problems in tool results.

**Architecture:** `internal/creds` becomes two layers: tiny raw byte backends (macOS `security` wrapper, 99designs keyring for Linux/Windows, 0600 file) and one record store above them that owns encoding, versioning, size checks and an account index. A new `internal/lockfile` provides heartbeat lockfiles used by `creds` (index) and `auth` (per-account session lock). `auth` owns the session lifecycle and the single error→sentence mapping (`auth.Explain`) used by CLI and MCP.

**Tech Stack:** Go 1.25 (no CGO), `/usr/bin/security`, `github.com/99designs/keyring` (non-darwin), cobra, mcp-go. `github.com/zalando/go-keyring` is removed.

**Spec:** `docs/superpowers/specs/2026-11-06-reliable-credentials-design.md`

## Global Constraints

- Go 1.25+, `CGO_ENABLED=0`; CI builds/tests on Linux, macOS, Windows — use `filepath`, no darwin-only code in files without a build tag, and every macOS-wrapper unit test runs on all OSes via a fake runner.
- Logs go to stderr only; stdout is the MCP channel.
- Error strings are capitalized sentences that say how to fix (ST1005 is disabled).
- Unit tests never touch the real keychain or Pressable. Real-keychain test only behind `PRESSWRENCH_KEYCHAIN_TEST=1`.
- No secret ever appears in a subprocess argv (secrets go to `security -i` on stdin).
- No compatibility with per-attribute items from earlier builds; they are ignored.
- Read-only mode, blocklist and `checkPolicy` are untouched.
- Values fixed by the spec: record format `v: 1`; keys `session:<account>`, `session:default`, index key `accounts`; keychain service `presswrench`; item label `PressWrench session (<account-label>)`; keychain call timeout 60 s; lock heartbeat 15 s; lock staleness 60 s since last touch; lock wait 30 s; WinCred limit 2560 bytes; env var `PRESSWRENCH_CREDENTIAL_STORE` = `keyring` | `file`; marker file `<user config dir>/presswrench/store`.
- Verified on the author's Mac 2026-11-06: `security` exits 44 for a missing item; `security -i` propagates a failed inner command's exit code (44, 2, …); a base64 value with `-l "<label>"` round-trips via `find-generic-password -w`. Expected but unverified: 36 = errSecInteractionNotAllowed (locked / no UI), 128 = user cancelled, 51 = errSecAuthFailed.

## Review Focus

1. Account slugs with hyphens/digits (`my-site-2`) in `security -i` command lines and lockfile names: must round-trip and stay quoted. → test in Task 3.
2. Index and record diverge (crash between the two writes; index lists a deleted record; record exists but unindexed): `Accounts()` lists exactly the signed-in records and self-heals. → test in Task 2.
3. Two processes saving different accounts at the same moment: both end up in the index. → test in Task 2.
4. Login interrupted after client registration (browser closed, Ctrl-C): record holds only `client_id`, account is not listed, the next login reuses the client without re-registering. → test in Task 6.
5. Stored `access_expiry` missing/0 or record without access token: treated as expired → refresh, never an error. → test in Task 2.

---

### Task 1: Heartbeat lockfile package

**Files:**
- Create: `internal/lockfile/lockfile.go`
- Test: `internal/lockfile/lockfile_test.go`

**Interfaces:**
- Produces:
  - `var StaleAfter = 60 * time.Second; var Heartbeat = 15 * time.Second; var Poll = 100 * time.Millisecond` (tests shrink them)
  - `type Lock struct{ ... }`
  - `func Acquire(ctx context.Context, path string, wait time.Duration) (*Lock, error)` — O_EXCL create (dir created 0700, file 0600); breaks a lock whose mtime is older than `StaleAfter`; on timeout returns `*HeldError`; on ctx done returns `ctx.Err()`.
  - `func (l *Lock) SetReason(reason string) error` — rewrites the file's content (one line, non-secret).
  - `func (l *Lock) Release()` — stops heartbeat, removes file; idempotent.
  - `type HeldError struct{ Path, Reason string }` with `Error()`: `"Timed out waiting for another PressWrench process (lock " + Path + ")"`, plus `": " + Reason` when set.

- [ ] **Step 1: Write the failing tests**

```go
func TestAcquire_Serializes(t *testing.T)            // second Acquire(wait 50ms) while held → *HeldError; after Release → succeeds
func TestAcquire_BreaksStale(t *testing.T)           // create file, os.Chtimes to now-61s → Acquire succeeds immediately
func TestHeartbeat_KeepsLockFresh(t *testing.T)      // StaleAfter=100ms, Heartbeat=20ms; hold 300ms; concurrent Acquire(wait 250ms) → *HeldError
func TestHeldError_CarriesReason(t *testing.T)       // SetReason("x couldn't save"); failed Acquire's HeldError.Reason == "x couldn't save"
func TestRelease_Idempotent(t *testing.T)            // Release twice, no panic, file gone
```

- [ ] **Step 2: Run** `go test ./internal/lockfile/ -v` — Expected: FAIL (package doesn't exist).
- [ ] **Step 3: Implement** `internal/lockfile/lockfile.go`. Heartbeat = goroutine `os.Chtimes(path, now, now)` every `Heartbeat` until Release. `HeldError.Reason` is the file's trimmed content read at timeout.
- [ ] **Step 4: Run** `go test ./internal/lockfile/ -race -v` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(lockfile): heartbeat lockfiles with holder reason`

---

### Task 2: Record store (creds core, file + adapted keyring backends, callers switched)

Switches the whole tree to the record API in one compiling step. macOS still uses zalando inside its raw adapter until Task 3.

**Files:**
- Create: `internal/creds/errors.go`, `internal/creds/record.go`, `internal/creds/recordstore.go`, `internal/creds/recordstore_test.go`
- Rewrite: `internal/creds/store.go` (interface, `Open`, `ListAccounts`, `ConfigDir`), `internal/creds/filestore.go` (raw file backend), `internal/creds/keyring_other.go` (raw adapter), `internal/creds/keychain_darwin.go` (raw adapter over zalando), `internal/creds/creds_test.go`, `internal/creds/keychain_darwin_test.go`
- Delete: `internal/creds/keychain_dump.go`, `internal/creds/keychain_dump_test.go`
- Modify: `internal/auth/session.go`, `internal/auth/signin.go`, `internal/auth/lock.go` (lock dir from `creds.ConfigDir`), `internal/auth/auth_test.go`, `internal/cli/accounts.go:100-107`, `internal/cli/uninstall.go:100-110`, `internal/wizard/hooks.go:75-82`

**Interfaces:**
- Consumes: `lockfile.Acquire`, `(*Lock).Release` (Task 1).
- Produces (package `creds`):
  - `type Kind int` with `KindOther, KindNotFound, KindLocked, KindDenied, KindTimeout, KindUnavailable, KindCorrupt, KindNewerFormat, KindTooLarge`
  - `type Error struct{ Kind Kind; Account string; Op string; Backend Source; Detail string; Err error }`, `Error()`, `Unwrap()`, `Is(target) bool` (true for `ErrNotFound` when `Kind == KindNotFound`)
  - `var ErrNotFound`; `func KindOf(err error) Kind` (KindOther for non-`*Error`); `func Permanent(err error) bool` (Denied, TooLarge, Corrupt, NewerFormat)
  - `const RecordVersion = 1`; `type Record struct{ V int "v"; ClientID "client_id"; RefreshToken "refresh_token"; AccessToken "access_token"; AccessExpiry int64 "access_expiry"; Identity "identity" }` (json tags as quoted, `omitempty` except `v`); `func (r Record) SignedIn() bool` (`RefreshToken != ""`)
  - `type Info struct{ Source Source; Description string; Warning string }`
  - `type Store interface{ Load(account string) (Record, error); Save(account string, r Record) error; Delete(account string) error; Accounts() ([]string, error); Info() Info }`
  - `func NewFileStore(path string) Store` (lock dir = `filepath.Dir(path)`), `func DefaultFilePath() (string, error)`, `func Open() (Store, error)` (for now: keyring, else file), `func ListAccounts() ([]string, error)`, `func Broken(err error) Store` (every method returns `err`; `Info()` = `{Source: SourceNotFound, Description: "unavailable", Warning: err.Error()}`)
  - `func ConfigDir() (string, error)` — `<os.UserConfigDir()>/presswrench`, overridable via unexported `var configDir` in tests
  - per-OS `func openKeyring() (rawBackend, Info, error)` (darwin in `keychain_darwin.go`, others in `keyring_other.go`); open failure → `*Error{Kind: KindUnavailable}`
  - unexported: `type rawBackend interface{ get(key string) ([]byte, error); set(key, label string, value []byte) error; del(key string) error; maxValue() int }` (absent → `*Error{Kind: KindNotFound}`; `del` of absent → nil; `maxValue` 0 = unlimited); `func newRecordStore(raw rawBackend, info Info, lockDir string) Store`; `func sessionKey(account string) string`; `const indexKey = "accounts"`
  - `DeleteSession`, `SessionKeys`, `Key*` constants, `GetFor/SetFor/DeleteFor`, `accountsFromKeys`, `Backend()` are removed.
- Produces (package `auth`): `SaveTokens(store creds.Store, account string, tr *TokenResponse, now time.Time) error` keeps its name but does Load → overwrite token fields + identity → Save (one write).

- [ ] **Step 1: Write the failing tests** in `internal/creds/recordstore_test.go` (use `NewFileStore` on `t.TempDir()`, plus a `fakeRaw` map backend with settable `max` and per-call error injection):

```go
func TestRecord_RoundTripAndVersion(t *testing.T)        // Save then Load equals input with V == 1
func TestRecord_NewerFormat(t *testing.T)                // raw value {"v":2,...} → KindOf(err) == KindNewerFormat, err.(*Error).Account == "acme"
func TestRecord_Corrupt(t *testing.T)                    // raw value "not json" → KindCorrupt
func TestSessionKey(t *testing.T)                        // sessionKey("") == "session:default"; sessionKey("acme") == "session:acme"
func TestAccounts_OnlySignedIn(t *testing.T)             // "", "acme" with refresh tokens, "half" with ClientID only → ["", "acme"]
func TestAccounts_SelfHealsIndex(t *testing.T)           // index lists "ghost" with no record → not listed, and index no longer contains it;
                                                          // record "orphan" written raw without index entry, then Save("orphan", …) → listed
func TestAccounts_ConcurrentSavesBothIndexed(t *testing.T) // two NewFileStore instances on same path, goroutines Save "a" and "b" (20 rounds) → Accounts == ["a","b"]
func TestDelete_RemovesRecordAndIndex(t *testing.T)      // Delete("acme") → Load ErrNotFound, not in Accounts; Delete of absent → nil
func TestSave_TooLarge(t *testing.T)                     // fakeRaw max=2560, record with 3000-char access token → KindTooLarge, raw untouched
func TestFileStore_ModeAndRemovalWhenEmpty(t *testing.T) // 0600 (skip perm check on windows); file removed after last Delete
```

And in `internal/auth/auth_test.go`, convert existing tests to `Load`/`Save` (assert on `Record` fields instead of keys) and add:

```go
func TestSession_ZeroExpiryRefreshes(t *testing.T) // signed-in record with AccessExpiry 0 → Token refreshes (f.refreshes == 1), no error
```

- [ ] **Step 2: Run** `go test ./internal/creds/ ./internal/auth/` — Expected: FAIL (compile errors: undefined `Load`, `Record`, …).
- [ ] **Step 3: Implement creds.** Record JSON is the raw value for every backend (keychain adapters base64 it themselves in Task 3; the file backend stores it as a string in `{"v":1,"items":{"<key>":"<record json>"}}`, atomic temp+rename as today). Index value: `{"v":1,"accounts":["default","acme"]}` (storage names, `default` ↔ `""`). Index read-modify-write runs under `lockfile.Acquire(ctx, <lockDir>/accounts.lock, 30*time.Second)`. `Save` writes the record first, then adds to the index if missing; `Delete` deletes the record, then removes from the index. `Save` checks `len(encoded) > raw.maxValue()` (when non-zero) before writing. Keyring adapter (`keyring_other.go`, `//go:build !darwin`): label `PressWrench session (<label>)`, `maxValue()` = 2560 when `runtime.GOOS == "windows"` else 0, `keyring.ErrKeyNotFound` → KindNotFound, other errors → KindOther with the message as Detail. Darwin adapter: zalando get/set/del of the base64 string, KindNotFound on `keyring.ErrNotFound`.
- [ ] **Step 4: Switch callers.** `auth.Session`, `SignIn`, `SignOut`, `registerAndStore` use `Load`/`Save` (SignOut saves a record with only `ClientID`); `cli accounts remove` and `uninstall` call `store.Delete(account)` after `SignOut`; `wizard.DefaultHooks` sets `StoreLabel` from `store.Info().Description` when `Info().Source == creds.SourceFile`. Behaviour otherwise unchanged in this task.
- [ ] **Step 5: Run** `go build ./... && go vet ./... && go test ./...` — Expected: all PASS.
- [ ] **Step 6: Commit** `refactor(creds): one versioned record per account with an account index`

---

### Task 3: macOS backend calls `/usr/bin/security` directly

**Files:**
- Create: `internal/creds/security.go` (no build tag), `internal/creds/security_test.go`
- Modify: `internal/creds/keychain_darwin.go` (only `openKeyring` wiring), `internal/creds/keychain_darwin_test.go` (real test on new API), `go.mod`, `go.sum`

**Interfaces:**
- Consumes: `rawBackend`, `*Error`, `Kind*` (Task 2).
- Produces:
  - `type runFunc func(ctx context.Context, stdin string, args ...string) (stdout, stderr []byte, exit int, err error)`
  - `var keychainTimeout = 60 * time.Second`
  - `func newSecurityBackend(service string, run runFunc) rawBackend`
  - `func classifySecurity(exit int, timedOut bool) Kind` — 44 → NotFound, 36 → Locked, 128 → Denied, 51 → Denied, timedOut → Timeout, else Other
  - `func execSecurity(ctx context.Context, stdin string, args ...string) (stdout, stderr []byte, exit int, err error)` — the real runner on `/usr/bin/security`

- [ ] **Step 1: Write the failing tests** (fake runner records argv + stdin):

```go
func TestSecurity_GetDecodes(t *testing.T)            // stdout base64("{"v":1}")+"\n" → get returns {"v":1}; argv == [find-generic-password -s presswrench -a session:acme -w]
func TestSecurity_SetKeepsSecretOffArgv(t *testing.T)  // argv == ["-i"]; stdin == `add-generic-password -U -s "presswrench" -a "session:my-site-2" -l "PressWrench session (my-site-2)" -w <base64>` + "\n"; no argv element contains the base64
func TestSecurity_ExitCodes(t *testing.T)              // table: 44→KindNotFound, 36→KindLocked, 128→KindDenied, 51→KindDenied, 2→KindOther; Detail carries trimmed stderr
func TestSecurity_Timeout(t *testing.T)                // keychainTimeout = 50ms; runner blocks on <-ctx.Done() → KindTimeout within 1s
func TestSecurity_DeleteMissingIsNil(t *testing.T)     // exit 44 on delete-generic-password → nil
func TestSecurity_GarbledValueIsCorrupt(t *testing.T)  // stdout "%%%" → KindCorrupt
```

- [ ] **Step 2: Run** `go test ./internal/creds/ -run Security -v` — Expected: FAIL (undefined `newSecurityBackend`).
- [ ] **Step 3: Implement** `security.go`. Each call uses `context.WithTimeout(context.Background(), keychainTimeout)`; `execSecurity` uses `exec.CommandContext` and reports `exit` from `*exec.ExitError`. Values are std base64 of the record. `maxValue()` = 0.
- [ ] **Step 4: Wire** `keychain_darwin.go`: `openKeyring()` stats `/usr/bin/security` (missing → KindUnavailable) and returns `newSecurityBackend(ServiceName, execSecurity)` with `Info{Source: SourceKeyring, Description: "macOS login keychain"}`; no subprocess at open. Update the real test to `Load`/`Save`/`Delete`/`Accounts` with a unique service, including account `my-site-2` and a value with quotes, `$HOME` and non-ASCII.
- [ ] **Step 5: Remove zalando:** `go mod tidy`; `grep -r zalando go.mod` — Expected: no match.
- [ ] **Step 6: Run** `go test ./... && GOOS=windows go vet ./... && GOOS=linux go vet ./...` and, on the Mac, `PRESSWRENCH_KEYCHAIN_TEST=1 go test ./internal/creds/ -run RealKeychain -v` — Expected: PASS.
- [ ] **Step 7: Commit** `feat(creds): call /usr/bin/security directly with timeouts and classified errors`

---

### Task 4: Sticky backend selection

**Files:**
- Create: `internal/creds/select.go`, `internal/creds/select_test.go`
- Modify: `internal/creds/store.go` (`Open` delegates), `internal/auth/signin.go` (remember backend after the final save), `.env.example`, `README.md` (env var table, if it lists `PRESSWRENCH_*` vars)

**Interfaces:**
- Consumes: `newRecordStore`, file backend, `openKeyring` (Tasks 2–3).
- Produces:
  - `const EnvCredentialStore = "PRESSWRENCH_CREDENTIAL_STORE"`
  - `type selectOpts struct{ env string; markerPath string; filePath string; lockDir string; openKeyring func() (rawBackend, Info, error) }`
  - `func openWith(o selectOpts) (Store, error)`
  - `func RememberBackend(s Store) error` — writes `keyring\n` or `file\n` to the marker (0600) when it differs; no-op for a `Broken` store.

Resolution (from the spec): env set → that backend (invalid value → `KindOther` error "PRESSWRENCH_CREDENTIAL_STORE must be keyring or file"; `keyring` + unreachable → KindUnavailable); else marker → authoritative (`keyring` + unreachable → KindUnavailable, `file` → file even if keyring works); else keyring, falling back to file. File `Info.Description`: `file <path>` plus ` (keyring unavailable: <reason>)`, ` (PRESSWRENCH_CREDENTIAL_STORE=file)` or ` (chosen at first sign-in)`. When env and marker disagree, `Info.Warning` = `PRESSWRENCH_CREDENTIAL_STORE=<env> overrides the <marker> store used at sign-in; sessions saved there aren't visible.`

- [ ] **Step 1: Write the failing test** — one table test:

```go
func TestOpenWith_Selection(t *testing.T)
// env      marker   keyring  → want
// ""       none     ok       → SourceKeyring
// ""       none     fails    → SourceFile, Description contains "keyring unavailable"
// ""       keyring  fails    → KindUnavailable
// ""       file     ok       → SourceFile
// "file"   keyring  ok       → SourceFile, Warning non-empty
// "keyring" none    fails    → KindUnavailable
// "bogus"  none     ok       → error mentioning PRESSWRENCH_CREDENTIAL_STORE
func TestRememberBackend_WritesMarker(t *testing.T) // file store → marker "file\n", mode 0600 (non-windows); second call no rewrite (mtime unchanged)
```

- [ ] **Step 2: Run** `go test ./internal/creds/ -run 'OpenWith|Remember' -v` — Expected: FAIL.
- [ ] **Step 3: Implement** `select.go`; `Open()` = `openWith` with real env, `<ConfigDir>/store`, `DefaultFilePath()`, `openKeyring`.
- [ ] **Step 4: Call** `creds.RememberBackend(store)` at the end of a successful `auth.SignIn` (error logged, not returned). Add `# PRESSWRENCH_CREDENTIAL_STORE=file   # keyring | file (default: keyring, else file)` to `.env.example`.
- [ ] **Step 5: Run** `go test ./...` — Expected: PASS.
- [ ] **Step 6: Commit** `feat(creds): remember the credential backend and add PRESSWRENCH_CREDENTIAL_STORE`

---

### Task 5: Classified errors reach the user (`auth.Explain`)

**Files:**
- Create: `internal/auth/explain.go`, `internal/auth/explain_test.go`
- Modify: `internal/auth/oauth.go:38-40`, `internal/auth/session.go` (error propagation, `State`), `internal/mcpserver/tools_gateway.go:150-156`, `internal/mcpserver/server_test.go`, `internal/cli/serve.go` (`loginCommand` → `auth.LoginCommand`), `internal/cli/status.go`, `internal/cli/doctor.go`

**Interfaces:**
- Consumes: `creds.KindOf`, `*creds.Error` (Task 2), `*lockfile.HeldError` (Task 1).
- Produces:
  - `type LoginRequiredError struct{ Account string; Expired bool }` with `Is(target) bool` true for `ErrLoginRequired`
  - `func LoginCommand(account string) string` (moved from cli), `func AccountLabel(account string) string` (`"default"` for `""`)
  - `func Explain(err error) string`
  - `func (s *Session) State() (creds.Source, error)` replaces `Source()`: `(SourceEnv, nil)`; `(store Info().Source, nil)` when signed in; otherwise `(SourceNotFound, err)` with `*LoginRequiredError` or the store's `*creds.Error`.
  - `Session.Token` returns `*LoginRequiredError{Account}` when there's no record / no refresh token, `{Expired: true}` after invalid_grant, and any other store error **unchanged**.

Exact copy for `Explain` (`<cmd>` = `LoginCommand(account)`, `<label>` = `AccountLabel(account)`):

| Error | Sentence |
|---|---|
| LoginRequired | `Not signed in to Pressable (account <label>). Run ` + "`<cmd>`" + ` in a terminal, then retry.` |
| LoginRequired, Expired | `The Pressable sign-in for account <label> expired or was revoked. Run ` + "`<cmd>`" + ` in a terminal, then retry.` |
| KindLocked (darwin) | `The macOS keychain is locked or can't show a prompt here (for example over SSH). Unlock it with ` + "`security unlock-keychain`" + `, then retry.` |
| KindLocked (other OS) | `The system keyring is locked. Unlock it, then retry.` |
| KindDenied | `Access to PressWrench's keychain item was denied. Retry and choose Always Allow when macOS asks.` |
| KindTimeout | `macOS is waiting for you to approve keychain access for PressWrench. Approve the dialog (Always Allow), then retry.` |
| KindUnavailable | `The system keyring isn't available (<Detail>). Start it, or set PRESSWRENCH_CREDENTIAL_STORE=file and sign in again with ` + "`<cmd>`" + `.` |
| KindCorrupt | `The stored PressWrench session for account <label> is damaged. Run ` + "`<cmd>`" + ` to sign in again.` |
| KindNewerFormat | `The session for account <label> was saved by a newer PressWrench. Upgrade PressWrench, or sign in again with ` + "`<cmd>`" + `.` |
| KindTooLarge | `The PressWrench session for account <label> is too large for the system keyring (<Detail>). Set PRESSWRENCH_CREDENTIAL_STORE=file and sign in again.` |
| HeldError with Reason | `Another PressWrench process holds a newer session it couldn't save: <Reason>` |
| HeldError, no Reason | `Another PressWrench process is refreshing the Pressable session. Retry in a moment.` |
| anything else | `err.Error()` |

- [ ] **Step 1: Write the failing tests:**

```go
func TestExplain(t *testing.T)                              // one row per table line above (Locked row uses runtime.GOOS); assert exact strings
func TestSession_LockedKeychainIsNotLoginRequired(t *testing.T) // faultyStore Load → &creds.Error{Kind: KindLocked, Account: "acme"}; Token err: KindOf == KindLocked, !errors.Is(err, ErrLoginRequired); State() returns same err
func TestSession_InvalidGrantIsExpired(t *testing.T)        // fake AS answers invalid_grant → errors.As LoginRequiredError with Expired true
```

`faultyStore` (in `auth_test.go`): wraps a real `creds.Store`, with `loadErr error` and `saveErrs []error` consumed one per `Save` call, counting `saves`. Task 7 reuses it.

In `internal/mcpserver/server_test.go`, the existing login-required case asserts the text contains `presswrench login`; add a case where the gateway returns `&creds.Error{Kind: creds.KindLocked}` → result text equals `auth.Explain` of it.

- [ ] **Step 2: Run** `go test ./internal/auth/ ./internal/mcpserver/` — Expected: FAIL.
- [ ] **Step 3: Implement** `explain.go`, the `Session` changes, and `errResult` → `mcp.NewToolResultError(auth.Explain(err))`. Update `status.go` (`State()` instead of `Source()`) and `doctor.go` (`u.Fail(auth.Explain(err), "")` for any Token error) so the tree compiles.
- [ ] **Step 4: Run** `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(auth): classified storage errors with one actionable message each`

---

### Task 6: Account lock for refresh, login, logout and remove

**Files:**
- Modify: `internal/auth/lock.go` (rewrite on `lockfile`), `internal/auth/session.go`, `internal/auth/signin.go`, `internal/auth/auth_test.go`, `internal/cli/accounts.go`, `internal/cli/uninstall.go`

**Interfaces:**
- Consumes: `lockfile.Acquire/Release` (Task 1), `creds.ConfigDir` (Task 2).
- Produces:
  - `var lockWait = 30 * time.Second` (tests shrink it); `func lockAccount(ctx context.Context, account string) (*lockfile.Lock, error)` — path `<lockDir()>/session.lock` or `session-<account>.lock`, where auth's existing test seam `var lockDir` now defaults to `creds.ConfigDir`
  - `func RemoveAccount(ctx context.Context, store creds.Store, account, authURL string) error` — under the lock: revoke (best effort), `store.Delete(account)`
  - `SignOut` takes the lock around load → revoke → save `{ClientID}`
  - `SignIn` takes the lock only for (1) load client id / register + save `{ClientID}` and (2) re-load, apply tokens, save — never during `Login()`
- `acquireRefreshLock` is removed; `TestRefreshLock_SerializesAndBreaksStale` is deleted (covered by Task 1).

- [ ] **Step 1: Write the failing tests:**

```go
func TestSignIn_DoesNotHoldLockDuringBrowser(t *testing.T) // OpenBrowser fake first calls lockAccount(ctx,"") with lockWait=100ms → must succeed (then Release), then follows the URL; SignIn succeeds
func TestSignIn_InterruptedKeepsClientOnly(t *testing.T)    // OpenBrowser returns error → SignIn fails; Load("") has ClientID != "" and RefreshToken == ""; Accounts() == []; second SignIn → fake AS registrations == 1
func TestSession_SlowRefreshNotDoubleSpent(t *testing.T)    // lockfile.StaleAfter=100ms, Heartbeat=20ms; fake AS delays /token 300ms, rotate=true; two Sessions on one store call Token concurrently after expiry → f.refreshes == 1, both succeed
func TestRemoveAccount_DeletesRecord(t *testing.T)          // signed-in "acme" → RemoveAccount → Load ErrNotFound, not in Accounts, revoke called
```

(The fake AS needs a `delay time.Duration` and a `registrations` counter if absent.)

- [ ] **Step 2: Run** `go test ./internal/auth/ -v` — Expected: FAIL.
- [ ] **Step 3: Implement** the lock helpers and the `SignIn`/`SignOut`/`RemoveAccount`/refresh changes; `cli accounts remove` and `uninstall --remove-credentials` call `auth.RemoveAccount` instead of `SignOut` + `Delete`.
- [ ] **Step 4: Run** `go test ./... -race` — Expected: PASS.
- [ ] **Step 5: Commit** `fix(auth): heartbeat account lock for refresh, login, logout and remove`

---

### Task 7: Never lose a rotated refresh token

**Files:**
- Modify: `internal/auth/session.go`, `internal/auth/auth_test.go`

**Interfaces:**
- Consumes: `faultyStore` (Task 5), `lockAccount`, `(*lockfile.Lock).SetReason` (Tasks 1, 6), `creds.Permanent` (Task 2), `Explain` (Task 5).
- Produces:
  - `var saveBackoff = []time.Duration{200 * time.Millisecond, time.Second}` (3 attempts total; tests set zeros)
  - `var pendingRetry = 30 * time.Second`
  - `func (s *Session) Close()` — stops the retry timer and releases a held lock; idempotent; safe when nothing is pending
  - Unexported state on `Session`: `pending *creds.Record`, `spent string` (the refresh token this process exchanged), `held *lockfile.Lock`

Behaviour (spec, "Refresh persistence"): after a refresh, save with retries (stop early on `creds.Permanent`). On final failure: keep `pending`, keep `held`, `held.SetReason(fmt.Sprintf("account %s: %s", AccountLabel(account), Explain(saveErr)))`, log at error level, return the new access token. Each later `Token` call and each `pendingRetry` tick tries a flush: re-load; if the stored refresh token != `spent` → drop `pending`, release; else save; on success → release. While `pending`, `Token` serves the in-memory token and uses `pending.RefreshToken` for any further refresh.

- [ ] **Step 1: Write the failing tests:**

```go
func TestSession_SaveFailureKeepsWorking(t *testing.T)        // saves always fail (KindOther) → Token returns new token; second Token returns same token; f.refreshes == 1; faultyStore.saves == 3
func TestSession_SaveFailureHoldsLock(t *testing.T)           // as above, lockWait=100ms; sibling Session (expired stored token) Token → *lockfile.HeldError, Reason contains "account default"; f.refreshes == 1
func TestSession_PendingFlushedWhenStoreRecovers(t *testing.T) // saves fail 3×, then succeed; next Token → stored RefreshToken == newest; sibling lockAccount succeeds
func TestSession_PendingDiscardedWhenSuperseded(t *testing.T)  // while pending, underlying store gets record with RefreshToken "from-login"; next Token → stored still "from-login"; lock released
func TestSession_DeniedNotRetried(t *testing.T)                // save err KindDenied → faultyStore.saves == 1
func TestSession_CloseReleasesLock(t *testing.T)               // pending session Close() → lockAccount succeeds; second Close no panic
```

- [ ] **Step 2: Run** `go test ./internal/auth/ -run Session -v` — Expected: FAIL.
- [ ] **Step 3: Implement** in `session.go`.
- [ ] **Step 4: Run** `go test ./... -race` — Expected: PASS.
- [ ] **Step 5: Commit** `fix(auth): keep a rotated session in memory and locked until it's saved`

---

### Task 8: `serve` always starts; tools explain session problems

**Files:**
- Modify: `internal/cli/serve.go`, `internal/mcpserver/tools_site.go` (ssh_status), `internal/mcpserver/server_test.go`
- Create: `internal/cli/serve_test.go`

**Interfaces:**
- Consumes: `creds.Broken` (Task 2), `Session.State`, `Session.Close`, `Explain` (Tasks 5, 7).
- Produces:
  - `func newServeDeps(cfg *config.Config, open func() (creds.Store, error)) *mcpserver.Deps` — never fails: an `open` error becomes `creds.Broken(err)`; starts a background goroutine that calls `Session.Token` once and logs `Explain(err)` at warn level (or "session ok" at debug). Never blocks startup.
  - `runServe` = `newServeDeps` + `defer deps.Session.Close()` + `defer deps.SSHPool.Close()` + `ServeStdio`. The not-signed-in fail-fast is removed. `PRESSWRENCH_ACCESS_TOKEN` path unchanged (no store opened).
  - `pressable_ssh_status` output gains `Session string \`json:"session,omitempty"\`` = `Explain(err)` when `State()` returns an error; the key info is still returned.

- [ ] **Step 1: Write the failing tests:**

```go
func TestNewServeDeps_OpenFailureStillServes(t *testing.T)   // open returns &creds.Error{Kind: KindUnavailable, Detail: "no dbus"} → deps non-nil; deps.Session.Token err → Explain contains "PRESSWRENCH_CREDENTIAL_STORE=file"
func TestNewServeDeps_NotSignedInStillServes(t *testing.T)   // empty file store → deps non-nil, returns promptly (< 1s)
func TestSSHStatus_ReportsSessionProblem(t *testing.T)        // in mcpserver: Deps with Broken store → ssh_status result not an error, JSON has "session" containing the Explain text and "keyPath"
func TestGatewayTool_NotSignedInExplains(t *testing.T)        // pressable_discover with empty store → isError, text contains "presswrench login"
```

- [ ] **Step 2: Run** `go test ./internal/cli/ ./internal/mcpserver/ -v` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(serve): always start and report session problems through tool results`

---

### Task 9: CLI surfaces show the store and the real problem

**Files:**
- Modify: `internal/cli/status.go`, `internal/cli/doctor.go`, `internal/cli/login.go`, `internal/cli/accounts.go` (list errors), `internal/cli/accounts_test.go`
- Create: `internal/cli/status_test.go` (if absent)

**Interfaces:**
- Consumes: `Store.Info`, `Session.State`, `Explain`, `LoginCommand`, `AccountLabel` (Tasks 2–5).
- Produces:
  - `var openStore = creds.Open` in package `cli` (all commands use it; tests replace it)
  - `sessionStatus` gains `Problem string \`json:"problem,omitempty"\`` (Explain of a non-login-required `State()` error); `statusOutput` gains `Store string \`json:"store"\`` and `StoreWarning string \`json:"storeWarning,omitempty"\``
  - Text output: one `Credentials: <Info.Description>` line under the binary line (with a Warn mark and the warning when set); a non-signed-in account with a `Problem` prints a Fail mark and the Problem instead of "not signed in".
  - `doctor`: first step per run, `Credential store · <Description>` (Warn when `Warning != ""` or the file is a keyring-unavailable fallback); Token failure → `u.Fail(auth.Explain(err), "")`.
  - `login`: failures print `auth.Explain(err)`.
  - `accounts list`: if `ListAccounts` fails, print a Warn line with `Explain(err)` and still list client-config entries.

- [ ] **Step 1: Write the failing tests:**

```go
func TestBuildAccountStatus_LockedKeychain(t *testing.T) // openStore → store whose Load fails KindLocked → SignedIn false, Problem contains "security unlock-keychain"
func TestBuildStatus_ShowsStoreAndWarning(t *testing.T)   // openStore → file store with Info.Warning "x" → Store == Description, StoreWarning == "x"
func TestListAccounts_StoreErrorStillListsClients(t *testing.T) // ListAccounts error → rows from client configs still returned
```

- [ ] **Step 2: Run** `go test ./internal/cli/ -v` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go build ./... && go vet ./... && go test ./... && golangci-lint run` — Expected: PASS, no lint findings.
- [ ] **Step 5: Commit** `feat(cli): show the credential store and the real session problem`

---

### Task 10: Docs and real-machine verification

**Files:**
- Modify: `CLAUDE.md` (creds line in Architecture; Gotchas: macOS keychain bullet rewritten for the direct `security` wrapper + exit-code mapping + 60 s timeout; replace the `Store.Accounts()` bullet with the record/index layout; add sticky backend + `PRESSWRENCH_CREDENTIAL_STORE`; refresh-lock bullet → heartbeat lock incl. login/logout/remove and the unsaved-session rule; `serve` always starts)

- [ ] **Step 1: Update `CLAUDE.md`** as listed; keep entries terse, matching the file's style.
- [ ] **Step 2: Remove the old dev-build items from the author's keychain** (no product code): for each of `access_token access_expiry refresh_token identity oauth_client_id` and prefixes `""`, `dev:`, `e2e:`: `security delete-generic-password -s presswrench -a <prefix><attr>`; remove `~/Library/Application Support/presswrench/refresh*.lock`. Expected: `security dump-keychain | grep -c '"svce"<blob>="presswrench"'` → 0.
- [ ] **Step 3: Real-keychain test:** `PRESSWRENCH_KEYCHAIN_TEST=1 go test ./internal/creds/ -run RealKeychain -v` — Expected: PASS.
- [ ] **Step 4: End-to-end on the Mac** (two builds with different cdhashes, as on 2026-11-06): `login --account e2e` (browser, author approves) → item ACL lists only `/usr/bin/security`, label `PressWrench session (e2e)`; `serve` `list_sites` from both builds without a prompt; force expiry by saving a record with `access_expiry` 0 through a tiny `go run` helper or test hook, then `serve` refreshes and the stored refresh token changes; `status`/`doctor` show `Credentials: macOS login keychain`; `PRESSWRENCH_CREDENTIAL_STORE=file status` shows the override warning; `accounts remove --account e2e --yes` leaves no `session:e2e` item and `accounts` index without `e2e`. Then re-login `default` (and `dev` if wanted).
- [ ] **Step 5: Commit** `docs: credential storage design notes in CLAUDE.md`
