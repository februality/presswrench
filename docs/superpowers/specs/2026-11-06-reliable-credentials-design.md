# Reliable credential storage — design

Date: 2026-11-06 · Status: draft for approval (builder-checked) · Area: `internal/creds`, `internal/auth`, CLI status surfaces

## Intent

PressWrench keeps each account's Pressable OAuth session (client id, refresh token, cached access token, expiry, identity) in the OS keychain, with a 0600 file as fallback. The tool hasn't shipped and the only user is the author, so the storage layout can change freely **now**. After the first release it can't, cheaply. The goal is a store that degrades gracefully in every failure we can foresee: the user is never silently signed out, never sent to `login` when login isn't the fix, and never left with a hung tool call.

Success: every failure below ends in either (a) PressWrench carrying on correctly, or (b) one clear, capitalized error sentence that says what happened and the exact command or click that fixes it (house style, see CLAUDE.md "Error strings").

## Failures to cover (from the 2026-11-06 review)

| # | Failure | Today | Wanted |
|---|---------|-------|--------|
| 1 | Keychain password prompt appears (e.g. item ACL changed, OS change) | `security` waits forever; the MCP tool call hangs | Bounded wait, then an error naming the dialog and how to stop it recurring |
| 2a | Refresh succeeds, saving the rotated refresh token fails | Session lost; next run says "not signed in" | Retry; keep the new tokens in memory so this process keeps working and keeps trying to persist; loud log line |
| 2b | Partial write: refresh, access token, expiry are 3 separate items written in sequence | Readers can see a mix of old and new | One item per account, written in one operation |
| 2c | Refresh lock considered stale after 60 s, but a refresh can take 2 × 30 s HTTP requests | A second process can break the lock and spend the same refresh token (rotation → reuse → possible family revocation) | Lock holder keeps the lock fresh while it works; staleness only for a dead holder |
| 2d | `login` writes the session without taking the account lock | Can interleave with a `serve` refresh | `login`, `logout`, `accounts remove` and refresh all take the same per-account lock for their read-modify-write |
| 3a | Keychain locked / no GUI (SSH session) / user denied a prompt | Every read error becomes `ErrLoginRequired` "not signed in", sending the user to `login`, which then fails to save | Distinct errors: not signed in vs. keychain locked vs. access denied vs. keychain unavailable, each with its fix |
| 3b | Linux/WSL: Secret Service reachable for `login`, not for `serve` (different env) | `serve` silently falls back to an empty file store → "not signed in" | The chosen backend is recorded; a later process that can't reach it fails with "keyring unavailable" instead of silently switching |
| 3c | Silent plaintext fallback | Only visible as `source: file` in status | `status`/`doctor` say the file is in use and why; an explicit override exists |
| 4 | Account listing parses `security dump-keychain` text | An Apple format change makes accounts vanish from `status`/`accounts list` | Accounts come from an index item we own; no parsing of Apple output |
| 5 | Future layout change | No version marker anywhere | Every stored record carries a format version; unknown newer versions produce a clear error, older ones are migrated in code |
| 6 | Windows Credential Manager 2560-byte blob limit | Not checked | Size checked before write, clear error if exceeded (real records are ~300–400 bytes: tokens measured at ~44 chars) |

Measured on the author's Mac (2026-11-06): one `security find-generic-password` ≈ 35 ms; `security dump-keychain` ≈ 30 ms for 5.6k lines.

## Goals

- One stored record per account, versioned, written atomically per backend.
- Typed, classified storage errors, mapped to actionable messages at the CLI/MCP edge.
- Every keychain subprocess bounded by a timeout.
- Rotated refresh tokens are never lost because of a transient store failure while the process lives.
- Cross-process serialization for every session write.
- Backend choice is sticky and visible.
- Behaviour of all of the above covered by unit tests without touching the real keychain; the real-keychain test kept behind `PRESSWRENCH_KEYCHAIN_TEST=1`.

## Non-goals

- Migrating sessions written by earlier development builds (per-attribute items under service `presswrench`). There are no users; the author re-logs in. Old items are ignored, not read. (Cleaning them up is a one-off manual step, not product code.)
- Encrypting the file fallback. It stays 0600 plaintext, but becomes explicit.
- Changing OAuth, gateway, or SSH behaviour beyond the session/refresh path.

## Anti-goals (would be a failure even if it "works")

- Any failure mode that ends in "not signed in" when the session is actually still stored.
- Silently writing secrets somewhere the user didn't choose (e.g. falling back to the file because the keychain is momentarily locked).
- A tool call that can hang indefinitely on storage.
- Secrets in process arguments (visible in `ps`). Today's zalando path feeds `security -i` via stdin; keep that property.
- Another dependency on parsing Apple's human-readable output for anything load-bearing.

## Design

### Record

One record per account (JSON), roughly:

```json
{"v":1,"client_id":"…","refresh_token":"…","access_token":"…","access_expiry":1794101512,"identity":"Name <email>"}
```

- `v` is the format version. Reader: `v` > current → error "This session was saved by a newer PressWrench (format N). Upgrade PressWrench, or sign in again with `presswrench login`." Missing/garbled record → treated as corrupt: error naming the account and `presswrench login [--account X]` as the fix (never silently "not signed in").
- Logout keeps the record with `client_id` only (today's "keep the OAuth client for reuse" behaviour). An account "exists" (listed, signed in) only when `refresh_token` is non-empty — same rule as today's `Accounts()`.
- Storage key: `session:<account>`, with `default` for the default account (`default` is already a reserved account name in `validateAccount`). Index key: `accounts`.

### Store interface

Replace the per-attribute `GetFor/SetFor/DeleteFor` with record-level operations, roughly:

- `Load(account) (Record, error)` — `ErrNotFound` when absent.
- `Save(account, Record) error`
- `Delete(account) error` — absent is not an error.
- `Accounts() ([]string, error)` — from the index, filtered to records that exist and have a refresh token; also self-heals the index (drops names whose record is gone, best effort).
- `Backend() Source` and a human description (e.g. "macOS login keychain", "file ~/.config/presswrench/credentials.json (keyring unavailable: <reason>)").

Each backend implements a small raw byte layer (get/set/delete by key); record encoding, versioning, size checks and the index live once, above it. The existing callers (`auth.Session`, `auth.SignIn/SignOut`, `cli` status/doctor/accounts/login/uninstall, `wizard`) move to the record API.

### Errors

A typed storage error with a kind and a fix hint, at least:

| Kind | macOS signal (to verify) | Message direction |
|------|------------------|-------------------|
| NotFound | exit 44 (errSecItemNotFound −25300) | "Not signed in to Pressable (account X). Run `presswrench login [--account X]`." |
| Locked / NoInteraction | exit 36 (errSecInteractionNotAllowed −25308) | "The macOS keychain is locked or can't show a prompt here (e.g. over SSH). Unlock it with `security unlock-keychain` and retry." |
| Denied / Cancelled | exit 128 (userCanceled −128), 51 (errSecAuthFailed) | "Access to the PressWrench keychain item was denied. Retry and choose Always Allow." |
| Timeout | our deadline | "macOS is waiting for you to approve keychain access. Approve the dialog (Always Allow), then retry." |
| Unavailable | backend can't be opened | "The system keyring isn't available (<reason>). …" with the override env var |
| Corrupt / NewerFormat | decode failure / `v` too high | see Record |
| TooLarge | Windows size check | names the size and limit |

(`security` exits with the low byte of the OSStatus; the builder verifies the exact codes on a real Mac.) `auth.Session` must propagate non-NotFound errors as-is instead of converting them to `ErrLoginRequired`. `Source()` likewise must not report "not found" for a locked keychain — status shows the real state.

### macOS backend

- Call `/usr/bin/security` directly via our own thin wrapper (replacing zalando/go-keyring), so we control: `exec.CommandContext` timeouts, exit-code classification, and value encoding. Writes go through `security -i` on stdin (secret never in argv); store the record so it round-trips exactly (e.g. hex via `-X`, or base64 — builder's choice, test it with quotes, `$`, newlines, non-ASCII).
- Item: generic password, service `presswrench`, account = storage key, label `PressWrench session (<account>)` so Keychain Access shows something meaningful.
- `Accounts()` no longer uses `dump-keychain`; `keychain_dump.go` is deleted.
- Timeout: ~60 s for keychain calls, then the Timeout error (my call; a user at the desk has time to click, a headless `serve` doesn't hang forever).
- Keep `openKeyring` cheap (no prompt-capable call at open).

### Linux / Windows backend

Keep `99designs/keyring` (WinCred, Secret Service) behind the same raw layer. Classify its errors as far as it allows (at minimum NotFound vs. other); size check for WinCred before write.

### Backend selection (sticky)

- New env var `PRESSWRENCH_CREDENTIAL_STORE` = `keyring` | `file` (unset = auto). Added to `.env.example` and the config docs.
- One **global** marker (all accounts live in one backend), a small non-secret file in the user config dir (e.g. `presswrench/store`), written at the first successful `login`. Resolution order:
  1. `PRESSWRENCH_CREDENTIAL_STORE` set → that backend, for this process. If it differs from the marker, commands that read sessions warn once that sessions saved in the other store aren't visible; `login` with an override rewrites the marker. Sessions are not migrated between backends.
  2. Marker present → that backend, authoritative both ways: marker `keyring` + keyring unreachable → Unavailable error (no silent switch to the file); marker `file` + keyring now available → still the file.
  3. No marker → try keyring, else file (today's auto behaviour), and `login` records the result.
- `status`/`doctor` print the backend description including why the file is in use.

### Locking

- Generalize `acquireRefreshLock` into a per-account session lock used by refresh, `logout`, `accounts remove`, and `login`. **`login` never holds it across the browser wait**: it locks only its two short read-modify-write steps — (1) read client id / register and save a new one, (2) the final save, which re-reads the record under the lock and replaces only the token fields. (Holding it for minutes would fail every sibling refresh with a misleading message.) Index updates take a separate global index lock.
- Heartbeat: while held, the holder touches the lockfile every ~15 s; staleness stays 60 s since last touch. So a slow refresh is never broken into; a crashed holder still is.
- Lock wait timeout stays bounded and its error says another PressWrench process is refreshing.

### `serve` startup and error delivery

Decided by the author: **`serve` always starts and explains problems inside the chat.**

- `serve` no longer exits when there's no usable session (today it fails fast on `ErrLoginRequired`, so the AI client shows the server as failed and the instructions land only in client logs). It registers its tools regardless of session state.
- The startup check must not be able to block on a keychain prompt: either skip it or run it in the background with a short bound, logging the outcome to stderr. Startup must stay well inside MCP clients' connect timeouts.
- Every tool that needs a session (gateway tools, and SSH tools where they resolve sites via the gateway) returns the classified storage/auth error as its tool-result text: what happened + the exact fix (e.g. "Not signed in to Pressable (account dev). Run `presswrench login --account dev`, then retry."). Mapping from error kind to sentence lives in one place, shared by CLI (`status`, `doctor`, `login`) and MCP results.
- Tools that work without a session (e.g. `pressable_ssh_status` key info) keep working and include the session problem in their output where relevant.
- `PRESSWRENCH_ACCESS_TOKEN` behaviour unchanged.

### Refresh persistence

Pressable **does rotate** refresh tokens: verified 2026-11-06, a forced refresh returned a new refresh token and the old one changed in the store. Whether reusing a spent one revokes the whole token family is unknown, so assume it does.

- `Save` after a refresh retries a few times with short backoff on non-permanent errors (not on Denied/TooLarge).
- If it still fails, the process holds tokens nobody else knows about. It:
  - keeps the new refresh/access tokens in the `Session` (memory), marked unsaved, and returns the access token so the current call succeeds;
  - **keeps holding the account lock** (heartbeat running) until a save succeeds, so sibling processes can't spend the stale refresh token in the store. The lockfile carries a non-secret one-line reason; a sibling that times out waiting reports "Another PressWrench process has a newer session it couldn't save: <reason>. <fix>" rather than a generic refresh message;
  - logs at error level with the classified reason, and retries the save on each subsequent `Token` call and on a short background timer;
  - before each retry, re-reads the stored record: if its refresh token is no longer the one this process spent (a `login` or another writer replaced it), the unsaved tokens are discarded and the lock released — never overwrite a newer session;
  - releases the lock on exit (normal shutdown path); a crash leaves a lock that goes stale after 60 s.
- An invalid_grant path prefers the in-memory unsaved refresh token over the stored one.
- Never spend a refresh token without holding the lock.

## Constraints

- Go 1.25, no CGO, static binaries; CI on Linux, macOS, Windows (`filepath` paths).
- Logs to stderr only (stdout is MCP).
- Error strings are capitalized sentences that say how to fix (ST1005 disabled).
- Read-only/blocklist/policy code untouched.
- Unit tests never touch the real keychain or Pressable; macOS wrapper gets a fake runner seam (inject the command runner) so exit-code mapping, timeout and stdin quoting are tested on every OS.

## Decided by the author (2026-11-06)

- Cover all six failure areas above.
- No compatibility with sessions from earlier builds.
- `serve` always starts and reports session problems through tool results.

## Calls I made (builder may revisit with reason)

- Drop zalando/go-keyring for a direct `security` wrapper (needed for timeouts and exit-code classification).
- One JSON record per account + an index item, rather than per-attribute items.
- 60 s keychain timeout; 15 s lock heartbeat; 60 s staleness.
- Sticky backend marker file + `PRESSWRENCH_CREDENTIAL_STORE` override.
- Storage keys `session:<account>` / `session:default`, index `accounts`.
- A process holding an unsaved rotated session keeps the account lock until it saves (siblings wait, then get a specific error), and never overwrites a newer stored session.
- `login` locks only its short read-modify-write steps, not the browser wait.
- One global backend marker, authoritative both ways; the env override wins per process and `login` with it rewrites the marker; no cross-backend migration.

## Left to the builder

- Exact Go types and package layout inside `internal/creds`; how the raw layer is shaped.
- Encoding of the record inside the keychain item.
- Retry counts/backoff for saves.
- Exact message wording, within the directions above.
- Whether `doctor` gets a dedicated "credential store" check line (recommended).
