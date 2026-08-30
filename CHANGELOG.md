# Changelog

Notable changes to this project. Newest first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Every entry names the test file that proves it, so a claim here can be checked
with one command rather than taken on trust.

## Unreleased

### Security & robustness hardening (quality pass)

A dedicated review pass over every server, the terminal client and the WebMCP
engines. Each fix below names the test that proves it; the whole set lives in
`tests/hardening.test.ts` and `tests/web-server-queue.test.ts`.

**Crashes fixed**

- **Deleting a scan mid-run killed the API process.** The pipeline writes
  progress rows under a foreign key on `scans`; a concurrent `DELETE` made
  `Scanner.run()` throw `FOREIGN KEY constraint failed` out of a `void`-launched
  promise — an unhandled rejection, which terminates Node. `run()` now notices
  the vanished row and stops quietly, and the HTTP handler keeps a belt-and-
  braces `.catch`. Proven by: `tests/hardening.test.ts` ("resolves quietly when
  the scan row vanishes mid-run").
- **A malformed URL escape killed the landing-page server.** `GET /%E0%A4%A`
  threw `URIError` inside `site/serve.mjs`'s async handler — an uncaught
  exception. Both static servers now decode safely and answer 404; the API app
  was a 500, now a 404. Proven by: the hostile-path cases in
  `tests/hardening.test.ts`.
- **A bootstrap failure hung the terminal client forever.** The CLI started its
  MCP tool server, then failed provisioning — and returned from `main()` with
  the listening socket still holding the event loop open. The handle is now
  closed on the failure path; the CLI exits 1 with the remedy in well under a
  second.
- **A busy port crashed each server with a raw `EADDRINUSE` stack.** All three
  listeners (MCP, web console, scan API) now boot through
  `src/core/serve.ts::listenOrExit`, which prints one actionable line and exits
  non-zero. `isEntrypoint` moved there with it — and takes the caller's
  `import.meta.url` as a parameter, because a shared helper comparing *its own*
  URL silently disabled every entrypoint (pinned by
  `tests/hardening.test.ts` "isEntrypoint").

**Vulnerabilities closed**

- **The escrow tool handed out its own signing key.** `zkescrow_initiate_
  contract` returned `arbiterSecretKey`, so whoever could call the tool could
  forge arbiter release proofs. The catalog result now carries a fingerprint
  only; the engine keeps the real key for `signEscrowRelease`. Proven by:
  `tests/hardening.test.ts` "zkescrow_initiate_contract key redaction".
- **Rate limiting was keyed on a spoofable header.** `clientKey` took the
  *first* `x-forwarded-for` entry — client-supplied, trivially rotated. It now
  keys on the *last* hop (the one the trusted proxy appended), falling back to
  `x-real-ip`. Proven by: the rotation test in `tests/hardening.test.ts`.
- **Request bodies were unbounded.** `c.req.json()` reads the whole body before
  the 512 KB manifest check could speak. Both HTTP apps now mount hono's
  `bodyLimit` (1 MB) and answer 413. Proven by: "answers 413 for an oversized
  manifest" in `tests/hardening.test.ts`.
- **Model-controlled HTML reached `innerHTML`.** The web console's trace-tree
  renderer interpolated `step.toolName` — which `metaloop_inject_synthetic_
  tool` takes from the model — straight into markup. All dynamic
  interpolations in the console's templates now go through an `esc()` helper.
- **The MCP bearer check leaked the token's length** through its early return.
  It now compares SHA-256 digests with `crypto.timingSafeEqual`.
- **A model-supplied regex could throw or hang the caller.** `breachlab_trace_
  taint_flow` compiled `sourcePattern`/`sinkPattern` unguarded: an invalid
  pattern raised `SyntaxError`, a pathological one backtracked the thread.
  Patterns are length-capped and compiled with an escaped-literal fallback.
  The fix is mirrored into both browser bundles. Proven by: the hostile-pattern
  cases in `tests/hardening.test.ts`.
- **Failed tool calls died silently in the agent cockpit.** A rejecting
  `invokeTool` left an unhandled rejection and a dead transcript; the mission
  runner now renders the error into the stream.

**Race and lifecycle fixes**

- **Approvals raced the closing turn stream.** The web console rejected any
  second submission while a turn was in flight — but the approval-required
  event arrives *before* the stream closes, so a quick decision was dropped.
  `Conversation` now runs a serialized queue: messages get an immediate 409
  while busy, approvals are queued and applied in order, and a failed unit does
  not poison the queue. Proven by: `tests/web-server-queue.test.ts`.
- **Deleting a queued or running scan is refused with 409** instead of racing
  the pipeline; finished scans delete as before.
- **SSE streams for finished scans now close** after the terminal `end` frame
  instead of holding the socket with 15-second heartbeats forever.
- **The web console evicts idle conversations** past 100 sessions instead of
  pinning a runner and replay buffer per session forever, and `POST /api/
  session` is rate limited (each create burns harness-side quota).

**Cleanups**

- `redact()` cached its longest-first secret ordering: it had re-sorted the
  secret set on every call, including every streamed delta frame.
- `SentinelRunner`'s tool-call registry is capped at 500 entries instead of
  growing for the life of the session.
- `scan_dependencies` tolerates a failed lockfile fetch (falling back to
  manifest ranges with a warning) like the scan pipeline already did.
- `fetchCatalog` in `src/harness/provision.ts` goes through the hardened
  `httpJson` wrapper instead of a raw `fetch`.
- The duplicated zod schemas in `lookup_advisories`, `propose_patch` and
  `summarise_triage` are declared once and shared by the MCP schema and the
  handler guard, so they cannot drift.
- The terminal's Ctrl-C semantics: at an idle prompt the first Ctrl-C quits;
  during a turn it cancels the turn and a second Ctrl-C force-quits (it used
  to claim "cancelling…" while nothing was running). The goodbye line only
  advertises `SENTINEL_SESSION_ID` when a session exists.

## Previous release

### Open — needs a permission this project's automation does not have

**The CI pipeline is written and verified locally, but it does not run.** It
lives at `ci/github-actions-ci.yml` because moving it to
`.github/workflows/ci.yml` is what activates it, and that push is refused:

```
! [remote rejected] (refusing to allow a GitHub App to create or update
  workflow `.github/workflows/ci.yml` without `workflows` permission)
```

Anyone with the `workflows` permission can finish it in three commands:

```bash
mkdir -p .github/workflows
cp ci/github-actions-ci.yml .github/workflows/ci.yml
cp ci/pages.yml             .github/workflows/pages.yml
```

Until then, run the same five steps locally — they are the same commands, so
a green local run is exactly what CI would report.

### Added

- **An enforced lint gate.** `eslint.config.js` with
  `@typescript-eslint`'s *type-checked* recommended rules plus `max-lines`
  (500), `max-lines-per-function` (120), `max-depth` (4), `complexity` (20) and
  the `no-eval` / `no-implied-eval` / `no-new-func` / `require-await` family.
  `npm run lint` was already declared in `package.json` but there was no
  config, so it had never been able to run.
- **`tests/eslint-gate.test.ts`** — runs the real ESLint against a fixture
  containing an implicit `any` (`JSON.parse` → typed local → sink, with no
  `any` token for `no-explicit-any` to see) and fails if the gate lets it
  through, plus the counter-case that a narrowed read still passes. Written
  because the config once documented a protection it was not providing, and
  nothing failed.
- **A lint step in the verify pipeline.** `ci/github-actions-ci.yml` now runs
  secret scan → typecheck → **lint (`--max-warnings=0`)** → tests →
  `npm audit --audit-level=high`.
- **`tests/env-example.test.ts`** — derives the environment-variable list from
  the source (`process.env.X`, the `readOptional`/`readPort`/`readBool`
  readers, and the provider `envVar` table) and fails if `.env.example` or the
  README table drifts in either direction.
- **`tests/tools-registry.test.ts`** — pins the one-module-per-tool layout:
  name matches filename, exactly one tool per module, every module under
  300 lines, no duplicate registrations, destructive list derived from the
  annotations.
- **`tests/web-server-status.test.ts`** and **`tests/web-server-session.test.ts`**
  — the first tests to hit the Hono routes through `app.request()`. The
  web console's HTTP surface had none.

### Changed

- **`src/mcp/tools.ts` split into one module per tool** under
  `src/mcp/tools/`, with `tools.ts` reduced to a 65-line barrel exporting
  `TOOLS`, `DESTRUCTIVE_TOOLS` and `runTool`. The largest module is 113 lines.
  The public API is unchanged. The safety annotation that decides whether a
  human must approve a tool now lives in a file a reviewer can read end to
  end.
- **`.env.example`** gained `PORT`, `NO_COLOR`, `MOCK_MODEL_URL`,
  `SENTINEL_MCP_URL` and `SENTINEL_DB`; the README Configuration table gained
  the same four rows plus `SENTINEL_DB`.
- **`GET /api/session/:id/history`** resumes the harness session once instead
  of twice. It had been constructing two `SentinelRunner`s and calling
  `resumeSession` on both, one purely to check the session existed.

### Removed

Dead code the lint gate found, each of it a small lie the source was telling:

- `escapeRegExp` in `src/core/redact.ts`, defined and never called.
- `SentinelRunner.#config`, assigned in the constructor and never read.
- A dead `let answer = ""` initialisation in `src/cli/index.ts`.
- A stale `eslint-disable no-control-regex` in `src/core/github.ts` for a rule
  that does not fire on a character class.
- Three `any`s in the WebMCP tool contract (`src/webmcp/index.ts`). The
  interim `Record<string, any>` input was itself replaced later — see Fixed.
- `async` from `queryGitHub` and the two entry-point `main`s that never
  awaited anything.

### Fixed

- **`eslint.config.js` advertised a protection it did not have.** Its header
  said `@typescript-eslint/no-unsafe-*` keeps untrusted tool input from
  reaching GitHub writes, but it used `tseslint.configs.recommended` — the
  preset that does *not* include those rules — and supplied no TypeScript
  project, so no type information existed to lint against. A probe
  (`JSON.parse(text).command` passed straight to a `string` parameter, with no
  `any` written anywhere) exited 0. Now `recommendedTypeChecked` with
  `projectService` and `tsconfigRootDir`, and the same probe fails with three
  `no-unsafe-*` errors. `disableTypeChecked` is applied to `**/*.{js,mjs,cjs}`:
  the preset installs its parser and its type-aware rules for every file, so
  without that override ESLint aborted on `eslint.config.js` itself.

  Turning the rules on found 93 real violations, all of them fixed rather than
  waived:

  - `src/webmcp/index.ts` — every `execute` took `Record<string, any>` and
    handed fields straight to typed engine parameters. Now `Record<string,
    unknown>` read through `asString` / `asNumber` / `asBoolean` / `asRecord` /
    `asObjectArray`, so a malformed argument degrades to a default instead of
    poisoning an analysis. The comment claimed "engines re-validate what they
    need"; they did not.
  - `src/webmcp/breachlab.ts` — `analyzeCveAst` spread `JSON.parse(manifest).
    dependencies` from the very code it is auditing. Narrowed through
    `asDependencyMap` and a checked `name`.
  - `src/mcp/tools/` — `String(args.x ?? "")` on `unknown` arguments would
    have produced `"[object Object]"` and fed it to a git ref or a GitHub URL;
    now `asText` from `src/mcp/tools/shared.ts`.
  - `src/core/redact.ts`, `src/server/db.ts`, `src/harness/runner.ts` —
    remaining unsafe reads and casts the compiler already narrowed.
- `analyzeCveAst` accepted an `options` argument and never read it, so every
  `{ checkSupplyChain: true }` at a call site did nothing. The parameter is
  now `_options` and the docs say supply-chain checks are unconditional.

### Known debt

Five pre-existing shape violations, across eight sites, carry an inline
`eslint-disable` naming the reason, so the gate stays strict for new code and
the exceptions are visible at the line rather than waived globally in the
config:

| Where | Rule | Why it is still there |
| --- | --- | --- |
| `src/harness/runner.ts` `#translate` | complexity 47, 139 lines | one `case` per harness event type; splitting it scatters the translation table |
| `src/core/advisories.ts` `fromOsv` | complexity 24 | one linear walk of OSV's introduced/fixed event stream |
| `src/webmcp/breachlab.ts` `analyzeCveAst` | complexity 23, 176 lines | one branch per detection rule |
| `src/webmcp/breachlab.ts` `detonateSandbox` | complexity 23 | one branch per detonation intercept |
| `src/webmcp/biosynth.ts` `simulateMutation` | complexity 27 | one branch per stability rule |
| `src/server/api.ts` `buildApp`, `src/web/server.ts` `buildWebApp` | 209 / 171 lines | flat route tables |

No file currently trips `max-lines` — the largest is `src/webmcp/breachlab.ts`
at 452 counted lines (568 physical, the gap being comments and blanks that
`max-lines` skips). It is the first file that will trip it, and the largest
remaining target for a split. The hand-written browser bundles it is copied
into (`src/web/public/`, `site/js/`) are excluded from the gate as vendored
assets.
