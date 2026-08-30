# Changelog

Notable changes to this project. Newest first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Every entry names the test file that proves it, so a claim here can be checked
with one command rather than taken on trust.

## Unreleased

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
