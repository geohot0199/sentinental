<div align="center">

<!-- Hero banner -->

<br/>

<img src="https://img.shields.io/badge/SENTINEL-v0.2.0-22d3ee?style=for-the-badge&labelColor=0b0f18&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0iIzIyZDNlZSI+PHBhdGggZD0iTTggMEw4IDEuNUE2LjUgNi41IDAgMCAwIDEuNSA4QTYuNSA2LjUgMCAwIDAgOCAxNC41QTYuNSA2LjUgMCAwIDAgMTQuNSA4QTYuNSA2LjUgMCAwIDAgOCAweiIvPjwvc3ZnPg=="/>
<img src="https://img.shields.io/badge/tests-93_passed-34d399?style=for-the-badge&labelColor=0b0f18"/>
<img src="https://img.shields.io/badge/license-MIT-818cf8?style=for-the-badge&labelColor=0b0f18"/>
<img src="https://img.shields.io/badge/node-≥22.14-fbbf24?style=for-the-badge&labelColor=0b0f18&logo=node.js"/>
<img src="https://img.shields.io/badge/secrets-0_in_logs-34d399?style=for-the-badge&labelColor=0b0f18"/>

<br/><br/>

# 🛡️ SENTINEL

### An autonomous supply-chain CVE strike team.

**It reads your dependency tree, triages every advisory against the versions you *actually ship*, works out how risky each fix is, prepares the patch — and then *stops and asks a human* before it opens the pull request.**

Built on the [TrueForge](https://github.com/truefoundry/trueforge) agent harness.

<br/>

**🌐 [Landing Page](https://geohot0199.github.io/sentinental/)** · **[Releases](https://github.com/geohot0199/sentinental/releases)** · **[Architecture](docs/ARCHITECTURE.md)**

<br/>

</div>

---

## ⚡ The Problem

> A dependency advisory lands. Someone has to work out whether *this* repo is genuinely affected, whether the fix is a one-line bump or a breaking change, whether the test suite survives it, and then write the pull request.
>
> That is an afternoon per advisory, and most teams do it late or not at all.

**The bottleneck is not knowledge. It is that nobody has an afternoon.**

---

## 🔄 What SENTINEL Does

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTINEL Pipeline                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  01 Inventory ──→ 02 Triage ──→ 03 Delegate ──→ 04 Assess      │
│       │                │              │               │          │
│       ▼                ▼              ▼               ▼          │
│  lockfile         advisories      subagents       risk level    │
│  resolved         matched         spawned         per package   │
│                                                                  │
│  05 Plan ──→ 06 Patch ──→ 07 Verify ──→ 08 Propose             │
│      │            │            │             │                   │
│      ▼            ▼            ▼             ▼                   │
│  highest fix   ranges       tests in    ⚠️ WAIT FOR            │
│  version       preserved    sandbox       A HUMAN               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| Stage | What happens | Control |
| :--- | :--- | :---: |
| **🔍 Inventory** | Reads `package.json` and the lockfile from GitHub, resolving real installed versions rather than declared ranges. | 🤖 Agent |
| **🎯 Triage** | Queries the GitHub Advisory Database (OSV fallback) and keeps only advisories whose version range actually matches. | 🤖 Agent |
| **🔀 Delegate** | Spawns one subagent per affected package, each with a clean context window. | 🤖 Agent |
| **📊 Assess** | Works out whether each upgrade is a patch, minor or major bump, and how widely the package is imported. | 🤖 Agent |
| **📋 Plan** | Collapses findings into one safe target version per package — the *highest* fix version, so no advisory is left open. | 🤖 Agent |
| **🔧 Patch** | Generates the updated `package.json`, preserving the project's existing range operators. | 🤖 Agent |
| **✅ Verify** | Installs and runs the test suite in an isolated sandbox. | 🤖 Agent |
| **🚀 Propose** | Opens the pull request. **Pauses. Waits for a human.** | **👤 You** |

> **The last row is the point of the project.** The pause is real: the turn ends, the console shows the full tool call and its arguments, and nothing happens until a person clicks.

---

## 🏗️ Why the Harness is Doing the Work

SENTINEL contains **no agent loop**. There is no `while (toolCalls)`, no retry logic, no context compaction, no approval state machine. All of that is TrueForge's job, and reimplementing it would be exactly the thin wrapper this architecture is designed to avoid.

| Harness Capability | How SENTINEL Uses It |
| :--- | :--- |
| **Agent loop** | Runs the entire multi-step triage. We supply instructions and tools. |
| **MCP tools** | Seven domain tools over remote streamable HTTP, bearer-authenticated. |
| **Human checkpoints** | `open_pull_request` and `merge_pull_request` are gated. The pause is real: the turn ends and waits. |
| **Subagents** | One per advisory, so ten CVEs do not share (and exhaust) one context window. |
| **Sandbox** | Patch verification runs isolated; secrets stay in the harness. |
| **Session state** | Sessions survive a browser refresh; the transcript is replayed from the harness, not from our memory. |
| **Context engineering** | Deferred tool loading and compaction, configured per agent. |

Full reasoning, including the three architectures that were rejected and why, is in **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## 🚀 Quick Start

You need **Node.js ≥ 22.14**.

### Option 1: Install the CLI

```bash
# Download the packaged CLI
curl -L -O https://github.com/geohot0199/sentinental/raw/refs/tags/v0.2.0/releases/sentinel-strike-team-v0.2.0.tgz

# Install globally
npm install --global sentinel-strike-team-v0.2.0.tgz

# Configure and run
cp .env.example .env   # add your keys
sentinel --help
sentinel
```

### Option 2: Run from Source

```bash
# 1. Start the TrueForge harness (separate terminal, keep it running)
npx @truefoundry/trueforge@latest

# 2. Configure SENTINEL
git clone https://github.com/geohot0199/sentinental.git
cd sentinental
npm install
cp .env.example .env      # then add your keys

# 3. Run it
npm run web               # web console at http://localhost:3000
npm run cli               # or the terminal client
```

### Try It Without Any API Key

A scripted model endpoint is included so you can see the whole path — real advisory data, real tools, real approval gate — without spending anything:

```bash
node --experimental-strip-types scripts/mock-model.ts &   # terminal 1
echo "SENTINEL_DEMO_MODEL_URL=http://127.0.0.1:8899/v1" >> .env
npm run web
```

---

## ⚙️ Configuration

| Variable | Required | Purpose |
| :--- | :---: | :--- |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | one of | The model. SENTINEL picks whichever it finds and selects a model from the harness's own catalog. |
| `GITHUB_TOKEN` | **yes** | Reading manifests, opening pull requests. Scope it to the repos you want touched. |
| `SENTINEL_TARGET_REPO` | no | Default repository, as `owner/name`. |
| `DAYTONA_API_KEY` | recommended | Sandbox. Without it the agent is *instructed to report every patch as unverified*. |
| `SENTINEL_ALLOW_REMOTE_WRITES` | no | Hard kill switch. `false` makes destructive tools refuse before any network call. |

Every variable is documented in [`.env.example`](.env.example).

---

## 🛡️ Control and Safety

Safety here is structural, not a prompt instruction the model can talk itself out of.

### 1. The approval policy is declared on the tool, once

TrueForge resolves its `@read-only` / `@write` / `@destructive` approval selectors from MCP tool annotations. So the classification lives next to the implementation, and both front ends inherit it automatically:

| Tool | Annotation | Approval |
| :--- | :--- | :---: |
| `scan_dependencies`, `lookup_advisories`, `assess_blast_radius`, `summarise_triage`, `propose_patch` | `readOnlyHint` | no |
| `open_pull_request`, `merge_pull_request` | `destructiveHint` | **yes** |

A read-only tool cannot mutate a remote. Anything touching GitHub state is destructive by construction, so a mis-tagged tool fails closed.

### 2. Defence in depth on the irreversible path

- The agent spec gates `@destructive` *and* names both tools literally, so a mis-annotated tool is still caught.
- Destructive tool handlers check the kill switch **before any network call**.
- `GitHubClient` re-checks it again at the point of mutation.
- Branch names are generated by us and validated against git's ref rules — the model never supplies a ref.
- The web API only accepts approvals for tool calls the harness actually raised, so a forged request cannot approve something the UI never displayed.

### 3. Failing safe

Denial is the default everywhere: empty input, EOF, Escape key, and unparseable answers all deny. In the web UI, the **Deny** button holds focus, so a stray Enter keypress refuses rather than approves.

---

## 🔒 No Secrets, Anywhere

- Keys live only in `.env`, which is git-ignored, and are read at exactly one place ([`src/core/config.ts`](src/core/config.ts)).
- The browser never talks to the harness or a provider directly — everything is proxied, so no key is ever in front-end reach.
- Two-layer redaction ([`src/core/redact.ts`](src/core/redact.ts)) scrubs every log line, tool result and SSE frame: exact registered values, plus ten credential *shapes* to catch a key we never loaded (say, one the model read out of a file in the sandbox). A demo recording cannot leak a token.
- `npm run scan:secrets` fails the build on anything credential-shaped in a tracked file. It runs in CI.

---

## ✅ Verified, Not Asserted

Everything below was run against the real harness, not mocked.

```
$ npm test
Test Files  6 passed (6)
     Tests  93 passed (93)

$ npm run scan:secrets
✓ Scanned 33 tracked file(s). No secrets found.

$ node --experimental-strip-types scripts/e2e-approval.ts
  ✓ harness reached our MCP tools
  ✓ live advisory data returned through the harness
  ✓ destructive tool triggered an approval gate
  ✓ the gate correctly identified open_pull_request
  ✓ the approval prompt received the full tool arguments
  ✓ a read-only tool ran WITHOUT a gate
  ✓ denying the action was recorded by the harness
  ALL CHECKS PASSED
```

The end-to-end test drives the **real `SentinelRunner`** — the same class the CLI and web app use — against the real TrueForge harness, so it proves the shipped code path rather than a parallel reimplementation.

### A bug this caught

The SDK types imply tool calls arrive on `model.message`. In a live stream they do not: they arrive incrementally across `model.message.delta` frames, with the name in the first and arguments split across later ones, while the streamed `model.message` is empty. A client that trusts the types shows **`unknown_tool` with no arguments** on the approval dialog — a human being asked to authorise an irreversible action with nothing to judge it by.

Fixed in [`src/harness/runner.ts`](src/harness/runner.ts) with a delta accumulator, and locked down by six regression tests in [`tests/runner.test.ts`](tests/runner.test.ts).

---

## 📁 Project Layout

```
src/
  core/       config, redaction, semver, manifests, GitHub, HTTP, errors
  mcp/        the seven tools + the MCP HTTP server
  harness/    agent spec, provisioning, the shared session runner
  cli/        terminal client
  web/        HTTP API + browser console
site/         static landing page (published to GitHub Pages)
tests/        93 unit tests
scripts/      secret scanner, MCP probe, mock model, e2e approval test
docs/         architecture and rejected alternatives
```

Both clients drive the same `SentinelRunner`. That is deliberate: a divergence between two front ends on approval handling would be a genuine safety bug, so there is only one implementation of it.

---

## 🌐 Landing Page

`site/` is a standalone static page — no build step, no dependencies. It carries the overview, the full install (including the packaged CLI from the release), every environment variable, the safety model and the download links.

```bash
npm run site:dev        # http://localhost:4321
```

It is published to GitHub Pages by [`.github/workflows/pages.yml`](.github/workflows/pages.yml) whenever `site/` changes on `main`. The automation account that opens our pull requests cannot commit under `.github/workflows/`, so the file lives in [`ci/pages.yml`](ci/pages.yml) until it is enabled — see [`ci/README.md`](ci/README.md). Every download button points at GitHub — the page itself handles no secrets and stores nothing.

---

## 📋 Qodo Code Review Evidence

Every substantive change in this repository goes through a pull request reviewed by Qodo before merge. No direct pushes to `main`.

**Representative pull request:**
[#1 — feat: SENTINEL, autonomous supply-chain CVE triage agent on TrueForge](https://github.com/geohot0199/TrueForge-GitHub-repository-is-here-/pull/1)

**What our own review pass surfaced before Qodo ran** (recorded here because the same discipline applies whoever finds the issue — each was caught by a test that now guards it):

| Finding | Severity | Resolution |
| :--- | :---: | :--- |
| `open_pull_request` contacted GitHub *before* checking the read-only kill switch, so a read-only deployment still made outbound calls. | **High** | Kill switch moved ahead of all I/O |
| Approval dialog rendered `unknown_tool` with no arguments during a live turn — a human authorising an irreversible action with nothing to judge. | **High** | Root cause was streamed tool calls arguments; delta accumulator fix with 6 regression tests |
| Google API key pattern used a fixed `{35}` length, so a longer key passed through unredacted. | Medium | Widened to `{35,}`; the redaction suite now asserts each of ten credential shapes |
| `vitest` pulled in a transitive `esbuild` advisory (1 critical, 1 high). | Medium | Upgraded to `vitest@3`; `npm audit` is clean and runs in CI |

**What Qodo surfaced:**

- _Awaiting the first review round on [#1](https://github.com/geohot0199/TrueForge-GitHub-repository-is-here-/pull/1). Findings and decisions will be recorded here, with a follow-up review run against the final code._

**How findings are handled:** every valid High-severity finding is fixed before merge. Where a High finding is wrong, deferred, or intentional, it is dismissed in the Qodo thread with the reason recorded there, and a follow-up review is run against the final code so the PR history shows the resolution.

> **Note for reviewers:** the two most security-relevant files are [`src/mcp/tools.ts`](src/mcp/tools.ts) (approval classification) and [`src/core/redact.ts`](src/core/redact.ts) (secret redaction). Findings there are treated as High regardless of the severity assigned.

---

<div align="center">

### 📄 License

MIT — see [LICENSE](LICENSE).

<br/>

**Built with care. Secured by design.**

</div>

<!-- qodo wiring check -->
