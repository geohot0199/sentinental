<div align="center">

# SENTINEL

**An autonomous supply-chain CVE strike team, built on the [TrueForge](https://github.com/truefoundry/trueforge) agent harness.**

*It reads your dependency tree, triages every advisory against the versions you actually ship, works out how risky each fix is, prepares the patch — and then **stops and asks a human** before it opens the pull request.*

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node ≥ 22.14](https://img.shields.io/badge/Node-%E2%89%A5%2022.14-10b981.svg)]()
[![TrueForge](https://img.shields.io/badge/Harness-TrueForge-7c3aed.svg)](https://github.com/truefoundry/trueforge)
[![Tests](https://img.shields.io/badge/Tests-142%20passed-10b981.svg)]()

</div>

---

## Table of contents

1. [The problem](#the-problem)
2. [What SENTINEL does](#what-sentinel-does)
3. [Quick install](#quick-install)
4. [Installation](#installation)
   - [A. Packaged CLI](#a-install-the-packaged-cli)
   - [B. Run from source](#b-run-from-source)
   - [C. No API key demo](#c-no-api-key-demo)
5. [Configuration](#configuration)
6. [Architecture](#architecture)
7. [The 7 MCP tools](#the-7-mcp-tools)
8. [Control and safety](#control-and-safety)
9. [Why the harness does the work](#why-the-harness-does-the-work)
10. [Degradation strategy](#degradation-strategy)
11. [Local development & testing](#local-development--testing)
12. [Contributing](#contributing)
13. [A bug this caught](#a-bug-this-caught)
14. [Project layout](#project-layout)
15. [Included: the WebMCP OMNI-LAB demo](#included-the-webmcp-omni-lab-demo)
16. [FAQ](#faq)
17. [License](#license)

---

## The problem

> **Nobody has an afternoon.**

A dependency advisory lands. Someone has to work out whether *this* repository is genuinely affected, whether the fix is a one-line bump or a breaking change, whether the test suite survives it, and then write the pull request. That is an afternoon per advisory, and most teams do it late — or not at all.

Every software team on earth has this backlog. So the work is not knowledge work any more; it is repetition at scale, and **repetition is exactly what an agent should be doing.**

SENTINEL is the agent that does it. It is given a repository and told to go find what is rotting in the dependency tree. Everything up to the pull request is autonomous. **The pull request itself is not** — that is the irreversible step, and it stops there and asks.

---

## What SENTINEL does

Eight stages. The last one is yours.

```
sentinel — triage owner/repo

01 Inventory   lockfile resolved
02 Triage      14 advisories → 3 match
03 Delegate    3 subagents spawned
04 Assess      1 major · 2 patch
05 Plan        highest fix version
06 Patch       ranges preserved
07 Verify      93/93 in sandbox
08 Propose     waiting for a human

approval required: open_pull_request · destructive
```

1. **Inventory** — reads `package.json` and the lockfile from GitHub, resolving real installed versions rather than declared ranges.
2. **Triage** — queries the GitHub Advisory Database (OSV fallback) and keeps only advisories whose version range *actually matches*.
3. **Delegate** — spawns one subagent per affected package, each with a clean context window — ten CVEs do not share (and exhaust) one context.
4. **Assess** — works out whether each upgrade is a patch, minor or major bump, and how widely the package is imported.
5. **Plan** — collapses findings into one safe target version per package — the *highest* fix version, so no advisory is left open.
6. **Patch** — generates the updated `package.json`, preserving the project's existing range operators.
7. **Verify** — installs and runs the test suite in an isolated sandbox.
8. **Propose** — opens the pull request. **Pauses. Waits for a human.**

The last row is the point of the project. The pause is real: the turn ends, the console shows the full tool call and its arguments, and nothing happens until a person clicks.

---

## Quick install

```bash
npm install --global https://github.com/geohot0199/sentinental/raw/refs/tags/v0.2.0/releases/sentinel-strike-team-v0.2.0.tgz
```

Requires **Node.js ≥ 22.14**. Then add your keys and run `sentinel`.

---

## Installation

Everything you need, in three commands. Pick the path that fits. All downloads come straight from GitHub — there is no registry, no mirror, and nothing to sign up for.

### A. Install the packaged CLI

The packaged CLI from the **v0.2.0 release**. Requires **Node.js ≥ 22.14**.

```bash
# 1. Download the package (or press Download on the release page)
curl -L -O https://github.com/geohot0199/sentinental/raw/refs/tags/v0.2.0/releases/sentinel-strike-team-v0.2.0.tgz

# 2. Verify (optional)
sha256sum sentinel-strike-team-v0.2.0.tgz
# b14628e81bbcd73dc46429bb238b04a71c5524420a618a6757d4c89d9f5cef5c

# 3. Install globally
npm install --global sentinel-strike-team-v0.2.0.tgz

# 4. Add your keys
cp .env.example .env   # then add your provider + GitHub keys

# 5. Run it
sentinel --help
sentinel
```

One-liner instead of steps 1–3:

```bash
npm install --global https://github.com/geohot0199/sentinental/raw/refs/tags/v0.2.0/releases/sentinel-strike-team-v0.2.0.tgz
```

### B. Run from source

Full source, with the web console and the MCP tool server. Needs the TrueForge harness running alongside it.

```bash
# 1. Start the TrueForge harness (keep it running in a separate terminal)
npx @truefoundry/trueforge@latest

# 2. Clone and install
git clone https://github.com/geohot0199/sentinental.git
cd sentinental
npm install

# 3. Configure
cp .env.example .env      # then add your keys

# 4. Run it
npm run web               # web console at http://localhost:3000
```

…or the terminal client:

```bash
npm run cli               # the terminal client
```

…or just the MCP tool server:

```bash
npm run mcp               # the MCP tool server on http://127.0.0.1:8791
```

### C. No API key demo

A scripted model endpoint is included, so you can see the whole path — real advisory data, real tools, real approval gate — without spending anything.

```bash
# 1. Start the scripted model
node --experimental-strip-types scripts/mock-model.ts &   # terminal 1

# 2. Point SENTINEL at it
echo "SENTINEL_DEMO_MODEL_URL=http://127.0.0.1:8899/v1" >> .env

# 3. Run the console
npm run web
```

The terminal client works the same way with `npm run cli`.

### Before you start

- ✅ **Node.js ≥ 22.14** — the CLI uses type stripping
- ✅ **One model key** — OpenAI, Anthropic or Gemini
- ✅ **GitHub token** — fine-grained PAT, Contents + Pull requests read/write
- ⚠️ **Daytona key** — recommended; without it every patch is reported unverified

**Scope your token properly.** Grant the GitHub token access *only* to the repositories you want SENTINEL to touch. It is read-only in spirit — the only writes are the branch and the pull request, and both are gated behind you.

Running a demo? Set `SENTINEL_ALLOW_REMOTE_WRITES=false` and destructive tools refuse before any network call.

---

## Configuration

Every environment variable, in one table. Copy `.env.example` to `.env`, fill in what you need, leave the rest commented. It is git-ignored and read in exactly one place (`src/core/config.ts`).

| Variable | Required | Purpose |
| --- | --- | --- |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | one of | The model. SENTINEL picks whichever it finds and selects a model from the harness's own catalog. |
| `MODEL_PROVIDER` | optional | Force a provider: `openai` · `anthropic` · `google-gemini`. |
| `MODEL_ID` | optional | Force a specific model. Leave unset and SENTINEL picks a sensible mid-tier model. |
| `GITHUB_TOKEN` | yes | Reading manifests, opening pull requests. Scope it to the repos you want touched. |
| `SENTINEL_TARGET_REPO` | optional | Default repository, as `owner/name`. |
| `DAYTONA_API_KEY` | recommended | Sandbox. Without it the agent is instructed to report every patch as unverified. |
| `SENTINEL_ALLOW_REMOTE_WRITES` | optional | Hard kill switch. `false` makes destructive tools refuse before any network call. |
| `TRUEFORGE_URL` | optional | Harness URL. Default `http://127.0.0.1:8790`. |
| `SENTINEL_MCP_PORT` | optional | Tool server port. Default `8791`. |
| `SENTINEL_MCP_URL` | optional | URL the harness is given for the tool server. Set it when the harness cannot reach us on `127.0.0.1`. Default `http://127.0.0.1:<SENTINEL_MCP_PORT>/mcp`. |
| `SENTINEL_WEB_PORT` | optional | Web console port. Default `3000`. |
| `PORT` | optional | Port override read by the standalone API app (`npm run app`), falling back to `SENTINEL_WEB_PORT`, and by the landing-page server (`npm run site:dev`, default `4321`). |
| `SENTINEL_DB` | optional | SQLite file for the API app's scan history. Default `.sentinel/sentinel.db`. |
| `SENTINEL_MCP_TOKEN` | optional | Shared secret the harness uses to call SENTINEL's tool server. Unset means a fresh random token every boot. |
| `SENTINEL_DEMO_MODEL_URL` | optional | Point at the bundled scripted model for a keyless demo run. |
| `MOCK_MODEL_URL` | optional | Where `scripts/e2e-approval.ts` finds that scripted model. Default `http://127.0.0.1:8899/v1`. |
| `NO_COLOR` | optional | Set to any value to force plain text in the CLI. Colour is already off when stdout is not a TTY. |

Secrets never enter the repository or the model's context. Keys live in `.env` (git-ignored), are read once at provision time, handed to the harness over localhost, and stored by the harness. `npm run scan:secrets` runs in CI and fails the build on anything that looks like a live credential.

---

## Architecture

```
┌──────────────────┐        ┌──────────────────┐
│  Terminal client │        │    Web client    │
│  (src/cli)       │        │  (src/web)       │
│  Ink-free TTY    │        │  Hono + SSE + UI │
└────────┬─────────┘        └────────┬─────────┘
         │                            │
         │   both speak the SAME core │
         └─────────────┬──────────────┘
                       ▼
         ┌───────────────────────────────┐
         │  src/harness  (our thin layer) │
         │  • provision.ts  idempotent    │
         │    setup of providers/MCP/     │
         │    sandbox/agent               │
         │  • runner.ts  turn loop +      │
         │    approval pump + reconnect   │
         │  • events.ts  normalises the   │
         │    TrueForge event union       │
         └───────────────┬───────────────┘
                         │ @truefoundry/trueforge-sdk (HTTP)
                         ▼
         ╔═══════════════════════════════╗
         ║   TrueForge harness (theirs)  ║
         ║   agent loop · context mgmt   ║
         ║   subagents · approvals       ║
         ║   session state · sandbox     ║
         ╚═══╤═══════════╤═══════════╤═══╝
             │           │           │
       model │       MCP │   sandbox │
             ▼           ▼           ▼
        OpenAI /    src/mcp      Daytona
        Anthropic  (our tool     (isolated
        / Gemini    server)       exec)
```

### The critical design decision

**We do not reimplement any part of the agent loop.** No `while (toolCalls)`, no retry logic, no context compaction, no approval state machine. Those all exist in TrueForge, and re-writing them is exactly the "thin wrapper around a model" that the Best Use of TrueForge track penalises.

What we own is the two things the harness deliberately leaves to you:

1. **A tool server** (`src/mcp`) — the domain expertise. Remote MCP over streamable HTTP, because TrueForge 0.1.4 only accepts `type: "remote"`.
2. **Two front ends** (`src/cli`, `src/web`) — driving the same core.

The agent's *behaviour* lives in `src/harness/agent-spec.ts`, and deliberately contains no loop, no tool dispatch, and no approval bookkeeping:

```ts
// src/harness/agent-spec.ts (excerpt)
return {
  model: { name: config.provider.fqn },
  instructions: buildInstructions(config),
  mcpServers: [
    {
      name: MCP_SERVER_NAME,
      preload: true,
      enableTools: ["@all"],
      // Belt and braces: the selector catches anything annotated destructive,
      // and the literal names catch a tool whose annotation is wrong.
      requireApprovalForTools: ["@destructive", ...APPROVAL_REQUIRED],
    },
  ],
  config: {
    dynamicSubAgents: { enabled: true },
    askUserQuestions: { enabled: true },
    sandbox: { enabled: config.daytonaApiKey !== null, fileDownloads: true },
    iterationLimit: 60,
  },
};
```

---

## The 7 MCP tools

Seven domain tools over remote streamable HTTP, bearer-authenticated. Their safety classification is declared *on the tool* in one place, and both front ends inherit it automatically:

| Tool | Annotation | Approval |
| --- | --- | --- |
| `scan_dependencies` | `readOnlyHint` | no |
| `lookup_advisories` | `readOnlyHint` | no |
| `assess_blast_radius` | `readOnlyHint` | no |
| `summarise_triage` | `readOnlyHint` | no |
| `propose_patch` | `readOnlyHint` | no (writes only inside the sandbox) |
| `open_pull_request` | `destructiveHint` | **yes** |
| `merge_pull_request` | `destructiveHint` | **yes** |

Each tool lives in its own module under `src/mcp/tools/`; `src/mcp/tools.ts` is a barrel that exports the registry, the destructive list and the one function allowed to invoke a handler. The classification is a tiny, explicit helper they all share:

```ts
// src/mcp/tools/shared.ts (excerpt)
export const readOnly = (title: string): ToolAnnotations => ({
  title,
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
});

export const destructive = (title: string): ToolAnnotations => ({
  title,
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
});
```

And a destructive tool re-checks the kill switch *itself*, before any network call — the approval gate is the second line of defence, not the only one:

```ts
// src/mcp/tools/open-pull-request.ts (excerpt)
async handler(args, ctx) {
  if (!ctx.github.configured) throw notConfigured("GitHub access", "GITHUB_TOKEN");
  // Check the kill switch before ANY network call. The client re-checks it too,
  // but failing here means a read-only deployment never even contacts GitHub.
  assertWritesAllowed(ctx, "Opening a pull request");
  const ref = resolveRepo(args.repo, ctx.config);

  const repoInfo = await ctx.github.getRepo(ref);
  const base = /* ... default branch ... */;

  // We generate the branch name; the model never supplies a ref.
  const branch = remediationBranchName(title);
  await ctx.github.createBranch(ref, branch, base);
  await ctx.github.putFile(ref, filePath, fileContent, `fix(deps): ${title}`, branch);
  const pr = await ctx.github.createPullRequest(ref, { /* ... */ });

  return { ok: true, text: `Pull request #${pr.number} opened against ${base}: ${pr.url}` };
}
```

A read-only tool can never mutate a remote. Anything that touches GitHub state is destructive by construction, so a mis-tagged tool fails closed.

---

## Control and safety

**Structural, not a prompt the model can talk its way out of.**

### 1. The approval policy is declared on the tool, once

TrueForge resolves its `@read-only` / `@write` / `@destructive` approval selectors from MCP tool annotations. The classification lives next to the implementation, and both front ends inherit it automatically.

### 2. Defence in depth on the irreversible path

- ✅ The agent spec gates `@destructive` *and* names both tools literally.
- ✅ Destructive handlers check the kill switch **before any network call**.
- ✅ `GitHubClient` re-checks it again at the point of mutation.
- ✅ Branch names are generated by us and validated against git's ref rules — the model never supplies a ref.

```ts
// src/core/github.ts (excerpt)
/** Deterministic, collision-resistant, and never model-authored. */
export function remediationBranchName(seed: string): string {
  const slug = seed
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  const stamp = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  const nonce = globalThis.crypto.randomUUID().slice(0, 6);
  return `sentinel/${stamp}-${slug.length > 0 ? slug : "remediation"}-${nonce}`;
}
```

- ✅ The web API only accepts approvals for tool calls the harness actually raised.

### 3. Failing safe, and keeping secrets out

Denial is the default everywhere: empty input, EOF, Escape, and unparseable answers all deny. In the terminal client, an unrecognised answer denies:

```ts
// src/cli/index.ts (excerpt)
const approved = answer === "y" || answer === "yes";
decisions.push({
  toolCallId: approval.toolCallId,
  threadId: approval.threadId,
  approved,
  ...(approved ? {} : { reason: "The operator denied this action at the terminal." }),
});
```

- ✅ Keys live only in `.env`, git-ignored, read at one place.
- ✅ The browser never talks to the harness or a provider directly — everything is proxied.
- ✅ Two-layer redaction scrubs every log line, tool result and SSE frame: exact values plus ten credential shapes.
- ✅ The MCP token is compared in constant time, so it cannot be recovered by timing.
- ✅ `npm run scan:secrets` fails the build on anything credential-shaped. It runs in CI.

---

## Why the harness does the work

| Harness capability | How SENTINEL uses it |
| --- | --- |
| Agent loop | Runs the entire multi-step triage. We supply instructions and tools. |
| MCP tools | Seven domain tools over remote streamable HTTP, bearer-authenticated. |
| Human checkpoints | `open_pull_request` and `merge_pull_request` are gated. The pause is real. |
| Subagents | One per advisory, so ten CVEs do not share one context window. |
| Sandbox | Patch verification runs isolated; secrets stay in the harness. |
| Session state | Sessions survive a browser refresh; the transcript replays from the harness. |
| Context engineering | Deferred tool loading and compaction, configured per agent. |

Provisioning is idempotent (`create-or-update` on every boot), so starting the CLI or web server twice is safe:

```ts
// src/harness/provision.ts (excerpt)
async function provisionAgent(client, config, modelFqn, sandboxEnabled, steps) {
  const spec = buildAgentSpec(config);
  const existing = await client.agents.list();
  const match = existing.data?.find((a) => a.name === AGENT_NAME);

  if (match === undefined) {
    await client.agents.create({ name: AGENT_NAME, manifest: resolved });
    steps.push(`Agent "${AGENT_NAME}" created.`);
  } else {
    await client.agents.update(match.id, { manifest: resolved });
    steps.push(`Agent "${AGENT_NAME}" updated.`);
  }
}
```

---

## Degradation strategy

The harness is configured from env, and each capability degrades independently rather than failing the whole run:

| Missing | Behaviour |
| --- | --- |
| Model key | Hard fail at provision, with the exact env var named. |
| `DAYTONA_API_KEY` | Sandbox disabled; patch verification is skipped and clearly reported as unverified rather than silently claimed. |
| `GITHUB_TOKEN` | GitHub tools return a typed "not configured" error; scanning and triage still work. |
| Harness not running | Clients print the `npx @truefoundry/trueforge` command instead of a stack trace. |

---

## Local development & testing

```bash
npm install              # install dependencies
npm test                 # run all unit and integration tests (211 passing)
npm run test:watch       # watch mode
npm run typecheck        # strict TypeScript, noEmit
npm run scan:secrets     # fail on anything credential-shaped
npm run lint             # eslint
npm run build            # tsc emit to dist/
npm run site:dev         # serve the landing page at http://localhost:4321
```

Verified against the real harness, not a reimplementation. The end-to-end approval test drives the real `SentinelRunner` — the same class the CLI and web app use:

```
$ npm test
Test Files  18 passed (18)
     Tests  211 passed (211)

$ npm run scan:secrets
✓ Scanned 90 tracked file(s). No secrets found.
```

Before pushing, `node --experimental-strip-types scripts/scan-secrets.ts --staged`
scans only what is staged — the same check CI runs, without waiting for it.

The end-to-end approval gate can also be run directly:

```
$ node --experimental-strip-types scripts/e2e-approval.ts
  ✓ harness reached our MCP tools
  ✓ live advisory data returned through the harness
  ✓ destructive tool triggered an approval gate
  ✓ the gate correctly identified open_pull_request
  ✓ a read-only tool ran WITHOUT a gate
  ALL CHECKS PASSED
```

CI (see [`ci/github-actions-ci.yml`](ci/github-actions-ci.yml)) runs, in order: **secret scan → typecheck → lint → unit tests → dependency audit**. Every step is the same command you run locally, so a green local run is a green CI run.

That pipeline does not run on GitHub yet: it has to be copied to `.github/workflows/ci.yml` by someone holding the `workflows` permission, which this project's automation does not have. `ci/README.md` has the three commands, and the gap is logged as open debt in `CHANGELOG.md`.

---

## Contributing

The bar is deliberately mechanical, so it can be checked rather than argued
about.

**A change and its test land in the same commit.** Every commit that alters
behaviour names the `tests/*.test.ts` file that pins it, in the message. A
commit that cannot name one is a commit that changed something nobody can
prove still works.

**Keep a PR under roughly 200 changed lines.** One module or one bugfix. If a
diff needs a map, it is two PRs.

**Run the gate before pushing**, in the order CI runs it:

```bash
npm run scan:secrets     # or: ... scripts/scan-secrets.ts --staged
npm run typecheck
npm run lint -- --max-warnings=0
npm test
```

`eslint.config.js` enforces `max-lines` 500, `max-lines-per-function` 120,
`max-depth` 4 and `complexity` 20. When a module outgrows those numbers the
answer is to split it, not to raise the limit — the safety annotations in
`src/mcp/tools/` sit next to the code they guard, and that only works while
the file is readable end to end. If you must take an exception, put the
`eslint-disable` at the line with a reason, and record it in the
**Known debt** table in [`CHANGELOG.md`](CHANGELOG.md) so the next person can
see what is owed.

**Update `CHANGELOG.md` with the change.** Not the git log — the reasoning and
the trade-off, which is what a reviewer six months from now actually needs.

---

## A bug this caught

The SDK types imply tool calls arrive on `model.message`. In a live stream they do not: they arrive incrementally across `model.message.delta` frames, with the name in the first and arguments split across later ones, while the streamed `model.message` is empty. A client that trusts the types shows `unknown_tool` with no arguments on the approval dialog — a human being asked to authorise an irreversible action with nothing to judge it by.

Fixed in `src/harness/runner.ts` with a delta accumulator, and locked down by regression tests:

```ts
// src/harness/runner.ts (excerpt)
class DeltaAccumulator {
  readonly #byIndex = new Map<string, { id: string; name: string; args: string }>();

  push(messageId, index, id, name, argsFragment) {
    const key = `${messageId}#${index}`;
    const current = this.#byIndex.get(key) ?? { id: "", name: "", args: "" };
    if (id !== undefined && id.length > 0) current.id = id;
    if (name !== undefined && name.length > 0) current.name = name;
    if (argsFragment !== undefined && argsFragment.length > 0) current.args += argsFragment;
    this.#byIndex.set(key, current);
    return current.id.length > 0 && current.name.length > 0 ? current : null;
  }
}
```

---

## Project layout

```
src/
  cli/           Terminal client (drives the same runner as the web app)
  web/           Hono web console + SSE event stream
  harness/       provision.ts · runner.ts · agent-spec.ts (the thin layer)
  mcp/           The MCP tool server (server.ts) + the 7 tools, one per file in tools/
  core/          GitHub client, advisory lookup, manifest, semver, redaction, config
  webmcp/        The WebMCP OMNI-LAB modules (browser demo, see below)
site/            Static SENTINEL landing page (GitHub Pages source)
tests/           18 suites, 211 tests
scripts/         mock-model · e2e-approval · probe-mcp · scan-secrets
ci/              GitHub Actions workflows (verify + Pages), pending the copy
                 into .github/workflows/ — see ci/README.md
docs/            ARCHITECTURE.md
CHANGELOG.md     What changed, newest first, each entry naming its test
```

---

## Included: the WebMCP OMNI-LAB demo

The repository also ships a client-side WebMCP demonstration — **SENTINEL OMNI-LAB**, five in-browser laboratories (BreachLab AST triage, BioSynth 3D protein CAD, ChronoForensic OSINT, MetaLoop swarm debugger, and a ZK escrow arbiter) that register 20 tools via the W3C/OpenAI `document.modelContext.registerTool(...)` standard. It is served by the web console:

```bash
npm run web              # SENTINEL console at http://localhost:3000 (OMNI-LAB demo included)
```

The demo's escrow and forensic modules use **real SHA-256 / HMAC-SHA-256** digests, require a milestone to be verified before escrow release, and render agent output through `textContent` (not `innerHTML`) — see the Qodo review notes on PR #5 for the full history of those fixes.

---

## FAQ

**Will it open a pull request without asking me?**

No. `open_pull_request` and `merge_pull_request` are annotated `destructiveHint`, so the harness raises a real approval gate. The turn ends and waits. Denial is the default for every input it cannot interpret.

**Do I need an API key to try it?**

No. A scripted model endpoint ships with the repo, so the whole path — real advisory data, real tools, real gate — runs without spending anything. See the [No API key demo](#c-no-api-key-demo) section.

**Which ecosystems does it cover?**

Node and npm: it reads `package.json` plus the lockfile and triages against the GitHub Advisory Database, with OSV as a fallback.

**What happens without a sandbox key?**

The agent cannot execute or test a patch, and is explicitly instructed to report every patch as **unverified**. It never guesses that a fix works.

**Can I run it fully read-only?**

Yes — set `SENTINEL_ALLOW_REMOTE_WRITES=false`. Destructive tools then refuse before any network call, regardless of what the model or the approval UI says.

**Could a demo recording leak a token?**

Not through us. Redaction runs in two layers — exact registered values plus ten credential *shapes*, so even a key the model read out of a file in the sandbox is scrubbed from every log line, tool result and SSE frame.

---

## License

MIT. Free, open source. Grab the packaged CLI from the release page — or clone the repo and read every line first.

```bash
git clone https://github.com/geohot0199/sentinental.git
```

- [Download v0.2.0](https://github.com/geohot0199/sentinental/releases/latest)
- [View on GitHub](https://github.com/geohot0199/sentinental)
- [Landing page](https://geohot0199.github.io/sentinental/)
- [Architecture notes](docs/ARCHITECTURE.md)
