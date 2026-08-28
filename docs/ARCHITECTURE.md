# SENTINEL — Architecture

> Autonomous supply-chain CVE strike team, built on the [TrueForge](https://github.com/truefoundry/trueforge) agent harness.

## 1. The job we hand over

A dependency advisory drops. Someone has to: find out whether *this* repo is
actually affected, work out whether the fix is a one-line bump or a breaking
change, prove the test suite still passes, and open a pull request a human can
review. That is an afternoon of context-switching per advisory, and most teams
do it late.

SENTINEL is the agent that does it. It is given a repository and told to go
find what is rotting in the dependency tree. Everything up to the pull request
is autonomous. The pull request itself is not — that is the irreversible step,
and it stops there and asks.

## 2. Why this job (against the judging criteria)

| Criterion | How this job scores |
| --- | --- |
| Potential impact | Every software team on earth has this backlog. The output is a reviewable PR, not a chat answer. |
| Creativity | Not "chat with your docs". A multi-agent triage crew that reproduces, patches, and proves its own fix. |
| Technical excellence | Forces real MCP tools, real sandbox execution, real subagent fan-out, real approval gating. Nothing is mockable. |
| Use of sponsor tools | The harness is doing the work: TrueForge runs the loop, the tool calls, the sandbox, the approvals, the session state. Our code is a tool server + two thin clients. |
| Control and safety | Patch/test run in a sandbox. `open_pull_request` and `merge_pull_request` are `destructive` and gated behind human approval. |
| Presentation | The pause is the demo. The agent visibly stops and waits for a click. |

## 3. Architecture

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

**We do not reimplement any part of the agent loop.** No `while (toolCalls)`,
no retry logic, no context compaction, no approval state machine. Those all
exist in TrueForge and re-writing them is exactly the "thin wrapper around a
model" the Best Use of TrueForge track penalises.

What we own is the two things the harness deliberately leaves to you:

1. **A tool server** (`src/mcp`) — the domain expertise. Remote MCP over
   streamable HTTP, because TrueForge 0.1.4 only accepts `type: "remote"`.
2. **Two front ends** (`src/cli`, `src/web`) — driving the same core.

### Tool safety classification

TrueForge's `requireApprovalForTools` selectors (`@read-only`, `@write`,
`@destructive`) are resolved from **MCP tool annotations**. So the gate is
declared on the tool itself, in one place, and both clients inherit it:

| Tool | Annotation | Approval |
| --- | --- | --- |
| `scan_dependencies` | `readOnlyHint` | no |
| `lookup_advisories` | `readOnlyHint` | no |
| `assess_blast_radius` | `readOnlyHint` | no |
| `propose_patch` | `readOnlyHint` | no (writes only inside the sandbox) |
| `open_pull_request` | `destructiveHint` | **yes** |
| `merge_pull_request` | `destructiveHint` | **yes** |

A read-only tool can never mutate a remote. Anything that touches GitHub state
is destructive by construction, so a mis-tagged tool fails closed.

### Subagent fan-out

One advisory triage is independent of the next, so the root agent delegates:
`dynamicSubAgents` is enabled, and the instructions tell the root agent to spawn
one subagent per advisory. Each gets a clean context window — which is the
actual reason to do it, since ten CVE advisories will blow past any context
limit if they share one thread.

## 4. Alternatives considered, and why they lost

**A. Everything in one TrueForge "Code Mode" script.** Fewer moving parts, and
Code Mode really is elegant. Rejected: the whole run becomes one opaque tool
call, so there is nothing to approve and nothing to watch. It optimises away
the two things being judged.

**B. Local stdio MCP server.** Simpler to run. Rejected: TrueForge 0.1.4's
`McpServerType` is the literal `"remote"` — stdio is not accepted. Verified
against the shipped SDK types, not assumed.

**C. Our own approval UI storing decisions in our own DB.** Rejected: TrueForge
already persists `tool.approval_required` against the turn and resumes on
`user.tool_approval`. Duplicating it would mean two sources of truth and a
resume path that breaks on reconnect.

**D. Terminal-only.** Rejected: the Savile Row track is judged on a running
interface, and an approval prompt is a fundamentally visual thing. But the
terminal client ships too, because it is the honest way to prove the core is
front-end-agnostic — the same `runner.ts` drives both.

## 5. Degradation strategy

The harness is configured from env, and each capability degrades independently
rather than failing the whole run:

| Missing | Behaviour |
| --- | --- |
| Model key | Hard fail at provision, with the exact env var named. |
| `DAYTONA_API_KEY` | Sandbox disabled; patch verification is skipped and clearly reported as unverified rather than silently claimed. |
| `GITHUB_TOKEN` | GitHub tools return a typed "not configured" error; scanning and triage still work. |
| Harness not running | Clients print the `npx @truefoundry/trueforge` command instead of a stack trace. |

## 6. Secrets

No key ever enters the repository or the model's context. Keys live in `.env`
(git-ignored), are read once at provision time, handed to the harness over
localhost, and stored by the harness. `scripts/scan-secrets.ts` runs in CI and
fails the build on anything that looks like a live credential; the same
redaction helper scrubs every log line and SSE frame the web UI emits, so a
demo recording cannot leak a token.
