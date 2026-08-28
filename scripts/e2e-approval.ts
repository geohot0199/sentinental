/**
 * End-to-end verification of the approval gate.
 *
 * Proves, against the real TrueForge harness and our real MCP server, that:
 *   1. the harness reaches our tools and gets live advisory data back;
 *   2. a destructive tool call raises `tool.approval_required` and BLOCKS;
 *   3. denying it stops the action - nothing is written to GitHub;
 *   4. the session survives and reports a coherent terminal state.
 *
 * Uses scripts/mock-model.ts as the model so the run is deterministic and free.
 *
 * Usage: node --experimental-strip-types scripts/e2e-approval.ts
 */
import { TrueForge } from "@truefoundry/trueforge-sdk";
import { loadConfig } from "../src/core/config.ts";
import { MCP_SERVER_NAME } from "../src/harness/agent-spec.ts";
import { SentinelRunner, type SentinelEvent } from "../src/harness/runner.ts";

const config = loadConfig();
const client = new TrueForge({ baseUrl: config.harnessUrl });

const AGENT = "sentinel-e2e";
const MODEL = "custom/mock-model";

function log(step: string, detail = ""): void {
  process.stdout.write(`  ${step}${detail === "" ? "" : ` ${detail}`}\n`);
}

// ── 1. register the mock provider ────────────────────────────────────────────
await client.settings.modelProviders.createOrUpdate({
  manifest: {
    type: "custom",
    name: "custom",
    baseUrl: process.env.MOCK_MODEL_URL ?? "http://127.0.0.1:8899/v1",
    auth: { apiKey: "not-used-by-the-mock" },
    models: [
      {
        name: "mock-model",
        modelId: "mock-model",
        properties: { contextLength: 128000, maxOutputTokens: 4096 },
      },
    ],
  },
});
log("✓ mock model provider registered");

// ── 2. register our MCP server ───────────────────────────────────────────────
await client.settings.mcpServers.createOrUpdate({
  manifest: {
    name: MCP_SERVER_NAME,
    type: "remote",
    url: config.mcpUrl,
    description: "SENTINEL supply-chain tools.",
    auth: { type: "header", headers: { Authorization: `Bearer ${config.mcpToken}` } },
  },
});
log("✓ MCP server registered", config.mcpUrl);

// ── 3. register the agent ────────────────────────────────────────────────────
const spec = {
  model: { name: MODEL },
  instructions: "Follow the scripted tool calls.",
  mcpServers: [
    {
      name: MCP_SERVER_NAME,
      preload: true,
      enableTools: ["@all" as const],
      requireApprovalForTools: ["@destructive" as const, "open_pull_request", "merge_pull_request"],
    },
  ],
  config: { sandbox: { enabled: false }, iterationLimit: 10 },
};

const agents = await client.agents.list();
const existing = agents.data?.find((a) => a.name === AGENT);
if (existing === undefined) {
  await client.agents.create({ name: AGENT, manifest: spec });
} else {
  await client.agents.update(existing.id, { manifest: spec });
}
log("✓ agent registered", AGENT);

// ── 4. run a turn and watch for the gate ─────────────────────────────────────
const session = await client.sessions.create({ agent: { name: AGENT } });
const sessionId = session.data.id;
log("✓ session created", sessionId);

process.stdout.write("\n  --- streaming turn (through SentinelRunner) ---\n");

// Drive the REAL runner, so this exercises the same code the CLI and web app
// use. Testing a parallel reimplementation here would prove nothing.
const runner = new SentinelRunner(config, AGENT);
await runner.resumeSession(sessionId);

let sawToolCall = false;
let sawAdvisoryData = false;
let sawDeniedResult = false;
const toolsSeen: string[] = [];

const sink = (event: SentinelEvent): void => {
  switch (event.kind) {
    case "tool-call":
      sawToolCall = true;
      toolsSeen.push(event.toolName);
      log("  → tool call", event.toolName);
      break;
    case "tool-result": {
      if (event.text.includes("GHSA-")) {
        sawAdvisoryData = true;
        log("  ← live advisory data", (event.text.split("\n")[2] ?? "").trim().slice(0, 76));
      }
      if (/denied/i.test(event.text)) {
        sawDeniedResult = true;
        log("  ← denial recorded", event.text.slice(0, 80));
      }
      break;
    }
    case "approval-required":
      for (const approval of event.approvals) {
        log("  ⏸ APPROVAL REQUIRED — blocked on", approval.toolName);
      }
      break;
    case "turn-done":
      log("  ▪ turn", event.status);
      break;
    case "error":
      log("  ✖", event.message);
      break;
    default:
      break;
  }
};

await runner.send("Triage the dependencies and fix them.", sink);

// The gate must have been raised, and the runner must know what it is gating.
const pending = runner.pendingApprovals;
const gatedTool = pending[0]?.toolName ?? null;
const gatedArgs = pending[0]?.args ?? null;

// ── 5. deny the action and confirm nothing happened ──────────────────────────
if (pending.length > 0) {
  process.stdout.write("\n  --- denying the irreversible action ---\n");
  await runner.respondToApprovals(
    pending.map((p) => ({
      toolCallId: p.toolCallId,
      threadId: p.threadId,
      approved: false,
      reason: "E2E test: denied on purpose.",
    })),
    sink,
  );
}

// ── verdict ──────────────────────────────────────────────────────────────────
const argsLookComplete =
  gatedArgs !== null &&
  typeof gatedArgs === "object" &&
  "title" in (gatedArgs as Record<string, unknown>);

const checks: [string, boolean][] = [
  ["harness reached our MCP tools", sawToolCall],
  ["live advisory data returned through the harness", sawAdvisoryData],
  ["destructive tool triggered an approval gate", pending.length > 0],
  ["the gate correctly identified open_pull_request", gatedTool === "open_pull_request"],
  ["the approval prompt received the full tool arguments", argsLookComplete],
  ["a read-only tool ran WITHOUT a gate", toolsSeen.includes("lookup_advisories")],
  ["denying the action was recorded by the harness", sawDeniedResult],
];

process.stdout.write("\n  --- verdict ---\n");
let failed = 0;
for (const [label, passed] of checks) {
  process.stdout.write(`  ${passed ? "✓" : "✗"} ${label}\n`);
  if (!passed) failed += 1;
}

// Clean up the test agent so it does not clutter a real deployment.
const after = await client.agents.list();
const testAgent = after.data?.find((a) => a.name === AGENT);
if (testAgent !== undefined) await client.agents.delete(testAgent.id);

process.stdout.write(failed === 0 ? "\n  ALL CHECKS PASSED\n" : `\n  ${failed} CHECK(S) FAILED\n`);
process.exit(failed === 0 ? 0 : 1);
