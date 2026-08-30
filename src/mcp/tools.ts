/**
 * SENTINEL's tool surface.
 *
 * Each tool lives in `./tools/`, one module per tool, so the file a reviewer
 * opens is the file that defines a single behaviour — including the safety
 * annotation that governs whether the harness must ask a human first. This
 * module is the public API: the registry, the destructive-tool list, and the
 * one function that is allowed to invoke a handler.
 *
 * Importers (`src/mcp/server.ts`, the tests) never touch the per-tool modules.
 */
import { toSentinelError } from "../core/errors.ts";
import { redact } from "../core/redact.ts";
import type { ToolContext, ToolDefinition, ToolResult } from "./tools/shared.ts";
import { assessBlastRadius } from "./tools/assess-blast-radius.ts";
import { lookupAdvisoriesTool } from "./tools/lookup-advisories.ts";
import { mergePullRequest } from "./tools/merge-pull-request.ts";
import { openPullRequest } from "./tools/open-pull-request.ts";
import { proposePatch } from "./tools/propose-patch.ts";
import { scanDependencies } from "./tools/scan-dependencies.ts";
import { triageSummary } from "./tools/summarise-triage.ts";

export type {
  ToolAnnotations,
  ToolContext,
  ToolDefinition,
  ToolResult,
} from "./tools/shared.ts";

/**
 * Every tool the model may call, in the order it should reach for them:
 * scan, look up, assess, plan, propose — and only then write.
 */
export const TOOLS = [
  scanDependencies,
  lookupAdvisoriesTool,
  assessBlastRadius,
  triageSummary,
  proposePatch,
  openPullRequest,
  mergePullRequest,
] as const;

/** Names of every tool that mutates something outside this process. */
export const DESTRUCTIVE_TOOLS: readonly string[] = TOOLS.filter(
  (t) => t.annotations.destructiveHint,
).map((t) => t.name);

/**
 * Execute a tool, converting any failure into a model-readable result and
 * redacting the output. Nothing else should call handlers directly.
 */
export async function runTool(
  tool: ToolDefinition,
  args: Record<string, unknown>,
  ctx: ToolContext,
): Promise<ToolResult> {
  try {
    const result = await tool.handler(args, ctx);
    return { ...result, text: redact(result.text) };
  } catch (cause) {
    const error = toSentinelError(cause);
    return { ok: false, text: redact(error.toModelText()) };
  }
}
