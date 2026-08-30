/**
 * What every SENTINEL tool shares: the definition shape, the safety
 * annotations, and the two guards the destructive tools must pass.
 *
 * The safety classification lives here, in `annotations`, and TrueForge
 * resolves its `@read-only` / `@write` / `@destructive` approval selectors from
 * exactly these hints. So the approval policy is declared once, next to the
 * implementations, and both the CLI and the web UI inherit it automatically.
 *
 * Rules every tool in this directory follows:
 *   - readOnlyHint tools make no remote mutation, ever.
 *   - destructiveHint tools re-check `allowRemoteWrites` themselves.
 *   - No handler throws out of `runTool`; every failure becomes a typed,
 *     model-readable result.
 */
import { z } from "zod";
import type { SentinelConfig } from "../../core/config.ts";
import { SentinelError } from "../../core/errors.ts";
import type { GitHubClient, RepoRef } from "../../core/github.ts";
import { parseRepo } from "../../core/github.ts";

export interface ToolAnnotations {
  readonly title: string;
  readonly readOnlyHint: boolean;
  readonly destructiveHint: boolean;
  readonly idempotentHint: boolean;
  readonly openWorldHint: boolean;
}

export interface ToolResult {
  readonly ok: boolean;
  readonly text: string;
  readonly data?: unknown;
}

export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly annotations: ToolAnnotations;
  readonly inputSchema: z.ZodRawShape;
  /** May be synchronous: a tool with no I/O has nothing to await. */
  readonly handler: (
    args: Record<string, unknown>,
    ctx: ToolContext,
  ) => ToolResult | Promise<ToolResult>;
}

export interface ToolContext {
  readonly config: SentinelConfig;
  readonly github: GitHubClient;
}

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

/** Cap list output so a huge repo cannot blow the model's context window. */
export const MAX_DEPENDENCIES_REPORTED = 150;
export const MAX_ADVISORY_PACKAGES = 40;

/**
 * Fail a destructive tool before it performs any I/O when the deployment is
 * read-only. `GitHubClient` enforces this too; doing it here as well means a
 * read-only run makes no outbound request at all, which is easier to audit.
 */
export function assertWritesAllowed(ctx: ToolContext, action: string): void {
  if (!ctx.github.writesAllowed) {
    throw new SentinelError(
      "forbidden",
      `${action} is blocked: SENTINEL is running in read-only mode.`,
      "Set SENTINEL_ALLOW_REMOTE_WRITES=true to permit remote writes.",
    );
  }
}

/** The `repo` argument, falling back to the configured default target. */
export function resolveRepo(input: unknown, config: SentinelConfig): RepoRef {
  const raw = typeof input === "string" && input.trim().length > 0 ? input : config.targetRepo;
  if (raw === null || raw === undefined) {
    throw new SentinelError(
      "invalid_input",
      "No repository given and no default configured.",
      "Pass `repo` as \"owner/name\", or set SENTINEL_TARGET_REPO in .env.",
    );
  }
  return parseRepo(raw);
}
