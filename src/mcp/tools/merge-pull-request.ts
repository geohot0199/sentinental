/** Merge an open pull request into the base branch. Destructive and unrecoverable. */
import { z } from "zod";
import { notConfigured, SentinelError } from "../../core/errors.ts";
import { assertWritesAllowed, destructive, resolveRepo, type ToolDefinition } from "./shared.ts";

export const mergePullRequest: ToolDefinition = {
  name: "merge_pull_request",
  description:
    "IRREVERSIBLE AND UNRECOVERABLE. Merge an open pull request into the base branch. " +
    "This changes what ships. Requires human approval.",
  annotations: destructive("Merge a pull request"),
  inputSchema: {
    repo: z.string().optional().describe('Repository as "owner/name".'),
    number: z.number().int().positive().describe("Pull request number."),
    method: z.enum(["merge", "squash", "rebase"]).optional().describe("Merge method. Default squash."),
  },
  async handler(args, ctx) {
    if (!ctx.github.configured) throw notConfigured("GitHub access", "GITHUB_TOKEN");
    assertWritesAllowed(ctx, "Merging a pull request");
    const ref = resolveRepo(args.repo, ctx.config);
    const number = Number(args.number);
    if (!Number.isInteger(number) || number <= 0) {
      throw new SentinelError("invalid_input", "`number` must be a positive integer.");
    }
    const method = (typeof args.method === "string" ? args.method : "squash") as
      | "merge"
      | "squash"
      | "rebase";

    const result = await ctx.github.mergePullRequest(ref, number, method);
    return {
      ok: result.merged,
      text: result.merged
        ? `Pull request #${number} merged via ${method}.`
        : `Pull request #${number} was NOT merged: ${result.message}`,
      data: result,
    };
  },
};
