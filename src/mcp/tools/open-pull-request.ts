/** Create a branch, commit the patched file, and open a pull request. Destructive. */
import { z } from "zod";
import { notConfigured, SentinelError } from "../../core/errors.ts";
import { remediationBranchName } from "../../core/github.ts";
import { asText, assertWritesAllowed, destructive, resolveRepo, type ToolDefinition } from "./shared.ts";

export const openPullRequest: ToolDefinition = {
  name: "open_pull_request",
  description:
    "IRREVERSIBLE. Create a branch, commit the patched file, and open a pull request on GitHub. " +
    "This is visible to the whole repository and notifies reviewers. " +
    "Only call this after the patch has been verified. Requires human approval.",
  annotations: destructive("Open a pull request"),
  inputSchema: {
    repo: z.string().optional().describe('Repository as "owner/name".'),
    title: z.string().min(1).max(200).describe("Pull request title."),
    body: z.string().min(1).max(60_000).describe("Pull request description, in Markdown."),
    filePath: z.string().describe('Path of the file to commit, e.g. "package.json".'),
    fileContent: z.string().min(1).describe("Full new content of that file."),
    baseBranch: z.string().optional().describe("Base branch. Defaults to the repo default branch."),
    draft: z.boolean().optional().describe("Open as a draft. Default false."),
  },
  async handler(args, ctx) {
    if (!ctx.github.configured) throw notConfigured("GitHub access", "GITHUB_TOKEN");
    // Check the kill switch before ANY network call. The client re-checks it too,
    // but failing here means a read-only deployment never even contacts GitHub.
    assertWritesAllowed(ctx, "Opening a pull request");
    const ref = resolveRepo(args.repo, ctx.config);

    const title = asText(args.title).trim();
    const body = asText(args.body).trim();
    const filePath = asText(args.filePath).trim();
    const fileContent = asText(args.fileContent);
    if (title.length === 0 || body.length === 0 || filePath.length === 0 || fileContent.length === 0) {
      throw new SentinelError(
        "invalid_input",
        "title, body, filePath and fileContent are all required.",
      );
    }

    const repoInfo = await ctx.github.getRepo(ref);
    const base =
      typeof args.baseBranch === "string" && args.baseBranch.length > 0
        ? args.baseBranch
        : repoInfo.defaultBranch;

    // We generate the branch name; the model never supplies a ref.
    const branch = remediationBranchName(title);
    await ctx.github.createBranch(ref, branch, base);
    await ctx.github.putFile(ref, filePath, fileContent, `fix(deps): ${title}`, branch);

    const footer =
      "\n\n---\n_Opened by SENTINEL, an autonomous supply-chain triage agent running on the " +
      "TrueForge harness. A human approved this action before it was taken._";
    const pr = await ctx.github.createPullRequest(ref, {
      title,
      body: `${body}${footer}`,
      head: branch,
      base,
      draft: args.draft === true,
    });

    return {
      ok: true,
      text: `Pull request #${pr.number} opened against ${base}: ${pr.url}\nBranch: ${branch}`,
      data: { number: pr.number, url: pr.url, branch, base },
    };
  },
};
