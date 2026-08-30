/** Read a repository's manifests and return its dependency inventory. */
import { z } from "zod";
import { scanManifest, type Dependency } from "../../core/manifest.ts";
import { notConfigured, SentinelError } from "../../core/errors.ts";
import { MAX_DEPENDENCIES_REPORTED, readOnly, resolveRepo, type ToolDefinition } from "./shared.ts";

export const scanDependencies: ToolDefinition = {
  name: "scan_dependencies",
  description:
    "Read a GitHub repository's package.json and lockfile and return its dependency inventory " +
    "with resolved versions. Read-only. Start here: every other tool needs the versions this returns.",
  annotations: readOnly("Scan dependency manifest"),
  inputSchema: {
    repo: z
      .string()
      .optional()
      .describe('Repository as "owner/name". Defaults to the configured target repository.'),
    branch: z.string().optional().describe("Branch to read. Defaults to the repo's default branch."),
    includeDev: z
      .boolean()
      .optional()
      .describe("Include devDependencies. Default true; set false to triage production only."),
  },
  async handler(args, ctx) {
    if (!ctx.github.configured) throw notConfigured("GitHub access", "GITHUB_TOKEN");
    const ref = resolveRepo(args.repo, ctx.config);
    const includeDev = args.includeDev !== false;

    const repoInfo = await ctx.github.getRepo(ref);
    const branch = typeof args.branch === "string" && args.branch.length > 0
      ? args.branch
      : repoInfo.defaultBranch;

    const packageJson = await ctx.github.getFile(ref, "package.json", branch);
    if (packageJson === null) {
      throw new SentinelError(
        "not_found",
        `No package.json at the root of ${ref.owner}/${ref.repo}@${branch}.`,
        "SENTINEL currently triages npm projects only.",
      );
    }

    // Try lockfiles in descending order of fidelity.
    let lockRaw: string | null = null;
    let lockName: string | null = null;
    for (const candidate of ["package-lock.json", "npm-shrinkwrap.json"]) {
      lockRaw = await ctx.github.getFile(ref, candidate, branch);
      if (lockRaw !== null) {
        lockName = candidate;
        break;
      }
    }

    const scan = scanManifest(packageJson, lockRaw, lockName);
    const filtered = includeDev
      ? scan.dependencies
      : scan.dependencies.filter((d) => d.scope === "production");

    const shown = filtered.slice(0, MAX_DEPENDENCIES_REPORTED);
    const lines = [
      `Repository: ${ref.owner}/${ref.repo}@${branch}`,
      `Project: ${scan.projectName ?? "(unnamed)"}`,
      `Lockfile: ${lockName ?? "none (versions are estimates from declared ranges)"}`,
      `Dependencies: ${filtered.length}${filtered.length > shown.length ? ` (showing first ${shown.length})` : ""}`,
      "",
      ...shown.map(
        (d: Dependency) =>
          `- ${d.name}@${d.version} [${d.scope}]${d.resolved ? "" : " (estimated from range)"}`,
      ),
    ];
    if (scan.warnings.length > 0) {
      lines.push("", "Warnings:", ...scan.warnings.map((w) => `- ${w}`));
    }

    return {
      ok: true,
      text: lines.join("\n"),
      data: {
        repo: `${ref.owner}/${ref.repo}`,
        branch,
        defaultBranch: repoInfo.defaultBranch,
        lockfile: lockName,
        dependencies: shown,
        totalDependencies: filtered.length,
        warnings: scan.warnings,
      },
    };
  },
};
