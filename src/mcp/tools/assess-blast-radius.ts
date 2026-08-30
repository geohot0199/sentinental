/** Weigh an upgrade: what it clears, what it breaks, how widely the package is used. */
import { z } from "zod";
import { lookupAdvisories } from "../../core/advisories.ts";
import { SentinelError } from "../../core/errors.ts";
import { httpJson } from "../../core/http.ts";
import { isValidPackageName } from "../../core/manifest.ts";
import { classifyBump } from "../../core/semver.ts";
import { asText, readOnly, resolveRepo, type ToolDefinition } from "./shared.ts";

export const assessBlastRadius: ToolDefinition = {
  name: "assess_blast_radius",
  description:
    "Assess how risky it is to upgrade a vulnerable package: how many advisories the bump clears, " +
    "whether it crosses a major version, and how widely the package is imported in the repository. " +
    "Read-only. Use this to decide whether a fix is safe to automate or needs a human.",
  annotations: readOnly("Assess upgrade blast radius"),
  inputSchema: {
    repo: z.string().optional().describe('Repository as "owner/name".'),
    packageName: z.string().describe("Package being upgraded."),
    fromVersion: z.string().describe("Currently installed version."),
    toVersion: z.string().describe("Proposed target version."),
  },
  async handler(args, ctx) {
    const packageName = asText(args.packageName);
    const fromVersion = asText(args.fromVersion);
    const toVersion = asText(args.toVersion);
    if (!isValidPackageName(packageName)) {
      throw new SentinelError("invalid_input", `Invalid package name "${packageName}".`);
    }

    const bump = classifyBump(fromVersion, toVersion);
    const before = await lookupAdvisories(packageName, fromVersion, "npm", ctx.config.githubToken);
    const after = await lookupAdvisories(packageName, toVersion, "npm", ctx.config.githubToken);
    const cleared = before.matches.length - after.matches.length;

    // Import-site count needs code search, which needs a token and may be off.
    let usageNote = "Import-site count unavailable (GitHub code search not configured).";
    let usageCount: number | null = null;
    if (ctx.github.configured) {
      try {
        const ref = resolveRepo(args.repo, ctx.config);
        const query = `q=${encodeURIComponent(`"${packageName}" repo:${ref.owner}/${ref.repo}`)}&per_page=1`;
        const search = await httpJson<{ total_count?: number }>(
          `https://api.github.com/search/code?${query}`,
          {
            headers: {
              accept: "application/vnd.github+json",
              authorization: `Bearer ${ctx.config.githubToken ?? ""}`,
              "user-agent": "sentinel-strike-team",
            },
            retries: 0,
          },
        );
        usageCount = search.total_count ?? 0;
        usageNote = `${usageCount} file(s) in the repository mention "${packageName}".`;
      } catch {
        usageNote = "Import-site count unavailable (code search returned an error or is rate limited).";
      }
    }

    const risk =
      bump === "major"
        ? "HIGH — crosses a major version, so breaking changes are expected. A human should review the changelog."
        : bump === "minor"
          ? "MEDIUM — minor bump; usually additive but verify the test suite."
          : bump === "patch"
            ? "LOW — patch bump; intended to be backwards compatible."
            : "UNKNOWN — could not classify this version change.";

    return {
      ok: true,
      text: [
        `Blast radius: ${packageName} ${fromVersion} -> ${toVersion}`,
        `Bump type: ${bump}`,
        `Risk: ${risk}`,
        `Advisories cleared by this upgrade: ${cleared >= 0 ? cleared : 0}`,
        `Advisories still open after the upgrade: ${after.matches.length}`,
        usageNote,
      ].join("\n"),
      data: {
        packageName,
        fromVersion,
        toVersion,
        bump,
        advisoriesBefore: before.matches.length,
        advisoriesAfter: after.matches.length,
        cleared: Math.max(cleared, 0),
        usageCount,
      },
    };
  },
};
