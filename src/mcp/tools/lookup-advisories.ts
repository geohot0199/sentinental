/** Check pinned versions against the GitHub Advisory Database (OSV fallback). */
import { z } from "zod";
import {
  lookupAdvisories,
  severityRank,
  type AdvisoryMatch,
} from "../../core/advisories.ts";
import { SentinelError, toSentinelError } from "../../core/errors.ts";
import { isValidPackageName } from "../../core/manifest.ts";
import { MAX_ADVISORY_PACKAGES, readOnly, type ToolDefinition } from "./shared.ts";

export const lookupAdvisoriesTool: ToolDefinition = {
  name: "lookup_advisories",
  description:
    "Check specific package versions against the GitHub Advisory Database (OSV fallback) and " +
    "return only advisories that genuinely affect those versions. Read-only. " +
    "Call this with the output of scan_dependencies.",
  annotations: readOnly("Look up security advisories"),
  inputSchema: {
    packages: z
      .array(
        z.object({
          name: z.string().describe("Package name, e.g. lodash"),
          version: z.string().describe("Installed version, e.g. 4.17.11"),
        }),
      )
      .min(1)
      .max(MAX_ADVISORY_PACKAGES)
      .describe(`Packages to check (max ${MAX_ADVISORY_PACKAGES} per call).`),
    minSeverity: z
      .enum(["low", "moderate", "high", "critical"])
      .optional()
      .describe("Drop advisories below this severity. Default: low (report everything)."),
  },
  async handler(args, ctx) {
    const parsed = z
      .array(z.object({ name: z.string(), version: z.string() }))
      .safeParse(args.packages);
    if (!parsed.success) {
      throw new SentinelError("invalid_input", "`packages` must be a list of {name, version}.");
    }

    const floor = severityRank(
      (typeof args.minSeverity === "string" ? args.minSeverity : "low") as
        | "low"
        | "moderate"
        | "high"
        | "critical",
    );

    const all: AdvisoryMatch[] = [];
    const problems: string[] = [];

    // Bounded concurrency: fast, but never a burst that trips rate limiting.
    const queue = parsed.data.slice(0, MAX_ADVISORY_PACKAGES);
    const CONCURRENCY = 5;
    let cursor = 0;
    async function worker(): Promise<void> {
      for (;;) {
        const index = cursor;
        cursor += 1;
        const item = queue[index];
        if (item === undefined) return;
        if (!isValidPackageName(item.name)) {
          problems.push(`Skipped invalid package name: ${JSON.stringify(item.name)}`);
          continue;
        }
        try {
          const result = await lookupAdvisories(item.name, item.version, "npm", ctx.config.githubToken);
          all.push(...result.matches.filter((m) => severityRank(m.advisory.severity) >= floor));
          problems.push(...result.warnings);
        } catch (cause) {
          problems.push(`${item.name}: ${toSentinelError(cause).message}`);
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));

    if (all.length === 0) {
      return {
        ok: true,
        text: [
          `Checked ${queue.length} package(s). No advisories matched the installed versions.`,
          ...(problems.length > 0 ? ["", "Notes:", ...problems.map((p) => `- ${p}`)] : []),
        ].join("\n"),
        data: { matches: [], checked: queue.length, warnings: problems },
      };
    }

    const lines = [`Found ${all.length} advisory match(es) across ${queue.length} package(s):`, ""];
    for (const match of all) {
      const a = match.advisory;
      lines.push(
        `${a.severity.toUpperCase()}${a.cvssScore === null ? "" : ` (CVSS ${a.cvssScore})`} — ${match.packageName}@${match.installedVersion}`,
        `  ${a.id}${a.cve === null ? "" : ` / ${a.cve}`}: ${a.summary}`,
        `  Vulnerable range: ${a.vulnerableRange}`,
        `  First patched: ${a.firstPatchedVersion ?? "no fix published"}${match.bump === "unknown" ? "" : ` (${match.bump} bump)`}`,
        `  ${a.url}`,
        "",
      );
    }
    if (problems.length > 0) lines.push("Notes:", ...problems.map((p) => `- ${p}`));

    return { ok: true, text: lines.join("\n"), data: { matches: all, warnings: problems } };
  },
};
