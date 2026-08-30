/** Turn advisory matches into a prioritised plan with one safe target version per package. */
import { z } from "zod";
import { resolveSafeVersion, severityRank } from "../../core/advisories.ts";
import { SentinelError } from "../../core/errors.ts";
import { classifyBump } from "../../core/semver.ts";
import { readOnly, type ToolDefinition } from "./shared.ts";

export const triageSummary: ToolDefinition = {
  name: "summarise_triage",
  description:
    "Turn a set of advisory matches into a prioritised remediation plan with a single safe target " +
    "version per package. Read-only, no network access. Use this before proposing a patch.",
  annotations: { ...readOnly("Summarise triage"), openWorldHint: false },
  inputSchema: {
    matches: z
      .array(
        z.object({
          packageName: z.string(),
          installedVersion: z.string(),
          severity: z.enum(["critical", "high", "moderate", "low", "unknown"]),
          advisoryId: z.string(),
          firstPatchedVersion: z.string().nullable().optional(),
        }),
      )
      .min(1)
      .describe("Advisory matches, typically from lookup_advisories."),
  },
  handler(args) {
    const parsed = z
      .array(
        z.object({
          packageName: z.string(),
          installedVersion: z.string(),
          severity: z.enum(["critical", "high", "moderate", "low", "unknown"]),
          advisoryId: z.string(),
          firstPatchedVersion: z.string().nullable().optional(),
        }),
      )
      .safeParse(args.matches);
    if (!parsed.success) {
      throw new SentinelError("invalid_input", "`matches` is malformed.");
    }

    const byPackage = new Map<string, typeof parsed.data>();
    for (const match of parsed.data) {
      const bucket = byPackage.get(match.packageName) ?? [];
      bucket.push(match);
      byPackage.set(match.packageName, bucket);
    }

    const plan = [...byPackage.entries()].map(([name, entries]) => {
      const first = entries[0];
      const installed = first === undefined ? "unknown" : first.installedVersion;
      const target = resolveSafeVersion(
        entries.map((e) => ({
          packageName: name,
          installedVersion: e.installedVersion,
          advisory: {
            id: e.advisoryId,
            cve: null,
            summary: "",
            severity: e.severity,
            cvssScore: null,
            url: "",
            vulnerableRange: "",
            firstPatchedVersion: e.firstPatchedVersion ?? null,
            source: "github" as const,
          },
          recommendedVersion: e.firstPatchedVersion ?? null,
          bump: "unknown" as const,
        })),
      );
      const worst = entries
        .map((e) => e.severity)
        .sort((a, b) => severityRank(b) - severityRank(a))[0] ?? "unknown";
      return {
        packageName: name,
        installedVersion: installed,
        targetVersion: target,
        worstSeverity: worst,
        advisoryCount: entries.length,
        bump: target === null ? "unknown" : classifyBump(installed, target),
      };
    });

    plan.sort((a, b) => severityRank(b.worstSeverity) - severityRank(a.worstSeverity));

    const actionable = plan.filter((p) => p.targetVersion !== null);
    const blocked = plan.filter((p) => p.targetVersion === null);

    return {
      ok: true,
      text: [
        `Remediation plan for ${plan.length} affected package(s):`,
        "",
        ...actionable.map(
          (p) =>
            `- [${p.worstSeverity.toUpperCase()}] ${p.packageName}: ${p.installedVersion} -> ${p.targetVersion} (${p.bump} bump, clears ${p.advisoryCount} advisory/ies)`,
        ),
        ...(blocked.length > 0
          ? [
              "",
              "No published fix — needs a human decision:",
              ...blocked.map(
                (p) => `- [${p.worstSeverity.toUpperCase()}] ${p.packageName}@${p.installedVersion}`,
              ),
            ]
          : []),
      ].join("\n"),
      data: { plan, actionable: actionable.length, blocked: blocked.length },
    };
  },
};
