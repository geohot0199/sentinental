/** Produce the patched package.json for review, without writing anything. */
import { z } from "zod";
import { notConfigured, SentinelError } from "../../core/errors.ts";
import { isValidPackageName } from "../../core/manifest.ts";
import { readOnly, resolveRepo, type ToolDefinition } from "./shared.ts";

/** One {name, toVersion} pair. Declared once: the MCP schema and the handler guard must not drift. */
const upgradeSchema = z.object({
  name: z.string().describe("Package to upgrade."),
  toVersion: z.string().describe("Target version, without a range prefix."),
});

export const proposePatch: ToolDefinition = {
  name: "propose_patch",
  description:
    "Produce the exact updated package.json content that upgrades the given packages to safe versions. " +
    "Read-only: this returns file content for review and does NOT write anything to GitHub. " +
    "Verify it in the sandbox, then use open_pull_request to propose it.",
  annotations: readOnly("Propose a dependency patch"),
  inputSchema: {
    repo: z.string().optional().describe('Repository as "owner/name".'),
    branch: z.string().optional().describe("Branch to read package.json from."),
    upgrades: z
      .array(upgradeSchema)
      .min(1)
      .max(50)
      .describe("Upgrades to apply."),
  },
  async handler(args, ctx) {
    if (!ctx.github.configured) throw notConfigured("GitHub access", "GITHUB_TOKEN");
    const ref = resolveRepo(args.repo, ctx.config);
    const parsed = z.array(upgradeSchema).min(1).safeParse(args.upgrades);
    if (!parsed.success) {
      throw new SentinelError("invalid_input", "`upgrades` must be a list of {name, toVersion}.");
    }

    const branch = typeof args.branch === "string" && args.branch.length > 0 ? args.branch : undefined;
    const raw = await ctx.github.getFile(ref, "package.json", branch);
    if (raw === null) {
      throw new SentinelError("not_found", `No package.json found in ${ref.owner}/${ref.repo}.`);
    }

    const pkg = JSON.parse(raw) as Record<string, unknown>;
    const sections = ["dependencies", "devDependencies", "optionalDependencies"] as const;
    const applied: string[] = [];
    const skipped: string[] = [];

    for (const upgrade of parsed.data) {
      if (!isValidPackageName(upgrade.name)) {
        skipped.push(`${upgrade.name}: invalid package name`);
        continue;
      }
      let found = false;
      for (const section of sections) {
        const record = pkg[section];
        if (typeof record !== "object" || record === null) continue;
        const table = record as Record<string, string>;
        const current = table[upgrade.name];
        if (current === undefined) continue;
        // Preserve the operator the project already uses (^, ~ or exact).
        const prefix = /^[\^~]/.exec(current)?.[0] ?? "";
        table[upgrade.name] = `${prefix}${upgrade.toVersion}`;
        applied.push(`${upgrade.name}: ${current} -> ${prefix}${upgrade.toVersion} (${section})`);
        found = true;
        break;
      }
      if (!found) skipped.push(`${upgrade.name}: not present in package.json`);
    }

    if (applied.length === 0) {
      throw new SentinelError(
        "invalid_input",
        `None of the requested upgrades matched a dependency in package.json. ${skipped.join("; ")}`,
      );
    }

    // Two-space indent and trailing newline: npm's own convention, so the diff
    // stays minimal instead of reformatting the whole file.
    const updated = `${JSON.stringify(pkg, null, 2)}\n`;

    return {
      ok: true,
      text: [
        `Proposed ${applied.length} upgrade(s) to package.json:`,
        ...applied.map((a) => `- ${a}`),
        ...(skipped.length > 0 ? ["", "Skipped:", ...skipped.map((s) => `- ${s}`)] : []),
        "",
        "This is a proposal only. Nothing has been written to GitHub.",
        "Updated package.json follows:",
        "```json",
        updated.trim(),
        "```",
      ].join("\n"),
      data: { path: "package.json", content: updated, applied, skipped },
    };
  },
};
