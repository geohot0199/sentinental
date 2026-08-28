/**
 * SENTINEL's tool definitions.
 *
 * The safety classification lives here, in the `annotations`, and TrueForge
 * resolves its `@read-only` / `@write` / `@destructive` approval selectors from
 * exactly these hints. So the approval policy is declared once, next to the
 * implementation, and both the CLI and the web UI inherit it automatically.
 *
 * Rules enforced in this file:
 *   - readOnlyHint tools make no remote mutation, ever.
 *   - destructiveHint tools re-check `allowRemoteWrites` themselves.
 *   - No handler throws; every failure becomes a typed, model-readable result.
 */
import { z } from "zod";
import {
  lookupAdvisories,
  resolveSafeVersion,
  severityRank,
  type AdvisoryMatch,
} from "../core/advisories.ts";
import type { SentinelConfig } from "../core/config.ts";
import { SentinelError, notConfigured, toSentinelError } from "../core/errors.ts";
import {
  GitHubClient,
  parseRepo,
  remediationBranchName,
  type RepoRef,
} from "../core/github.ts";
import { isValidPackageName, scanManifest, type Dependency } from "../core/manifest.ts";
import { redact } from "../core/redact.ts";
import { classifyBump } from "../core/semver.ts";

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
  readonly handler: (args: Record<string, unknown>, ctx: ToolContext) => Promise<ToolResult>;
}

export interface ToolContext {
  readonly config: SentinelConfig;
  readonly github: GitHubClient;
}

const readOnly = (title: string): ToolAnnotations => ({
  title,
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
});

const destructive = (title: string): ToolAnnotations => ({
  title,
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
});

/** Cap list output so a huge repo cannot blow the model's context window. */
const MAX_DEPENDENCIES_REPORTED = 150;
const MAX_ADVISORY_PACKAGES = 40;

/**
 * Fail a destructive tool before it performs any I/O when the deployment is
 * read-only. `GitHubClient` enforces this too; doing it here as well means a
 * read-only run makes no outbound request at all, which is easier to audit.
 */
function assertWritesAllowed(ctx: ToolContext, action: string): void {
  if (!ctx.github.writesAllowed) {
    throw new SentinelError(
      "forbidden",
      `${action} is blocked: SENTINEL is running in read-only mode.`,
      "Set SENTINEL_ALLOW_REMOTE_WRITES=true to permit remote writes.",
    );
  }
}

function resolveRepo(input: unknown, config: SentinelConfig): RepoRef {
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

// --------------------------------------------------------- scan_dependencies

const scanDependencies: ToolDefinition = {
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

// --------------------------------------------------------- lookup_advisories

const lookupAdvisoriesTool: ToolDefinition = {
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

// ------------------------------------------------------- assess_blast_radius

const assessBlastRadius: ToolDefinition = {
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
    const packageName = String(args.packageName ?? "");
    const fromVersion = String(args.fromVersion ?? "");
    const toVersion = String(args.toVersion ?? "");
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
        const search = await import("../core/http.ts").then((m) =>
          m.httpJson<{ total_count?: number }>(`https://api.github.com/search/code?${query}`, {
            headers: {
              accept: "application/vnd.github+json",
              authorization: `Bearer ${ctx.config.githubToken ?? ""}`,
              "user-agent": "sentinel-strike-team",
            },
            retries: 0,
          }),
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

// ------------------------------------------------------------- propose_patch

const proposePatch: ToolDefinition = {
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
      .array(
        z.object({
          name: z.string().describe("Package to upgrade."),
          toVersion: z.string().describe("Target version, without a range prefix."),
        }),
      )
      .min(1)
      .max(50)
      .describe("Upgrades to apply."),
  },
  async handler(args, ctx) {
    if (!ctx.github.configured) throw notConfigured("GitHub access", "GITHUB_TOKEN");
    const ref = resolveRepo(args.repo, ctx.config);
    const parsed = z
      .array(z.object({ name: z.string(), toVersion: z.string() }))
      .min(1)
      .safeParse(args.upgrades);
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

// -------------------------------------------------------- open_pull_request

const openPullRequest: ToolDefinition = {
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

    const title = String(args.title ?? "").trim();
    const body = String(args.body ?? "").trim();
    const filePath = String(args.filePath ?? "").trim();
    const fileContent = String(args.fileContent ?? "");
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

// ------------------------------------------------------- merge_pull_request

const mergePullRequest: ToolDefinition = {
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

// ------------------------------------------------------------ triage_summary

const triageSummary: ToolDefinition = {
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
  async handler(args) {
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

export const TOOLS: readonly ToolDefinition[] = [
  scanDependencies,
  lookupAdvisoriesTool,
  assessBlastRadius,
  triageSummary,
  proposePatch,
  openPullRequest,
  mergePullRequest,
];

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
