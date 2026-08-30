/**
 * The triage pipeline, as a background job.
 *
 * This is the real thing: it reads a manifest, resolves versions, queries the
 * GitHub Advisory Database (OSV fallback) and computes a remediation plan and a
 * patched package.json. It reuses the same `src/core` modules the MCP tools and
 * the CLI use, so there is exactly one implementation of the domain logic.
 *
 * Progress is written to the database as it goes, so a browser that connects
 * late still replays the whole run.
 */
import {
  lookupAdvisories,
  resolveSafeVersion,
  severityRank,
  type AdvisoryMatch,
  type Severity,
} from "../core/advisories.ts";
import type { SentinelConfig } from "../core/config.ts";
import { toSentinelError } from "../core/errors.ts";
import { GitHubClient, parseRepo } from "../core/github.ts";
import { isValidPackageName, scanManifest, type Dependency } from "../core/manifest.ts";
import { classifyBump } from "../core/semver.ts";
import type { EventRow, SentinelDb } from "./db.ts";

/** Never triage more than this per scan: bounds runtime and API quota. */
const MAX_PACKAGES = 60;
/** Parallel advisory lookups. High enough to be quick, low enough to be polite. */
const CONCURRENCY = 6;

export interface PlanEntry {
  readonly packageName: string;
  readonly installedVersion: string;
  readonly targetVersion: string | null;
  readonly worstSeverity: Severity;
  readonly advisoryCount: number;
  readonly bump: string;
}

export type ScanListener = (event: EventRow) => void;

export class Scanner {
  readonly #db: SentinelDb;
  readonly #config: SentinelConfig;
  /** scanId -> listeners, so several browser tabs can watch one scan. */
  readonly #listeners = new Map<string, Set<ScanListener>>();

  constructor(db: SentinelDb, config: SentinelConfig) {
    this.#db = db;
    this.#config = config;
  }

  subscribe(scanId: string, listener: ScanListener): () => void {
    const set = this.#listeners.get(scanId) ?? new Set<ScanListener>();
    set.add(listener);
    this.#listeners.set(scanId, set);
    return () => {
      set.delete(listener);
      if (set.size === 0) this.#listeners.delete(scanId);
    };
  }

  /** Persist a progress line, then fan it out to anyone watching. */
  #emit(scanId: string, stage: string, message: string): void {
    const event = this.#db.addEvent(scanId, stage, message);
    for (const listener of this.#listeners.get(scanId) ?? []) {
      try {
        listener(event);
      } catch {
        // A broken listener must never abort the scan.
      }
    }
  }

  /**
   * Run a scan to completion. Callers do not await this: the HTTP handler
   * returns the id immediately and the browser follows the SSE stream.
   */
  async run(scanId: string): Promise<void> {
    const scan = this.#db.getScan(scanId);
    if (scan === null) return;

    try {
      this.#db.setScanStatus(scanId, "running");
      this.#emit(scanId, "start", `Scan started for ${scan.target}.`);

      // ---------------------------------------------------- 01 inventory
      const { manifestRaw, lockRaw, lockName, label } = await this.#loadManifest(scan);
      const inventory = scanManifest(manifestRaw, lockRaw, lockName);
      for (const warning of inventory.warnings) this.#emit(scanId, "inventory", warning);

      const dependencies = inventory.dependencies;
      this.#emit(
        scanId,
        "inventory",
        `Resolved ${dependencies.length} dependencies from ${label}${lockName === null ? "" : ` + ${lockName}`}.`,
      );

      if (dependencies.length === 0) {
        this.#db.setScanTotals(scanId, 0, 0, null);
        this.#db.setScanStatus(scanId, "done");
        this.#emit(scanId, "done", "No dependencies to triage.");
        return;
      }

      // ------------------------------------------------------- 02 triage
      const queue = dependencies.filter((d) => isValidPackageName(d.name)).slice(0, MAX_PACKAGES);
      if (queue.length < dependencies.length) {
        this.#emit(
          scanId,
          "triage",
          `Triaging the first ${queue.length} of ${dependencies.length} dependencies.`,
        );
      }

      const matches = await this.#triage(scanId, queue);

      // -------------------------------------------------------- 03 store
      this.#db.addFindings(
        scanId,
        matches.map((m) => ({
          packageName: m.packageName,
          installedVersion: m.installedVersion,
          advisoryId: m.advisory.id,
          cve: m.advisory.cve,
          severity: m.advisory.severity,
          cvssScore: m.advisory.cvssScore,
          summary: m.advisory.summary,
          url: m.advisory.url,
          vulnerableRange: m.advisory.vulnerableRange,
          recommendedVersion: m.recommendedVersion,
          bump: m.bump,
        })),
      );

      const worst =
        matches.length === 0
          ? null
          : matches
              .map((m) => m.advisory.severity)
              .sort((a, b) => severityRank(b) - severityRank(a))[0] ?? null;
      this.#db.setScanTotals(scanId, dependencies.length, matches.length, worst);

      // --------------------------------------------------------- 04 plan
      const plan = buildPlan(matches);
      this.#db.setScanPlan(scanId, plan);

      if (plan.length === 0) {
        this.#emit(scanId, "plan", "No affected packages. Nothing to patch.");
      } else {
        this.#emit(
          scanId,
          "plan",
          `Remediation plan: ${plan.filter((p) => p.targetVersion !== null).length} upgradable, ` +
            `${plan.filter((p) => p.targetVersion === null).length} awaiting a published fix.`,
        );
      }

      // -------------------------------------------------------- 05 patch
      const patch = buildPatch(manifestRaw, plan);
      this.#db.setScanPatch(scanId, patch);
      if (patch.applied.length > 0) {
        this.#emit(
          scanId,
          "patch",
          `Patched package.json with ${patch.applied.length} upgrade(s), range operators preserved.`,
        );
      }

      // ------------------------------------------------------ 06 propose
      this.#db.setScanStatus(scanId, "done");
      this.#emit(
        scanId,
        "done",
        matches.length === 0
          ? "Scan complete. No advisories match the versions in use."
          : `Scan complete. ${matches.length} advisory match(es) across ${plan.length} package(s).`,
      );
    } catch (cause) {
      const error = toSentinelError(cause);
      const detail = error.remedy === null ? error.message : `${error.message} ${error.remedy}`;
      this.#db.setScanStatus(scanId, "failed", detail);
      this.#emit(scanId, "error", detail);
    }
  }

  /** Fetch the manifest, either from GitHub or from the pasted body. */
  async #loadManifest(scan: { id: string; source: string; target: string }): Promise<{
    manifestRaw: string;
    lockRaw: string | null;
    lockName: string | null;
    label: string;
  }> {
    if (scan.source === "manifest") {
      const stored = this.#db.getScanManifest(scan.id);
      if (stored === null) throw new Error("The submitted manifest could not be read back.");
      this.#emit(scan.id, "inventory", "Reading the submitted package.json.");
      return { manifestRaw: stored, lockRaw: null, lockName: null, label: "the submitted manifest" };
    }

    const ref = parseRepo(scan.target);
    const github = new GitHubClient(this.#config.githubToken, this.#config.allowRemoteWrites);
    this.#emit(scan.id, "inventory", `Reading ${ref.owner}/${ref.repo} from GitHub.`);

    const info = await github.getRepo(ref);
    const branch = info.defaultBranch;
    this.#emit(scan.id, "inventory", `Default branch: ${branch}.`);

    const manifestRaw = await github.getFile(ref, "package.json", branch);
    if (manifestRaw === null) {
      throw new Error(
        `No package.json at the root of ${ref.owner}/${ref.repo}@${branch}. SENTINEL triages npm projects.`,
      );
    }

    // Lockfiles give real installed versions; try them in fidelity order.
    let lockRaw: string | null = null;
    let lockName: string | null = null;
    for (const candidate of ["package-lock.json", "npm-shrinkwrap.json"]) {
      try {
        lockRaw = await github.getFile(ref, candidate, branch);
      } catch {
        lockRaw = null; // Too large for the contents API, or unreadable.
      }
      if (lockRaw !== null) {
        lockName = candidate;
        break;
      }
    }
    if (lockName === null) {
      this.#emit(scan.id, "inventory", "No readable lockfile; versions estimated from ranges.");
    }

    return { manifestRaw, lockRaw, lockName, label: `${ref.owner}/${ref.repo}@${branch}` };
  }

  /** Look advisories up with bounded concurrency, reporting progress as it goes. */
  async #triage(scanId: string, queue: readonly Dependency[]): Promise<AdvisoryMatch[]> {
    const all: AdvisoryMatch[] = [];
    const seenWarnings = new Set<string>();
    let cursor = 0;
    let done = 0;

    const worker = async (): Promise<void> => {
      for (;;) {
        const index = cursor;
        cursor += 1;
        const dep = queue[index];
        if (dep === undefined) return;

        try {
          const result = await lookupAdvisories(
            dep.name,
            dep.version,
            "npm",
            this.#config.githubToken,
          );
          if (result.matches.length > 0) {
            all.push(...result.matches);
            const worst = result.matches[0]?.advisory.severity ?? "unknown";
            this.#emit(
              scanId,
              "triage",
              `${dep.name}@${dep.version}: ${result.matches.length} advisory match(es), worst ${worst}.`,
            );
          }
          // Report each distinct degradation once, not once per package.
          for (const warning of result.warnings) {
            if (!seenWarnings.has(warning)) {
              seenWarnings.add(warning);
              this.#emit(scanId, "triage", warning);
            }
          }
        } catch (cause) {
          this.#emit(
            scanId,
            "triage",
            `${dep.name}: lookup failed (${toSentinelError(cause).message}).`,
          );
        }

        done += 1;
        if (done % 10 === 0 || done === queue.length) {
          this.#emit(scanId, "progress", `Checked ${done}/${queue.length} packages.`);
        }
      }
    };

    await Promise.all(
      Array.from({ length: Math.min(CONCURRENCY, queue.length) }, () => worker()),
    );
    return all;
  }
}

/**
 * Collapse advisory matches into one row per package, targeting the *highest*
 * fix version so no advisory is left open by the upgrade.
 */
export function buildPlan(matches: readonly AdvisoryMatch[]): PlanEntry[] {
  const byPackage = new Map<string, AdvisoryMatch[]>();
  for (const match of matches) {
    const bucket = byPackage.get(match.packageName) ?? [];
    bucket.push(match);
    byPackage.set(match.packageName, bucket);
  }

  const plan = [...byPackage.entries()].map(([packageName, entries]) => {
    const installedVersion = entries[0]?.installedVersion ?? "unknown";
    const targetVersion = resolveSafeVersion(entries);
    const worstSeverity =
      entries
        .map((e) => e.advisory.severity)
        .sort((a, b) => severityRank(b) - severityRank(a))[0] ?? "unknown";
    return {
      packageName,
      installedVersion,
      targetVersion,
      worstSeverity,
      advisoryCount: entries.length,
      bump: targetVersion === null ? "unknown" : classifyBump(installedVersion, targetVersion),
    };
  });

  plan.sort((a, b) => severityRank(b.worstSeverity) - severityRank(a.worstSeverity));
  return plan;
}

export interface PatchResult {
  readonly path: string;
  readonly content: string | null;
  readonly applied: readonly string[];
  readonly skipped: readonly string[];
}

/**
 * Produce the updated package.json, preserving whichever range operator the
 * project already uses so the diff stays minimal.
 */
export function buildPatch(manifestRaw: string, plan: readonly PlanEntry[]): PatchResult {
  const applied: string[] = [];
  const skipped: string[] = [];

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(manifestRaw) as Record<string, unknown>;
  } catch {
    return { path: "package.json", content: null, applied, skipped: ["package.json is not valid JSON."] };
  }

  const sections = ["dependencies", "devDependencies", "optionalDependencies"] as const;

  for (const entry of plan) {
    if (entry.targetVersion === null) {
      skipped.push(`${entry.packageName}: no published fix`);
      continue;
    }
    let found = false;
    for (const section of sections) {
      const record = pkg[section];
      if (typeof record !== "object" || record === null) continue;
      const table = record as Record<string, string>;
      const current = table[entry.packageName];
      if (current === undefined) continue;
      const prefix = /^[\^~]/.exec(current)?.[0] ?? "";
      table[entry.packageName] = `${prefix}${entry.targetVersion}`;
      applied.push(
        `${entry.packageName}: ${current} → ${prefix}${entry.targetVersion} (${section})`,
      );
      found = true;
      break;
    }
    if (!found) skipped.push(`${entry.packageName}: transitive, not in package.json`);
  }

  // npm's own formatting, so the diff is the change and nothing else.
  const content = applied.length > 0 ? `${JSON.stringify(pkg, null, 2)}\n` : null;
  return { path: "package.json", content, applied, skipped };
}
