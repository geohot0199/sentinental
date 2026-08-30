/**
 * Advisory intelligence.
 *
 * Primary source is the GitHub Advisory Database (rich, deduplicated, gives us
 * `first_patched_version` directly). OSV is the fallback so the agent still
 * works for an operator with no GitHub token or in a network where GitHub is
 * unreachable.
 */
import { httpJson } from "./http.ts";
import { SentinelError } from "./errors.ts";
import { classifyBump, compareVersions, versionInRange, type BumpKind } from "./semver.ts";

export type Severity = "critical" | "high" | "moderate" | "low" | "unknown";

export interface Advisory {
  readonly id: string;
  readonly cve: string | null;
  readonly summary: string;
  readonly severity: Severity;
  readonly cvssScore: number | null;
  readonly url: string;
  /** Range the installed version was matched against. */
  readonly vulnerableRange: string;
  readonly firstPatchedVersion: string | null;
  readonly source: "github" | "osv";
}

export interface AdvisoryMatch {
  readonly packageName: string;
  readonly installedVersion: string;
  readonly advisory: Advisory;
  /** Smallest safe version, and how big a jump it is. */
  readonly recommendedVersion: string | null;
  readonly bump: BumpKind;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
  unknown: 0,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER[severity];
}

function normaliseSeverity(raw: unknown): Severity {
  if (typeof raw !== "string") return "unknown";
  const value = raw.toLowerCase();
  if (value === "critical" || value === "high" || value === "low") return value;
  if (value === "moderate" || value === "medium") return "moderate";
  return "unknown";
}

// ---------------------------------------------------------------- GitHub

interface GhVulnerability {
  package?: { ecosystem?: string; name?: string };
  vulnerable_version_range?: string;
  first_patched_version?: string | null;
}

interface GhAdvisory {
  ghsa_id?: string;
  cve_id?: string | null;
  summary?: string;
  severity?: string;
  html_url?: string;
  cvss_severities?: { cvss_v3?: { score?: number }; cvss_v4?: { score?: number } };
  vulnerabilities?: GhVulnerability[];
}

function pickCvss(advisory: GhAdvisory): number | null {
  const v4 = advisory.cvss_severities?.cvss_v4?.score;
  if (typeof v4 === "number" && v4 > 0) return v4;
  const v3 = advisory.cvss_severities?.cvss_v3?.score;
  if (typeof v3 === "number" && v3 > 0) return v3;
  return null;
}

async function queryGitHub(
  packageName: string,
  ecosystem: string,
  token: string | null,
): Promise<GhAdvisory[]> {
  const url = `https://api.github.com/advisories?ecosystem=${encodeURIComponent(ecosystem)}&affects=${encodeURIComponent(packageName)}&per_page=100`;
  const headers: Record<string, string> = {
    accept: "application/vnd.github+json",
    "user-agent": "sentinel-strike-team",
    "x-github-api-version": "2022-11-28",
  };
  if (token !== null) headers.authorization = `Bearer ${token}`;
  return httpJson<GhAdvisory[]>(url, { headers, timeoutMs: 15_000 });
}

function fromGitHub(
  advisory: GhAdvisory,
  packageName: string,
  installedVersion: string,
): AdvisoryMatch | null {
  // A single advisory often lists one entry per release line (for example
  // node-fetch "< 2.6.7" and ">= 3.0.0, < 3.1.1" under CVE-2022-0235). Match on
  // the entry whose range actually covers the installed version, not merely the
  // first entry naming the package, or older majors are silently cleared.
  const entries = (advisory.vulnerabilities ?? []).filter(
    (v) => v.package?.name?.toLowerCase() === packageName.toLowerCase(),
  );
  const entry = entries.find((v) => {
    const candidate = v.vulnerable_version_range ?? "";
    return candidate.length > 0 && versionInRange(installedVersion, candidate);
  });
  if (entry === undefined) return null;

  const range = entry.vulnerable_version_range ?? "";

  const patched = entry.first_patched_version ?? null;
  return {
    packageName,
    installedVersion,
    advisory: {
      id: advisory.ghsa_id ?? "UNKNOWN",
      cve: advisory.cve_id ?? null,
      summary: advisory.summary ?? "No summary provided.",
      severity: normaliseSeverity(advisory.severity),
      cvssScore: pickCvss(advisory),
      url: advisory.html_url ?? `https://github.com/advisories/${advisory.ghsa_id ?? ""}`,
      vulnerableRange: range,
      firstPatchedVersion: patched,
      source: "github",
    },
    recommendedVersion: patched,
    bump: patched === null ? "unknown" : classifyBump(installedVersion, patched),
  };
}

// ------------------------------------------------------------------- OSV

interface OsvEvent {
  introduced?: string;
  fixed?: string;
}
interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: { type?: string; events?: OsvEvent[] }[];
}
interface OsvVuln {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  affected?: OsvAffected[];
  database_specific?: { severity?: string };
}

function fromOsv(vuln: OsvVuln, packageName: string, installedVersion: string): AdvisoryMatch | null {
  const affectedEntries = (vuln.affected ?? []).filter(
    (a) => a.package?.name?.toLowerCase() === packageName.toLowerCase(),
  );

  // OSV splits release lines across `affected` entries and across `ranges`
  // within an entry, each a stream of introduced/fixed events. Evaluate every
  // interval and keep the one covering the installed version, so an old major
  // is not cleared by a newer line's range.
  let rangeText: string | null = null;
  let fixed: string | null = null;

  outer: for (const affected of affectedEntries) {
    for (const range of affected.ranges ?? []) {
      let introducedAt: string | null = null;
      for (const event of range.events ?? []) {
        if (typeof event.introduced === "string") {
          introducedAt = event.introduced;
          continue;
        }
        if (typeof event.fixed !== "string") continue;

        const parts: string[] = [];
        if (introducedAt !== null && introducedAt !== "0") parts.push(`>= ${introducedAt}`);
        parts.push(`< ${event.fixed}`);
        const candidate = parts.join(", ");
        if (versionInRange(installedVersion, candidate)) {
          rangeText = candidate;
          fixed = event.fixed;
          break outer;
        }
        introducedAt = null;
      }

      // An interval left open (introduced with no fix) is still vulnerable.
      if (introducedAt !== null) {
        const candidate = introducedAt === "0" ? ">= 0.0.0" : `>= ${introducedAt}`;
        if (versionInRange(installedVersion, candidate)) {
          rangeText = candidate;
          fixed = null;
          break outer;
        }
      }
    }
  }

  if (rangeText === null) return null;

  const id = vuln.id ?? "UNKNOWN";
  const cve = (vuln.aliases ?? []).find((a) => a.startsWith("CVE-")) ?? null;
  return {
    packageName,
    installedVersion,
    advisory: {
      id,
      cve,
      summary: vuln.summary ?? vuln.details?.slice(0, 200) ?? "No summary provided.",
      severity: normaliseSeverity(vuln.database_specific?.severity),
      cvssScore: null,
      url: `https://osv.dev/vulnerability/${id}`,
      vulnerableRange: rangeText,
      firstPatchedVersion: fixed,
      source: "osv",
    },
    recommendedVersion: fixed,
    bump: fixed === null ? "unknown" : classifyBump(installedVersion, fixed),
  };
}

async function queryOsv(
  packageName: string,
  ecosystem: string,
  version: string,
): Promise<OsvVuln[]> {
  const body = JSON.stringify({
    package: { name: packageName, ecosystem: ecosystem === "npm" ? "npm" : ecosystem },
    version,
  });
  const result = await httpJson<{ vulns?: OsvVuln[] }>("https://api.osv.dev/v1/query", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    timeoutMs: 15_000,
    retries: 1,
  });
  return result.vulns ?? [];
}

// --------------------------------------------------------------- public

export interface LookupResult {
  readonly matches: readonly AdvisoryMatch[];
  readonly source: "github" | "osv" | "none";
  /** Populated when a source failed but another succeeded. */
  readonly warnings: readonly string[];
}

/**
 * Look up advisories affecting one installed package version.
 *
 * Tries GitHub, falls back to OSV, and reports a warning rather than throwing
 * when the primary source is unavailable - a degraded scan is far more useful
 * to the agent than a failed turn.
 */
export async function lookupAdvisories(
  packageName: string,
  installedVersion: string,
  ecosystem = "npm",
  githubToken: string | null = null,
): Promise<LookupResult> {
  if (packageName.trim().length === 0) {
    throw new SentinelError("invalid_input", "packageName must not be empty.");
  }
  const warnings: string[] = [];

  try {
    const advisories = await queryGitHub(packageName, ecosystem, githubToken);
    const matches = advisories
      .map((a) => fromGitHub(a, packageName, installedVersion))
      .filter((m): m is AdvisoryMatch => m !== null);
    return { matches: sortMatches(matches), source: "github", warnings };
  } catch (cause) {
    warnings.push(
      `GitHub Advisory Database unavailable (${cause instanceof Error ? cause.message : "unknown"}); falling back to OSV.`,
    );
  }

  try {
    const vulns = await queryOsv(packageName, ecosystem, installedVersion);
    const matches = vulns
      .map((v) => fromOsv(v, packageName, installedVersion))
      .filter((m): m is AdvisoryMatch => m !== null);
    return { matches: sortMatches(matches), source: "osv", warnings };
  } catch (cause) {
    warnings.push(
      `OSV unavailable (${cause instanceof Error ? cause.message : "unknown"}).`,
    );
  }

  return { matches: [], source: "none", warnings };
}

/** Worst first, so a truncated list still shows what matters. */
export function sortMatches(matches: readonly AdvisoryMatch[]): AdvisoryMatch[] {
  return [...matches].sort((a, b) => {
    const bySeverity = severityRank(b.advisory.severity) - severityRank(a.advisory.severity);
    if (bySeverity !== 0) return bySeverity;
    const byScore = (b.advisory.cvssScore ?? 0) - (a.advisory.cvssScore ?? 0);
    if (byScore !== 0) return byScore;
    return a.advisory.id.localeCompare(b.advisory.id);
  });
}

/**
 * Pick the single version that clears every advisory for a package: the highest
 * of the individual fix versions. Bumping to anything lower leaves a hole.
 */
export function resolveSafeVersion(matches: readonly AdvisoryMatch[]): string | null {
  let best: string | null = null;
  for (const match of matches) {
    const candidate = match.recommendedVersion;
    if (candidate === null) continue;
    if (best === null) {
      best = candidate;
      continue;
    }
    try {
      if (compareVersions(candidate, best) > 0) best = candidate;
    } catch {
      // Unparseable fix version: keep the one we can reason about.
    }
  }
  return best;
}
