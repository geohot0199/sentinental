import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SentinelDb } from "../src/server/db.ts";
import { buildPatch, buildPlan, type PlanEntry } from "../src/server/scanner.ts";
import type { AdvisoryMatch, Severity } from "../src/core/advisories.ts";
import type { FindingRow } from "../src/server/db.ts";

/** The flattened row shape the database stores, derived from a match. */
function row(m: AdvisoryMatch): Omit<FindingRow, "id" | "scanId"> {
  return {
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
  };
}

function match(
  packageName: string,
  installedVersion: string,
  severity: Severity,
  recommendedVersion: string | null,
  id = `GHSA-${packageName}-${severity}`,
): AdvisoryMatch {
  return {
    packageName,
    installedVersion,
    advisory: {
      id,
      cve: null,
      summary: `${packageName} is vulnerable`,
      severity,
      cvssScore: 7.5,
      url: `https://github.com/advisories/${id}`,
      vulnerableRange: "< 9.9.9",
      firstPatchedVersion: recommendedVersion,
      source: "github",
    },
    recommendedVersion,
    bump: "minor",
  };
}

describe("buildPlan", () => {
  it("collapses many advisories into one row per package", () => {
    const plan = buildPlan([
      match("lodash", "4.17.11", "high", "4.17.21", "GHSA-a"),
      match("lodash", "4.17.11", "critical", "4.18.0", "GHSA-b"),
      match("lodash", "4.17.11", "low", "4.17.12", "GHSA-c"),
    ]);

    expect(plan).toHaveLength(1);
    expect(plan[0]?.packageName).toBe("lodash");
    expect(plan[0]?.advisoryCount).toBe(3);
  });

  // One upgrade must clear every advisory, so the target is the highest fix.
  it("targets the highest fix version, not the first", () => {
    const plan = buildPlan([
      match("lodash", "4.17.11", "high", "4.17.21", "GHSA-a"),
      match("lodash", "4.17.11", "critical", "4.18.0", "GHSA-b"),
    ]);

    expect(plan[0]?.targetVersion).toBe("4.18.0");
  });

  it("reports the worst severity across the package's advisories", () => {
    const plan = buildPlan([
      match("axios", "0.21.0", "low", "0.21.1", "GHSA-a"),
      match("axios", "0.21.0", "critical", "0.21.2", "GHSA-b"),
      match("axios", "0.21.0", "moderate", "0.21.3", "GHSA-c"),
    ]);

    expect(plan[0]?.worstSeverity).toBe("critical");
  });

  it("orders the plan worst first", () => {
    const plan = buildPlan([
      match("low-pkg", "1.0.0", "low", "1.0.1"),
      match("critical-pkg", "1.0.0", "critical", "2.0.0"),
      match("moderate-pkg", "1.0.0", "moderate", "1.1.0"),
    ]);

    expect(plan.map((p) => p.packageName)).toEqual([
      "critical-pkg",
      "moderate-pkg",
      "low-pkg",
    ]);
  });

  it("marks a package with no published fix as unknown", () => {
    const plan = buildPlan([match("orphan", "1.0.0", "high", null)]);

    expect(plan[0]?.targetVersion).toBeNull();
    expect(plan[0]?.bump).toBe("unknown");
  });

  it("returns an empty plan for no matches", () => {
    expect(buildPlan([])).toEqual([]);
  });
});

/** `JSON.parse` returns `any`; give the generated patch a shape to read. */
interface PatchManifest {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}
function parsePatch(content: string | null): PatchManifest {
  return JSON.parse(content ?? "{}") as PatchManifest;
}

describe("buildPatch", () => {
  const manifest = JSON.stringify(
    {
      name: "demo",
      dependencies: { lodash: "^4.17.11", minimist: "1.2.0" },
      devDependencies: { vitest: "~1.0.0" },
    },
    null,
    2,
  );

  function plan(entries: Partial<PlanEntry>[]): PlanEntry[] {
    return entries.map((e) => ({
      packageName: "x",
      installedVersion: "1.0.0",
      targetVersion: "2.0.0",
      worstSeverity: "high",
      advisoryCount: 1,
      bump: "major",
      ...e,
    }));
  }

  // A patch that rewrites "^4.17.11" to a pin would silently change the
  // project's update policy, so the operator has to survive.
  it("preserves the caret range operator", () => {
    const result = buildPatch(manifest, plan([{ packageName: "lodash", targetVersion: "4.18.0" }]));
    const parsed = parsePatch(result.content);

    expect(parsed.dependencies?.lodash).toBe("^4.18.0");
  });

  it("preserves the tilde operator and patches devDependencies", () => {
    const result = buildPatch(manifest, plan([{ packageName: "vitest", targetVersion: "1.6.1" }]));
    const parsed = parsePatch(result.content);

    expect(parsed.devDependencies?.vitest).toBe("~1.6.1");
  });

  it("keeps an exact pin exact", () => {
    const result = buildPatch(manifest, plan([{ packageName: "minimist", targetVersion: "1.2.6" }]));
    const parsed = parsePatch(result.content);

    expect(parsed.dependencies?.minimist).toBe("1.2.6");
  });

  it("leaves untouched packages alone", () => {
    const result = buildPatch(manifest, plan([{ packageName: "lodash", targetVersion: "4.18.0" }]));
    const parsed = parsePatch(result.content);

    expect(parsed.dependencies?.minimist).toBe("1.2.0");
    expect(parsed.devDependencies?.vitest).toBe("~1.0.0");
    expect(parsed.name).toBe("demo");
  });

  it("skips a transitive package that is not declared", () => {
    const result = buildPatch(manifest, plan([{ packageName: "deep-dep", targetVersion: "3.0.0" }]));

    expect(result.content).toBeNull();
    expect(result.skipped[0]).toContain("transitive");
  });

  it("skips a package with no published fix", () => {
    const result = buildPatch(manifest, plan([{ packageName: "lodash", targetVersion: null }]));

    expect(result.applied).toEqual([]);
    expect(result.skipped[0]).toContain("no published fix");
  });

  it("returns no content when nothing changed", () => {
    expect(buildPatch(manifest, []).content).toBeNull();
  });

  it("reports invalid JSON instead of throwing", () => {
    const result = buildPatch("{ not json", plan([{ packageName: "lodash" }]));

    expect(result.content).toBeNull();
    expect(result.skipped[0]).toContain("not valid JSON");
  });

  it("emits 2-space JSON with a trailing newline", () => {
    const result = buildPatch(manifest, plan([{ packageName: "lodash", targetVersion: "4.18.0" }]));

    expect(result.content?.endsWith("\n")).toBe(true);
    expect(result.content).toContain('\n  "dependencies"');
  });
});

describe("SentinelDb", () => {
  let dir: string;
  let db: SentinelDb;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "sentinel-db-"));
    db = new SentinelDb(join(dir, "test.db"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("round-trips a scan", () => {
    db.createScan("s1", "manifest", "demo", '{"name":"demo"}');
    const scan = db.getScan("s1");

    expect(scan?.id).toBe("s1");
    expect(scan?.status).toBe("queued");
    expect(scan?.target).toBe("demo");
    expect(db.getScanManifest("s1")).toBe('{"name":"demo"}');
  });

  it("returns null for an unknown scan", () => {
    expect(db.getScan("nope")).toBeNull();
    expect(db.listFindings("nope")).toEqual([]);
  });

  it("records status transitions and an error message", () => {
    db.createScan("s1", "repo", "owner/repo", null);
    db.setScanStatus("s1", "running");
    expect(db.getScan("s1")?.status).toBe("running");

    db.setScanStatus("s1", "failed", "upstream exploded");
    const scan = db.getScan("s1");
    expect(scan?.status).toBe("failed");
    expect(scan?.error).toBe("upstream exploded");
    expect(scan?.finishedAt).not.toBeNull();
  });

  it("stores findings and derives the worst severity", () => {
    db.createScan("s1", "manifest", "demo", "{}");
    db.addFindings("s1", [
      row(match("axios", "0.21.0", "moderate", "0.21.1", "GHSA-a")),
      row(match("lodash", "4.17.11", "critical", "4.18.0", "GHSA-b")),
    ]);
    db.setScanTotals("s1", 5, 2, "critical");

    const scan = db.getScan("s1");
    expect(scan?.findingCount).toBe(2);
    expect(scan?.worstSeverity).toBe("critical");

    const findings = db.listFindings("s1");
    expect(findings).toHaveLength(2);
    expect(findings[0]?.severity).toBe("critical"); // worst first
    expect(findings[0]?.packageName).toBe("lodash");
  });

  it("appends events with a monotonic sequence", () => {
    db.createScan("s1", "manifest", "demo", "{}");
    db.addEvent("s1", "start", "one");
    db.addEvent("s1", "triage", "two");
    db.addEvent("s1", "done", "three");

    const events = db.listEvents("s1");
    expect(events.map((e) => e.message)).toEqual(["one", "two", "three"]);
    expect(events[0]!.seq).toBeLessThan(events[1]!.seq);
    expect(events[1]!.seq).toBeLessThan(events[2]!.seq);
  });

  it("keeps each scan's events and findings separate", () => {
    db.createScan("s1", "manifest", "a", "{}");
    db.createScan("s2", "manifest", "b", "{}");
    db.addEvent("s1", "start", "for s1");
    db.addFindings("s2", [row(match("lodash", "4.17.11", "high", "4.18.0"))]);

    expect(db.listEvents("s1")).toHaveLength(1);
    expect(db.listEvents("s2")).toHaveLength(0);
    expect(db.listFindings("s1")).toHaveLength(0);
    expect(db.listFindings("s2")).toHaveLength(1);
  });

  it("lists scans newest first and honours the limit", () => {
    for (const id of ["s1", "s2", "s3"]) db.createScan(id, "manifest", id, "{}");

    const all = db.listScans(10);
    expect(all).toHaveLength(3);
    expect(all[0]?.id).toBe("s3");
    expect(db.listScans(2)).toHaveLength(2);
  });

  it("stores and returns the plan and patch", () => {
    db.createScan("s1", "manifest", "demo", "{}");
    const plan = buildPlan([match("lodash", "4.17.11", "critical", "4.18.0")]);
    db.setScanPlan("s1", plan);
    db.setScanPatch("s1", { path: "package.json", content: "{}", applied: ["lodash"], skipped: [] });

    expect(db.getScanPlan("s1")).toHaveLength(1);
    expect((db.getScanPatch("s1") as { content: string }).content).toBe("{}");
  });

  it("cascades a delete to findings and events", () => {
    db.createScan("s1", "manifest", "demo", "{}");
    db.addFindings("s1", [row(match("lodash", "4.17.11", "high", "4.18.0"))]);
    db.addEvent("s1", "start", "hello");

    expect(db.deleteScan("s1")).toBe(true);
    expect(db.getScan("s1")).toBeNull();
    expect(db.listFindings("s1")).toEqual([]);
    expect(db.listEvents("s1")).toEqual([]);
    expect(db.deleteScan("s1")).toBe(false);
  });

  it("aggregates statistics", () => {
    db.createScan("s1", "manifest", "demo", "{}");
    db.addFindings("s1", [
      row(match("lodash", "4.17.11", "critical", "4.18.0", "GHSA-a")),
      row(match("axios", "0.21.0", "high", "0.21.1", "GHSA-b")),
    ]);

    const stats = db.stats();
    expect(stats.scans).toBe(1);
    expect(stats.findings).toBe(2);
    expect(stats.critical).toBe(1);
    expect(stats.packages).toBe(2);
  });

  // node:sqlite refuses to bind `undefined`; a single advisory missing an
  // optional field must not abort the whole finding set.
  it("stores a finding whose optional fields are absent", () => {
    db.createScan("s1", "manifest", "demo", "{}");
    db.addFindings("s1", [
      {
        packageName: "mystery",
        installedVersion: "1.0.0",
        advisoryId: "GHSA-none",
        severity: "unknown",
        summary: "no metadata",
        url: "https://example.invalid",
        vulnerableRange: ">= 0",
        bump: "unknown",
      } as Omit<FindingRow, "id" | "scanId">,
    ]);

    const finding = db.listFindings("s1")[0];
    expect(finding?.cve).toBeNull();
    expect(finding?.cvssScore).toBeNull();
    expect(finding?.recommendedVersion).toBeNull();
  });

  it("survives a manifest containing quotes and unicode", () => {
    const nasty = JSON.stringify({ name: "it's \"quoted\" 🔒", dependencies: {} });
    db.createScan("s1", "manifest", "weird", nasty);

    expect(db.getScanManifest("s1")).toBe(nasty);
  });
});
