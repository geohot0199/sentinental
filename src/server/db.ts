/**
 * SENTINEL application database.
 *
 * Uses Node's built-in `node:sqlite`, so persistence adds no dependency and no
 * native build step. The file lives under `.sentinel/` which is git-ignored.
 *
 * Everything here is synchronous by design: SQLite writes are fast, the working
 * set is tiny, and a synchronous statement is far easier to reason about than a
 * pool. Every query is a prepared statement with bound parameters - no string
 * interpolation reaches SQL.
 */
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

export type ScanStatus = "queued" | "running" | "done" | "failed";

export interface ScanRow {
  readonly id: string;
  readonly source: "repo" | "manifest";
  readonly target: string;
  readonly status: ScanStatus;
  readonly createdAt: string;
  readonly finishedAt: string | null;
  readonly dependencyCount: number;
  readonly findingCount: number;
  readonly worstSeverity: string | null;
  readonly error: string | null;
}

export interface FindingRow {
  readonly id: number;
  readonly scanId: string;
  readonly packageName: string;
  readonly installedVersion: string;
  readonly advisoryId: string;
  readonly cve: string | null;
  readonly severity: string;
  readonly cvssScore: number | null;
  readonly summary: string;
  readonly url: string;
  readonly vulnerableRange: string;
  readonly recommendedVersion: string | null;
  readonly bump: string;
}

export interface EventRow {
  readonly seq: number;
  readonly scanId: string;
  readonly stage: string;
  readonly message: string;
  readonly at: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS scans (
  id               TEXT PRIMARY KEY,
  source           TEXT NOT NULL,
  target           TEXT NOT NULL,
  status           TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  finished_at      TEXT,
  dependency_count INTEGER NOT NULL DEFAULT 0,
  finding_count    INTEGER NOT NULL DEFAULT 0,
  worst_severity   TEXT,
  error            TEXT,
  manifest         TEXT,
  plan             TEXT,
  patch            TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id             TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  package_name        TEXT NOT NULL,
  installed_version   TEXT NOT NULL,
  advisory_id         TEXT NOT NULL,
  cve                 TEXT,
  severity            TEXT NOT NULL,
  cvss_score          REAL,
  summary             TEXT NOT NULL,
  url                 TEXT NOT NULL,
  vulnerable_range    TEXT NOT NULL,
  recommended_version TEXT,
  bump                TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  seq     INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  stage   TEXT NOT NULL,
  message TEXT NOT NULL,
  at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_scan   ON events(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
`;

/** Narrow a raw sqlite row (Record<string, SQLOutputValue>) to a typed shape. */
const str = (v: unknown): string => (typeof v === "string" ? v : String(v ?? ""));
const strOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);
const num = (v: unknown): number => (typeof v === "number" ? v : Number(v ?? 0));
const numOrNull = (v: unknown): number | null => (typeof v === "number" ? v : null);

function toScan(row: Record<string, unknown>): ScanRow {
  return {
    id: str(row.id),
    source: str(row.source) === "repo" ? "repo" : "manifest",
    target: str(row.target),
    status: str(row.status) as ScanStatus,
    createdAt: str(row.created_at),
    finishedAt: strOrNull(row.finished_at),
    dependencyCount: num(row.dependency_count),
    findingCount: num(row.finding_count),
    worstSeverity: strOrNull(row.worst_severity),
    error: strOrNull(row.error),
  };
}

function toFinding(row: Record<string, unknown>): FindingRow {
  return {
    id: num(row.id),
    scanId: str(row.scan_id),
    packageName: str(row.package_name),
    installedVersion: str(row.installed_version),
    advisoryId: str(row.advisory_id),
    cve: strOrNull(row.cve),
    severity: str(row.severity),
    cvssScore: numOrNull(row.cvss_score),
    summary: str(row.summary),
    url: str(row.url),
    vulnerableRange: str(row.vulnerable_range),
    recommendedVersion: strOrNull(row.recommended_version),
    bump: str(row.bump),
  };
}

export class SentinelDb {
  readonly #db: DatabaseSync;

  constructor(file: string) {
    if (file !== ":memory:") mkdirSync(dirname(resolve(file)), { recursive: true });
    this.#db = new DatabaseSync(file);
    // WAL keeps reads non-blocking while a scan writes progress events.
    if (file !== ":memory:") this.#db.exec("PRAGMA journal_mode = WAL;");
    this.#db.exec("PRAGMA foreign_keys = ON;");
    this.#db.exec(SCHEMA);
  }

  close(): void {
    this.#db.close();
  }

  // ------------------------------------------------------------- scans

  createScan(id: string, source: "repo" | "manifest", target: string, manifest: string | null): void {
    this.#db
      .prepare(
        `INSERT INTO scans (id, source, target, status, created_at, manifest)
         VALUES (?, ?, ?, 'queued', ?, ?)`,
      )
      .run(id, source, target, new Date().toISOString(), manifest);
  }

  setScanStatus(id: string, status: ScanStatus, error: string | null = null): void {
    const finished = status === "done" || status === "failed" ? new Date().toISOString() : null;
    this.#db
      .prepare(`UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE id = ?`)
      .run(status, error ?? null, finished, id);
  }

  setScanTotals(
    id: string,
    dependencyCount: number,
    findingCount: number,
    worstSeverity: string | null,
  ): void {
    this.#db
      .prepare(
        `UPDATE scans SET dependency_count = ?, finding_count = ?, worst_severity = ? WHERE id = ?`,
      )
      .run(dependencyCount, findingCount, worstSeverity ?? null, id);
  }

  setScanPlan(id: string, plan: unknown): void {
    this.#db.prepare(`UPDATE scans SET plan = ? WHERE id = ?`).run(JSON.stringify(plan), id);
  }

  setScanPatch(id: string, patch: unknown): void {
    this.#db.prepare(`UPDATE scans SET patch = ? WHERE id = ?`).run(JSON.stringify(patch), id);
  }

  getScan(id: string): ScanRow | null {
    const row = this.#db.prepare(`SELECT * FROM scans WHERE id = ?`).get(id);
    return row === undefined ? null : toScan(row as Record<string, unknown>);
  }

  /** Parsed JSON column, or null when absent/corrupt. */
  #getJsonColumn(id: string, column: "plan" | "patch" | "manifest"): unknown {
    const row = this.#db.prepare(`SELECT ${column} AS v FROM scans WHERE id = ?`).get(id) as
      | Record<string, unknown>
      | undefined;
    const raw = row?.v;
    if (typeof raw !== "string" || raw.length === 0) return null;
    if (column === "manifest") return raw;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  getScanPlan(id: string): unknown {
    return this.#getJsonColumn(id, "plan");
  }

  getScanPatch(id: string): unknown {
    return this.#getJsonColumn(id, "patch");
  }

  getScanManifest(id: string): string | null {
    const value = this.#getJsonColumn(id, "manifest");
    return typeof value === "string" ? value : null;
  }

  listScans(limit = 50): ScanRow[] {
    const capped = Math.max(1, Math.min(200, Math.trunc(limit)));
    const rows = this.#db
      // created_at only has millisecond resolution, so two scans queued in the
      // same tick would order arbitrarily. rowid is monotonic and breaks the tie
      // by true insertion order.
      .prepare(`SELECT * FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ?`)
      .all(capped);
    return rows.map((r) => toScan(r as Record<string, unknown>));
  }

  deleteScan(id: string): boolean {
    const result = this.#db.prepare(`DELETE FROM scans WHERE id = ?`).run(id);
    return Number(result.changes) > 0;
  }

  // ---------------------------------------------------------- findings

  addFindings(scanId: string, findings: readonly Omit<FindingRow, "id" | "scanId">[]): void {
    if (findings.length === 0) return;
    const insert = this.#db.prepare(
      `INSERT INTO findings
         (scan_id, package_name, installed_version, advisory_id, cve, severity,
          cvss_score, summary, url, vulnerable_range, recommended_version, bump)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    // One transaction: a partially written finding set would misreport risk.
    this.#db.exec("BEGIN");
    try {
      for (const f of findings) {
        insert.run(
          scanId,
          f.packageName,
          f.installedVersion,
          f.advisoryId,
          // node:sqlite rejects `undefined`, so an omitted nullable field must
          // become an explicit NULL rather than aborting the whole insert.
          f.cve ?? null,
          f.severity,
          f.cvssScore ?? null,
          f.summary,
          f.url,
          f.vulnerableRange,
          f.recommendedVersion ?? null,
          f.bump,
        );
      }
      this.#db.exec("COMMIT");
    } catch (cause) {
      this.#db.exec("ROLLBACK");
      throw cause;
    }
  }

  listFindings(scanId: string): FindingRow[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM findings WHERE scan_id = ?
         ORDER BY CASE severity
           WHEN 'critical' THEN 0 WHEN 'high' THEN 1
           WHEN 'moderate' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
         cvss_score DESC NULLS LAST, package_name`,
      )
      .all(scanId);
    return rows.map((r) => toFinding(r as Record<string, unknown>));
  }

  // ------------------------------------------------------------ events

  addEvent(scanId: string, stage: string, message: string): EventRow {
    const at = new Date().toISOString();
    const result = this.#db
      .prepare(`INSERT INTO events (scan_id, stage, message, at) VALUES (?, ?, ?, ?)`)
      .run(scanId, stage, message, at);
    return { seq: Number(result.lastInsertRowid), scanId, stage, message, at };
  }

  listEvents(scanId: string, afterSeq = 0): EventRow[] {
    const rows = this.#db
      .prepare(`SELECT * FROM events WHERE scan_id = ? AND seq > ? ORDER BY seq`)
      .all(scanId, afterSeq);
    return rows.map((r) => {
      const row = r as Record<string, unknown>;
      return {
        seq: num(row.seq),
        scanId: str(row.scan_id),
        stage: str(row.stage),
        message: str(row.message),
        at: str(row.at),
      };
    });
  }

  // ------------------------------------------------------------- stats

  stats(): { scans: number; findings: number; critical: number; packages: number } {
    const one = (sql: string): number => {
      const row = this.#db.prepare(sql).get() as Record<string, unknown> | undefined;
      return num(row?.n);
    };
    return {
      scans: one(`SELECT COUNT(*) AS n FROM scans`),
      findings: one(`SELECT COUNT(*) AS n FROM findings`),
      critical: one(`SELECT COUNT(*) AS n FROM findings WHERE severity = 'critical'`),
      packages: one(`SELECT COUNT(DISTINCT package_name) AS n FROM findings`),
    };
  }
}
