/**
 * `.env.example` is documentation, and documentation that is wrong is worse
 * than none: an operator who copies it and finds a variable missing assumes
 * the variable does not exist.
 *
 * These tests make the file a checked artefact. Anything the source reads out
 * of `process.env` must appear in `.env.example` and in the Configuration
 * table in `README.md`, with no entries left behind for variables nobody
 * reads any more.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCANNED_DIRS = ["src", "scripts", "site"];
/** Bundles and build output are generated; the sources behind them are scanned. */
const SKIPPED_PATH_PARTS = new Set(["node_modules", "dist", "public", ".git"]);
const SCANNED_EXTENSIONS = new Set([".ts", ".js", ".mjs"]);

/**
 * Every way this codebase reads an environment variable:
 *   - `process.env.FOO` and `process.env["FOO"]`, anywhere in src/scripts/site
 *   - `readOptional("FOO")` / `readPort("FOO", …)` / `readBool("FOO", …)`,
 *     the three private readers in src/core/config.ts, which is the single
 *     place secrets enter the process
 *
 * If a fourth reader is ever added, add it here — the "finds the variables
 * that are known to be read" test below exists to make that omission visible.
 */
const ENV_READ_PATTERNS: readonly RegExp[] = [
  /process\.env\s*(?:\.\s*([A-Z][A-Z0-9_]*)|\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\])/g,
  /\b(?:readOptional|readPort|readBool)\s*\(\s*"([A-Z][A-Z0-9_]*)"/g,
  // The provider key names live in the PROVIDER_ENV table as data, so they are
  // never written as `process.env.X` anywhere.
  /\benvVar:\s*"([A-Z][A-Z0-9_]*)"/g,
];

/**
 * Names that look like configuration and are not.
 *
 * `AWS_SECRET_ACCESS_KEY` appears only inside the deliberately vulnerable
 * sample snippets the demo UIs feed to the BreachLab analyzer, and inside the
 * test fixtures for it. It is content SENTINEL detects, never a variable it
 * reads, so listing it in `.env.example` would be actively misleading.
 */
const NOT_CONFIGURATION = new Set(["AWS_SECRET_ACCESS_KEY"]);

function* walk(dir: string): Generator<string> {
  for (const entry of readdirSync(dir)) {
    if (SKIPPED_PATH_PARTS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      yield* walk(full);
    } else if (SCANNED_EXTENSIONS.has(entry.slice(entry.lastIndexOf(".")))) {
      yield full;
    }
  }
}

/** Every scanned file, as a repo-relative path. */
function scannedFiles(): string[] {
  return SCANNED_DIRS.flatMap((dir) => [...walk(resolve(ROOT, dir))]).map((file) =>
    relative(ROOT, file),
  ).sort();
}

/** Every `(name, file)` pair the patterns find, fixtures already removed. */
function* environmentReads(): Generator<{ name: string; file: string }> {
  for (const file of scannedFiles()) {
    const source = readFileSync(resolve(ROOT, file), "utf8");
    for (const pattern of ENV_READ_PATTERNS) {
      for (const match of source.matchAll(pattern)) {
        const name = match[1] ?? match[2];
        if (name === undefined || NOT_CONFIGURATION.has(name)) continue;
        yield { name, file };
      }
    }
  }
}

function variablesReadBySource(): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const { name, file } of environmentReads()) {
    const seen = found.get(name) ?? [];
    if (!seen.includes(file)) seen.push(file);
    found.set(name, seen);
  }
  return found;
}

/** Names declared in `.env.example`, whether commented out or not. */
function declaredInEnvExample(): Set<string> {
  const declared = new Set<string>();
  for (const line of readFileSync(join(ROOT, ".env.example"), "utf8").split("\n")) {
    const match = /^\s*#?\s*([A-Z][A-Z0-9_]*)\s*=/.exec(line);
    if (match?.[1] !== undefined) declared.add(match[1]);
  }
  return declared;
}

/** Names in the README's Configuration table, which lists `A` / `B` per row. */
function documentedInReadme(): Set<string> {
  const documented = new Set<string>();
  const readme = readFileSync(join(ROOT, "README.md"), "utf8").split("\n");
  const start = readme.findIndex((line) => line.startsWith("| Variable |"));
  expect(start, "README Configuration table header not found").toBeGreaterThan(0);
  for (const line of readme.slice(start + 2)) {
    if (!line.startsWith("|")) break;
    for (const name of line.matchAll(/`([A-Z][A-Z0-9_]*)`/g)) {
      if (name[1] !== undefined) documented.add(name[1]);
    }
  }
  return documented;
}

describe(".env.example matches what the source reads", () => {
  const read = variablesReadBySource();
  const declared = declaredInEnvExample();
  const documented = documentedInReadme();

  it("finds the variables that are known to be read", () => {
    // Guards the scanner itself: if this list stops matching reality the rest
    // of the file is asserting nothing.
    for (const expected of [
      "GITHUB_TOKEN", // via readOptional in config.ts
      "SENTINEL_WEB_PORT", // via readPort
      "SENTINEL_ALLOW_REMOTE_WRITES", // via readBool
      "MODEL_ID", // via process.env in provision.ts
      "PORT",
      "NO_COLOR",
    ]) {
      expect(read.has(expected), `${expected} should be detected`).toBe(true);
    }
  });

  it("excludes only variables named as fixtures, not ones that merely look odd", () => {
    // The exclusion has to be explicit: the raw scan does find this name, in
    // the sample exploit code, so an implicit rule would silently widen.
    const raw = new Set<string>();
    for (const file of scannedFiles()) {
      const source = readFileSync(resolve(ROOT, file), "utf8");
      for (const pattern of ENV_READ_PATTERNS) {
        for (const match of source.matchAll(pattern)) {
          if (match[1] !== undefined) raw.add(match[1]);
          if (match[2] !== undefined) raw.add(match[2]);
        }
      }
    }
    expect(raw.has("AWS_SECRET_ACCESS_KEY"), "the raw scan does find it").toBe(true);
    expect(read.has("AWS_SECRET_ACCESS_KEY")).toBe(false);
    expect(NOT_CONFIGURATION.size).toBe(1);
  });

  it("declares every variable the source reads", () => {
    const missing = [...read.keys()].filter((name) => !declared.has(name)).sort();
    expect(missing.map((name) => `${name} (${read.get(name)?.join(", ")})`)).toEqual([]);
  });

  it("has no entries for variables nothing reads", () => {
    const stale = [...declared].filter((name) => !read.has(name)).sort();
    expect(stale).toEqual([]);
  });

  it("documents every variable in the README table too", () => {
    const undocumented = [...read.keys()].filter((name) => !documented.has(name)).sort();
    expect(undocumented).toEqual([]);
  });

  it("gives each entry a one-line description", () => {
    const lines = readFileSync(join(ROOT, ".env.example"), "utf8").split("\n");
    lines.forEach((line, index) => {
      if (!/^\s*#?\s*[A-Z][A-Z0-9_]*\s*=/.test(line)) return;
      const above = lines.slice(Math.max(0, index - 3), index).join("\n");
      expect(above, `no comment above ${line.trim()}`).toMatch(/^\s*#.*\S/m);
    });
  });
});
