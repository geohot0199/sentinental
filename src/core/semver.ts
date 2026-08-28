/**
 * A deliberately small semver implementation.
 *
 * We only need two things: compare two versions, and decide whether a version
 * falls inside an advisory's `vulnerable_version_range` (the GitHub/OSV shape,
 * e.g. `>= 4.0.0, < 4.18.0`). Pulling in a general semver library would drag in
 * range grammar we never use, and this is the code path that decides whether we
 * tell a human "you are vulnerable" - it is worth being able to read all of it.
 *
 * Prerelease handling follows semver 2.0.0 precedence rules.
 */

export interface ParsedVersion {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  /** Dot-separated prerelease identifiers; empty when this is a release. */
  readonly prerelease: readonly string[];
}

const VERSION_RE = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Strip range operators and npm decoration from a raw dependency string. */
export function cleanVersion(raw: string): string {
  return raw.trim().replace(/^[\^~=v><\s]+/, "").trim();
}

export function parseVersion(raw: string): ParsedVersion | null {
  const match = VERSION_RE.exec(cleanVersion(raw));
  if (match === null) return null;
  const [, major, minor, patch, prerelease] = match;
  return {
    major: Number(major),
    minor: minor === undefined ? 0 : Number(minor),
    patch: patch === undefined ? 0 : Number(patch),
    prerelease: prerelease === undefined ? [] : prerelease.split("."),
  };
}

function comparePrerelease(a: readonly string[], b: readonly string[]): number {
  // A release outranks any prerelease of the same version.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;

  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1; // shorter set of identifiers is lower
    if (y === undefined) return 1;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) {
      const diff = Number(x) - Number(y);
      if (diff !== 0) return diff < 0 ? -1 : 1;
    } else if (xNum !== yNum) {
      return xNum ? -1 : 1; // numeric identifiers sort below alphanumeric
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/** Returns -1, 0 or 1. Throws on unparseable input rather than guessing. */
export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (left === null) throw new Error(`Unparseable version: "${a}"`);
  if (right === null) throw new Error(`Unparseable version: "${b}"`);
  if (left.major !== right.major) return left.major < right.major ? -1 : 1;
  if (left.minor !== right.minor) return left.minor < right.minor ? -1 : 1;
  if (left.patch !== right.patch) return left.patch < right.patch ? -1 : 1;
  return comparePrerelease(left.prerelease, right.prerelease);
}

const COMPARATOR_RE = /^(>=|<=|>|<|=)?\s*(.+)$/;

/** Evaluate one comparator such as `>= 4.0.0` against a version. */
function satisfiesComparator(version: string, comparator: string): boolean {
  const match = COMPARATOR_RE.exec(comparator.trim());
  if (match === null) return false;
  const operator = match[1] ?? "=";
  const operand = match[2];
  if (operand === undefined) return false;
  if (parseVersion(operand) === null) return false;

  const cmp = compareVersions(version, operand);
  switch (operator) {
    case ">=":
      return cmp >= 0;
    case "<=":
      return cmp <= 0;
    case ">":
      return cmp > 0;
    case "<":
      return cmp < 0;
    default:
      return cmp === 0;
  }
}

/**
 * Evaluate an advisory range like `>= 4.0.0, < 4.18.0`.
 *
 * Comma-separated comparators are ANDed, matching GitHub and OSV semantics.
 * Returns false for anything we cannot parse: refusing to claim a match is the
 * safe direction for a false *positive*, and the caller surfaces the ambiguity.
 */
export function versionInRange(version: string, range: string): boolean {
  const cleaned = cleanVersion(version);
  if (parseVersion(cleaned) === null) return false;
  const parts = range
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  if (parts.length === 0) return false;
  return parts.every((part) => satisfiesComparator(cleaned, part));
}

/** Classify a bump so the agent can explain upgrade risk without guessing. */
export type BumpKind = "none" | "patch" | "minor" | "major" | "unknown";

export function classifyBump(from: string, to: string): BumpKind {
  const a = parseVersion(from);
  const b = parseVersion(to);
  if (a === null || b === null) return "unknown";
  if (a.major !== b.major) return "major";
  if (a.minor !== b.minor) return "minor";
  if (a.patch !== b.patch) return "patch";
  return "none";
}
