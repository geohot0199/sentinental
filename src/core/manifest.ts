/**
 * Dependency manifest parsing.
 *
 * We resolve installed versions from a lockfile where one exists, because
 * `package.json` records a *range* (`^4.17.11`) and an advisory applies to a
 * concrete version. Falling back to the range's lower bound is explicitly
 * flagged as an estimate, so the agent never reports a guess as a fact.
 */
import { SentinelError } from "./errors.ts";
import { cleanVersion, parseVersion } from "./semver.ts";

export interface Dependency {
  readonly name: string;
  /** Concrete version if resolved from a lockfile, else the declared range. */
  readonly version: string;
  readonly declaredRange: string;
  readonly scope: "production" | "development" | "optional" | "peer";
  /** False when the version came from a range rather than a lockfile. */
  readonly resolved: boolean;
}

export interface ManifestScan {
  readonly ecosystem: "npm";
  readonly projectName: string | null;
  readonly dependencies: readonly Dependency[];
  readonly lockfile: string | null;
  readonly warnings: readonly string[];
}

/** Reject path traversal and absurd package names before they reach a URL. */
const PACKAGE_NAME_RE = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

export function isValidPackageName(name: string): boolean {
  return name.length > 0 && name.length <= 214 && PACKAGE_NAME_RE.test(name);
}

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface LockfileV2 {
  lockfileVersion?: number;
  packages?: Record<string, { version?: string }>;
  dependencies?: Record<string, { version?: string }>;
}

/**
 * Build name -> version from an npm lockfile. Handles v1 (`dependencies`) and
 * v2/v3 (`packages`, keyed by install path).
 */
export function parseLockfile(raw: string): Map<string, string> {
  const resolved = new Map<string, string>();
  let lock: LockfileV2;
  try {
    lock = JSON.parse(raw) as LockfileV2;
  } catch {
    throw new SentinelError("invalid_input", "Lockfile is not valid JSON.");
  }

  if (lock.packages !== undefined) {
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (path.length === 0) continue; // the root project itself
      const marker = "node_modules/";
      const index = path.lastIndexOf(marker);
      if (index === -1) continue;
      const name = path.slice(index + marker.length);
      const version = entry.version;
      // Keep the shallowest copy: it is the one the app actually loads.
      if (typeof version === "string" && !resolved.has(name)) {
        resolved.set(name, version);
      }
    }
  }

  if (lock.dependencies !== undefined) {
    for (const [name, entry] of Object.entries(lock.dependencies)) {
      if (typeof entry.version === "string" && !resolved.has(name)) {
        resolved.set(name, entry.version);
      }
    }
  }

  return resolved;
}

function collect(
  target: Dependency[],
  warnings: string[],
  record: Record<string, string> | undefined,
  scope: Dependency["scope"],
  resolvedVersions: Map<string, string>,
): void {
  for (const [name, range] of Object.entries(record ?? {})) {
    if (!isValidPackageName(name)) {
      warnings.push(`Skipped dependency with an invalid package name: ${JSON.stringify(name)}`);
      continue;
    }
    // Non-registry specifiers have no advisory story; say so rather than guess.
    if (/^(?:file:|link:|git\+|github:|https?:|workspace:)/.test(range)) {
      warnings.push(`${name}: non-registry specifier "${range}" cannot be checked for advisories.`);
      continue;
    }

    const locked = resolvedVersions.get(name);
    if (locked !== undefined) {
      target.push({ name, version: locked, declaredRange: range, scope, resolved: true });
      continue;
    }

    const estimate = cleanVersion(range);
    if (parseVersion(estimate) === null) {
      warnings.push(`${name}: cannot determine a version from "${range}"; skipped.`);
      continue;
    }
    target.push({ name, version: estimate, declaredRange: range, scope, resolved: false });
  }
}

/**
 * Parse a package.json plus optional lockfile into a flat dependency list.
 * Pure - no I/O - so it is trivially testable and cannot touch the filesystem.
 */
export function scanManifest(
  packageJsonRaw: string,
  lockfileRaw: string | null = null,
  lockfileName: string | null = null,
): ManifestScan {
  let pkg: PackageJson;
  try {
    pkg = JSON.parse(packageJsonRaw) as PackageJson;
  } catch {
    throw new SentinelError("invalid_input", "package.json is not valid JSON.");
  }
  if (typeof pkg !== "object" || pkg === null) {
    throw new SentinelError("invalid_input", "package.json must be a JSON object.");
  }

  const warnings: string[] = [];
  let resolvedVersions = new Map<string, string>();
  if (lockfileRaw !== null) {
    try {
      resolvedVersions = parseLockfile(lockfileRaw);
    } catch (cause) {
      warnings.push(
        `Lockfile could not be parsed (${cause instanceof Error ? cause.message : "unknown"}); falling back to declared ranges.`,
      );
    }
  } else {
    warnings.push(
      "No lockfile provided. Versions are estimated from declared ranges and may not match what is installed.",
    );
  }

  const dependencies: Dependency[] = [];
  collect(dependencies, warnings, pkg.dependencies, "production", resolvedVersions);
  collect(dependencies, warnings, pkg.devDependencies, "development", resolvedVersions);
  collect(dependencies, warnings, pkg.optionalDependencies, "optional", resolvedVersions);
  collect(dependencies, warnings, pkg.peerDependencies, "peer", resolvedVersions);

  return {
    ecosystem: "npm",
    projectName: typeof pkg.name === "string" ? pkg.name : null,
    dependencies,
    lockfile: lockfileName,
    warnings,
  };
}
