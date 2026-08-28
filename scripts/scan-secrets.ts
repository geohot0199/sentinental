/**
 * Repository secret scanner.
 *
 * Fails the build if anything that looks like a live credential is committed.
 * Runs in CI and is worth running before any demo recording.
 *
 * Usage: node --experimental-strip-types scripts/scan-secrets.ts [--staged]
 */
import { execSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";

interface Rule {
  readonly name: string;
  readonly re: RegExp;
  /** Substrings that mark a match as an obvious placeholder. */
  readonly allowIfContains?: readonly string[];
}

const RULES: readonly Rule[] = [
  { name: "GitHub personal access token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: "GitHub fine-grained token", re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g },
  { name: "OpenAI API key", re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35,}\b/g },
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
  { name: "AWS access key id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "Daytona API key", re: /\bdtn_[A-Za-z0-9]{20,}\b/g },
  { name: "Private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
  {
    name: "Hardcoded assignment of a secret-looking value",
    re: /\b(?:api[_-]?key|apikey|secret|password|token)\s*[:=]\s*["'][A-Za-z0-9_\-/+]{24,}["']/gi,
    allowIfContains: [
      "example",
      "placeholder",
      "your-",
      "xxx",
      "changeme",
      "redacted",
      "fake",
      "dummy",
      "test",
      "sample",
      "<",
    ],
  },
];

/** Never scanned: build output, dependencies, and the ignored env file itself. */
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".venv",
  "__pycache__",
]);

const SKIP_FILES = new Set([".env", ".env.local", "package-lock.json"]);

/** Files that legitimately contain credential *patterns* as test fixtures. */
const PATTERN_FIXTURE_FILES = new Set([
  "tests/redact.test.ts",
  "scripts/scan-secrets.ts",
  "src/core/redact.ts",
]);

const BINARY_EXT =
  /\.(png|jpe?g|gif|webp|ico|svg|pdf|zip|gz|tgz|woff2?|ttf|eot|mp4|mov|mp3|wasm)$/i;

const MAX_FILE_BYTES = 2 * 1024 * 1024;

function listFiles(staged: boolean): string[] {
  const command = staged
    ? "git diff --cached --name-only --diff-filter=ACM"
    : "git ls-files";
  const output = execSync(command, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

interface Finding {
  readonly file: string;
  readonly line: number;
  readonly rule: string;
  readonly excerpt: string;
}

/**
 * @param absolutePath where to read from
 * @param relativePath repo-relative path, used for every allow/skip decision so
 *        the rules behave the same regardless of where the scan is run from
 */
function scanFile(absolutePath: string, relativePath: string): Finding[] {
  const findings: Finding[] = [];
  const normalised = relativePath.replaceAll("\\", "/");

  if (PATTERN_FIXTURE_FILES.has(normalised)) return findings;

  const parts = normalised.split("/");
  if (parts.some((part) => SKIP_DIRS.has(part))) return findings;
  if (SKIP_FILES.has(parts[parts.length - 1] ?? "")) return findings;
  if (BINARY_EXT.test(normalised)) return findings;

  let contents: string;
  try {
    if (statSync(absolutePath).size > MAX_FILE_BYTES) return findings;
    contents = readFileSync(absolutePath, "utf8");
  } catch {
    return findings;
  }

  const lines = contents.split("\n");
  for (const [index, text] of lines.entries()) {
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      const matches = text.match(rule.re);
      if (matches === null) continue;

      const lower = text.toLowerCase();
      const allowed = (rule.allowIfContains ?? []).some((hint) => lower.includes(hint));
      if (allowed) continue;

      findings.push({
        file: normalised,
        line: index + 1,
        rule: rule.name,
        // Show only the shape, never the full value.
        excerpt: `${(matches[0] ?? "").slice(0, 8)}…`,
      });
    }
  }
  return findings;
}

function main(): void {
  const staged = process.argv.includes("--staged");
  const root = process.cwd();
  const files = listFiles(staged);
  const findings: Finding[] = [];

  for (const file of files) {
    findings.push(...scanFile(resolve(root, file), file));
  }

  // Independent check: a committed .env is a finding on its own.
  if (files.some((f) => f === ".env")) {
    findings.push({
      file: ".env",
      line: 0,
      rule: ".env is tracked by git and must not be",
      excerpt: "",
    });
  }

  if (findings.length === 0) {
    process.stdout.write(`✓ Scanned ${files.length} tracked file(s). No secrets found.\n`);
    return;
  }

  process.stderr.write(`\n✖ ${findings.length} potential secret(s) found:\n\n`);
  for (const finding of findings) {
    process.stderr.write(`  ${finding.file}:${finding.line}  ${finding.rule}  ${finding.excerpt}\n`);
  }
  process.stderr.write("\nRemove the value, rotate it, and use an environment variable.\n");
  process.exit(1);
}

main();
