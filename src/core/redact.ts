/**
 * Secret redaction.
 *
 * Two independent layers, because either one alone fails in a predictable way:
 *
 *  1. Exact-value redaction - anything registered from config. Catches the keys
 *     we know about, including short ones a pattern would miss.
 *  2. Pattern redaction - known credential shapes. Catches keys we never loaded,
 *     e.g. one the *model* echoed back out of a file it read in the sandbox.
 *
 * Everything the CLI prints and every SSE frame the web UI emits goes through
 * `redact`, so a live demo recording cannot leak a token.
 */

/** Values registered at boot from config. Module-level so every layer shares it. */
const knownSecrets = new Set<string>();

/** Secrets shorter than this are too likely to appear in ordinary prose. */
const MIN_SECRET_LENGTH = 8;

export function registerSecret(value: string | null | undefined): void {
  if (typeof value !== "string") return;
  const trimmed = value.trim();
  if (trimmed.length < MIN_SECRET_LENGTH) return;
  knownSecrets.add(trimmed);
}

export function registerSecrets(values: readonly (string | null | undefined)[]): void {
  for (const value of values) registerSecret(value);
}

/** Test seam. Not used in normal operation. */
export function __clearSecretsForTest(): void {
  knownSecrets.clear();
}

/**
 * Credential shapes worth catching generically. Ordered longest-prefix-first so
 * a more specific rule wins before a general one rewrites its prefix.
 */
const PATTERNS: readonly { readonly name: string; readonly re: RegExp }[] = [
  { name: "github-pat", re: /\bgh[pousr]_[A-Za-z0-9]{16,255}\b/g },
  { name: "github-fine-grained", re: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g },
  { name: "openai", re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: "anthropic", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  // {35,} rather than exactly {35}: a longer key must still be caught, and a
  // fixed length silently fails open on anything non-standard.
  { name: "google", re: /\bAIza[0-9A-Za-z_-]{35,}\b/g },
  { name: "slack", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "aws-access-key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "daytona", re: /\bdtn_[A-Za-z0-9]{16,}\b/g },
  { name: "sentinel-mcp", re: /\bsn_[a-f0-9]{32}\b/g },
  { name: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  // Bare JWTs, which is what an OIDC access token looks like.
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
];

const MASK = "[REDACTED]";

/** Redact a single string. Safe to call on any user- or model-supplied text. */
export function redact(input: string): string {
  if (input.length === 0) return input;
  let output = input;

  // Layer 1: exact known values, longest first so a key containing another
  // key's prefix is not partially rewritten.
  const sorted = [...knownSecrets].sort((a, b) => b.length - a.length);
  for (const secret of sorted) {
    if (output.includes(secret)) {
      output = output.replaceAll(secret, MASK);
    }
  }

  // Layer 2: shape-based.
  for (const { re } of PATTERNS) {
    // Regexes are module-level with /g, so reset lastIndex before each use.
    re.lastIndex = 0;
    output = output.replace(re, MASK);
  }
  return output;
}

/** Keys whose values are always masked regardless of shape. */
const SENSITIVE_KEY = /^(?:.*_)?(?:api[_-]?key|apikey|token|secret|password|passwd|authorization|auth|credential|private[_-]?key)s?$/i;

/**
 * Recursively redact a JSON-shaped value. Used on every event payload before it
 * reaches a terminal or a browser.
 */
export function redactDeep<T>(value: T, depth = 0): T {
  if (depth > 32) return value; // cycle / bomb guard
  if (typeof value === "string") return redact(value) as unknown as T;
  if (value === null || typeof value !== "object") return value;

  if (Array.isArray(value)) {
    const items: unknown[] = value;
    return items.map((item) => redactDeep(item, depth + 1)) as unknown as T;
  }

  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEY.test(key) && typeof val === "string" && val.length > 0) {
      out[key] = MASK;
    } else {
      out[key] = redactDeep(val, depth + 1);
    }
  }
  return out as unknown as T;
}

/** Show enough of a key to identify it, never enough to use it. */
export function fingerprint(secret: string): string {
  if (secret.length <= 8) return MASK;
  return `${secret.slice(0, 4)}…${secret.slice(-2)} (${secret.length} chars)`;
}
