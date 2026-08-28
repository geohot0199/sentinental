/**
 * Typed failures.
 *
 * Tool handlers must never throw a raw exception at the model: a stack trace is
 * both a poor prompt and a plausible way to leak a path or a token. Every
 * failure becomes one of these, with a message written to be read by an LLM.
 */

export type SentinelErrorCode =
  | "not_configured"
  | "invalid_input"
  | "upstream_failure"
  | "not_found"
  | "forbidden"
  | "rate_limited"
  | "timeout"
  | "internal";

export class SentinelError extends Error {
  readonly code: SentinelErrorCode;
  /** Concrete next action for the operator, when one exists. */
  readonly remedy: string | null;

  constructor(code: SentinelErrorCode, message: string, remedy: string | null = null) {
    super(message);
    this.name = "SentinelError";
    this.code = code;
    this.remedy = remedy;
  }

  /** Rendered into the tool result the model actually reads. */
  toModelText(): string {
    return this.remedy === null
      ? `[${this.code}] ${this.message}`
      : `[${this.code}] ${this.message}\nHow to fix: ${this.remedy}`;
  }
}

export function notConfigured(what: string, envVar: string): SentinelError {
  return new SentinelError(
    "not_configured",
    `${what} is not configured, so this tool cannot run.`,
    `Set ${envVar} in your .env and restart SENTINEL.`,
  );
}

/** Normalise anything caught in a catch block into a SentinelError. */
export function toSentinelError(cause: unknown): SentinelError {
  if (cause instanceof SentinelError) return cause;
  if (cause instanceof Error) {
    if (cause.name === "AbortError" || /timed? ?out/i.test(cause.message)) {
      return new SentinelError("timeout", `Operation timed out: ${cause.message}`);
    }
    return new SentinelError("internal", cause.message);
  }
  return new SentinelError("internal", String(cause));
}
