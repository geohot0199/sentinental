/**
 * Hardened fetch wrapper used for every outbound call.
 *
 * Adds: timeouts (an agent must never hang a turn forever), bounded response
 * size (a hostile or broken endpoint must not exhaust memory), retry with
 * backoff on transient status codes, and typed errors.
 */
import { SentinelError, toSentinelError } from "./errors.ts";

export interface HttpOptions {
  readonly method?: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
  readonly timeoutMs?: number;
  readonly retries?: number;
  /** Hard cap on the response body. Default 8 MiB. */
  readonly maxBytes?: number;
}

const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_RETRIES = 2;
const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readCapped(response: Response, maxBytes: number): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > maxBytes) {
    throw new SentinelError(
      "upstream_failure",
      `Response too large: ${declared} bytes exceeds the ${maxBytes} byte cap.`,
    );
  }
  const body = response.body;
  if (body === null) return "";

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new SentinelError(
          "upstream_failure",
          `Response exceeded the ${maxBytes} byte cap while streaming.`,
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
    // Discard anything still buffered so the socket is not held open.
    await body.cancel().catch(() => undefined);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

export interface HttpResult {
  readonly status: number;
  readonly ok: boolean;
  readonly text: string;
  readonly headers: Headers;
}

export async function httpRequest(url: string, options: HttpOptions = {}): Promise<HttpResult> {
  const {
    method = "GET",
    headers = {},
    body,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    retries = DEFAULT_RETRIES,
    maxBytes = DEFAULT_MAX_BYTES,
  } = options;

  let lastError: SentinelError | null = null;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        method,
        headers,
        body,
        signal: controller.signal,
        redirect: "follow",
      });
      const text = await readCapped(response, maxBytes);

      if (!response.ok && RETRYABLE_STATUS.has(response.status) && attempt < retries) {
        // Honour Retry-After when the server sends one; it usually knows better.
        const retryAfter = Number(response.headers.get("retry-after") ?? "0");
        const backoff = retryAfter > 0 ? retryAfter * 1000 : 2 ** attempt * 500;
        lastError = new SentinelError(
          response.status === 429 ? "rate_limited" : "upstream_failure",
          `HTTP ${response.status} from ${safeUrl(url)}`,
        );
        await sleep(Math.min(backoff, 10_000));
        continue;
      }

      return { status: response.status, ok: response.ok, text, headers: response.headers };
    } catch (cause) {
      lastError = toSentinelError(cause);
      if (attempt < retries) {
        await sleep(2 ** attempt * 500);
        continue;
      }
    } finally {
      clearTimeout(timer);
    }
  }

  throw (
    lastError ?? new SentinelError("upstream_failure", `Request to ${safeUrl(url)} failed.`)
  );
}

/** Strip query strings from URLs before they reach a log or a model. */
export function safeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "<invalid url>";
  }
}

export async function httpJson<T>(url: string, options: HttpOptions = {}): Promise<T> {
  const result = await httpRequest(url, {
    ...options,
    headers: { accept: "application/json", ...options.headers },
  });
  if (!result.ok) {
    throw new SentinelError(
      result.status === 404
        ? "not_found"
        : result.status === 403 || result.status === 401
          ? "forbidden"
          : "upstream_failure",
      `HTTP ${result.status} from ${safeUrl(url)}: ${result.text.slice(0, 300)}`,
    );
  }
  try {
    return JSON.parse(result.text) as T;
  } catch {
    throw new SentinelError("upstream_failure", `Non-JSON response from ${safeUrl(url)}.`);
  }
}
