/**
 * SENTINEL application API.
 *
 * A real backend for the website: it runs live triage against the GitHub
 * Advisory Database, persists every scan to SQLite, streams progress over SSE
 * and serves the static front end.
 *
 * Boundaries kept deliberately tight:
 *  - The browser never holds a token. Every credentialed call happens here.
 *  - Every response is redacted before it leaves the process.
 *  - Write endpoints are rate limited and bounded in size.
 */
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { readFileSync, existsSync } from "node:fs";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describeCapabilities, loadConfig, type SentinelConfig } from "../core/config.ts";
import { toSentinelError } from "../core/errors.ts";
import { parseRepo } from "../core/github.ts";
import { redactDeep, registerSecrets } from "../core/redact.ts";
import { isEntrypoint, listenOrExit } from "../core/serve.ts";
import { SentinelDb } from "./db.ts";
import { Scanner } from "./scanner.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = resolve(HERE, "..", "..", "site");

/** Largest accepted JSON body. Bounds the memory one request can pin. */
const MAX_BODY_BYTES = 1024 * 1024;

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

/**
 * Decode the path portion of a request URL, or null when it is malformed.
 *
 * `decodeURIComponent` throws on a malformed escape (`/%E0%A4%A`); an unhandled
 * throw here would be a 500 at best and, in the dependency-free `site/serve.mjs`
 * server, an uncaught exception that kills the process. Malformed input is a
 * client error, so it degrades to null and the caller answers 404.
 */
export function decodeUrlPath(urlPath: string): string | null {
  const bare = urlPath.split("?")[0]?.split("#")[0] ?? "";
  try {
    return decodeURIComponent(bare);
  } catch {
    return null;
  }
}

/** Resolve a URL path inside the site directory, or null if it escapes. */
function safeSitePath(urlPath: string): string | null {
  const decoded = decodeUrlPath(urlPath);
  if (decoded === null) return null;
  const relative = normalize(decoded).replace(/^([/\\])+/, "");
  const full = resolve(SITE_ROOT, relative);
  if (full !== SITE_ROOT && !full.startsWith(SITE_ROOT + sep)) return null;
  return full;
}

/**
 * Fixed-window rate limiter, per client, for the endpoints that cost money or
 * upstream quota. In-memory is the right scope: this is a single process.
 */
class RateLimiter {
  readonly #hits = new Map<string, { count: number; resetAt: number }>();
  readonly #limit: number;
  readonly #windowMs: number;

  constructor(limit: number, windowMs: number) {
    this.#limit = limit;
    this.#windowMs = windowMs;
  }

  check(key: string): { ok: boolean; retryAfter: number } {
    const now = Date.now();
    const entry = this.#hits.get(key);
    if (entry === undefined || now > entry.resetAt) {
      this.#hits.set(key, { count: 1, resetAt: now + this.#windowMs });
      // Opportunistic sweep so the map cannot grow without bound.
      if (this.#hits.size > 5000) {
        for (const [k, v] of this.#hits) if (now > v.resetAt) this.#hits.delete(k);
      }
      return { ok: true, retryAfter: 0 };
    }
    if (entry.count >= this.#limit) {
      return { ok: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    }
    entry.count += 1;
    return { ok: true, retryAfter: 0 };
  }
}

const MAX_MANIFEST_BYTES = 512 * 1024;

function clientKey(c: { req: { header: (name: string) => string | undefined } }): string {
  // Behind the preview proxy the socket address is useless, so prefer the
  // forwarded chain and fall back to a constant (limits become global).
  // The *last* entry of `x-forwarded-for` is the hop our own proxy appended;
  // the first is client-supplied and trivially rotated to sidestep the limit.
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded !== undefined && forwarded.length > 0) {
    const hops = forwarded.split(",").map((h) => h.trim()).filter((h) => h.length > 0);
    const nearest = hops.at(-1);
    if (nearest !== undefined) return nearest;
  }
  return c.req.header("x-real-ip") ?? "local";
}

export interface AppDeps {
  readonly config: SentinelConfig;
  readonly db: SentinelDb;
  readonly scanner: Scanner;
}

// eslint-disable-next-line max-lines-per-function -- flat route table; splitting it moves it out of review
export function buildApp(deps: AppDeps): Hono {
  const { config, db, scanner } = deps;
  const app = new Hono();

  // Cap every request body before any handler runs. The 512 KB manifest check
  // below is about policy; this is about memory - `c.req.json()` reads the
  // whole body before the handler gets a say.
  app.use("/api/*", bodyLimit({ maxSize: MAX_BODY_BYTES, onError: (c) =>
    c.json({ error: `Request body exceeds the ${Math.floor(MAX_BODY_BYTES / 1024)} KB limit.` }, 413),
  }));

  const scanLimiter = new RateLimiter(10, 60_000);

  // ------------------------------------------------------------- health
  app.get("/api/health", (c) => c.json({ ok: true, uptime: Math.round(process.uptime()) }));

  // ------------------------------------------------------------- status
  app.get("/api/status", (c) => {
    const capabilities = describeCapabilities(config);
    // Booleans and names only. Never a key, never a URL with credentials.
    return c.json({
      github: capabilities.github,
      sandbox: capabilities.sandbox,
      model: capabilities.model,
      remoteWrites: config.allowRemoteWrites,
      targetRepo: config.targetRepo,
      notes: capabilities.notes,
      advisorySource: "GitHub Advisory Database (OSV fallback)",
      stats: db.stats(),
    });
  });

  // -------------------------------------------------------- create scan
  app.post("/api/scans", async (c) => {
    const limit = scanLimiter.check(clientKey(c));
    if (!limit.ok) {
      return c.json(
        { error: `Too many scans. Try again in ${limit.retryAfter}s.` },
        429,
        { "retry-after": String(limit.retryAfter) },
      );
    }

    const body = (await c.req.json().catch(() => ({}))) as {
      repo?: unknown;
      manifest?: unknown;
    };

    const hasRepo = typeof body.repo === "string" && body.repo.trim().length > 0;
    const hasManifest = typeof body.manifest === "string" && body.manifest.trim().length > 0;
    if (!hasRepo && !hasManifest) {
      return c.json({ error: "Provide either `repo` (owner/name) or `manifest` (package.json)." }, 400);
    }

    let source: "repo" | "manifest";
    let target: string;
    let manifest: string | null = null;

    if (hasRepo) {
      if (!config.githubToken) {
        return c.json(
          {
            error: "Scanning a repository needs a GitHub token.",
            remedy: "Set GITHUB_TOKEN in .env, or paste a package.json instead.",
          },
          503,
        );
      }
      try {
        const ref = parseRepo(String(body.repo));
        target = `${ref.owner}/${ref.repo}`;
        source = "repo";
      } catch (cause) {
        return c.json({ error: toSentinelError(cause).message }, 400);
      }
    } else {
      const raw = String(body.manifest);
      if (Buffer.byteLength(raw, "utf8") > MAX_MANIFEST_BYTES) {
        return c.json({ error: "That package.json is too large (512 KB limit)." }, 413);
      }
      // Fail fast on malformed JSON rather than inside the background job.
      try {
        const parsed: unknown = JSON.parse(raw);
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          return c.json({ error: "package.json must be a JSON object." }, 400);
        }
        const name = (parsed as { name?: unknown }).name;
        target = typeof name === "string" && name.length > 0 ? name : "pasted manifest";
      } catch {
        return c.json({ error: "That is not valid JSON." }, 400);
      }
      manifest = raw;
      source = "manifest";
    }

    const id = globalThis.crypto.randomUUID();
    db.createScan(id, source, target, manifest);

    // Return immediately; the browser follows /events for progress. `run()`
    // never rejects (it owns its failure reporting), and this catch is the
    // belt to those braces: an unexpected throw must not become an unhandled
    // rejection that kills the process.
    void scanner.run(id).catch(() => undefined);

    return c.json({ id, source, target, status: "queued" }, 202);
  });

  // --------------------------------------------------------- list scans
  app.get("/api/scans", (c) => {
    const limit = Number(c.req.query("limit") ?? "30");
    return c.json({ scans: db.listScans(Number.isFinite(limit) ? limit : 30) });
  });

  // ---------------------------------------------------------- one scan
  app.get("/api/scans/:id", (c) => {
    const id = c.req.param("id");
    const scan = db.getScan(id);
    if (scan === null) return c.json({ error: "No such scan." }, 404);
    return c.json(
      redactDeep({
        scan,
        findings: db.listFindings(id),
        plan: db.getScanPlan(id),
        patch: db.getScanPatch(id),
        events: db.listEvents(id),
      }),
    );
  });

  app.delete("/api/scans/:id", (c) => {
    const id = c.req.param("id");
    const scan = db.getScan(id);
    if (scan === null) return c.json({ error: "No such scan." }, 404);
    // Refuse to delete a scan that is queued or running: the pipeline writes
    // progress as it goes, and yanking the row out from under it turns the
    // delete into a race. Cancel-then-delete is a deliberate two-step.
    if (scan.status === "queued" || scan.status === "running") {
      return c.json({ error: "That scan is still in progress. Wait for it to finish first." }, 409);
    }
    const removed = db.deleteScan(id);
    return removed ? c.json({ deleted: true }) : c.json({ error: "No such scan." }, 404);
  });

  // -------------------------------------------------------------- patch
  /** The patched package.json as a download. */
  app.get("/api/scans/:id/patch", (c) => {
    const id = c.req.param("id");
    const patch = db.getScanPatch(id) as { content?: unknown } | null;
    const content = patch === null ? null : patch.content;
    if (typeof content !== "string") {
      return c.json({ error: "This scan produced no patch." }, 404);
    }
    return c.body(content, 200, {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="package.json"`,
    });
  });

  // ------------------------------------------------------------ stream
  app.get("/api/scans/:id/events", (c) => {
    const id = c.req.param("id");
    if (db.getScan(id) === null) return c.json({ error: "No such scan." }, 404);

    const encoder = new TextEncoder();
    let unsubscribe: (() => void) | null = null;
    let heartbeat: NodeJS.Timeout | null = null;
    let closed = false;

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const push = (event: string, data: unknown): void => {
          try {
            controller.enqueue(
              encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
            );
          } catch {
            // Client vanished mid-write; the abort handler cleans up.
          }
        };
        /** Push the terminal frame, then release the connection. */
        const finish = (status: "done" | "failed"): void => {
          push("end", { status });
          if (heartbeat !== null) clearInterval(heartbeat);
          unsubscribe?.();
          closed = true;
          try {
            controller.close();
          } catch {
            // Already closed by the abort handler.
          }
        };

        // Replay first so a late subscriber sees the whole run, then follow.
        let lastSeq = 0;
        for (const event of db.listEvents(id)) {
          push("progress", event);
          lastSeq = event.seq;
        }

        const current = db.getScan(id);
        if (current !== null && (current.status === "done" || current.status === "failed")) {
          // Nothing will ever arrive on the subscription: end the stream now
          // instead of holding the socket open with heartbeats forever.
          finish(current.status);
          return;
        }

        unsubscribe = scanner.subscribe(id, (event) => {
          if (closed || event.seq <= lastSeq) return; // Already replayed or finished.
          lastSeq = event.seq;
          push("progress", event);
          if (event.stage === "done" || event.stage === "error") {
            finish(event.stage === "done" ? "done" : "failed");
          }
        });

        // Proxies love to kill an idle SSE connection.
        heartbeat = setInterval(() => {
          if (!closed) push("ping", { t: Date.now() });
        }, 15_000);

        c.req.raw.signal.addEventListener("abort", () => {
          if (heartbeat !== null) clearInterval(heartbeat);
          unsubscribe?.();
          try {
            controller.close();
          } catch {
            // Already closed.
          }
        });
      },
      cancel() {
        if (heartbeat !== null) clearInterval(heartbeat);
        unsubscribe?.();
      },
    });

    return new Response(stream, {
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
        "x-accel-buffering": "no",
      },
    });
  });

  // ------------------------------------------------------------ lookup
  /** Ad-hoc single-package advisory lookup, used by the docs playground. */
  app.get("/api/advisories", async (c) => {
    const name = (c.req.query("package") ?? "").trim();
    const version = (c.req.query("version") ?? "").trim();
    if (name.length === 0 || version.length === 0) {
      return c.json({ error: "Both `package` and `version` are required." }, 400);
    }
    const limit = scanLimiter.check(`adv:${clientKey(c)}`);
    if (!limit.ok) return c.json({ error: "Too many lookups." }, 429);

    try {
      const { lookupAdvisories } = await import("../core/advisories.ts");
      const result = await lookupAdvisories(name, version, "npm", config.githubToken);
      return c.json(redactDeep(result));
    } catch (cause) {
      return c.json({ error: toSentinelError(cause).message }, 502);
    }
  });

  // ------------------------------------------------------- static site
  app.get("*", (c) => {
    const requested = new URL(c.req.url).pathname;
    const path = requested === "/" ? "/index.html" : requested;
    let full = safeSitePath(path);
    // null covers both traversal attempts and malformed escapes; answering
    // "not found" to both leaks nothing and never 500s.
    if (full === null) return c.text("Not found", 404);

    // Allow extensionless routes (/labs -> labs.html).
    if (!existsSync(full) && extname(full) === "") {
      const withHtml = `${full}.html`;
      if (existsSync(withHtml)) full = withHtml;
    }
    if (!existsSync(full)) return c.text("Not found", 404);

    try {
      const body = readFileSync(full);
      const type = MIME[extname(full).toLowerCase()] ?? "application/octet-stream";
      return c.body(body, 200, {
        "content-type": type,
        // HTML must revalidate so a deploy is picked up; assets may cache.
        "cache-control": type.startsWith("text/html") ? "no-cache" : "public, max-age=300",
      });
    } catch {
      return c.text("Not found", 404);
    }
  });

  return app;
}

async function main(): Promise<void> {
  const config = loadConfig();
  registerSecrets([
    config.githubToken,
    config.daytonaApiKey,
    config.mcpToken,
    config.provider?.apiKey,
  ]);

  const dbFile = process.env.SENTINEL_DB ?? join(process.cwd(), ".sentinel", "sentinel.db");
  const db = new SentinelDb(dbFile);
  const scanner = new Scanner(db, config);
  const app = buildApp({ config, db, scanner });

  const port = Number(process.env.PORT ?? config.webPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    process.stderr.write(`PORT must be an integer between 1 and 65535, got "${process.env.PORT}"\n`);
    process.exit(1);
  }
  // 0.0.0.0 so a hosted preview can reach it; a busy port exits with one
  // clear line instead of a stack trace.
  await listenOrExit(app, { port, label: "SENTINEL app" });

  const capabilities = describeCapabilities(config);
  process.stdout.write(`SENTINEL app on http://0.0.0.0:${port}\n`);
  process.stdout.write(`  database   ${dbFile}\n`);
  process.stdout.write(`  github     ${capabilities.github ? "token present" : "no token (paste a manifest to scan)"}\n`);
  for (const note of capabilities.notes) process.stdout.write(`  ! ${note}\n`);

  const shutdown = (): void => {
    try {
      db.close();
    } finally {
      process.exit(0);
    }
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

if (isEntrypoint(import.meta.url)) {
  main().catch((cause: unknown) => {
    process.stderr.write(`fatal: ${toSentinelError(cause).message}\n`);
    process.exit(1);
  });
}
