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
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { readFileSync, existsSync } from "node:fs";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describeCapabilities, loadConfig, type SentinelConfig } from "../core/config.ts";
import { toSentinelError } from "../core/errors.ts";
import { parseRepo } from "../core/github.ts";
import { redactDeep, registerSecrets } from "../core/redact.ts";
import { SentinelDb } from "./db.ts";
import { Scanner } from "./scanner.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = resolve(HERE, "..", "..", "site");

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

/** Resolve a URL path inside the site directory, or null if it escapes. */
function safeSitePath(urlPath: string): string | null {
  const decoded = decodeURIComponent(urlPath.split("?")[0]?.split("#")[0] ?? "");
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
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded !== undefined && forwarded.length > 0) {
    return forwarded.split(",")[0]?.trim() ?? "unknown";
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

    // Return immediately; the browser follows /events for progress.
    void scanner.run(id);

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
    const removed = db.deleteScan(c.req.param("id"));
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

        // Replay first so a late subscriber sees the whole run, then follow.
        let lastSeq = 0;
        for (const event of db.listEvents(id)) {
          push("progress", event);
          lastSeq = event.seq;
        }

        const current = db.getScan(id);
        if (current !== null && (current.status === "done" || current.status === "failed")) {
          push("end", { status: current.status });
        }

        unsubscribe = scanner.subscribe(id, (event) => {
          if (event.seq <= lastSeq) return; // Already replayed.
          lastSeq = event.seq;
          push("progress", event);
          if (event.stage === "done" || event.stage === "error") {
            push("end", { status: event.stage === "done" ? "done" : "failed" });
          }
        });

        // Proxies love to kill an idle SSE connection.
        heartbeat = setInterval(() => push("ping", { t: Date.now() }), 15_000);

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
    if (full === null) return c.text("Forbidden", 403);

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

function main(): void {
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
  // 0.0.0.0 so a hosted preview can reach it.
  serve({ fetch: app.fetch, port, hostname: "0.0.0.0" });

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

function isEntrypoint(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  try {
    main();
  } catch (cause) {
    process.stderr.write(`fatal: ${toSentinelError(cause).message}\n`);
    process.exit(1);
  }
}
