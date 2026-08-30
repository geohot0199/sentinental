/**
 * SENTINEL web server.
 *
 * Drives the same `SentinelRunner` as the terminal client. Streams agent
 * activity to the browser over SSE and accepts approval decisions back.
 *
 * Deliberate choices:
 *  - The browser never talks to the harness or to any provider directly, so no
 *    key is ever in front-end reach. Everything is proxied through here.
 *  - Every frame is redacted before it leaves the process.
 *  - Sessions are per-connection objects in memory; the durable state lives in
 *    the harness, so a browser refresh replays from there rather than from us.
 */
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  describeCapabilities,
  loadConfig,
  type SentinelConfig,
} from "../core/config.ts";
import { toSentinelError } from "../core/errors.ts";
import { redactDeep, registerSecrets } from "../core/redact.ts";
import { isEntrypoint, listenOrExit } from "../core/serve.ts";
import { provision, type ProvisionResult } from "../harness/provision.ts";
import { SentinelRunner, type SentinelEvent } from "../harness/runner.ts";
import { startMcpServer } from "../mcp/server.ts";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Largest accepted JSON body (session messages are capped well below this). */
const MAX_BODY_BYTES = 1024 * 1024;
/** Live conversations kept in memory before the oldest is evicted. */
const MAX_CONVERSATIONS = 100;

/**
 * One live conversation. Holds the runner plus a fan-out list of SSE listeners
 * so a second browser tab can watch the same session.
 */
class Conversation {
  readonly runner: SentinelRunner;
  readonly #listeners = new Set<(event: SentinelEvent) => void>();
  /** Replay buffer so a reconnecting tab sees what it missed. */
  readonly #log: SentinelEvent[] = [];
  /**
   * Serialised work queue. Two turns on one session is a protocol error, but
   * rejecting a second submission outright loses it: an approval decision can
   * legitimately arrive while the paused turn's event stream is still closing.
   * Enqueueing keeps the ordering guarantee without dropping work.
   */
  #chain: Promise<void> = Promise.resolve();
  #queued = 0;
  /** Touched on every enqueue; drives eviction of idle conversations. */
  lastActivityAt = Date.now();

  constructor(config: SentinelConfig) {
    this.runner = new SentinelRunner(config);
  }

  get busy(): boolean {
    return this.#queued > 0;
  }

  get log(): readonly SentinelEvent[] {
    return this.#log;
  }

  subscribe(listener: (event: SentinelEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  emit(event: SentinelEvent): void {
    const safe = redactDeep(event);
    this.#log.push(safe);
    // Bound the buffer; the harness keeps the authoritative history.
    if (this.#log.length > 1000) this.#log.shift();
    for (const listener of this.#listeners) {
      try {
        listener(safe);
      } catch {
        // A dead listener must not break the others or the turn.
      }
    }
  }

  /**
   * Queue `work` to run after everything already queued on this session.
   * Resolves when this unit finishes; rejects only if this unit itself threw -
   * an earlier failure does not poison the queue.
   */
  enqueue(work: () => Promise<void>): Promise<void> {
    this.lastActivityAt = Date.now();
    this.#queued += 1;
    const run = this.#chain.then(work, work);
    // Keep the chain alive regardless of this unit's outcome.
    this.#chain = run.catch(() => undefined);
    void run.then(
      () => {
        this.#queued -= 1;
      },
      () => {
        this.#queued -= 1;
      },
    );
    return run;
  }
}

const conversations = new Map<string, Conversation>();

/**
 * Drop the oldest idle conversations when the map outgrows its cap.
 *
 * Every `POST /api/session` pins a runner and a replay buffer forever; without
 * this, a long-running console leaks memory one demo at a time. Eviction is
 * harmless: the harness holds the durable history, so an evicted session is
 * rebuilt on demand by the history route.
 */
function rememberConversation(id: string, conversation: Conversation): void {
  conversations.set(id, conversation);
  if (conversations.size <= MAX_CONVERSATIONS) return;

  const idle = [...conversations.entries()]
    .filter(([, c]) => !c.busy)
    .sort((a, b) => a[1].lastActivityAt - b[1].lastActivityAt);
  let excess = conversations.size - MAX_CONVERSATIONS;
  for (const [key] of idle) {
    if (excess <= 0) break;
    conversations.delete(key);
    excess -= 1;
  }
}

function sseFrame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/** Fixed-window limiter for creating sessions (each one hits the harness). */
class SessionLimiter {
  readonly #hits = new Map<string, { count: number; resetAt: number }>();

  check(key: string, limit: number, windowMs: number): { ok: boolean; retryAfter: number } {
    const now = Date.now();
    const entry = this.#hits.get(key);
    if (entry === undefined || now > entry.resetAt) {
      this.#hits.set(key, { count: 1, resetAt: now + windowMs });
      return { ok: true, retryAfter: 0 };
    }
    if (entry.count >= limit) {
      return { ok: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    }
    entry.count += 1;
    return { ok: true, retryAfter: 0 };
  }
}

const sessionLimiter = new SessionLimiter();

/** Best-effort client identity for rate limiting (see the API app's notes). */
function clientKey(c: { req: { header: (name: string) => string | undefined } }): string {
  // The *last* XFF hop is the one our own proxy appended; the first is
  // client-supplied and trivially rotated.
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded !== undefined && forwarded.length > 0) {
    const hops = forwarded.split(",").map((h) => h.trim()).filter((h) => h.length > 0);
    const nearest = hops.at(-1);
    if (nearest !== undefined) return nearest;
  }
  return c.req.header("x-real-ip") ?? "local";
}

// eslint-disable-next-line max-lines-per-function -- flat route table; splitting it moves it out of review
export function buildWebApp(
  config: SentinelConfig,
  provisioning: ProvisionResult | null,
  provisionError: string | null,
): Hono {
  const app = new Hono();

  // Bound request memory before any handler reads a body.
  app.use(
    "/api/*",
    bodyLimit({
      maxSize: MAX_BODY_BYTES,
      onError: (c) =>
        c.json(
          { error: `Request body exceeds the ${Math.floor(MAX_BODY_BYTES / 1024)} KB limit.` },
          413,
        ),
    }),
  );

  // ------------------------------------------------------------- status
  app.get("/api/status", (c) => {
    const capabilities = describeCapabilities(config);
    return c.json({
      ready: provisionError === null,
      error: provisionError,
      // Booleans and names only - never a key, never a URL with credentials.
      model: provisioning?.modelFqn ?? null,
      sandbox: provisioning?.sandboxEnabled ?? false,
      github: capabilities.github,
      remoteWrites: config.allowRemoteWrites,
      targetRepo: config.targetRepo,
      warnings: provisioning?.warnings ?? capabilities.notes,
    });
  });

  // ------------------------------------------------------------ session
  app.post("/api/session", async (c) => {
    if (provisionError !== null) {
      return c.json({ error: provisionError }, 503);
    }
    // Each session is a harness-side object; creating them in a loop burns
    // upstream quota, so create is rate limited per client.
    const limit = sessionLimiter.check(clientKey(c), 10, 60_000);
    if (!limit.ok) {
      return c.json(
        { error: `Too many sessions. Try again in ${limit.retryAfter}s.` },
        429,
        { "retry-after": String(limit.retryAfter) },
      );
    }
    try {
      const conversation = new Conversation(config);
      const sessionId = await conversation.runner.startSession();
      rememberConversation(sessionId, conversation);
      return c.json({ sessionId });
    } catch (cause) {
      const error = toSentinelError(cause);
      return c.json({ error: error.message, remedy: error.remedy }, 502);
    }
  });

  /** Replay a session's transcript, so a refresh does not lose the run. */
  app.get("/api/session/:id/history", async (c) => {
    const id = c.req.param("id");
    const conversation = conversations.get(id);
    if (conversation === undefined) {
      // Not in memory: rebuild from the harness, which is the real source. A
      // session the harness does not know either is a 404, not an empty
      // transcript - the browser has to be able to tell the two apart.
      try {
        const rebuilt = new Conversation(config);
        await rebuilt.runner.resumeSession(id);
        const events = await rebuilt.runner.history(id);
        rememberConversation(id, rebuilt);
        return c.json({ events: events.map((e) => redactDeep(e)) });
      } catch (cause) {
        return c.json({ error: toSentinelError(cause).message }, 404);
      }
    }
    return c.json({ events: conversation.log });
  });

  // ------------------------------------------------------------- stream
  app.get("/api/session/:id/stream", (c) => {
    const id = c.req.param("id");
    const conversation = conversations.get(id);
    if (conversation === undefined) return c.json({ error: "Unknown session." }, 404);

    const encoder = new TextEncoder();
    let unsubscribe: (() => void) | null = null;
    let heartbeat: NodeJS.Timeout | null = null;

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const push = (event: string, data: unknown): void => {
          try {
            controller.enqueue(encoder.encode(sseFrame(event, data)));
          } catch {
            // Client vanished mid-write; cleanup runs via the abort handler.
          }
        };

        push("ready", { sessionId: id, busy: conversation.busy });
        unsubscribe = conversation.subscribe((event) => push("agent", event));

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

  // ------------------------------------------------------------ message
  app.post("/api/session/:id/message", async (c) => {
    const id = c.req.param("id");
    const conversation = conversations.get(id);
    if (conversation === undefined) return c.json({ error: "Unknown session." }, 404);

    const body = (await c.req.json().catch(() => ({}))) as { message?: unknown };
    const message = typeof body.message === "string" ? body.message.trim() : "";
    if (message.length === 0) return c.json({ error: "A message is required." }, 400);
    if (message.length > 20_000) return c.json({ error: "Message is too long." }, 413);
    if (conversation.busy) {
      // A second message mid-turn is a genuine caller bug: say so immediately
      // rather than accepting and failing later on the SSE stream.
      return c.json({ error: "This session is already running a turn." }, 409);
    }

    // Kick the turn off in the background and return immediately; the browser
    // is already watching the SSE stream, so blocking here buys nothing.
    void conversation
      .enqueue(async () => {
        conversation.emit({ kind: "assistant", text: `> ${message}`, threadId: "user" });
        await conversation.runner.send(message, (event) => conversation.emit(event));
      })
      .catch((cause: unknown) => {
        conversation.emit({ kind: "error", message: toSentinelError(cause).message });
      });

    return c.json({ accepted: true });
  });

  // ----------------------------------------------------------- approval
  app.post("/api/session/:id/approval", async (c) => {
    const id = c.req.param("id");
    const conversation = conversations.get(id);
    if (conversation === undefined) return c.json({ error: "Unknown session." }, 404);

    const body = (await c.req.json().catch(() => ({}))) as {
      decisions?: { toolCallId?: unknown; threadId?: unknown; approved?: unknown; reason?: unknown }[];
    };
    const raw = Array.isArray(body.decisions) ? body.decisions : [];
    if (raw.length === 0) return c.json({ error: "No decisions supplied." }, 400);

    // Only resolve approvals the harness actually asked for. Without this, a
    // crafted request could approve a tool call the UI never displayed.
    const pending = new Map(conversation.runner.pendingApprovals.map((p) => [p.toolCallId, p]));
    const decisions = raw
      .filter((d) => typeof d.toolCallId === "string" && pending.has(d.toolCallId))
      .map((d) => {
        const match = pending.get(d.toolCallId as string);
        return {
          toolCallId: d.toolCallId as string,
          threadId: match?.threadId ?? (typeof d.threadId === "string" ? d.threadId : "main"),
          approved: d.approved === true,
          reason:
            typeof d.reason === "string" && d.reason.length > 0
              ? d.reason.slice(0, 500)
              : "Denied by the operator in the web console.",
        };
      });

    if (decisions.length === 0) {
      return c.json({ error: "None of those approvals are pending." }, 409);
    }

    // Enqueued, not rejected: this POST can legitimately race the turn stream
    // closing after the approval-required event. The queue applies it next.
    void conversation
      .enqueue(async () => {
        await conversation.runner.respondToApprovals(decisions, (event) =>
          conversation.emit(event),
        );
      })
      .catch((cause: unknown) => {
        conversation.emit({ kind: "error", message: toSentinelError(cause).message });
      });

    return c.json({ accepted: decisions.length });
  });

  // ------------------------------------------------------------- cancel
  app.post("/api/session/:id/cancel", async (c) => {
    const conversation = conversations.get(c.req.param("id"));
    if (conversation === undefined) return c.json({ error: "Unknown session." }, 404);
    await conversation.runner.cancel();
    return c.json({ cancelled: true });
  });

  // --------------------------------------------------------------- html
  const indexPath = join(HERE, "public", "index.html");
  app.get("/", (c) => c.html(readFileSync(indexPath, "utf8")));
  app.get("/app.js", (c) =>
    c.body(readFileSync(join(HERE, "public", "app.js"), "utf8"), 200, {
      "content-type": "text/javascript; charset=utf-8",
    }),
  );
  app.get("/styles.css", (c) =>
    c.body(readFileSync(join(HERE, "public", "styles.css"), "utf8"), 200, {
      "content-type": "text/css; charset=utf-8",
    }),
  );
  app.get("/webmcp-bundle.js", (c) =>
    c.body(readFileSync(join(HERE, "public", "webmcp-bundle.js"), "utf8"), 200, {
      "content-type": "text/javascript; charset=utf-8",
    }),
  );

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

  await startMcpServer(config);
  process.stdout.write(`SENTINEL tool server on http://127.0.0.1:${config.mcpPort}/mcp\n`);

  let provisioning: ProvisionResult | null = null;
  let provisionError: string | null = null;
  try {
    provisioning = await provision(config);
    for (const step of provisioning.steps) process.stdout.write(`  · ${step}\n`);
    for (const warning of provisioning.warnings) process.stdout.write(`  ! ${warning}\n`);
  } catch (cause) {
    const error = toSentinelError(cause);
    provisionError = error.remedy === null ? error.message : `${error.message} ${error.remedy}`;
    process.stdout.write(`  ! ${provisionError}\n`);
  }

  const app = buildWebApp(config, provisioning, provisionError);
  // 0.0.0.0 so the hosted preview can reach it; a busy port exits with one
  // clear line instead of a stack trace.
  await listenOrExit(app, { port: config.webPort, label: "SENTINEL console" });
  process.stdout.write(`SENTINEL console on http://0.0.0.0:${config.webPort}\n`);
}

if (isEntrypoint(import.meta.url)) {
  main().catch((cause: unknown) => {
    process.stderr.write(`fatal: ${toSentinelError(cause).message}\n`);
    process.exit(1);
  });
}
