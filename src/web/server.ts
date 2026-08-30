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
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  describeCapabilities,
  loadConfig,
  type SentinelConfig,
} from "../core/config.ts";
import { toSentinelError } from "../core/errors.ts";
import { redactDeep, registerSecrets } from "../core/redact.ts";
import { provision, type ProvisionResult } from "../harness/provision.ts";
import { SentinelRunner, type SentinelEvent } from "../harness/runner.ts";
import { startMcpServer } from "../mcp/server.ts";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * One live conversation. Holds the runner plus a fan-out list of SSE listeners
 * so a second browser tab can watch the same session.
 */
class Conversation {
  readonly runner: SentinelRunner;
  readonly #listeners = new Set<(event: SentinelEvent) => void>();
  /** Replay buffer so a reconnecting tab sees what it missed. */
  readonly #log: SentinelEvent[] = [];
  #busy = false;

  constructor(config: SentinelConfig) {
    this.runner = new SentinelRunner(config);
  }

  get busy(): boolean {
    return this.#busy;
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

  /** Serialise turns: two concurrent turns on one session is a protocol error. */
  async run(work: () => Promise<void>): Promise<void> {
    if (this.#busy) {
      throw new Error("This session is already running a turn.");
    }
    this.#busy = true;
    try {
      await work();
    } finally {
      this.#busy = false;
    }
  }
}

const conversations = new Map<string, Conversation>();

function sseFrame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

// eslint-disable-next-line max-lines-per-function -- flat route table; splitting it moves it out of review
export function buildWebApp(
  config: SentinelConfig,
  provisioning: ProvisionResult | null,
  provisionError: string | null,
): Hono {
  const app = new Hono();

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
    try {
      const conversation = new Conversation(config);
      const sessionId = await conversation.runner.startSession();
      conversations.set(sessionId, conversation);
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
        conversations.set(id, rebuilt);
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

    // Kick the turn off in the background and return immediately; the browser
    // is already watching the SSE stream, so blocking here buys nothing.
    void conversation
      .run(async () => {
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

    void conversation
      .run(async () => {
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

  startMcpServer(config);
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
  // 0.0.0.0 so the hosted preview can reach it.
  serve({ fetch: app.fetch, port: config.webPort, hostname: "0.0.0.0" });
  process.stdout.write(`SENTINEL console on http://0.0.0.0:${config.webPort}\n`);
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
  main().catch((cause: unknown) => {
    process.stderr.write(`fatal: ${toSentinelError(cause).message}\n`);
    process.exit(1);
  });
}
