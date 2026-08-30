/**
 * Integration coverage for the web console's session routes, driven through
 * Hono's `app.request()` so the real router and the real validation run.
 *
 * The point of these tests is the failure paths. A route that returns 200 for
 * a session it does not know, accepts an approval nobody asked for, or lets a
 * harness error escape as an unhandled 500 is the difference between an
 * operator seeing "not ready" and an operator staring at a stack trace mid
 * incident.
 *
 * The runner is mocked; the HTTP contract around it is not.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SentinelConfig } from "../src/core/config.ts";
import { SentinelError } from "../src/core/errors.ts";
import type { ProvisionResult } from "../src/harness/provision.ts";
import type { PendingApproval, SentinelEvent } from "../src/harness/runner.ts";

interface RunnerMock {
  startSession(): Promise<string>;
  send(message: string, sink: (event: SentinelEvent) => void): Promise<void>;
  respondToApprovals(
    decisions: readonly unknown[],
    sink: (event: SentinelEvent) => void,
  ): Promise<void>;
  cancel(): Promise<void>;
  resumeSession(sessionId: string): Promise<void>;
  history(sessionId: string): Promise<SentinelEvent[]>;
  pendingApprovals: PendingApproval[];
  calls: string[];
}

const mock = vi.hoisted<RunnerMock>(() => ({
  // The default issues a fresh id on every call. `buildWebApp` stores sessions
  // in a module-level map that every app instance shares, so a repeated id
  // would let one test's session leak into the next test's "unknown id" checks.
  startSession: vi.fn(),
  send: vi.fn(async () => {}),
  respondToApprovals: vi.fn(async () => {}),
  cancel: vi.fn(async () => {}),
  resumeSession: vi.fn(async () => {}),
  history: vi.fn(async () => [] as SentinelEvent[]),
  pendingApprovals: [],
  calls: [],
}));

vi.mock("../src/harness/runner.ts", () => ({
  SentinelRunner: class {
    readonly pendingApprovals: PendingApproval[] = mock.pendingApprovals;
    constructor(config: unknown) {
      mock.calls.push((config as SentinelConfig).harnessUrl);
    }
    startSession = mock.startSession;
    send = mock.send;
    respondToApprovals = mock.respondToApprovals;
    cancel = mock.cancel;
    resumeSession = mock.resumeSession;
    history = mock.history;
  },
}));

const { buildWebApp } = await import("../src/web/server.ts");

const config: SentinelConfig = {
  harnessUrl: "http://127.0.0.1:8790",
  mcpPort: 8791,
  mcpUrl: "http://127.0.0.1:8791/mcp",
  mcpToken: "sn_aaaabbbbccccddddeeeeffffaaaabbbb",
  webPort: 3000,
  provider: null,
  githubToken: null,
  daytonaApiKey: null,
  targetRepo: null,
  allowRemoteWrites: false,
};

const provisioned: ProvisionResult = {
  modelFqn: "openai/gpt-4.1",
  sandboxEnabled: true,
  mcpServer: "sentinel-supply-chain",
  agentName: "sentinel",
  steps: [],
  warnings: [],
};

/** A provisioned app, which is the state every session route assumes. */
function app(provisionError: string | null = null) {
  return buildWebApp(config, provisioned, provisionError);
}

async function post(
  target: ReturnType<typeof app>,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await target.request(path, {
    method: "POST",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

/** Creates a real session through the route, so the id is genuinely known. */
async function createSession(): Promise<string> {
  const { status, body } = await post(app(), "/api/session");
  expect(status).toBe(200);
  return body.sessionId as string;
}

/** Monotonic across the file, never reset, so ids never collide. */
let issued = 0;

beforeEach(() => {
  // No vitest config in this repo, so mocks are not cleared automatically.
  vi.clearAllMocks();
  mock.calls.length = 0;
  mock.pendingApprovals.length = 0;
  vi.mocked(mock.startSession).mockImplementation(async () => `session-${(issued += 1)}`);
  // Unknown to the harness by default; the rebuild test overrides this.
  vi.mocked(mock.resumeSession).mockRejectedValue(
    new SentinelError("not_found", "No such session."),
  );
  vi.mocked(mock.history).mockResolvedValue([]);
});

describe("POST /api/session", () => {
  it("returns the session id the harness issued", async () => {
    const { status, body } = await post(app(), "/api/session");

    expect(status).toBe(200);
    expect(Object.keys(body)).toEqual(["sessionId"]);
    expect(body.sessionId).toMatch(/^session-\d+$/);
    // The runner is constructed from the real config, not a partial copy.
    expect(mock.calls[0]).toBe(config.harnessUrl);
  });

  it("refuses with 503 and the remedy when provisioning failed", async () => {
    const failure = "Start it with: npx @truefoundry/trueforge@latest";
    const { status, body } = await post(app(failure), "/api/session");

    expect(status).toBe(503);
    expect(body).toEqual({ error: failure });
    expect(mock.startSession).not.toHaveBeenCalled();
  });

  it("turns a harness failure into a 502 with a remedy, not a 500", async () => {
    vi.mocked(mock.startSession).mockRejectedValue(
      new SentinelError(
        "not_configured",
        "Cannot reach the TrueForge harness.",
        "Start the harness and retry.",
      ),
    );

    const { status, body } = await post(app(), "/api/session");

    expect(status).toBe(502);
    expect(body.error).toBe("Cannot reach the TrueForge harness.");
    expect(body.remedy).toBe("Start the harness and retry.");
  });
});

describe("session routes reject an unknown id", () => {
  it("404s on history, message, approval and cancel alike", async () => {
    const target = app();

    expect((await target.request("/api/session/nope/history")).status).toBe(404);
    expect((await post(target, "/api/session/nope/message", { message: "hi" })).status).toBe(404);
    expect((await post(target, "/api/session/nope/approval", { decisions: [{}] })).status).toBe(404);
    expect((await post(target, "/api/session/nope/cancel")).status).toBe(404);
  });

  it("404s the stream too, as JSON rather than an empty event stream", async () => {
    const response = await app().request("/api/session/nope/stream");
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "Unknown session." });
  });

  it("rebuilds history from the harness when the session is not in memory", async () => {
    vi.mocked(mock.resumeSession).mockResolvedValue(undefined);
    vi.mocked(mock.history).mockResolvedValue([
      { kind: "assistant", text: "recovered transcript", threadId: "main" },
    ]);

    const response = await app().request("/api/session/older-session/history");
    const body = (await response.json()) as { events: SentinelEvent[] };

    expect(response.status).toBe(200);
    expect(body.events).toEqual([
      { kind: "assistant", text: "recovered transcript", threadId: "main" },
    ]);
    expect(mock.resumeSession).toHaveBeenCalledWith("older-session");
  });
});

describe("POST /api/session/:id/message", () => {
  it("400s on a blank message", async () => {
    const id = await createSession();
    for (const message of ["", "   "]) {
      const { status, body } = await post(app(), `/api/session/${id}/message`, { message });
      expect(status, JSON.stringify(message)).toBe(400);
      expect(body.error).toBe("A message is required.");
    }
  });

  it("400s when the body carries no message at all", async () => {
    const id = await createSession();
    const { status } = await post(app(), `/api/session/${id}/message`, { text: "wrong key" });
    expect(status).toBe(400);
  });

  it("413s a message over the 20k limit instead of forwarding it", async () => {
    const id = await createSession();
    const { status, body } = await post(app(), `/api/session/${id}/message`, {
      message: "x".repeat(20_001),
    });

    expect(status).toBe(413);
    expect(body.error).toBe("Message is too long.");
    expect(mock.send).not.toHaveBeenCalled();
  });

  it("accepts a valid message and hands it to the runner", async () => {
    const id = await createSession();
    const { status, body } = await post(app(), `/api/session/${id}/message`, {
      message: "scan acme/widget",
    });

    expect(status).toBe(200);
    expect(body).toEqual({ accepted: true });
    await vi.waitFor(() => expect(mock.send).toHaveBeenCalledWith("scan acme/widget", expect.any(Function)));
  });
});

describe("POST /api/session/:id/approval", () => {
  it("400s when no decisions are supplied", async () => {
    const id = await createSession();
    const { status, body } = await post(app(), `/api/session/${id}/approval`, { decisions: [] });

    expect(status).toBe(400);
    expect(body.error).toBe("No decisions supplied.");
  });

  it("409s a decision for a tool call nobody asked to approve", async () => {
    const id = await createSession();
    const { status, body } = await post(app(), `/api/session/${id}/approval`, {
      decisions: [{ toolCallId: "call_never_requested", approved: true }],
    });

    expect(status).toBe(409);
    expect(body.error).toBe("None of those approvals are pending.");
    expect(mock.respondToApprovals).not.toHaveBeenCalled();
  });

  it("resolves a pending approval, defaulting a denial to a stated reason", async () => {
    mock.pendingApprovals.push({
      toolCallId: "call_1",
      threadId: "main",
      toolName: "open_pull_request",
      args: {},
      requestedAt: new Date(0).toISOString(),
    });
    const id = await createSession();

    const { status, body } = await post(app(), `/api/session/${id}/approval`, {
      decisions: [{ toolCallId: "call_1", approved: false }],
    });

    expect(status).toBe(200);
    expect(body).toEqual({ accepted: 1 });
    await vi.waitFor(() =>
      expect(mock.respondToApprovals).toHaveBeenCalledWith(
        [
          {
            toolCallId: "call_1",
            threadId: "main",
            approved: false,
            reason: "Denied by the operator in the web console.",
          },
        ],
        expect.any(Function),
      ),
    );
  });
});

describe("POST /api/session/:id/cancel", () => {
  it("cancels the runner and says so", async () => {
    const id = await createSession();
    const { status, body } = await post(app(), `/api/session/${id}/cancel`);

    expect(status).toBe(200);
    expect(body).toEqual({ cancelled: true });
    expect(mock.cancel).toHaveBeenCalledTimes(1);
  });
});

describe("GET /api/session/:id/history", () => {
  it("redacts a secret before it reaches the browser", async () => {
    vi.mocked(mock.resumeSession).mockResolvedValue(undefined);
    vi.mocked(mock.history).mockResolvedValue([
      {
        kind: "assistant",
        text: "using token sn_aaaabbbbccccddddeeeeffffaaaabbbb to call GitHub",
        threadId: "main",
      },
    ]);

    const response = await app().request("/api/session/leaky-session/history");
    const body = (await response.json()) as { events: SentinelEvent[] };

    expect(response.status).toBe(200);
    expect(JSON.stringify(body)).not.toContain("sn_aaaabbbbccccddddeeeeffffaaaabbbb");
  });
});
