/**
 * Session-turn serialisation on the web console.
 *
 * The old implementation rejected any second submission while a turn was in
 * flight ("This session is already running a turn."). That was correct for a
 * duplicate message and wrong for approvals: the approval-required event
 * arrives *before* the turn's event stream closes, so a browser that POSTs its
 * decision quickly raced the stream and the decision was lost. These tests pin
 * the queue: messages are refused while busy, approvals are queued and applied
 * in order, and nothing leaks between sessions.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SentinelConfig } from "../src/core/config.ts";
import type { ProvisionResult } from "../src/harness/provision.ts";
import type { PendingApproval, SentinelEvent } from "../src/harness/runner.ts";

interface RunnerMock {
  startSession: () => Promise<string>;
  send: (message: string, sink: (event: SentinelEvent) => void) => Promise<void>;
  respondToApprovals: (
    decisions: readonly unknown[],
    sink: (event: SentinelEvent) => void,
  ) => Promise<void>;
  cancel: () => Promise<void>;
  resumeSession: (sessionId: string) => Promise<void>;
  history: (sessionId: string) => Promise<SentinelEvent[]>;
  pendingApprovals: PendingApproval[];
}

const mock = vi.hoisted<RunnerMock>(() => ({
  startSession: vi.fn(),
  send: vi.fn(async () => {}),
  respondToApprovals: vi.fn(async () => {}),
  cancel: vi.fn(async () => {}),
  resumeSession: vi.fn(async () => {}),
  history: vi.fn(async () => [] as SentinelEvent[]),
  pendingApprovals: [],
}));

vi.mock("../src/harness/runner.ts", () => ({
  SentinelRunner: class {
    readonly pendingApprovals: PendingApproval[] = mock.pendingApprovals;
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

let issued = 0;

beforeEach(() => {
  vi.clearAllMocks();
  setPending([]);
  vi.mocked(mock.startSession).mockImplementation(async () => `session-${(issued += 1)}`);
});

async function post(
  app: ReturnType<typeof buildWebApp>,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await app.request(path, {
    method: "POST",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

/** A deferred the test resolves manually, standing in for a live turn. */
function deferred(): { promise: Promise<void>; resolve: () => void; reject: (e: unknown) => void } {
  let resolve!: () => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** One approval the harness is currently waiting on. */
function pendingApproval(id: string): PendingApproval {
  return {
    toolCallId: id,
    threadId: "main",
    toolName: "open_pull_request",
    args: { title: "demo" },
    requestedAt: new Date().toISOString(),
  };
}

/**
 * Replace the pending-approval list *in place*: the mocked runner instances
 * hold the array by reference, so reassigning the field would not be visible
 * to sessions created earlier.
 */
function setPending(approvals: PendingApproval[]): void {
  mock.pendingApprovals.splice(0, mock.pendingApprovals.length, ...approvals);
}

describe("session turn serialisation", () => {
  it("refuses a second message with 409 while a turn is running", async () => {
    const app = buildWebApp(config, provisioned, null);
    const { body } = await post(app, "/api/session");
    const id = body.sessionId as string;

    const gate = deferred();
    vi.mocked(mock.send).mockImplementation(() => gate.promise);

    const first = await post(app, `/api/session/${id}/message`, { message: "scan the repo" });
    expect(first.status).toBe(200);

    const second = await post(app, `/api/session/${id}/message`, { message: "and again" });
    expect(second.status).toBe(409);

    gate.resolve();
    await vi.waitFor(() => expect(mock.send).toHaveBeenCalledTimes(1));
  });

  it("queues an approval decision that races the closing turn stream", async () => {
    const app = buildWebApp(config, provisioned, null);
    const { body } = await post(app, "/api/session");
    const id = body.sessionId as string;

    const gate = deferred();
    vi.mocked(mock.send).mockImplementation(() => gate.promise);
    await post(app, `/api/session/${id}/message`, { message: "open the PR" });
    // While the turn is still streaming (gate unresolved), the harness asks
    // for approval and the browser answers immediately.
    setPending([pendingApproval("call-1")]);

    const decision = await post(app, `/api/session/${id}/approval`, {
      decisions: [{ toolCallId: "call-1", approved: false }],
    });
    // Before the queue this hit the busy rejection path and the decision was
    // dropped on the floor.
    expect(decision.status).toBe(200);
    expect(decision.body.accepted).toBe(1);

    gate.resolve();
    await vi.waitFor(() => expect(mock.respondToApprovals).toHaveBeenCalledTimes(1));
    const applied = vi.mocked(mock.respondToApprovals).mock.calls[0]?.[0] as readonly {
      toolCallId: string;
      approved: boolean;
    }[];
    expect(applied[0]?.toolCallId).toBe("call-1");
    expect(applied[0]?.approved).toBe(false);
  });

  it("runs queued work in order and clears busy when the queue drains", async () => {
    const app = buildWebApp(config, provisioned, null);
    const { body } = await post(app, "/api/session");
    const id = body.sessionId as string;

    const order: string[] = [];
    const gate = deferred();
    vi.mocked(mock.send).mockImplementation(async (message) => {
      order.push(message);
      if (message === "first") await gate.promise;
    });

    await post(app, `/api/session/${id}/message`, { message: "first" });
    setPending([pendingApproval("call-1"), pendingApproval("call-2")]);
    await post(app, `/api/session/${id}/approval`, {
      decisions: [{ toolCallId: "call-1", approved: true }],
    });
    gate.resolve();

    // Both units drain before the session is idle again.
    await vi.waitFor(() => {
      expect(order).toEqual(["first"]);
      expect(mock.respondToApprovals).toHaveBeenCalledTimes(1);
    });

    // And the session accepts new work afterwards.
    const next = await post(app, `/api/session/${id}/message`, { message: "second" });
    expect(next.status).toBe(200);
    await vi.waitFor(() => expect(order).toEqual(["first", "second"]));
  });

  it("a queued unit that throws does not poison later work", async () => {
    const app = buildWebApp(config, provisioned, null);
    const { body } = await post(app, "/api/session");
    const id = body.sessionId as string;

    vi.mocked(mock.send).mockRejectedValueOnce(new Error("harness hiccup"));
    await post(app, `/api/session/${id}/message`, { message: "explode" });
    await vi.waitFor(() => expect(mock.send).toHaveBeenCalledTimes(1));

    const followup = await post(app, `/api/session/${id}/message`, { message: "retry" });
    expect(followup.status).toBe(200);
    await vi.waitFor(() => expect(mock.send).toHaveBeenCalledTimes(2));
  });

  it("unknown approvals are still refused, queued or not", async () => {
    const app = buildWebApp(config, provisioned, null);
    const { body } = await post(app, "/api/session");
    const id = body.sessionId as string;

    const gate = deferred();
    vi.mocked(mock.send).mockImplementation(() => gate.promise);
    await post(app, `/api/session/${id}/message`, { message: "go" });

    // Nothing pending at all -> the fabricated decision must not pass.
    setPending([]);
    const fabricated = await post(app, `/api/session/${id}/approval`, {
      decisions: [{ toolCallId: "never-asked", approved: true }],
    });
    expect(fabricated.status).toBe(409);

    gate.resolve();
    await vi.waitFor(() => expect(mock.send).toHaveBeenCalledTimes(1));
  });
});
