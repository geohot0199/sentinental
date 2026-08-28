/**
 * Runner event-translation tests.
 *
 * These lock in the fix for a real bug found during end-to-end testing against
 * TrueForge 0.1.4: tool calls arrive incrementally on `model.message.delta`
 * (id and name first, argument fragments after), while the streamed
 * `model.message` is empty. A client that reads tool calls off `model.message`
 * alone - which is what the SDK types imply - shows "unknown_tool" on the
 * approval prompt and hides the arguments a human is supposed to be judging.
 *
 * That is a safety bug, not a cosmetic one, so it is tested directly.
 */
import { describe, expect, it } from "vitest";
import type { SentinelConfig } from "../src/core/config.ts";
import { SentinelRunner, type SentinelEvent } from "../src/harness/runner.ts";

const config: SentinelConfig = {
  harnessUrl: "http://127.0.0.1:8790",
  mcpPort: 8791,
  mcpUrl: "http://127.0.0.1:8791/mcp",
  mcpToken: "test-token-value",
  webPort: 3000,
  provider: null,
  githubToken: null,
  daytonaApiKey: null,
  targetRepo: null,
  allowRemoteWrites: true,
};

/** Uses the runner's documented `@internal` test seam. */
function translate(runner: SentinelRunner, event: unknown): SentinelEvent[] {
  return runner._translateForTest(event);
}

describe("streamed tool-call accumulation", () => {
  const MESSAGE_ID = "msg_01";

  function deltaWithNameAndId() {
    return {
      type: "model.message.delta",
      id: MESSAGE_ID,
      threadId: "main",
      toolCalls: [
        {
          index: 0,
          id: "call_1",
          type: "function",
          function: { name: "open_pull_request", arguments: "" },
        },
      ],
    };
  }

  function deltaWithArgs(fragment: string) {
    return {
      type: "model.message.delta",
      id: MESSAGE_ID,
      threadId: "main",
      toolCalls: [{ index: 0, function: { arguments: fragment } }],
    };
  }

  function finishDelta() {
    return {
      type: "model.message.delta",
      id: MESSAGE_ID,
      threadId: "main",
      finishReason: "tool_calls",
    };
  }

  it("emits a tool-call as soon as the name arrives", () => {
    const runner = new SentinelRunner(config);
    const events = translate(runner, deltaWithNameAndId());
    const call = events.find((e) => e.kind === "tool-call");
    expect(call).toBeDefined();
    expect(call?.kind === "tool-call" && call.toolName).toBe("open_pull_request");
  });

  it("emits the tool-call only once across many delta frames", () => {
    const runner = new SentinelRunner(config);
    const all = [
      ...translate(runner, deltaWithNameAndId()),
      ...translate(runner, deltaWithArgs('{"title":"Bump lodash"')),
      ...translate(runner, deltaWithArgs(',"body":"details"}')),
      ...translate(runner, finishDelta()),
    ];
    expect(all.filter((e) => e.kind === "tool-call")).toHaveLength(1);
  });

  it("names the tool correctly on the approval gate", () => {
    const runner = new SentinelRunner(config);
    translate(runner, deltaWithNameAndId());
    translate(runner, deltaWithArgs('{"title":"Bump lodash to 4.18.0"}'));
    translate(runner, finishDelta());

    const events = translate(runner, {
      type: "tool.approval_required",
      id: "evt_1",
      createdAt: "2026-08-28T00:00:00Z",
      threadId: "main",
      toolCalls: [{ id: "call_1", sourceEventId: MESSAGE_ID }],
    });

    const gate = events.find((e) => e.kind === "approval-required");
    expect(gate?.kind === "approval-required" && gate.approvals[0]?.toolName).toBe(
      "open_pull_request",
    );
    // The regression: this used to be "unknown_tool".
    expect(gate?.kind === "approval-required" && gate.approvals[0]?.toolName).not.toBe(
      "unknown_tool",
    );
  });

  it("gives the approval gate the fully reassembled arguments", () => {
    const runner = new SentinelRunner(config);
    translate(runner, deltaWithNameAndId());
    translate(runner, deltaWithArgs('{"title":"Bump lodash"'));
    translate(runner, deltaWithArgs(',"body":"clears GHSA-x"}'));
    translate(runner, finishDelta());

    const events = translate(runner, {
      type: "tool.approval_required",
      id: "evt_1",
      createdAt: "2026-08-28T00:00:00Z",
      threadId: "main",
      toolCalls: [{ id: "call_1", sourceEventId: MESSAGE_ID }],
    });

    const gate = events.find((e) => e.kind === "approval-required");
    const args = gate?.kind === "approval-required" ? gate.approvals[0]?.args : null;
    // Arguments split across frames must be reassembled, or a human approves blind.
    expect(args).toMatchObject({ title: "Bump lodash", body: "clears GHSA-x" });
  });

  it("tracks two concurrent tool calls independently by index", () => {
    const runner = new SentinelRunner(config);
    translate(runner, {
      type: "model.message.delta",
      id: MESSAGE_ID,
      threadId: "main",
      toolCalls: [
        { index: 0, id: "call_a", function: { name: "scan_dependencies", arguments: "" } },
        { index: 1, id: "call_b", function: { name: "lookup_advisories", arguments: "" } },
      ],
    });
    const events = translate(runner, {
      type: "tool.approval_required",
      id: "evt",
      createdAt: "2026-08-28T00:00:00Z",
      threadId: "main",
      toolCalls: [
        { id: "call_a", sourceEventId: MESSAGE_ID },
        { id: "call_b", sourceEventId: MESSAGE_ID },
      ],
    });
    const gate = events.find((e) => e.kind === "approval-required");
    const names =
      gate?.kind === "approval-required" ? gate.approvals.map((a) => a.toolName) : [];
    expect(names).toEqual(["scan_dependencies", "lookup_advisories"]);
  });

  it("does not double-report when history replay repeats a live tool call", () => {
    const runner = new SentinelRunner(config);
    translate(runner, deltaWithNameAndId());
    // The same call, now arriving in the complete replay shape.
    const replay = translate(runner, {
      type: "model.message",
      id: MESSAGE_ID,
      threadId: "main",
      createdAt: "2026-08-28T00:00:00Z",
      toolCalls: [
        { id: "call_1", type: "function", function: { name: "open_pull_request", arguments: "{}" } },
      ],
    });
    expect(replay.filter((e) => e.kind === "tool-call")).toHaveLength(0);
  });
});

describe("event translation", () => {
  it("reports a subagent thread but not the main thread", () => {
    const runner = new SentinelRunner(config);
    expect(
      translate(runner, { type: "thread.created", threadId: "main" }).filter(
        (e) => e.kind === "subagent",
      ),
    ).toHaveLength(0);
    expect(
      translate(runner, { type: "thread.created", threadId: "sub_1" }).filter(
        (e) => e.kind === "subagent",
      ),
    ).toHaveLength(1);
  });

  it("extracts the status from a structured turn.done state", () => {
    const runner = new SentinelRunner(config);
    const events = translate(runner, {
      type: "turn.done",
      id: "t1",
      createdAt: "2026-08-28T00:00:00Z",
      threadId: null,
      state: { status: "done" },
    });
    const done = events.find((e) => e.kind === "turn-done");
    expect(done?.kind === "turn-done" && done.status).toBe("done");
  });

  it("redacts a credential appearing in assistant text", () => {
    const runner = new SentinelRunner(config);
    const events = translate(runner, {
      type: "model.message",
      id: "m",
      threadId: "main",
      createdAt: "2026-08-28T00:00:00Z",
      content: `key ${["ghp", "abcdefghijklmnopqrstuvwxyz0123456789"].join("_")} here`,
    });
    const assistant = events.find((e) => e.kind === "assistant");
    expect(assistant?.kind === "assistant" && assistant.text).toContain("[REDACTED]");
  });

  it("ignores an unknown event type rather than throwing", () => {
    const runner = new SentinelRunner(config);
    expect(() => translate(runner, { type: "some.future.event" })).not.toThrow();
    expect(translate(runner, { type: "some.future.event" })).toEqual([]);
  });
});
