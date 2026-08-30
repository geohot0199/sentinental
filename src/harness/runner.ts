/**
 * The shared session runner.
 *
 * Both the terminal client and the web client drive this exact module, which is
 * what keeps their behaviour identical - especially around approvals, where a
 * divergence between two front ends would be a genuine safety bug.
 *
 * What this is NOT: an agent loop. TrueForge owns the loop. This translates the
 * harness's event stream into a narrow, UI-shaped interface and pumps approval
 * decisions back in.
 */
import { TrueForge, type TrueForgeApi } from "@truefoundry/trueforge-sdk";
import type { SentinelConfig } from "../core/config.ts";
import { SentinelError, toSentinelError } from "../core/errors.ts";
import { redact, redactDeep } from "../core/redact.ts";
import { AGENT_NAME } from "./agent-spec.ts";

/** A pending tool call the human must decide on. */
export interface PendingApproval {
  readonly toolCallId: string;
  readonly threadId: string;
  readonly toolName: string;
  /** Arguments, redacted, ready to show a human. */
  readonly args: unknown;
  readonly requestedAt: string;
}

export type SentinelEvent =
  | { kind: "session"; sessionId: string }
  | { kind: "turn-start"; turnId: string }
  | { kind: "thinking"; text: string }
  | { kind: "assistant"; text: string; threadId: string }
  | { kind: "delta"; text: string; threadId: string }
  | { kind: "tool-call"; toolName: string; args: unknown; threadId: string; toolCallId: string }
  | { kind: "tool-result"; toolCallId: string; text: string; threadId: string }
  | { kind: "subagent"; threadId: string; name: string }
  | { kind: "sandbox"; detail: string }
  | { kind: "approval-required"; approvals: readonly PendingApproval[] }
  | { kind: "mcp-auth-required"; url: string; server: string }
  | { kind: "turn-done"; status: string; turnId: string }
  | { kind: "error"; message: string };

export type EventSink = (event: SentinelEvent) => void;

/** Decision a client feeds back for a pending approval. */
export interface ApprovalDecision {
  readonly toolCallId: string;
  readonly threadId: string;
  readonly approved: boolean;
  readonly reason?: string;
}

/**
 * Remembers which tool call produced which tool name, so an approval prompt can
 * say "open_pull_request" instead of an opaque id. The harness sends the name on
 * the model.message that requested the call, and the id alone on the approval
 * event, so the correlation has to happen client-side.
 */
class ToolCallRegistry {
  readonly #names = new Map<string, string>();
  readonly #args = new Map<string, unknown>();

  record(id: string, name: string, args: unknown): void {
    if (id.length === 0) return;
    if (name.length > 0) this.#names.set(id, name);
    this.#args.set(id, args);
  }

  has(id: string): boolean {
    return this.#names.has(id);
  }

  name(id: string): string {
    return this.#names.get(id) ?? "unknown_tool";
  }

  args(id: string): unknown {
    return this.#args.get(id) ?? {};
  }
}

/**
 * Accumulates streamed tool calls.
 *
 * The harness streams a tool call across several `model.message.delta` frames:
 * the first carries the id and name, later ones append argument fragments. Only
 * the replayed (non-streaming) `model.message` is ever complete. So a client
 * that reads tool calls off `model.message` alone - as the type definitions
 * suggest - sees nothing during a live turn, and an approval prompt ends up
 * labelled "unknown_tool". Verified against TrueForge 0.1.4.
 */
class DeltaAccumulator {
  readonly #byIndex = new Map<string, { id: string; name: string; args: string }>();

  #key(messageId: string, index: number): string {
    return `${messageId}#${index}`;
  }

  /** Fold one delta frame in; returns the call if it now has an id and name. */
  push(
    messageId: string,
    index: number,
    id: string | undefined,
    name: string | undefined,
    argsFragment: string | undefined,
  ): { id: string; name: string; args: string } | null {
    const key = this.#key(messageId, index);
    const current = this.#byIndex.get(key) ?? { id: "", name: "", args: "" };
    if (id !== undefined && id.length > 0) current.id = id;
    if (name !== undefined && name.length > 0) current.name = name;
    if (argsFragment !== undefined && argsFragment.length > 0) current.args += argsFragment;
    this.#byIndex.set(key, current);
    return current.id.length > 0 && current.name.length > 0 ? current : null;
  }

  /** Everything accumulated for one message, once it finishes. */
  drain(messageId: string): { id: string; name: string; args: string }[] {
    const out: { id: string; name: string; args: string }[] = [];
    for (const [key, value] of [...this.#byIndex.entries()]) {
      if (key.startsWith(`${messageId}#`)) {
        out.push(value);
        this.#byIndex.delete(key);
      }
    }
    return out;
  }
}

function parseArgs(raw: unknown): unknown {
  if (typeof raw !== "string") return redactDeep(raw);
  try {
    return redactDeep(JSON.parse(raw));
  } catch {
    return redact(raw);
  }
}

function textOf(content: TrueForgeApi.ModelMessageEventContent | null | undefined): string {
  if (content === null || content === undefined) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") return part;
        if (part !== null && typeof part === "object" && "text" in part) {
          const text = (part as { text?: unknown }).text;
          return typeof text === "string" ? text : "";
        }
        return "";
      })
      .join("");
  }
  return "";
}

export class SentinelRunner {
  readonly #client: TrueForge;
  readonly #registry = new ToolCallRegistry();
  readonly #deltas = new DeltaAccumulator();

  #sessionId: string | null = null;
  #pending: PendingApproval[] = [];
  #lastTurnId: string | null = null;
  readonly #agentName: string;

  /**
   * @param agentName overrides the registered agent to bind sessions to. Exists
   *        so the end-to-end test can drive this exact class against a scripted
   *        agent instead of shipping a second, untested implementation.
   */
  constructor(config: SentinelConfig, agentName: string = AGENT_NAME) {
    this.#agentName = agentName;
    this.#client = new TrueForge({ baseUrl: config.harnessUrl });
  }

  get sessionId(): string | null {
    return this.#sessionId;
  }

  get pendingApprovals(): readonly PendingApproval[] {
    return this.#pending;
  }

  /** Create a session bound to the registered named agent. */
  async startSession(): Promise<string> {
    const response = await this.#client.sessions.create({ agent: { name: this.#agentName } });
    const id = response.data?.id;
    if (typeof id !== "string") {
      throw new SentinelError("upstream_failure", "Harness did not return a session id.");
    }
    this.#sessionId = id;
    return id;
  }

  /** Rejoin an existing session, which is what makes reconnect work. */
  async resumeSession(sessionId: string): Promise<void> {
    await this.#client.sessions.get(sessionId);
    this.#sessionId = sessionId;
  }

  /** Replay a session's history so a reconnecting UI can rebuild its view. */
  async history(sessionId: string): Promise<SentinelEvent[]> {
    const events: SentinelEvent[] = [];
    // The harness pages events newest-first, so collect then reverse to get the
    // chronological order a UI needs to rebuild a transcript.
    const page = await this.#client.sessions.listEvents(sessionId, { limit: 100 });
    const collected: TrueForgeApi.SessionEventItem[] = [];
    for await (const item of page) {
      collected.push(item);
      if (collected.length >= 500) break; // bound the replay
    }
    for (const item of collected.reverse()) {
      events.push(...this.#translate(item.event));
    }
    return events;
  }

  /** Send a user message and stream the turn. */
  async send(message: string, sink: EventSink): Promise<void> {
    await this.#runTurn([{ type: "user.message", content: message }], sink);
  }

  /** Resolve pending approvals and resume the paused turn. */
  async respondToApprovals(
    decisions: readonly ApprovalDecision[],
    sink: EventSink,
  ): Promise<void> {
    if (decisions.length === 0) return;
    const input: TrueForgeApi.TurnInputItem[] = decisions.map((decision) => ({
      type: "user.tool_approval",
      threadId: decision.threadId,
      toolCallId: decision.toolCallId,
      approval: decision.approved
        ? { status: "allow" }
        : { status: "deny", reason: decision.reason ?? "Denied by the operator." },
    }));

    const decided = new Set(decisions.map((d) => d.toolCallId));
    this.#pending = this.#pending.filter((p) => !decided.has(p.toolCallId));

    await this.#runTurn(input, sink);
  }

  async cancel(): Promise<void> {
    if (this.#sessionId === null) return;
    try {
      await this.#client.sessions.cancel(this.#sessionId);
    } catch {
      // Cancelling an already-finished turn is not an error worth surfacing.
    }
  }

  async #runTurn(input: TrueForgeApi.TurnInputItem[], sink: EventSink): Promise<void> {
    const sessionId = this.#sessionId;
    if (sessionId === null) {
      throw new SentinelError("invalid_input", "No active session. Call startSession() first.");
    }

    try {
      const stream = await this.#client.sessions.createTurnStream(sessionId, { input });
      for await (const event of stream) {
        for (const translated of this.#translate(event)) {
          sink(translated);
        }
      }
    } catch (cause) {
      const error = toSentinelError(cause);
      sink({ kind: "error", message: redact(error.toModelText()) });
      throw error;
    }
  }

  /**
   * Test seam for `#translate`.
   *
   * Event translation is the piece most worth testing (it is where the approval
   * gate gets its tool name) but it depends on accumulated stream state, so it
   * cannot be a free function. This exposes it without widening the real API.
   *
   * @internal
   */
  _translateForTest(event: unknown): SentinelEvent[] {
    return this.#translate(event as TrueForgeApi.TurnStreamingEvent);
  }

  /**
   * Translate one harness event into zero or more UI events.
   *
   * Kept pure and synchronous so it can be reused for both live streaming and
   * history replay - the reconnect path and the live path cannot drift.
   */
  // eslint-disable-next-line complexity, max-lines-per-function -- one case per harness event type
  #translate(event: TrueForgeApi.TurnStreamingEvent): SentinelEvent[] {
    const out: SentinelEvent[] = [];

    switch (event.type) {
      case "turn.created": {
        this.#lastTurnId = event.id;
        out.push({ kind: "turn-start", turnId: event.id });
        break;
      }

      case "thread.created": {
        // A thread other than `main` is a subagent the harness spawned.
        const threadId = (event as { threadId?: string }).threadId ?? "main";
        if (threadId !== "main") {
          out.push({ kind: "subagent", threadId, name: threadId });
        }
        break;
      }

      case "sandbox.created": {
        out.push({ kind: "sandbox", detail: "Sandbox provisioned for this turn." });
        break;
      }

      case "model.message": {
        const message = event;
        const threadId = message.threadId ?? "main";

        if (typeof message.reasoningContent === "string" && message.reasoningContent.length > 0) {
          out.push({ kind: "thinking", text: redact(message.reasoningContent) });
        }

        const text = textOf(message.content);
        if (text.trim().length > 0) {
          out.push({ kind: "assistant", text: redact(text), threadId });
        }

        // Populated on history replay, and empty during a live stream (where
        // the deltas carry the tool calls instead). `firstSighting` keeps the
        // two paths from double-reporting the same call.
        for (const call of message.toolCalls ?? []) {
          const id = (call as { id?: string }).id ?? "";
          const fn = (call as { function?: { name?: string; arguments?: unknown } }).function;
          const name = fn?.name ?? "unknown_tool";
          const args = parseArgs(fn?.arguments);
          const firstSighting = !this.#registry.has(id);
          this.#registry.record(id, name, args);
          if (firstSighting) {
            out.push({ kind: "tool-call", toolName: name, args, threadId, toolCallId: id });
          }
        }
        break;
      }

      case "model.message.delta": {
        const delta = event as unknown as {
          id?: string;
          content?: unknown;
          threadId?: string;
          finishReason?: string | null;
          toolCalls?: {
            index?: number;
            id?: string;
            function?: { name?: string; arguments?: string };
          }[];
        };
        const threadId = delta.threadId ?? "main";
        const messageId = delta.id ?? "";

        const text = typeof delta.content === "string" ? delta.content : "";
        if (text.length > 0) {
          out.push({ kind: "delta", text: redact(text), threadId });
        }

        // Fold streamed tool-call fragments together. Emit the `tool-call` event
        // as soon as the name is known so the UI reacts immediately, then keep
        // folding arguments so the approval prompt shows the complete payload.
        for (const call of delta.toolCalls ?? []) {
          const index = call.index ?? 0;
          const merged = this.#deltas.push(
            messageId,
            index,
            call.id,
            call.function?.name,
            call.function?.arguments,
          );
          if (merged === null) continue;

          const firstSighting = !this.#registry.has(merged.id);
          this.#registry.record(merged.id, merged.name, parseArgs(merged.args));
          if (firstSighting) {
            out.push({
              kind: "tool-call",
              toolName: merged.name,
              args: parseArgs(merged.args),
              threadId,
              toolCallId: merged.id,
            });
          }
        }

        // On the terminating frame, commit the fully-assembled arguments.
        if (typeof delta.finishReason === "string" && messageId.length > 0) {
          for (const call of this.#deltas.drain(messageId)) {
            this.#registry.record(call.id, call.name, parseArgs(call.args));
          }
        }
        break;
      }

      case "tool.response": {
        const response = event;
        out.push({
          kind: "tool-result",
          toolCallId: response.toolCallId,
          text: redact(response.content ?? ""),
          threadId: response.threadId ?? "main",
        });
        break;
      }

      case "tool.approval_required": {
        const approval = event;
        const approvals: PendingApproval[] = approval.toolCalls.map((call) => ({
          toolCallId: call.id,
          threadId: approval.threadId,
          toolName: this.#registry.name(call.id),
          args: this.#registry.args(call.id),
          requestedAt: approval.createdAt,
        }));
        // De-duplicate: a replayed history could otherwise queue the same
        // approval twice and prompt the human for a decision already made.
        for (const item of approvals) {
          if (!this.#pending.some((p) => p.toolCallId === item.toolCallId)) {
            this.#pending.push(item);
          }
        }
        out.push({ kind: "approval-required", approvals });
        break;
      }

      case "mcp.auth_required": {
        const auth = event as unknown as { authorizationUrl?: string; serverName?: string };
        out.push({
          kind: "mcp-auth-required",
          url: auth.authorizationUrl ?? "",
          server: auth.serverName ?? "unknown",
        });
        break;
      }

      case "turn.done": {
        const done = event;
        const status =
          typeof done.state === "string"
            ? done.state
            : ((done.state as { status?: string } | undefined)?.status ?? "done");
        out.push({ kind: "turn-done", status, turnId: this.#lastTurnId ?? done.id });
        break;
      }

      default:
        // Unknown event types are ignored rather than crashing the stream: the
        // harness may add events, and an old client should degrade quietly.
        break;
    }

    return out;
  }
}
