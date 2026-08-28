/**
 * Terminal rendering. Pure string helpers so they can be unit tested without a TTY.
 */
import type { PendingApproval, SentinelEvent } from "../harness/runner.ts";

const useColour =
  process.env.NO_COLOR === undefined && (process.stdout.isTTY ?? false);

const code = (n: string) => (text: string) => (useColour ? `\u001B[${n}m${text}\u001B[0m` : text);

export const dim = code("2");
export const bold = code("1");
export const red = code("31");
export const green = code("32");
export const yellow = code("33");
export const blue = code("34");
export const magenta = code("35");
export const cyan = code("36");

/** Truncate a value for a single-line preview without breaking mid-escape. */
export function preview(value: unknown, max = 120): string {
  let text: string;
  try {
    text = typeof value === "string" ? value : JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (text === undefined) return "";
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length <= max ? collapsed : `${collapsed.slice(0, max - 1)}…`;
}

export function banner(): string {
  return [
    "",
    bold("  SENTINEL") + dim("  ·  supply-chain strike team"),
    dim("  running on the TrueForge agent harness"),
    "",
  ].join("\n");
}

/** Render the approval prompt. This is the most safety-critical output we produce. */
export function renderApprovalPrompt(approvals: readonly PendingApproval[]): string {
  const lines = [
    "",
    yellow("  ┌─────────────────────────────────────────────────────────────┐"),
    yellow("  │  APPROVAL REQUIRED — the agent has stopped and is waiting.  │"),
    yellow("  └─────────────────────────────────────────────────────────────┘"),
    "",
  ];
  for (const [index, approval] of approvals.entries()) {
    lines.push(`  ${bold(`${index + 1}.`)} ${bold(red(approval.toolName))}`);
    const args = approval.args;
    if (args !== null && typeof args === "object") {
      for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
        lines.push(`     ${dim(key)}: ${preview(value, 160)}`);
      }
    } else {
      lines.push(`     ${preview(args, 160)}`);
    }
    lines.push("");
  }
  lines.push(dim("  This action cannot be undone."));
  return lines.join("\n");
}

/** Render a streamed event. Returns null for events with no terminal output. */
export function renderEvent(event: SentinelEvent): string | null {
  switch (event.kind) {
    case "session":
      return dim(`  session ${event.sessionId}`);
    case "turn-start":
      return dim(`  ▸ turn ${event.turnId}`);
    case "thinking":
      return dim(`  ${magenta("thinking")} ${preview(event.text, 160)}`);
    case "assistant":
      return `\n${event.threadId === "main" ? "" : dim(`  [${event.threadId}]\n`)}${event.text}\n`;
    case "delta":
      return null; // deltas are written raw by the caller, without a newline
    case "tool-call":
      return `  ${cyan("→")} ${bold(event.toolName)} ${dim(preview(event.args))}`;
    case "tool-result": {
      const firstLine = event.text.split("\n")[0] ?? "";
      return `  ${green("←")} ${dim(preview(firstLine, 140))}`;
    }
    case "subagent":
      return `  ${blue("⑂")} subagent ${bold(event.name)} started`;
    case "sandbox":
      return `  ${blue("▣")} ${event.detail}`;
    case "approval-required":
      return renderApprovalPrompt(event.approvals);
    case "mcp-auth-required":
      return yellow(`  ! ${event.server} needs authorisation: ${event.url}`);
    case "turn-done":
      return dim(`  ▪ turn ${event.status}`);
    case "error":
      return red(`  ✖ ${event.message}`);
    default:
      return null;
  }
}
