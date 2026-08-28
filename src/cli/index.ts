#!/usr/bin/env node
/**
 * SENTINEL terminal client.
 *
 * Drives the same `SentinelRunner` as the web app. The approval flow here is a
 * blocking prompt on stdin: the agent genuinely stops until a human answers,
 * which is the point.
 */
import { createInterface, type Interface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { loadConfig, describeCapabilities, type SentinelConfig } from "../core/config.ts";
import { toSentinelError } from "../core/errors.ts";
import { registerSecrets } from "../core/redact.ts";
import { provision } from "../harness/provision.ts";
import { startMcpServer } from "../mcp/server.ts";
import {
  SentinelRunner,
  type ApprovalDecision,
  type PendingApproval,
  type SentinelEvent,
} from "../harness/runner.ts";
import { banner, bold, cyan, dim, green, red, renderEvent, yellow } from "./render.ts";

function write(text: string): void {
  stdout.write(`${text}\n`);
}

/**
 * Ask the human about each pending approval. Defaults to DENY on empty input,
 * on EOF, and on anything unrecognised: the safe direction for an irreversible
 * action is always "no".
 */
async function askApprovals(
  rl: Interface,
  approvals: readonly PendingApproval[],
): Promise<ApprovalDecision[]> {
  const decisions: ApprovalDecision[] = [];
  for (const approval of approvals) {
    let answer = "";
    try {
      answer = (
        await rl.question(
          `  ${bold("Approve")} ${red(approval.toolName)}? ${dim("[y/N]")} `,
        )
      )
        .trim()
        .toLowerCase();
    } catch {
      answer = ""; // stream closed - treat as denial
    }
    const approved = answer === "y" || answer === "yes";
    decisions.push({
      toolCallId: approval.toolCallId,
      threadId: approval.threadId,
      approved,
      ...(approved ? {} : { reason: "The operator denied this action at the terminal." }),
    });
    write(approved ? green("  ✓ approved") : yellow("  ✗ denied"));
  }
  return decisions;
}

async function bootstrap(config: SentinelConfig): Promise<SentinelRunner> {
  write(dim("  starting local tool server…"));
  startMcpServer(config);

  write(dim("  provisioning the harness…"));
  const result = await provision(config);
  for (const step of result.steps) write(dim(`    · ${step}`));
  for (const warning of result.warnings) write(yellow(`    ! ${warning}`));

  write("");
  write(
    `  ${dim("model")} ${bold(result.modelFqn)}   ${dim("sandbox")} ${
      result.sandboxEnabled ? green("on") : yellow("off")
    }   ${dim("github")} ${config.githubToken !== null ? green("on") : yellow("off")}`,
  );

  return new SentinelRunner(config);
}

async function main(): Promise<void> {
  const config = loadConfig();
  registerSecrets([
    config.githubToken,
    config.daytonaApiKey,
    config.mcpToken,
    config.provider?.apiKey,
  ]);

  write(banner());

  const capabilities = describeCapabilities(config);
  if (!capabilities.model) {
    write(red("  No model provider key found."));
    for (const note of capabilities.notes) write(dim(`  ${note}`));
    write(dim("\n  Copy .env.example to .env and add a key, then run again.\n"));
    process.exitCode = 1;
    return;
  }

  let runner: SentinelRunner;
  try {
    runner = await bootstrap(config);
  } catch (cause) {
    const error = toSentinelError(cause);
    write(red(`\n  ${error.message}`));
    if (error.remedy !== null) write(dim(`  ${error.remedy}`));
    process.exitCode = 1;
    return;
  }

  const sessionId = await runner.startSession();
  write(dim(`  session ${sessionId}`));
  write(dim("  type a task, or /quit to exit. /cancel stops a running turn.\n"));

  const rl = createInterface({ input: stdin, output: stdout });

  // Ctrl-C cancels the running turn rather than killing the process, so a
  // half-finished turn is not left running server-side.
  let interrupted = false;
  rl.on("SIGINT", () => {
    if (interrupted) process.exit(130);
    interrupted = true;
    write(yellow("\n  cancelling… (press Ctrl-C again to force quit)"));
    void runner.cancel();
  });

  const sink = (event: SentinelEvent): void => {
    if (event.kind === "delta") {
      stdout.write(event.text);
      return;
    }
    const line = renderEvent(event);
    if (line !== null) write(line);
  };

  for (;;) {
    let input: string;
    try {
      input = (await rl.question(cyan("sentinel› "))).trim();
    } catch {
      break; // EOF
    }
    if (input.length === 0) continue;
    if (input === "/quit" || input === "/exit") break;
    if (input === "/cancel") {
      await runner.cancel();
      continue;
    }
    if (input === "/session") {
      write(dim(`  ${runner.sessionId ?? "none"}`));
      continue;
    }

    interrupted = false;
    try {
      await runner.send(input, sink);

      // Drain approvals until the agent stops asking. Each answered batch
      // resumes the turn, which may in turn request more.
      for (;;) {
        const pending = runner.pendingApprovals;
        if (pending.length === 0) break;
        const decisions = await askApprovals(rl, pending);
        await runner.respondToApprovals(decisions, sink);
      }
    } catch (cause) {
      const error = toSentinelError(cause);
      write(red(`\n  ${error.message}`));
      if (error.remedy !== null) write(dim(`  ${error.remedy}`));
    }
    write("");
  }

  rl.close();
  write(dim("\n  session preserved. reconnect with SENTINEL_SESSION_ID=" + (runner.sessionId ?? "")));
  process.exit(0);
}

main().catch((cause: unknown) => {
  const error = toSentinelError(cause);
  process.stderr.write(`${red(`fatal: ${error.message}`)}\n`);
  process.exit(1);
});
