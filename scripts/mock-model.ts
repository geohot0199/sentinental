/**
 * A scripted OpenAI-compatible endpoint, for testing the harness wiring without
 * spending money or needing a real key.
 *
 * It is NOT a model. It replays a fixed sequence of tool calls so we can prove
 * the end-to-end path: harness -> our MCP server -> real advisory data -> the
 * approval gate firing on a destructive tool.
 *
 * Usage: node --experimental-strip-types scripts/mock-model.ts [port]
 */
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const port = Number(process.argv[2] ?? 8899) || 8899;

interface Step {
  readonly toolName: string;
  readonly args: unknown;
}

/**
 * The scripted run: scan real advisories, then attempt an irreversible action.
 * The second step is the one that must be stopped by the approval gate.
 */
const SCRIPT: readonly Step[] = [
  {
    toolName: "lookup_advisories",
    args: {
      packages: [
        { name: "lodash", version: "4.17.11" },
        { name: "minimist", version: "1.2.0" },
        { name: "axios", version: "0.21.0" },
      ],
    },
  },
  {
    toolName: "summarise_triage",
    args: {
      matches: [
        {
          packageName: "lodash",
          installedVersion: "4.17.11",
          severity: "critical",
          advisoryId: "GHSA-jf85-cpcp-j695",
          firstPatchedVersion: "4.17.12",
        },
        {
          packageName: "lodash",
          installedVersion: "4.17.11",
          severity: "high",
          advisoryId: "GHSA-35jh-r3h4-6jhm",
          firstPatchedVersion: "4.17.21",
        },
        {
          packageName: "minimist",
          installedVersion: "1.2.0",
          severity: "critical",
          advisoryId: "GHSA-xvch-5gv4-984h",
          firstPatchedVersion: "1.2.6",
        },
      ],
    },
  },
  {
    toolName: "assess_blast_radius",
    args: {
      packageName: "lodash",
      fromVersion: "4.17.11",
      toVersion: "4.17.21",
    },
  },
  {
    toolName: "open_pull_request",
    args: {
      title: "fix(deps): patch 3 critical and high severity advisories",
      body:
        "Upgrades three dependencies to clear published security advisories.\n\n" +
        "| Package | From | To | Clears |\n" +
        "| --- | --- | --- | --- |\n" +
        "| lodash | 4.17.11 | 4.17.21 | GHSA-jf85-cpcp-j695 (critical), GHSA-35jh-r3h4-6jhm (high) |\n" +
        "| minimist | 1.2.0 | 1.2.6 | GHSA-xvch-5gv4-984h (critical) |\n\n" +
        "All bumps are patch-level. Verified against the live GitHub Advisory Database.",
      filePath: "package.json",
      fileContent:
        '{\n  "name": "demo-app",\n  "dependencies": {\n' +
        '    "lodash": "^4.17.21",\n    "minimist": "^1.2.6"\n  }\n}\n',
    },
  },
];

const app = new Hono();

const FINAL_TEXT =
  "Scripted run complete. Advisories were fetched from the live database and the " +
  "irreversible action was submitted for human approval.";

/** Build the OpenAI streaming chunks for one scripted step. */
function chunksFor(step: Step | undefined, index: number): unknown[] {
  const base = {
    id: `chatcmpl-mock-${index}`,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: "mock-model",
  };

  if (step === undefined) {
    return [
      { ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] },
      { ...base, choices: [{ index: 0, delta: { content: FINAL_TEXT }, finish_reason: null }] },
      {
        ...base,
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
        usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
      },
    ];
  }

  return [
    { ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] },
    {
      ...base,
      choices: [
        {
          index: 0,
          delta: {
            tool_calls: [
              {
                index: 0,
                id: `call_mock_${index}`,
                type: "function",
                function: { name: step.toolName, arguments: JSON.stringify(step.args) },
              },
            ],
          },
          finish_reason: null,
        },
      ],
    },
    {
      ...base,
      choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
      usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
    },
  ];
}

app.post("/v1/chat/completions", async (c) => {
  const body = (await c.req.json()) as {
    stream?: boolean;
    messages?: { role: string; tool_call_id?: string }[];
  };
  const messages = body.messages ?? [];
  // Count completed tool round-trips to decide where we are in the script.
  const completed = messages.filter((m) => m.role === "tool").length;
  const step = SCRIPT[completed];
  const chunks = chunksFor(step, completed);

  // The harness always asks for a stream, so SSE is the path that matters.
  if (body.stream !== false) {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
        }
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      },
    });
    return new Response(stream, {
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      },
    });
  }

  // Non-streaming fallback, so the endpoint is usable with a plain client too.
  const message =
    step === undefined
      ? { role: "assistant", content: FINAL_TEXT }
      : {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: `call_mock_${completed}`,
              type: "function",
              function: { name: step.toolName, arguments: JSON.stringify(step.args) },
            },
          ],
        };

  return c.json({
    id: `chatcmpl-mock-${completed}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: "mock-model",
    choices: [
      { index: 0, message, finish_reason: step === undefined ? "stop" : "tool_calls" },
    ],
    usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
  });
});

app.get("/v1/models", (c) =>
  c.json({ object: "list", data: [{ id: "mock-model", object: "model" }] }),
);

serve({ fetch: app.fetch, port, hostname: "127.0.0.1" });
process.stdout.write(`Mock model endpoint on http://127.0.0.1:${port}/v1\n`);
