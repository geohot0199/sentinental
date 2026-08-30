/**
 * SENTINEL's MCP tool server.
 *
 * Speaks streamable HTTP because TrueForge 0.1.4 only accepts remote MCP
 * servers (`McpServerType` is the literal "remote" - verified against the
 * shipped SDK types, not assumed).
 *
 * Bearer auth is enforced on every request. The harness holds the token; the
 * model never sees it. This matters because the server exposes tools that can
 * open pull requests.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
// Web-standard transport: takes a `Request` and returns a `Response`, which is
// exactly what Hono hands us. The Node variant expects (req, res) instead.
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { Hono } from "hono";
import { createHash, timingSafeEqual } from "node:crypto";
import { isEntrypoint, listenOrExit } from "../core/serve.ts";
import { loadConfig, type SentinelConfig } from "../core/config.ts";
import { GitHubClient } from "../core/github.ts";
import { registerSecrets } from "../core/redact.ts";
import { runTool, TOOLS, type ToolContext } from "./tools.ts";

export function buildMcpServer(config: SentinelConfig): McpServer {
  const server = new McpServer(
    { name: "sentinel-supply-chain", version: "0.1.0" },
    {
      instructions:
        "Supply-chain security tools. Tools annotated read-only never mutate anything. " +
        "Tools annotated destructive open or merge pull requests and require human approval.",
    },
  );

  const ctx: ToolContext = {
    config,
    github: new GitHubClient(config.githubToken, config.allowRemoteWrites),
  };

  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.annotations.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: {
          title: tool.annotations.title,
          readOnlyHint: tool.annotations.readOnlyHint,
          destructiveHint: tool.annotations.destructiveHint,
          idempotentHint: tool.annotations.idempotentHint,
          openWorldHint: tool.annotations.openWorldHint,
        },
      },
      async (args: Record<string, unknown>) => {
        const result = await runTool(tool, args ?? {}, ctx);
        return {
          content: [{ type: "text" as const, text: result.text }],
          isError: !result.ok,
        };
      },
    );
  }

  return server;
}

/**
 * Constant-time token comparison that does not leak the secret's length.
 *
 * Comparing SHA-256 digests with `crypto.timingSafeEqual` means the early exit
 * is on a fixed-size hash, not on the token itself: length, prefix, and byte
 * position are all invisible to a timing probe.
 */
function safeEqual(presented: string, expected: string): boolean {
  const a = createHash("sha256").update(presented).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

export function buildApp(config: SentinelConfig): Hono {
  const app = new Hono();

  app.get("/health", (c) =>
    c.json({
      status: "ok",
      service: "sentinel-mcp",
      tools: TOOLS.length,
      // Booleans only. Never the values.
      github: config.githubToken !== null,
      remoteWrites: config.allowRemoteWrites,
    }),
  );

  app.all("/mcp", async (c) => {
    const header = c.req.header("authorization") ?? "";
    const presented = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!safeEqual(presented, config.mcpToken)) {
      return c.json({ error: "unauthorized" }, 401);
    }

    // Stateless transport: one server instance per request. Simpler to reason
    // about than shared session state, and the harness reconnects freely.
    const server = buildMcpServer(config);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    c.req.raw.signal.addEventListener("abort", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    return transport.handleRequest(c.req.raw);
  });

  return app;
}

/**
 * Bind the MCP tool server and resolve once the socket is actually listening.
 *
 * A busy port is fatal here (one clear line via `listenOrExit`): both callers
 * - the CLI and the web console - are useless without their tool server.
 */
export async function startMcpServer(config: SentinelConfig): Promise<{ close: () => void }> {
  const app = buildApp(config);
  return await listenOrExit(app, {
    port: config.mcpPort,
    hostname: "127.0.0.1",
    label: "SENTINEL MCP server",
  });
}

if (isEntrypoint(import.meta.url)) {
  const config = loadConfig();
  registerSecrets([config.githubToken, config.daytonaApiKey, config.mcpToken, config.provider?.apiKey]);
  await startMcpServer(config);
  process.stdout.write(
    `SENTINEL MCP server listening on http://127.0.0.1:${config.mcpPort}/mcp (${TOOLS.length} tools)\n`,
  );
}
