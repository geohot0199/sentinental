/**
 * Developer probe: connect to the running SENTINEL MCP server as a real MCP
 * client, list the tools, and optionally call one. Used to verify the wire
 * contract (especially the safety annotations) without going through an LLM.
 *
 * Usage: node --experimental-strip-types scripts/probe-mcp.ts [toolName] [jsonArgs]
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/core/config.ts";

const config = loadConfig();
const token = process.env.SENTINEL_MCP_TOKEN ?? config.mcpToken;

const transport = new StreamableHTTPClientTransport(new URL(config.mcpUrl), {
  requestInit: { headers: { authorization: `Bearer ${token}` } },
});

const client = new Client({ name: "sentinel-probe", version: "0.1.0" });
await client.connect(transport);

const { tools } = await client.listTools();
process.stdout.write(`Connected. ${tools.length} tool(s):\n\n`);
for (const tool of tools) {
  const a = tool.annotations ?? {};
  const flags = [
    a.readOnlyHint === true ? "read-only" : null,
    a.destructiveHint === true ? "DESTRUCTIVE" : null,
    a.idempotentHint === true ? "idempotent" : null,
  ]
    .filter((f) => f !== null)
    .join(", ");
  process.stdout.write(`  ${tool.name.padEnd(22)} [${flags}]\n`);
}

const toolName = process.argv[2];
if (toolName !== undefined) {
  const rawArgs = process.argv[3] ?? "{}";
  process.stdout.write(`\nCalling ${toolName} with ${rawArgs}\n\n`);
  const result = await client.callTool({
    name: toolName,
    arguments: JSON.parse(rawArgs) as Record<string, unknown>,
  });
  const content = (result.content ?? []) as { type: string; text?: string }[];
  for (const part of content) {
    if (part.type === "text") process.stdout.write(`${part.text ?? ""}\n`);
  }
  process.stdout.write(`\nisError: ${String(result.isError ?? false)}\n`);
}

await client.close();
process.exit(0);
