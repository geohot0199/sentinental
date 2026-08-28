/**
 * Tool-layer tests.
 *
 * The most important assertion in this file is the safety-annotation one: it is
 * what TrueForge's approval selectors resolve against, so if it regresses the
 * agent silently gains the ability to open pull requests without asking.
 */
import { describe, expect, it } from "vitest";
import type { SentinelConfig } from "../src/core/config.ts";
import { GitHubClient } from "../src/core/github.ts";
import { DESTRUCTIVE_TOOLS, TOOLS, runTool, type ToolContext } from "../src/mcp/tools.ts";

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
  allowRemoteWrites: false,
};

const ctx: ToolContext = {
  config,
  github: new GitHubClient(config.githubToken, config.allowRemoteWrites),
};

function tool(name: string) {
  const found = TOOLS.find((t) => t.name === name);
  if (found === undefined) throw new Error(`No such tool: ${name}`);
  return found;
}

describe("tool safety annotations", () => {
  it("marks exactly the two GitHub-mutating tools as destructive", () => {
    expect([...DESTRUCTIVE_TOOLS].sort()).toEqual(["merge_pull_request", "open_pull_request"]);
  });

  it("never marks a tool both read-only and destructive", () => {
    for (const t of TOOLS) {
      expect(t.annotations.readOnlyHint && t.annotations.destructiveHint, t.name).toBe(false);
    }
  });

  it("marks every non-destructive tool read-only", () => {
    for (const t of TOOLS) {
      if (!t.annotations.destructiveHint) {
        expect(t.annotations.readOnlyHint, t.name).toBe(true);
      }
    }
  });

  it("gives every tool a description an LLM can act on", () => {
    for (const t of TOOLS) {
      expect(t.description.length, t.name).toBeGreaterThan(40);
      expect(t.annotations.title.length, t.name).toBeGreaterThan(0);
    }
  });

  it("warns in the description of each destructive tool", () => {
    for (const name of DESTRUCTIVE_TOOLS) {
      expect(tool(name).description).toMatch(/IRREVERSIBLE/);
    }
  });

  it("exposes unique tool names", () => {
    expect(new Set(TOOLS.map((t) => t.name)).size).toBe(TOOLS.length);
  });
});

describe("runTool error handling", () => {
  it("converts a missing GitHub token into a typed result, never a throw", async () => {
    const result = await runTool(tool("scan_dependencies"), { repo: "a/b" }, ctx);
    expect(result.ok).toBe(false);
    expect(result.text).toContain("not_configured");
    expect(result.text).toContain("GITHUB_TOKEN");
  });

  it("rejects a malformed repository reference", async () => {
    const withToken: ToolContext = {
      config: { ...config, githubToken: "ghp_fake" },
      github: new GitHubClient("ghp_fake", false),
    };
    const result = await runTool(tool("scan_dependencies"), { repo: "../../etc" }, withToken);
    expect(result.ok).toBe(false);
    expect(result.text).toContain("invalid_input");
  });

  it("blocks a destructive tool in read-only mode", async () => {
    const withToken: ToolContext = {
      config: { ...config, githubToken: "ghp_fake" },
      github: new GitHubClient("ghp_fake", false),
    };
    const result = await runTool(
      tool("open_pull_request"),
      {
        repo: "octocat/hello",
        title: "t",
        body: "b",
        filePath: "package.json",
        fileContent: "{}",
      },
      withToken,
    );
    expect(result.ok).toBe(false);
    expect(result.text).toMatch(/read-only|forbidden/);
  });

  it("validates required arguments before touching the network", async () => {
    const withToken: ToolContext = {
      config: { ...config, githubToken: "ghp_fake" },
      github: new GitHubClient("ghp_fake", true),
    };
    const result = await runTool(
      tool("open_pull_request"),
      { repo: "octocat/hello", title: "", body: "", filePath: "", fileContent: "" },
      withToken,
    );
    expect(result.ok).toBe(false);
    expect(result.text).toContain("invalid_input");
  });

  it("redacts a credential that appears in tool output", async () => {
    const leaky = {
      name: "leaky",
      description: "test only",
      annotations: {
        title: "Leaky",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {},
      // Assembled at runtime so the literal never appears in the repository
      // and the secret scanner has nothing to flag.
      handler: async () => ({
        ok: true,
        text: `token is ${["ghp", "abcdefghijklmnopqrstuvwxyz0123456789"].join("_")}`,
      }),
    };
    const result = await runTool(leaky, {}, ctx);
    expect(result.text).not.toContain("abcdefghijklmnop");
    expect(result.text).toContain("[REDACTED]");
  });
});

describe("summarise_triage", () => {
  it("picks the highest fix version so no advisory is left open", async () => {
    const result = await runTool(
      tool("summarise_triage"),
      {
        matches: [
          {
            packageName: "lodash",
            installedVersion: "4.17.11",
            severity: "critical",
            advisoryId: "GHSA-a",
            firstPatchedVersion: "4.17.12",
          },
          {
            packageName: "lodash",
            installedVersion: "4.17.11",
            severity: "high",
            advisoryId: "GHSA-b",
            firstPatchedVersion: "4.18.0",
          },
        ],
      },
      ctx,
    );
    expect(result.ok).toBe(true);
    // 4.17.12 would leave GHSA-b unfixed.
    expect(result.text).toContain("4.18.0");
    expect(result.text).not.toMatch(/-> 4\.17\.12/);
  });

  it("escalates a package with no published fix to a human", async () => {
    const result = await runTool(
      tool("summarise_triage"),
      {
        matches: [
          {
            packageName: "abandoned",
            installedVersion: "1.0.0",
            severity: "high",
            advisoryId: "GHSA-x",
            firstPatchedVersion: null,
          },
        ],
      },
      ctx,
    );
    expect(result.text).toMatch(/No published fix/i);
    expect(result.text).toContain("abandoned");
  });

  it("orders the plan worst-severity-first", async () => {
    const result = await runTool(
      tool("summarise_triage"),
      {
        matches: [
          {
            packageName: "low-pkg",
            installedVersion: "1.0.0",
            severity: "low",
            advisoryId: "GHSA-l",
            firstPatchedVersion: "1.0.1",
          },
          {
            packageName: "crit-pkg",
            installedVersion: "1.0.0",
            severity: "critical",
            advisoryId: "GHSA-c",
            firstPatchedVersion: "2.0.0",
          },
        ],
      },
      ctx,
    );
    expect(result.text.indexOf("crit-pkg")).toBeLessThan(result.text.indexOf("low-pkg"));
  });

  it("rejects malformed input", async () => {
    const result = await runTool(tool("summarise_triage"), { matches: "nope" }, ctx);
    expect(result.ok).toBe(false);
    expect(result.text).toContain("invalid_input");
  });
});
