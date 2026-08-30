/**
 * Integration coverage for the web console's status endpoint.
 *
 * `GET /api/status` is what the browser renders before it lets an operator do
 * anything, so two properties matter and both are asserted here: the JSON
 * shape the front end binds to, and the fact that a fully-provisioned config
 * — every secret populated — still produces a response containing no secret.
 * The route is documented as "booleans and names only"; this is the test that
 * keeps that true.
 *
 * Driven through Hono's `app.request()` so the real router, the real
 * `describeCapabilities()` and the real `buildWebApp()` wiring all run.
 */
import { describe, expect, it, vi } from "vitest";
import type { SentinelConfig } from "../src/core/config.ts";
import type { ProvisionResult } from "../src/harness/provision.ts";

vi.mock("../src/harness/runner.ts", () => ({
  SentinelRunner: class {
    async startSession(): Promise<string> {
      return "unused-by-these-tests";
    }
  },
}));

const { buildWebApp } = await import("../src/web/server.ts");

/** Nothing configured: the shape a fresh clone sees before anyone edits .env. */
const bareConfig: SentinelConfig = {
  harnessUrl: "http://127.0.0.1:8790",
  mcpPort: 8791,
  mcpUrl: "http://127.0.0.1:8791/mcp",
  mcpToken: "sn_00001111222233334444555566667777",
  webPort: 3000,
  provider: null,
  githubToken: null,
  daytonaApiKey: null,
  targetRepo: null,
  allowRemoteWrites: true,
};

/** Everything set, including values that must never reach a browser. */
const provisionedConfig: SentinelConfig = {
  ...bareConfig,
  mcpToken: "sn_aaaabbbbccccddddeeeeffffaaaabbbb",
  provider: {
    id: "openai",
    envVar: "OPENAI_API_KEY",
    apiKey: "sk-test-provider-key-value",
    modelId: "gpt-4.1",
    fqn: "openai/gpt-4.1",
  },
  githubToken: "ghp_test_github_token_value",
  daytonaApiKey: "dtn_test_daytona_key_value",
  targetRepo: "acme/widget",
  allowRemoteWrites: false,
};

const provisioned: ProvisionResult = {
  modelFqn: "openai/gpt-4.1",
  sandboxEnabled: true,
  mcpServer: "sentinel-supply-chain",
  agentName: "sentinel",
  steps: ["registered mcp server"],
  warnings: ["sandbox image is pinned to an older digest"],
};

async function getStatus(
  config: SentinelConfig,
  provisioning: ProvisionResult | null,
  provisionError: string | null,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const app = buildWebApp(config, provisioning, provisionError);
  const response = await app.request("/api/status");
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe("GET /api/status", () => {
  it("reports not ready and no model when nothing is provisioned", async () => {
    const { status, body } = await getStatus(bareConfig, null, null);

    expect(status).toBe(200);
    expect(body).toEqual({
      ready: true,
      error: null,
      model: null,
      sandbox: false,
      github: false,
      remoteWrites: true,
      targetRepo: null,
      warnings: expect.arrayContaining([
        expect.stringContaining("No model key found"),
        expect.stringContaining("DAYTONA_API_KEY not set"),
        expect.stringContaining("GITHUB_TOKEN not set"),
      ]),
    });
  });

  it("reports the provisioned model, sandbox and warnings", async () => {
    const { status, body } = await getStatus(provisionedConfig, provisioned, null);

    expect(status).toBe(200);
    expect(body.ready).toBe(true);
    expect(body.error).toBeNull();
    expect(body.model).toBe("openai/gpt-4.1");
    expect(body.sandbox).toBe(true);
    expect(body.github).toBe(true);
    expect(body.remoteWrites).toBe(false);
    expect(body.targetRepo).toBe("acme/widget");
    // Provisioning warnings replace the capability notes once we have run.
    expect(body.warnings).toEqual(provisioned.warnings);
  });

  it("surfaces a provisioning failure without pretending to be ready", async () => {
    const failure = "Cannot reach the TrueForge harness at http://127.0.0.1:8790";
    const { status, body } = await getStatus(bareConfig, null, failure);

    expect(status).toBe(200);
    expect(body.ready).toBe(false);
    expect(body.error).toBe(failure);
    expect(body.model).toBeNull();
  });

  it("leaks no credential from a fully configured deployment", async () => {
    const { body } = await getStatus(provisionedConfig, provisioned, null);
    const serialised = JSON.stringify(body);

    for (const secret of [
      provisionedConfig.mcpToken,
      provisionedConfig.githubToken,
      provisionedConfig.daytonaApiKey,
      provisionedConfig.provider?.apiKey ?? "",
    ]) {
      expect(serialised).not.toContain(secret);
    }
    // The provider key's variable name is fine to mention; its value is not.
    expect(serialised).not.toContain("sk-test-provider-key-value");
    expect(Object.keys(body).sort()).toEqual([
      "error",
      "github",
      "model",
      "ready",
      "remoteWrites",
      "sandbox",
      "targetRepo",
      "warnings",
    ]);
  });
});
