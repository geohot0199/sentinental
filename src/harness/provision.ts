/**
 * Idempotent provisioning of the TrueForge harness.
 *
 * Running this twice must be safe: it is called on every CLI and web-server
 * boot. Everything here uses create-or-update semantics.
 *
 * Model choices come from the harness's own catalog rather than a hardcoded
 * list, because the catalog is versioned with the harness and a pinned model id
 * goes stale silently.
 */
import { TrueForge, type TrueForgeApi } from "@truefoundry/trueforge-sdk";
import type { SentinelConfig } from "../core/config.ts";
import { SentinelError } from "../core/errors.ts";
import { httpJson } from "../core/http.ts";
import { AGENT_NAME, buildAgentSpec, MCP_SERVER_NAME } from "./agent-spec.ts";

export interface ProvisionResult {
  readonly modelFqn: string;
  readonly sandboxEnabled: boolean;
  readonly mcpServer: string;
  readonly agentName: string;
  readonly steps: readonly string[];
  readonly warnings: readonly string[];
}

export function createClient(config: SentinelConfig): TrueForge {
  return new TrueForge({ baseUrl: config.harnessUrl });
}

/** Fail early with an actionable message rather than a socket error later. */
export async function assertHarnessReachable(config: SentinelConfig): Promise<void> {
  try {
    const response = await fetch(`${config.harnessUrl}/api/v1/capabilities`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
  } catch (cause) {
    throw new SentinelError(
      "not_configured",
      `Cannot reach the TrueForge harness at ${config.harnessUrl} (${cause instanceof Error ? cause.message : "unknown"}).`,
      "Start it with: npx @truefoundry/trueforge@latest",
    );
  }
}

interface CatalogModel {
  readonly name: string;
  readonly model_id: string;
  readonly properties?: Record<string, unknown>;
}
interface CatalogProvider {
  readonly type: string;
  readonly models?: CatalogModel[];
}

async function fetchCatalog(config: SentinelConfig): Promise<CatalogProvider[]> {
  // Through the hardened wrapper, like every other outbound call: bounded
  // response size, retries, and typed errors instead of a bare socket message.
  const body = await httpJson<{ data?: CatalogProvider[] }>(
    `${config.harnessUrl}/api/v1/catalogs/model-providers`,
    { timeoutMs: 10_000 },
  );
  return body.data ?? [];
}

/**
 * Choose a model for the configured provider.
 *
 * Preference order: an explicit MODEL_ID that exists in the catalog, then a
 * name matching our quality preferences, then the first model listed.
 */
function chooseModel(
  provider: CatalogProvider,
  requestedModelId: string | null,
): CatalogModel {
  const models = provider.models ?? [];
  if (models.length === 0) {
    throw new SentinelError(
      "not_configured",
      `The harness catalog lists no models for provider "${provider.type}".`,
    );
  }

  if (requestedModelId !== null) {
    const exact = models.find(
      (m) => m.name === requestedModelId || m.model_id === requestedModelId,
    );
    if (exact !== undefined) return exact;
  }

  // Prefer a mid-tier "sonnet/pro/flash"-class model: this workload is many
  // cheap tool calls, so the largest reasoning model is usually wasted spend.
  const preferred = ["sonnet", "pro", "flash", "mini", "turbo"];
  for (const hint of preferred) {
    const match = models.find((m) => m.name.includes(hint));
    if (match !== undefined) return match;
  }
  return models[0] as CatalogModel;
}

async function provisionModelProvider(
  client: TrueForge,
  config: SentinelConfig,
  steps: string[],
): Promise<string> {
  const provider = config.provider;
  if (provider === null) {
    throw new SentinelError(
      "not_configured",
      "No model provider API key found.",
      "Add OPENAI_API_KEY, ANTHROPIC_API_KEY or GEMINI_API_KEY to your .env.",
    );
  }

  // Demo mode registers a `custom` OpenAI-compatible provider pointed at the
  // scripted endpoint, so the whole path is exercisable without a real key.
  if (provider.id === "demo") {
    await client.settings.modelProviders.createOrUpdate({
      manifest: {
        type: "custom",
        name: "custom",
        baseUrl: provider.baseUrl ?? "http://127.0.0.1:8899/v1",
        auth: { apiKey: provider.apiKey },
        models: [
          {
            name: "mock-model",
            modelId: "mock-model",
            properties: { contextLength: 128_000, maxOutputTokens: 4096 },
          },
        ],
      },
    });
    steps.push("DEMO MODE: scripted mock model registered (no real provider key in use).");
    return "custom/mock-model";
  }

  const catalog = await fetchCatalog(config);
  const entry = catalog.find((p) => p.type === provider.id);
  if (entry === undefined) {
    throw new SentinelError(
      "not_configured",
      `The harness does not offer a "${provider.id}" provider.`,
      `Available: ${catalog.map((p) => p.type).join(", ")}`,
    );
  }

  const model = chooseModel(entry, process.env.MODEL_ID ?? null);

  // createOrUpdate: safe to run on every boot, and rotates the key if changed.
  await client.settings.modelProviders.createOrUpdate({
    manifest: {
      type: provider.id,
      auth: { apiKey: provider.apiKey },
      models: [
        {
          name: model.name,
          modelId: model.model_id,
          properties: model.properties ?? {},
        },
      ],
    },
  });

  const fqn = `${provider.id}/${model.name}`;
  steps.push(`Model provider "${provider.id}" configured with ${model.name}.`);
  return fqn;
}

async function provisionSandbox(
  client: TrueForge,
  config: SentinelConfig,
  steps: string[],
  warnings: string[],
): Promise<boolean> {
  if (config.daytonaApiKey === null) {
    warnings.push(
      "No DAYTONA_API_KEY: the sandbox is disabled, so the agent cannot execute or test patches. " +
        "It has been instructed to report patches as unverified.",
    );
    return false;
  }
  try {
    await client.settings.sandboxProviders.createOrUpdate({
      manifest: {
        type: "daytona",
        auth: { apiKey: config.daytonaApiKey },
        execTimeoutMs: 120_000,
        autoStopIntervalInMinutes: 10,
        autoArchiveIntervalInMinutes: 60,
        autoDeleteIntervalInMinutes: 1440,
      },
    });
    steps.push("Daytona sandbox provider configured.");
    return true;
  } catch (cause) {
    warnings.push(
      `Sandbox provisioning failed (${cause instanceof Error ? cause.message : "unknown"}); continuing without a sandbox.`,
    );
    return false;
  }
}

async function provisionMcpServer(
  client: TrueForge,
  config: SentinelConfig,
  steps: string[],
): Promise<void> {
  await client.settings.mcpServers.createOrUpdate({
    manifest: {
      name: MCP_SERVER_NAME,
      type: "remote",
      url: config.mcpUrl,
      description:
        "SENTINEL supply-chain tools: dependency scanning, advisory lookup, blast-radius " +
        "assessment, patch proposal, and gated pull request creation.",
      auth: {
        type: "header",
        headers: { Authorization: `Bearer ${config.mcpToken}` },
      },
    },
  });
  steps.push(`MCP server "${MCP_SERVER_NAME}" registered at ${config.mcpUrl}.`);
}

async function provisionAgent(
  client: TrueForge,
  config: SentinelConfig,
  modelFqn: string,
  sandboxEnabled: boolean,
  steps: string[],
): Promise<void> {
  const spec = buildAgentSpec(config);
  // Use the model the catalog actually gave us, and reflect real sandbox state.
  const resolved: TrueForgeApi.AgentSpec = {
    ...spec,
    model: { name: modelFqn },
    config: { ...spec.config, sandbox: { enabled: sandboxEnabled, fileDownloads: true } },
  };

  const existing = await client.agents.list();
  const match = existing.data?.find((a) => a.name === AGENT_NAME);

  if (match === undefined) {
    await client.agents.create({ name: AGENT_NAME, manifest: resolved });
    steps.push(`Agent "${AGENT_NAME}" created.`);
  } else {
    await client.agents.update(match.id, { manifest: resolved });
    steps.push(`Agent "${AGENT_NAME}" updated.`);
  }
}

/**
 * Bring the harness to the state SENTINEL needs. Idempotent.
 */
export async function provision(config: SentinelConfig): Promise<ProvisionResult> {
  await assertHarnessReachable(config);
  const client = createClient(config);
  const steps: string[] = [];
  const warnings: string[] = [];

  const modelFqn = await provisionModelProvider(client, config, steps);
  const sandboxEnabled = await provisionSandbox(client, config, steps, warnings);
  await provisionMcpServer(client, config, steps);
  await provisionAgent(client, config, modelFqn, sandboxEnabled, steps);

  if (config.githubToken === null) {
    warnings.push("No GITHUB_TOKEN: scanning and pull request tools will refuse to run.");
  }
  if (!config.allowRemoteWrites) {
    warnings.push("Remote writes are disabled: the agent can plan a fix but not open a pull request.");
  }

  return {
    modelFqn,
    sandboxEnabled,
    mcpServer: MCP_SERVER_NAME,
    agentName: AGENT_NAME,
    steps,
    warnings,
  };
}
