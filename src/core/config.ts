/**
 * Central configuration. Every secret enters the process here and nowhere else,
 * which is what makes the leak-scanning story defensible.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/** Model providers we know how to provision into TrueForge. */
export const SUPPORTED_PROVIDERS = ["openai", "anthropic", "google-gemini"] as const;
export type ProviderId = (typeof SUPPORTED_PROVIDERS)[number];

export interface ProviderConfig {
  /** `demo` is the scripted mock endpoint, not a real provider. */
  readonly id: ProviderId | "demo";
  /** Env var holding the key. Never the key itself in any log or error. */
  readonly envVar: string;
  readonly apiKey: string;
  /** Default model id used when the operator does not override it. */
  readonly modelId: string;
  /** Fully-qualified name the harness uses: `provider/model`. */
  readonly fqn: string;
  /** Only set in demo mode, where we register a custom OpenAI-compatible base. */
  readonly baseUrl?: string;
}

export interface SentinelConfig {
  /** Base URL of the running TrueForge harness. */
  readonly harnessUrl: string;
  /** Port our MCP tool server listens on. */
  readonly mcpPort: number;
  /** URL the harness uses to reach our MCP server. */
  readonly mcpUrl: string;
  /** Shared secret the harness presents to our MCP server. */
  readonly mcpToken: string;
  readonly webPort: number;
  readonly provider: ProviderConfig | null;
  readonly githubToken: string | null;
  readonly daytonaApiKey: string | null;
  /** Repository SENTINEL triages by default, as `owner/name`. */
  readonly targetRepo: string | null;
  /** When false, destructive tools are refused outright, before approval. */
  readonly allowRemoteWrites: boolean;
}

const PROVIDER_ENV: Record<ProviderId, { envVar: string; defaultModel: string }> = {
  openai: { envVar: "OPENAI_API_KEY", defaultModel: "gpt-4.1" },
  anthropic: { envVar: "ANTHROPIC_API_KEY", defaultModel: "claude-sonnet-4-20250514" },
  "google-gemini": { envVar: "GEMINI_API_KEY", defaultModel: "gemini-2.0-flash" },
};

/**
 * Minimal .env loader. We avoid a dependency here on purpose: fewer packages in
 * the path of a secret is a security property, not a style preference.
 */
export function loadDotEnv(cwd: string = process.cwd()): void {
  let raw: string;
  try {
    raw = readFileSync(resolve(cwd, ".env"), "utf8");
  } catch {
    return; // absent .env is normal
  }
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    // Real environment always wins over the file.
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

function readOptional(name: string): string | null {
  const value = process.env[name];
  if (value === undefined) return null;
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

function readPort(name: string, fallback: number): number {
  const raw = readOptional(name);
  if (raw === null) return fallback;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be an integer between 1 and 65535, got "${raw}"`);
  }
  return port;
}

function readBool(name: string, fallback: boolean): boolean {
  const raw = readOptional(name);
  if (raw === null) return fallback;
  return ["1", "true", "yes", "on"].includes(raw.toLowerCase());
}

/** Resolve which model provider to use, preferring an explicit MODEL_PROVIDER. */
export function resolveProvider(): ProviderConfig | null {
  // Demo mode: point the harness at a scripted OpenAI-compatible endpoint so the
  // full path (harness -> tools -> approval gate) is drivable with no API key.
  const demoBaseUrl = readOptional("SENTINEL_DEMO_MODEL_URL");
  if (demoBaseUrl !== null) {
    return {
      id: "demo",
      envVar: "SENTINEL_DEMO_MODEL_URL",
      apiKey: "unused-in-demo-mode",
      modelId: "mock-model",
      fqn: "custom/mock-model",
      baseUrl: demoBaseUrl,
    };
  }

  const explicit = readOptional("MODEL_PROVIDER") as ProviderId | null;
  const order: readonly ProviderId[] =
    explicit !== null && SUPPORTED_PROVIDERS.includes(explicit)
      ? [explicit]
      : SUPPORTED_PROVIDERS;

  for (const id of order) {
    const spec = PROVIDER_ENV[id];
    const apiKey = readOptional(spec.envVar);
    if (apiKey === null) continue;
    const modelId = readOptional("MODEL_ID") ?? spec.defaultModel;
    return { id, envVar: spec.envVar, apiKey, modelId, fqn: `${id}/${modelId}` };
  }
  return null;
}

/**
 * Generate a shared secret for the MCP server when the operator has not set
 * one. Random per boot, so a leaked value from a demo recording is already dead.
 */
function resolveMcpToken(): string {
  const configured = readOptional("SENTINEL_MCP_TOKEN");
  if (configured !== null) return configured;
  return `sn_${globalThis.crypto.randomUUID().replaceAll("-", "")}`;
}

export function loadConfig(): SentinelConfig {
  loadDotEnv();
  const mcpPort = readPort("SENTINEL_MCP_PORT", 8791);
  return {
    harnessUrl: (readOptional("TRUEFORGE_URL") ?? "http://127.0.0.1:8790").replace(/\/+$/, ""),
    mcpPort,
    mcpUrl: readOptional("SENTINEL_MCP_URL") ?? `http://127.0.0.1:${mcpPort}/mcp`,
    mcpToken: resolveMcpToken(),
    webPort: readPort("SENTINEL_WEB_PORT", 3000),
    provider: resolveProvider(),
    githubToken: readOptional("GITHUB_TOKEN"),
    daytonaApiKey: readOptional("DAYTONA_API_KEY"),
    targetRepo: readOptional("SENTINEL_TARGET_REPO"),
    allowRemoteWrites: readBool("SENTINEL_ALLOW_REMOTE_WRITES", true),
  };
}

/** Human-readable capability report, used by both clients at startup. */
export interface CapabilityReport {
  readonly model: boolean;
  readonly sandbox: boolean;
  readonly github: boolean;
  readonly notes: readonly string[];
}

export function describeCapabilities(config: SentinelConfig): CapabilityReport {
  const notes: string[] = [];
  if (config.provider === null) {
    notes.push(
      `No model key found. Set one of: ${SUPPORTED_PROVIDERS.map((p) => PROVIDER_ENV[p].envVar).join(", ")}`,
    );
  }
  if (config.daytonaApiKey === null) {
    notes.push("DAYTONA_API_KEY not set - sandbox disabled, patches will be reported as unverified.");
  }
  if (config.githubToken === null) {
    notes.push("GITHUB_TOKEN not set - pull request tools will refuse to run.");
  }
  if (!config.allowRemoteWrites) {
    notes.push("SENTINEL_ALLOW_REMOTE_WRITES=false - destructive tools are hard-disabled.");
  }
  return {
    model: config.provider !== null,
    sandbox: config.daytonaApiKey !== null,
    github: config.githubToken !== null,
    notes,
  };
}
