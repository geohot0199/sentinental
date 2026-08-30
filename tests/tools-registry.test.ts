/**
 * The tool registry is the approval surface: TrueForge resolves its
 * `@read-only` / `@write` / `@destructive` selectors from the annotations
 * registered here, so a tool missing from the registry is a tool the agent
 * cannot call, and one registered twice is a policy conflict.
 *
 * `tools.ts` is a barrel over `src/mcp/tools/*.ts`. These tests pin the mapping
 * between the two so the split cannot drift: one module per tool, one tool per
 * module, name matching filename, registry listing every module.
 */
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { DESTRUCTIVE_TOOLS, TOOLS, type ToolDefinition } from "../src/mcp/tools.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const TOOLS_DIR = resolve(HERE, "..", "src", "mcp", "tools");

/** `scan-dependencies.ts` -> `scan_dependencies`. */
function expectedToolName(file: string): string {
  const stem = file.replace(/\.ts$/, "");
  return stem.replaceAll("-", "_");
}

function toolsIn(mod: Record<string, unknown>): ToolDefinition[] {
  return Object.values(mod).filter(
    (value): value is ToolDefinition =>
      typeof value === "object" &&
      value !== null &&
      "name" in value &&
      "handler" in value &&
      "annotations" in value,
  );
}

/** Every tool module on disk, keyed by filename. `shared.ts` is not one. */
const toolFiles = readdirSync(TOOLS_DIR)
  .filter((f) => f.endsWith(".ts") && f !== "shared.ts")
  .sort();

const loaded = new Map<string, Record<string, unknown>>();

beforeAll(async () => {
  for (const file of [...toolFiles, "shared.ts"]) {
    loaded.set(file, (await import(pathToFileURL(resolve(TOOLS_DIR, file)).href)) as Record<string, unknown>);
  }
});

describe("per-tool module layout", () => {
  it("has one module per registered tool, and nothing else", () => {
    expect(toolFiles.length).toBe(TOOLS.length);
    expect(toolFiles.map(expectedToolName).sort()).toEqual(TOOLS.map((t) => t.name).sort());
  });

  it("exports exactly one tool per module, named after the file", () => {
    for (const file of toolFiles) {
      const tools = toolsIn(loaded.get(file) ?? {});
      expect(tools, `${file} exports ${tools.length} tools`).toHaveLength(1);
      expect(tools[0]?.name, file).toBe(expectedToolName(file));
    }
  });

  it("keeps every tool module under the size the lint gate enforces", () => {
    // 300 is the review budget for one tool: past it, a reviewer stops reading
    // the annotation that decides whether a human is asked first.
    for (const file of [...toolFiles, "shared.ts"]) {
      const source = readFileSync(resolve(TOOLS_DIR, file), "utf8");
      expect(source.split("\n").length, file).toBeLessThanOrEqual(300);
    }
  });

  it("keeps shared helpers out of the tool modules", () => {
    const shared = loaded.get("shared.ts") ?? {};
    expect(toolsIn(shared), "shared.ts must not define a tool").toHaveLength(0);
    expect(typeof shared.readOnly).toBe("function");
    expect(typeof shared.assertWritesAllowed).toBe("function");
  });
});

describe("tool registry integrity", () => {
  it("registers every tool exactly once", () => {
    const names = TOOLS.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
    expect([...names].sort()).toEqual(toolFiles.map(expectedToolName).sort());
  });

  it("derives the destructive list from the annotations, not a hardcoded set", () => {
    expect([...DESTRUCTIVE_TOOLS].sort()).toEqual(
      TOOLS.filter((t) => t.annotations.destructiveHint)
        .map((t) => t.name)
        .sort(),
    );
  });

  it("gives every tool a title, description, schema and handler", () => {
    for (const tool of TOOLS) {
      expect(tool.annotations.title.length, tool.name).toBeGreaterThan(0);
      expect(tool.description.length, tool.name).toBeGreaterThan(20);
      expect(typeof tool.inputSchema, tool.name).toBe("object");
      expect(typeof tool.handler, tool.name).toBe("function");
    }
  });
});
