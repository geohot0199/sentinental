/**
 * The lint gate is a safety control, not a style preference: `eslint.config.js`
 * claims that `@typescript-eslint/no-unsafe-*` keeps untrusted tool input from
 * flowing into GitHub writes without going through zod. That claim is only true
 * when the config actually supplies type information, and a config can be
 * edited into lying about it without anything else failing — swapping
 * `recommendedTypeChecked` for `recommended`, or dropping `projectService`,
 * keeps `npm run lint` green while every `no-unsafe-*` rule silently turns off.
 *
 * So these tests assert the behaviour rather than the text: they run the real
 * ESLint against a fixture that is unsafe and require it to be rejected.
 */
import { ESLint } from "eslint";
import { rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CONFIG = join(ROOT, "eslint.config.js");

/**
 * A fixture with no `any` token in it, so `no-explicit-any` cannot catch it:
 * `JSON.parse` returns `any`, which then flows into a typed local and out
 * through a return. This is exactly the shape the gate exists for.
 */
const UNSAFE_FIXTURE = `export function probe(rawText: string): string {
  const payload = JSON.parse(rawText);
  const cmd: string = payload.command;
  return cmd;
}
`;

/**
 * The fixture has to be a real file inside the TypeScript program for
 * `projectService` to resolve it, so it lives in `tests/` (covered by
 * `tsconfig.json`'s include) and is removed on the way out.
 */
const FIXTURE_PATH = join(ROOT, "tests", "__eslint_gate_probe.ts");
const FIXTURE_REL = "tests/__eslint_gate_probe.ts";

const eslint = new ESLint({ cwd: ROOT, overrideConfigFile: CONFIG });

async function lintFixture(source: string): Promise<string[]> {
  writeFileSync(FIXTURE_PATH, source, "utf8");
  const results = await eslint.lintFiles([FIXTURE_REL]);
  return results.flatMap((result) => result.messages.map((message) => message.ruleId ?? ""));
}

afterAll(() => {
  rmSync(FIXTURE_PATH, { force: true });
});

describe("the lint gate's type-aware rules", () => {
  it("rejects an implicit `any` flowing out of JSON.parse", async () => {
    const rules = await lintFixture(UNSAFE_FIXTURE);

    expect(rules).toContain("@typescript-eslint/no-unsafe-assignment");
    expect(rules).toContain("@typescript-eslint/no-unsafe-member-access");
  });

  it("rejects an implicit `any` passed into a typed parameter", async () => {
    const rules = await lintFixture(
      `export function probe(rawText: string): number {
  const payload = JSON.parse(rawText);
  return sendToShell(payload.command);
}
function sendToShell(command: string): number {
  return command.length;
}
`,
    );

    expect(rules).toContain("@typescript-eslint/no-unsafe-argument");
  });

  it("stays quiet about a validated read of the same input", async () => {
    // The counter-case: narrowing the parsed value must be enough to satisfy
    // the gate, otherwise the rule is noise and people will disable it.
    const rules = await lintFixture(
      `export function probe(rawText: string): string {
  const payload = JSON.parse(rawText) as { command?: unknown };
  return typeof payload.command === "string" ? payload.command : "";
}
`,
    );

    expect(rules.filter((rule) => rule.includes("no-unsafe"))).toEqual([]);
  });

  it("supplies the TypeScript program, which is what makes the rules real", async () => {
    // ESLint types `calculateConfigForFile` as `Promise<any>`, so narrow it
    // here rather than letting that `any` into the assertions below.
    const config = (await eslint.calculateConfigForFile("src/core/config.ts")) as {
      languageOptions?: { parserOptions?: Record<string, unknown> };
    };
    const parserOptions = config.languageOptions?.parserOptions;

    expect(parserOptions?.projectService).toBe(true);
    expect(parserOptions?.tsconfigRootDir).toBe(ROOT);
  });

  it("lints the config file itself, which sits outside the TypeScript program", async () => {
    // `recommendedTypeChecked` installs its parser and its type-aware rules for
    // every file. Without the `disableTypeChecked` override, ESLint aborts on
    // `eslint.config.js` with "a rule which requires type information, but
    // don't have parserOptions set" — which would fail every lint run.
    const results = await eslint.lintFiles(["eslint.config.js"]);

    expect(results).toHaveLength(1);
    expect(results[0]?.fatalErrorCount).toBe(0);
    expect(results[0]?.messages.filter((m) => m.fatal)).toEqual([]);
  });

  it("leaves the vendored browser bundles outside the gate entirely", async () => {
    // Hand-written bundles served as-is and excluded from tsconfig, so they
    // must never be handed to the TypeScript parser.
    for (const path of ["src/web/public/app.js", "site/js/agent.js", "site/serve.mjs"]) {
      expect(await eslint.isPathIgnored(path)).toBe(true);
    }
  });
});
