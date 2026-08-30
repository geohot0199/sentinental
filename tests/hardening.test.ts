/**
 * Regression coverage for the hardening pass.
 *
 * Each test here exists because the behaviour it pins was once broken in a way
 * that mattered: a scan deleted mid-run killed the process, a malformed URL
 * escape killed the static server, deleting a running scan raced the pipeline,
 * request bodies were unbounded, the rate limit was keyed on a spoofable
 * header, a model-supplied regex could throw, and the escrow tool leaked its
 * own signing key. If you delete one of these tests, you re-open the bug.
 */
import { describe, expect, it } from "vitest";
import { pathToFileURL } from "node:url";
import { describeCapabilities, type SentinelConfig } from "../src/core/config.ts";
import { decodeUrlPath } from "../src/server/api.ts";
import { isEntrypoint } from "../src/core/serve.ts";
import { SentinelDb } from "../src/server/db.ts";
import { Scanner } from "../src/server/scanner.ts";
import { buildApp } from "../src/server/api.ts";
import {
  WEBMCP_TOOLS_CATALOG,
  type WebMCPToolDefinition,
} from "../src/webmcp/index.ts";
import { ZkEscrow } from "../src/webmcp/index.ts";

const config: SentinelConfig = {
  harnessUrl: "http://127.0.0.1:8790",
  mcpPort: 8791,
  mcpUrl: "http://127.0.0.1:8791/mcp",
  mcpToken: "sn_aaaabbbbccccddddeeeeffffaaaabbbb",
  webPort: 3000,
  provider: null,
  githubToken: null,
  daytonaApiKey: null,
  targetRepo: null,
  allowRemoteWrites: false,
};

function appWith(db: SentinelDb): ReturnType<typeof buildApp> {
  return buildApp({ config, db, scanner: new Scanner(db, config) });
}

const NO_DEPS_MANIFEST = JSON.stringify({ name: "tiny", private: true });

// ---------------------------------------------------------------------------
// 01. A scan deleted mid-run must not throw out of Scanner.run
// ---------------------------------------------------------------------------

describe("Scanner resilience against a concurrently deleted scan", () => {
  it("resolves quietly when the scan row vanishes mid-run", async () => {
    const db = new SentinelDb(":memory:");
    const scanner = new Scanner(db, config);
    db.createScan("s1", "manifest", "pasted manifest", NO_DEPS_MANIFEST);

    // Simulate DELETE arriving between pipeline steps: remove the row the
    // moment the first progress event is written.
    let deleted = false;
    scanner.subscribe("s1", () => {
      if (!deleted) {
        deleted = true;
        db.deleteScan("s1");
      }
    });

    // Before the fix this threw `FOREIGN KEY constraint failed` out of run(),
    // which the API layer fires with `void` - an unhandled rejection that
    // terminates the process.
    await expect(scanner.run("s1")).resolves.toBeUndefined();
    db.close();
  });

  it("resolves quietly when the scan is already gone", async () => {
    const db = new SentinelDb(":memory:");
    const scanner = new Scanner(db, config);
    await expect(scanner.run("missing")).resolves.toBeUndefined();
    db.close();
  });
});

// ---------------------------------------------------------------------------
// 02. DELETE /api/scans/:id refuses in-flight scans instead of racing them
// ---------------------------------------------------------------------------

describe("DELETE /api/scans/:id", () => {
  it("returns 409 for a queued scan and 200 once it is finished", async () => {
    const db = new SentinelDb(":memory:");
    const app = appWith(db);
    db.createScan("s1", "manifest", "pasted manifest", NO_DEPS_MANIFEST);

    const busy = await app.request("/api/scans/s1", { method: "DELETE" });
    expect(busy.status).toBe(409);

    db.setScanStatus("s1", "done");
    const finished = await app.request("/api/scans/s1", { method: "DELETE" });
    expect(finished.status).toBe(200);
    db.close();
  });

  it("returns 404 for an unknown scan", async () => {
    const db = new SentinelDb(":memory:");
    const response = await appWith(db).request("/api/scans/nope", { method: "DELETE" });
    expect(response.status).toBe(404);
    db.close();
  });
});

// ---------------------------------------------------------------------------
// 03. Malformed URL escapes answer 404, never a 500 or a dead process
// ---------------------------------------------------------------------------

describe("static file serving under hostile paths", () => {
  it.each([
    ["/%E0%A4%A", 404], // malformed UTF-8 escape (URIError before the fix)
    ["/../../etc/passwd", 404],
    ["/%2e%2e/%2e%2e/etc/passwd", 404],
    ["/labs", 200], // sanity: legitimate extensionless route still works
  ])("%s -> %i", async (path, expected) => {
    const db = new SentinelDb(":memory:");
    const response = await appWith(db).request(path);
    expect(response.status).toBe(expected);
    db.close();
  });
});

describe("decodeUrlPath", () => {
  it("decodes ordinary and escaped paths", () => {
    expect(decodeUrlPath("/labs.html?x=1#frag")).toBe("/labs.html");
    expect(decodeUrlPath("/a%20b")).toBe("/a b");
  });

  it("returns null instead of throwing on a malformed escape", () => {
    expect(decodeUrlPath("/%E0%A4%A")).toBeNull();
    expect(decodeUrlPath("/%ZZ")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 04. Request bodies are bounded before handlers run
// ---------------------------------------------------------------------------

describe("body size limit", () => {
  it("answers 413 for an oversized manifest instead of parsing it", async () => {
    const db = new SentinelDb(":memory:");
    const huge = JSON.stringify({
      name: "bloat",
      dependencies: Object.fromEntries(
        Array.from({ length: 80_000 }, (_, i) => [`pkg-${i}`, "1.0.0"]),
      ),
    });
    expect(huge.length).toBeGreaterThan(1024 * 1024);

    const response = await appWith(db).request("/api/scans", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest: huge }),
    });
    expect(response.status).toBe(413);
    db.close();
  });
});

// ---------------------------------------------------------------------------
// 05. The rate limit keys on the proxy-appended hop, not a spoofable first one
// ---------------------------------------------------------------------------

describe("scan rate limiting", () => {
  function scanRequest(lastHop: string, spoofedFirst: string): RequestInit {
    return {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": `${spoofedFirst}, ${lastHop}`,
      },
      body: JSON.stringify({ repo: "owner/repo" }),
    };
  }

  it("blocks the 11th request from one client even with rotated first hops", async () => {
    const db = new SentinelDb(":memory:");
    const app = appWith(db);

    // repo scans without a GITHUB_TOKEN stop at 503 *after* the limiter, so a
    // 503 means "limit passed" and a 429 means "limit hit".
    for (let i = 0; i < 10; i += 1) {
      const response = await app.request("/api/scans", scanRequest("10.0.0.1", `spoof-${i}`));
      expect(response.status).toBe(503);
    }
    const blocked = await app.request("/api/scans", scanRequest("10.0.0.1", "spoof-final"));
    expect(blocked.status).toBe(429);
    db.close();
  });

  it("keeps distinct clients distinct", async () => {
    const db = new SentinelDb(":memory:");
    const app = appWith(db);
    for (let i = 0; i < 10; i += 1) {
      await app.request("/api/scans", scanRequest("10.0.0.1", `spoof-${i}`));
    }
    // A different nearest hop is a different bucket.
    const other = await app.request("/api/scans", scanRequest("10.0.0.2", "spoof-0"));
    expect(other.status).toBe(503);
    db.close();
  });
});

// ---------------------------------------------------------------------------
// 06. Model-supplied taint patterns can no longer throw
// ---------------------------------------------------------------------------

describe("breachlab_trace_taint_flow with hostile patterns", () => {
  async function runTaint(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    const tool = WEBMCP_TOOLS_CATALOG.find((t) => t.name === "breachlab_trace_taint_flow");
    expect(tool).toBeDefined();
    return (await (tool as WebMCPToolDefinition).execute(input)) as Record<string, unknown>;
  }

  it("survives an invalid regex instead of throwing SyntaxError", async () => {
    const result = await runTaint({
      code: "const a = req.query.x;\nvoid a;",
      sourcePattern: "([bad",
      sinkPattern: "eval(",
    });
    expect(Array.isArray(result.taintTrace)).toBe(true);
    expect(result.sourcePattern).toBe("([bad");
  });

  it("survives a pathological pattern without hanging", async () => {
    const result = await runTaint({
      code: "const a = req.query.x;",
      sourcePattern: "(a+)+$",
      sinkPattern: "eval",
    });
    expect(Array.isArray(result.taintTrace)).toBe(true);
  });

  it("ignores absurdly long patterns and uses the default instead", async () => {
    const result = await runTaint({
      code: "const a = req.query.x;\nvoid a;",
      sourcePattern: "req.query",
      sinkPattern: "x".repeat(5000),
    });
    expect(Array.isArray(result.taintTrace)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 07. The escrow tool must not hand its signing key to the caller
// ---------------------------------------------------------------------------

describe("zkescrow_initiate_contract key redaction", () => {
  it("returns a fingerprint, never the arbiter HMAC key", async () => {
    const tool = WEBMCP_TOOLS_CATALOG.find((t) => t.name === "zkescrow_initiate_contract");
    expect(tool).toBeDefined();
    const result = (await (tool as WebMCPToolDefinition).execute({
      contractorName: "Dev A",
      clientName: "Client B",
    })) as Record<string, unknown>;

    expect(typeof result.arbiterSecretKey).toBe("string");
    expect(result.arbiterSecretKey).toMatch(/^fingerprint:[0-9a-f]{16}$/);
  });

  it("still funds the contract and reports real milestones", async () => {
    const tool = WEBMCP_TOOLS_CATALOG.find((t) => t.name === "zkescrow_initiate_contract");
    const result = (await (tool as WebMCPToolDefinition).execute({
      contractorName: "Dev A",
      clientName: "Client B",
    })) as Record<string, unknown>;

    expect(result.contractState).toBe("FUNDED");
    expect(result.totalEscrowAmountUsd).toBe(1000);
    expect(Array.isArray(result.milestones)).toBe(true);
  });

  it("keeps the real key available to the engine for signing", () => {
    // The engine-level contract (used by signEscrowRelease) is unchanged.
    expect(ZkEscrow.DEMO_CONTRACT.arbiterSecretKey).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// 08. describeCapabilities stays boolean-only (pins the status route contract)
// ---------------------------------------------------------------------------

describe("capability report", () => {
  it("never contains a raw credential value", () => {
    const report = describeCapabilities({
      ...config,
      githubToken: "ghp_supersecretvalue123456",
      mcpToken: "sn_aaaabbbbccccddddeeeeffffaaaabbbb",
    });
    const flattened = JSON.stringify(report);
    expect(flattened).not.toContain("ghp_supersecretvalue123456");
    expect(flattened).not.toContain("sn_aaaabbbbccccddddeeeeffffaaaabbbb");
  });
});

// ---------------------------------------------------------------------------
// 09. isEntrypoint judges the *caller's* module URL, never its own
// ---------------------------------------------------------------------------

describe("isEntrypoint", () => {
  it("recognises the process entry script", () => {
    // Under vitest argv[1] is the vitest binary; whatever it is, its file URL
    // must be recognised.
    const entry = process.argv[1];
    expect(entry).toBeDefined();
    expect(isEntrypoint(pathToFileURL(entry as string).href)).toBe(true);
  });

  it("rejects every other module URL", () => {
    // Before this took a parameter, it compared its own module URL against
    // argv[1] - which made every server silently refuse to start under
    // `node src/...` while the tests still passed.
    expect(isEntrypoint("file:///somewhere/else/entry.ts")).toBe(false);
  });
});
