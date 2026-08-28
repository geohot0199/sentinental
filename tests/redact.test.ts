import { beforeEach, describe, expect, it } from "vitest";
import {
  __clearSecretsForTest,
  fingerprint,
  redact,
  redactDeep,
  registerSecret,
} from "../src/core/redact.ts";

beforeEach(() => {
  __clearSecretsForTest();
});

describe("redact - registered values", () => {
  it("masks an exact registered secret", () => {
    registerSecret("super-secret-value-123");
    expect(redact("token is super-secret-value-123 ok")).toBe("token is [REDACTED] ok");
  });

  it("masks every occurrence", () => {
    registerSecret("repeated-secret-value");
    const out = redact("repeated-secret-value and repeated-secret-value");
    expect(out).toBe("[REDACTED] and [REDACTED]");
    expect(out).not.toContain("repeated-secret-value");
  });

  it("ignores values too short to be a credential", () => {
    registerSecret("abc");
    expect(redact("abc is a common word")).toBe("abc is a common word");
  });

  it("masks the longer secret first when one contains another", () => {
    registerSecret("secretvalue");
    registerSecret("secretvalue-extended-form");
    expect(redact("secretvalue-extended-form")).toBe("[REDACTED]");
  });
});

describe("redact - credential shapes", () => {
  const cases: [string, string][] = [
    ["github classic", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
    ["github fine-grained", "github_pat_11ABCDEFG0abcdefghijkl_ABCDEFGHIJKLMNOP"],
    ["openai", "sk-abcdefghijklmnopqrstuvwxyz0123456789"],
    ["openai project", "sk-proj-abcdefghijklmnopqrstuvwxyz0123"],
    ["anthropic", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"],
    ["google", "AIzaSyA1234567890abcdefghijklmnopqrstuvw"],
    // Built at runtime so the fixture cannot be mistaken for a real credential
    // by GitHub secret scanning; the resulting value still has the exact Slack
    // shape the redactor must catch.
    ["slack", ["xoxb", "123456789012", "abcdefghijklmnop"].join("-")],
    ["aws", "AKIAIOSFODNN7EXAMPLE"],
    ["daytona", "dtn_abcdefghijklmnop1234567890"],
    ["jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"],
  ];

  for (const [name, secret] of cases) {
    it(`masks a ${name} token it has never seen before`, () => {
      const output = redact(`credential: ${secret} end`);
      expect(output).not.toContain(secret);
      expect(output).toContain("[REDACTED]");
    });
  }

  it("masks a PEM private key block", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc123\n-----END RSA PRIVATE KEY-----";
    expect(redact(pem)).toBe("[REDACTED]");
  });

  it("leaves ordinary prose untouched", () => {
    const text = "Upgrade lodash from 4.17.11 to 4.18.0 to clear GHSA-r5fr-rjxr-66jc.";
    expect(redact(text)).toBe(text);
  });

  it("is repeatable - a global regex must not leak state between calls", () => {
    const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    const first = redact(secret);
    const second = redact(secret);
    expect(first).toBe("[REDACTED]");
    expect(second).toBe("[REDACTED]");
  });
});

describe("redactDeep", () => {
  it("masks values under sensitive keys regardless of shape", () => {
    const input = { apiKey: "anything-at-all", nested: { authorization: "Bearer xyz" } };
    const output = redactDeep(input);
    expect(output.apiKey).toBe("[REDACTED]");
    expect(output.nested.authorization).toBe("[REDACTED]");
  });

  it("matches sensitive key names case-insensitively and with prefixes", () => {
    const output = redactDeep({
      GITHUB_TOKEN: "abcdefghijklmnop",
      api_key: "abcdefghijklmnop",
      Password: "hunter2000",
    });
    expect(Object.values(output)).toEqual(["[REDACTED]", "[REDACTED]", "[REDACTED]"]);
  });

  it("still pattern-redacts values under innocuous keys", () => {
    const output = redactDeep({ note: "use ghp_abcdefghijklmnopqrstuvwxyz0123456789 here" });
    expect(output.note).not.toContain("ghp_");
  });

  it("walks arrays", () => {
    const output = redactDeep([{ token: "abcdefghijklmnop" }, "plain"]);
    expect(output[0]).toEqual({ token: "[REDACTED]" });
    expect(output[1]).toBe("plain");
  });

  it("preserves non-string primitives", () => {
    const output = redactDeep({ count: 42, ok: true, missing: null });
    expect(output).toEqual({ count: 42, ok: true, missing: null });
  });

  it("does not hang on a deeply nested structure", () => {
    let nested: Record<string, unknown> = { token: "abcdefghijklmnop" };
    for (let i = 0; i < 100; i += 1) nested = { child: nested };
    expect(() => redactDeep(nested)).not.toThrow();
  });
});

describe("fingerprint", () => {
  it("shows enough to identify a key but not to use it", () => {
    const fp = fingerprint("ghp_abcdefghijklmnopqrstuvwxyz");
    expect(fp).toContain("ghp_");
    expect(fp).not.toContain("abcdefghijklmnop");
  });

  it("fully masks a short value", () => {
    expect(fingerprint("short")).toBe("[REDACTED]");
  });
});
