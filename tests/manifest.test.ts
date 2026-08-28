import { describe, expect, it } from "vitest";
import { SentinelError } from "../src/core/errors.ts";
import { isValidPackageName, parseLockfile, scanManifest } from "../src/core/manifest.ts";

describe("isValidPackageName", () => {
  it("accepts ordinary and scoped names", () => {
    expect(isValidPackageName("lodash")).toBe(true);
    expect(isValidPackageName("@truefoundry/trueforge-sdk")).toBe(true);
    expect(isValidPackageName("a-b.c_d")).toBe(true);
  });

  it("rejects names that could alter a request path", () => {
    for (const bad of ["", "../evil", "UPPERCASE", "has space", "a/b/c", ".hidden", "a".repeat(215)]) {
      expect(isValidPackageName(bad), bad).toBe(false);
    }
  });
});

describe("parseLockfile", () => {
  it("reads a v3 lockfile keyed by install path", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/minimist": { version: "1.2.6" },
      },
    });
    const resolved = parseLockfile(lock);
    expect(resolved.get("lodash")).toBe("4.17.21");
    expect(resolved.get("minimist")).toBe("1.2.6");
    expect(resolved.has("")).toBe(false);
  });

  it("prefers the shallowest copy of a nested duplicate", () => {
    const lock = JSON.stringify({
      packages: {
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/other/node_modules/lodash": { version: "3.0.0" },
      },
    });
    expect(parseLockfile(lock).get("lodash")).toBe("4.17.21");
  });

  it("reads a v1 lockfile", () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { lodash: { version: "4.17.21" } },
    });
    expect(parseLockfile(lock).get("lodash")).toBe("4.17.21");
  });

  it("throws a typed error on malformed JSON", () => {
    expect(() => parseLockfile("{not json")).toThrow(SentinelError);
  });
});

describe("scanManifest", () => {
  const pkg = JSON.stringify({
    name: "demo",
    dependencies: { lodash: "^4.17.11", express: "~4.18.0" },
    devDependencies: { vitest: "^3.0.0" },
  });

  it("prefers lockfile versions over declared ranges", () => {
    const lock = JSON.stringify({
      packages: { "node_modules/lodash": { version: "4.17.11" } },
    });
    const scan = scanManifest(pkg, lock, "package-lock.json");
    const lodash = scan.dependencies.find((d) => d.name === "lodash");
    expect(lodash?.version).toBe("4.17.11");
    expect(lodash?.resolved).toBe(true);
  });

  // The distinction that stops us reporting a guess as a fact.
  it("flags a version estimated from a range as unresolved", () => {
    const scan = scanManifest(pkg, null, null);
    const express = scan.dependencies.find((d) => d.name === "express");
    expect(express?.version).toBe("4.18.0");
    expect(express?.resolved).toBe(false);
    expect(scan.warnings.join(" ")).toMatch(/No lockfile/i);
  });

  it("records the scope of each dependency", () => {
    const scan = scanManifest(pkg, null, null);
    expect(scan.dependencies.find((d) => d.name === "lodash")?.scope).toBe("production");
    expect(scan.dependencies.find((d) => d.name === "vitest")?.scope).toBe("development");
  });

  it("skips non-registry specifiers with a warning instead of guessing", () => {
    const local = JSON.stringify({
      dependencies: { mine: "file:../mine", forked: "github:me/forked" },
    });
    const scan = scanManifest(local, null, null);
    expect(scan.dependencies).toHaveLength(0);
    expect(scan.warnings.join(" ")).toMatch(/non-registry/);
  });

  it("skips a dependency whose name could alter a URL", () => {
    const hostile = JSON.stringify({ dependencies: { "../../evil": "1.0.0" } });
    const scan = scanManifest(hostile, null, null);
    expect(scan.dependencies).toHaveLength(0);
    expect(scan.warnings.join(" ")).toMatch(/invalid package name/i);
  });

  it("degrades to declared ranges when the lockfile is corrupt", () => {
    const scan = scanManifest(pkg, "{broken", "package-lock.json");
    expect(scan.dependencies.length).toBeGreaterThan(0);
    expect(scan.warnings.join(" ")).toMatch(/could not be parsed/i);
  });

  it("throws on a malformed package.json", () => {
    expect(() => scanManifest("{not json")).toThrow(SentinelError);
  });
});
