import { describe, expect, it } from "vitest";
import {
  classifyBump,
  cleanVersion,
  compareVersions,
  parseVersion,
  versionInRange,
} from "../src/core/semver.ts";

describe("parseVersion", () => {
  it("parses a plain version", () => {
    expect(parseVersion("4.17.11")).toEqual({
      major: 4,
      minor: 17,
      patch: 11,
      prerelease: [],
    });
  });

  it("fills in omitted minor and patch", () => {
    expect(parseVersion("2")).toMatchObject({ major: 2, minor: 0, patch: 0 });
    expect(parseVersion("2.5")).toMatchObject({ major: 2, minor: 5, patch: 0 });
  });

  it("strips range operators and build metadata", () => {
    expect(parseVersion("^1.2.3")).toMatchObject({ major: 1, minor: 2, patch: 3 });
    expect(parseVersion("v1.2.3+build.99")).toMatchObject({ major: 1, minor: 2, patch: 3 });
  });

  it("captures prerelease identifiers", () => {
    expect(parseVersion("1.0.0-rc.1")?.prerelease).toEqual(["rc", "1"]);
  });

  it("returns null rather than guessing at junk", () => {
    for (const bad of ["", "not-a-version", "latest", "*", "1.2.3.4.5-!!"]) {
      expect(parseVersion(bad), bad).toBeNull();
    }
  });
});

describe("compareVersions", () => {
  it("orders by major, minor, then patch", () => {
    expect(compareVersions("1.0.0", "2.0.0")).toBe(-1);
    expect(compareVersions("1.2.0", "1.1.9")).toBe(1);
    expect(compareVersions("1.1.1", "1.1.1")).toBe(0);
  });

  it("ranks a release above its own prerelease", () => {
    expect(compareVersions("1.0.0", "1.0.0-rc.1")).toBe(1);
    expect(compareVersions("1.0.0-rc.1", "1.0.0")).toBe(-1);
  });

  it("orders prerelease identifiers per semver rules", () => {
    expect(compareVersions("1.0.0-alpha", "1.0.0-beta")).toBe(-1);
    expect(compareVersions("1.0.0-alpha.1", "1.0.0-alpha.2")).toBe(-1);
    // Numeric identifiers rank below alphanumeric ones.
    expect(compareVersions("1.0.0-1", "1.0.0-alpha")).toBe(-1);
    // A longer identifier set outranks a shorter prefix of it.
    expect(compareVersions("1.0.0-alpha", "1.0.0-alpha.1")).toBe(-1);
  });

  it("compares numeric identifiers numerically, not lexically", () => {
    expect(compareVersions("1.0.0-2", "1.0.0-10")).toBe(-1);
  });

  it("throws on unparseable input instead of silently returning 0", () => {
    expect(() => compareVersions("garbage", "1.0.0")).toThrow(/Unparseable/);
  });
});

describe("versionInRange", () => {
  it("matches real advisory ranges", () => {
    expect(versionInRange("4.17.11", ">= 4.0.0, < 4.18.0")).toBe(true);
    expect(versionInRange("4.18.0", ">= 4.0.0, < 4.18.0")).toBe(false);
    expect(versionInRange("3.9.0", ">= 4.0.0, < 4.18.0")).toBe(false);
  });

  it("handles inclusive upper bounds", () => {
    expect(versionInRange("4.17.23", ">= 4.0.0, <= 4.17.23")).toBe(true);
    expect(versionInRange("4.17.24", ">= 4.0.0, <= 4.17.23")).toBe(false);
  });

  it("handles an open lower bound", () => {
    expect(versionInRange("1.2.1", "< 1.2.2")).toBe(true);
    expect(versionInRange("1.2.2", "< 1.2.2")).toBe(false);
  });

  it("treats a bare version as an equality check", () => {
    expect(versionInRange("1.0.0", "1.0.0")).toBe(true);
    expect(versionInRange("1.0.1", "1.0.0")).toBe(false);
  });

  // Refusing to match is the safe direction: we would rather miss than invent
  // a vulnerability report about a version we could not parse.
  it("returns false for unparseable input rather than throwing", () => {
    expect(versionInRange("not-a-version", ">= 1.0.0")).toBe(false);
    expect(versionInRange("1.0.0", "")).toBe(false);
    expect(versionInRange("1.0.0", "garbage")).toBe(false);
  });

  it("ANDs every comparator in the range", () => {
    // Satisfies the lower bound but not the upper: must not match.
    expect(versionInRange("5.0.0", ">= 4.0.0, < 4.18.0")).toBe(false);
  });
});

describe("classifyBump", () => {
  it("classifies each bump kind", () => {
    expect(classifyBump("1.0.0", "2.0.0")).toBe("major");
    expect(classifyBump("1.0.0", "1.1.0")).toBe("minor");
    expect(classifyBump("1.0.0", "1.0.1")).toBe("patch");
    expect(classifyBump("1.0.0", "1.0.0")).toBe("none");
    expect(classifyBump("junk", "1.0.0")).toBe("unknown");
  });
});

describe("cleanVersion", () => {
  it("strips npm range decoration", () => {
    expect(cleanVersion("^1.2.3")).toBe("1.2.3");
    expect(cleanVersion("~1.2.3")).toBe("1.2.3");
    expect(cleanVersion(">=1.2.3")).toBe("1.2.3");
    expect(cleanVersion("  v1.2.3 ")).toBe("1.2.3");
  });
});
