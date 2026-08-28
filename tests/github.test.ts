import { describe, expect, it } from "vitest";
import { SentinelError } from "../src/core/errors.ts";
import {
  GitHubClient,
  isValidBranchName,
  parseRepo,
  remediationBranchName,
} from "../src/core/github.ts";

describe("parseRepo", () => {
  it("parses owner/repo", () => {
    expect(parseRepo("truefoundry/trueforge")).toEqual({
      owner: "truefoundry",
      repo: "trueforge",
    });
  });

  it("accepts a full GitHub URL and strips .git", () => {
    expect(parseRepo("https://github.com/truefoundry/trueforge.git")).toEqual({
      owner: "truefoundry",
      repo: "trueforge",
    });
  });

  // These are the inputs that would let a model reach a different API path.
  it("rejects path traversal and injection attempts", () => {
    const hostile = [
      "../../etc/passwd",
      "owner/../../../admin",
      "owner/repo/extra",
      "owner",
      "",
      "   ",
      "owner/..",
      "owner/.",
      "-badowner/repo",
      "owner/repo?query=1",
      "owner/repo#fragment",
      "own er/repo",
    ];
    for (const input of hostile) {
      expect(() => parseRepo(input), input).toThrow(SentinelError);
    }
  });

  it("rejects an over-long owner", () => {
    expect(() => parseRepo(`${"a".repeat(40)}/repo`)).toThrow(SentinelError);
  });
});

describe("isValidBranchName", () => {
  it("accepts our generated names", () => {
    expect(isValidBranchName("sentinel/20260828-fix-lodash-a1b2c3")).toBe(true);
  });

  it("rejects refs git itself would reject", () => {
    const bad = [
      "",
      "/leading",
      "trailing/",
      "has..dots",
      "has//double",
      "ends.lock",
      "has space",
      "has~tilde",
      "has^caret",
      "has:colon",
      "has?question",
      "has*star",
      "has[bracket",
      "has\\backslash",
      "has@{brace",
    ];
    for (const name of bad) {
      expect(isValidBranchName(name), name).toBe(false);
    }
  });
});

describe("remediationBranchName", () => {
  it("always produces a valid, namespaced branch", () => {
    for (const seed of ["Bump lodash to 4.18.0", "!!!", "", "a".repeat(200)]) {
      const branch = remediationBranchName(seed);
      expect(isValidBranchName(branch), branch).toBe(true);
      expect(branch.startsWith("sentinel/")).toBe(true);
    }
  });

  it("does not collide across calls with the same seed", () => {
    const a = remediationBranchName("same");
    const b = remediationBranchName("same");
    expect(a).not.toBe(b);
  });
});

describe("GitHubClient write guard", () => {
  const ref = { owner: "octocat", repo: "hello" };

  it("refuses every write when remote writes are disabled", async () => {
    const client = new GitHubClient("ghp_fake_token_value_here", false);
    // Each of these must reject *before* any network call is attempted.
    await expect(client.createBranch(ref, "sentinel/x", "main")).rejects.toThrow(/read-only/);
    await expect(client.putFile(ref, "a.json", "{}", "msg", "b")).rejects.toThrow(/read-only/);
    await expect(
      client.createPullRequest(ref, { title: "t", body: "b", head: "h", base: "m" }),
    ).rejects.toThrow(/read-only/);
    await expect(client.mergePullRequest(ref, 1)).rejects.toThrow(/read-only/);
  });

  it("reports that it is unconfigured without a token", () => {
    expect(new GitHubClient(null, true).configured).toBe(false);
    expect(new GitHubClient("ghp_x", true).configured).toBe(true);
  });

  it("refuses to read a traversing path", async () => {
    const client = new GitHubClient("ghp_fake_token_value_here", true);
    await expect(client.getFile(ref, "../../../etc/passwd")).rejects.toThrow(/\.\./);
  });

  it("refuses to write a traversing path even when writes are allowed", async () => {
    const client = new GitHubClient("ghp_fake_token_value_here", true);
    await expect(client.putFile(ref, "../outside.json", "{}", "m", "b")).rejects.toThrow(/\.\./);
  });
});
