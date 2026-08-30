import { afterEach, describe, expect, it, vi } from "vitest";
import {
  lookupAdvisories,
  resolveSafeVersion,
  severityRank,
  sortMatches,
  type AdvisoryMatch,
} from "../src/core/advisories.ts";
import * as http from "../src/core/http.ts";

/**
 * Stub the one network seam so these tests are hermetic. Everything below
 * exercises the real parsing and range logic.
 */
function stubHttp(handler: (url: string) => unknown): void {
  vi.spyOn(http, "httpJson").mockImplementation((url: string) => Promise.resolve(handler(url)));
}

/**
 * GHSA-r683-j2x4-v87g (CVE-2022-0235) is the shape that matters: one advisory
 * carrying a separate range per release line. The 3.x entry is listed first.
 */
const nodeFetchAdvisories = [
  {
    ghsa_id: "GHSA-r683-j2x4-v87g",
    cve_id: "CVE-2022-0235",
    summary: "node-fetch forwards secure headers to untrusted sites",
    severity: "high",
    html_url: "https://github.com/advisories/GHSA-r683-j2x4-v87g",
    cvss_severities: { cvss_v3: { score: 8.8 } },
    vulnerabilities: [
      {
        package: { name: "node-fetch", ecosystem: "npm" },
        vulnerable_version_range: ">= 3.0.0, < 3.1.1",
        first_patched_version: "3.1.1",
      },
      {
        package: { name: "node-fetch", ecosystem: "npm" },
        vulnerable_version_range: "< 2.6.7",
        first_patched_version: "2.6.7",
      },
    ],
  },
];

afterEach(() => {
  vi.restoreAllMocks();
});

describe("lookupAdvisories: GitHub parsing", () => {
  // Regression: `.find()` on the package name returned the 3.x entry, whose
  // range excludes 2.6.0, so every 2.x install was reported as clean.
  it("matches the release line the installed version belongs to", async () => {
    stubHttp(() => nodeFetchAdvisories);

    const result = await lookupAdvisories("node-fetch", "2.6.0", "npm", null);

    expect(result.source).toBe("github");
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.advisory.vulnerableRange).toBe("< 2.6.7");
    expect(result.matches[0]?.recommendedVersion).toBe("2.6.7");
    expect(result.matches[0]?.bump).toBe("patch");
  });

  it("still matches a later release line", async () => {
    stubHttp(() => nodeFetchAdvisories);

    const result = await lookupAdvisories("node-fetch", "3.0.5", "npm", null);

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.advisory.vulnerableRange).toBe(">= 3.0.0, < 3.1.1");
    expect(result.matches[0]?.recommendedVersion).toBe("3.1.1");
  });

  it("reports a fully patched version as clean", async () => {
    stubHttp(() => nodeFetchAdvisories);

    const result = await lookupAdvisories("node-fetch", "3.3.2", "npm", null);

    expect(result.matches).toEqual([]);
  });

  it("ignores entries for other packages in the same advisory", async () => {
    stubHttp(() => [
      {
        ghsa_id: "GHSA-multi",
        severity: "critical",
        vulnerabilities: [
          {
            package: { name: "other-package", ecosystem: "npm" },
            vulnerable_version_range: "< 99.0.0",
            first_patched_version: "99.0.0",
          },
        ],
      },
    ]);

    const result = await lookupAdvisories("node-fetch", "1.0.0", "npm", null);

    expect(result.matches).toEqual([]);
  });

  it("prefers the CVSS v4 score and keeps the CVE id", async () => {
    stubHttp(() => [
      {
        ghsa_id: "GHSA-score",
        cve_id: "CVE-2024-0001",
        severity: "critical",
        cvss_severities: { cvss_v3: { score: 7.5 }, cvss_v4: { score: 9.3 } },
        vulnerabilities: [
          {
            package: { name: "demo", ecosystem: "npm" },
            vulnerable_version_range: "< 2.0.0",
            first_patched_version: "2.0.0",
          },
        ],
      },
    ]);

    const result = await lookupAdvisories("demo", "1.0.0", "npm", null);

    expect(result.matches[0]?.advisory.cvssScore).toBe(9.3);
    expect(result.matches[0]?.advisory.cve).toBe("CVE-2024-0001");
    expect(result.matches[0]?.bump).toBe("major");
  });

  it("keeps an advisory with no published fix and marks the bump unknown", async () => {
    stubHttp(() => [
      {
        ghsa_id: "GHSA-nofix",
        severity: "moderate",
        vulnerabilities: [
          {
            package: { name: "demo", ecosystem: "npm" },
            vulnerable_version_range: ">= 0",
            first_patched_version: null,
          },
        ],
      },
    ]);

    const result = await lookupAdvisories("demo", "1.0.0", "npm", null);

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.recommendedVersion).toBeNull();
    expect(result.matches[0]?.bump).toBe("unknown");
  });
});

describe("lookupAdvisories: OSV fallback", () => {
  /** Force GitHub to fail so the OSV branch runs. */
  function stubOsvOnly(osvPayload: unknown): void {
    stubHttp((url) => {
      if (url.includes("api.github.com")) throw new Error("blocked");
      return osvPayload;
    });
  }

  it("falls back to OSV and records a warning", async () => {
    stubOsvOnly({
      vulns: [
        {
          id: "OSV-1",
          aliases: ["CVE-2022-0235"],
          summary: "example",
          database_specific: { severity: "HIGH" },
          affected: [
            {
              package: { name: "node-fetch", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.6.7" }] }],
            },
          ],
        },
      ],
    });

    const result = await lookupAdvisories("node-fetch", "2.6.0", "npm", null);

    expect(result.source).toBe("osv");
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.recommendedVersion).toBe("2.6.7");
    expect(result.warnings[0]).toContain("GitHub Advisory Database unavailable");
  });

  // The same multi-line problem exists in OSV's event stream, where a single
  // range object encodes several introduced/fixed intervals in sequence.
  it("picks the interval covering the installed version", async () => {
    stubOsvOnly({
      vulns: [
        {
          id: "OSV-2",
          affected: [
            {
              package: { name: "demo", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [
                    { introduced: "3.0.0" },
                    { fixed: "3.1.1" },
                    { introduced: "0" },
                    { fixed: "2.6.7" },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });

    const result = await lookupAdvisories("demo", "2.6.0", "npm", null);

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.advisory.vulnerableRange).toBe("< 2.6.7");
    expect(result.matches[0]?.recommendedVersion).toBe("2.6.7");
  });

  it("treats an unfixed interval as still vulnerable", async () => {
    stubOsvOnly({
      vulns: [
        {
          id: "OSV-3",
          affected: [
            {
              package: { name: "demo", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }] }],
            },
          ],
        },
      ],
    });

    const result = await lookupAdvisories("demo", "1.5.0", "npm", null);

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.recommendedVersion).toBeNull();
  });

  it("returns source none when both sources fail", async () => {
    stubHttp(() => {
      throw new Error("offline");
    });

    const result = await lookupAdvisories("demo", "1.0.0", "npm", null);

    expect(result.source).toBe("none");
    expect(result.matches).toEqual([]);
    expect(result.warnings).toHaveLength(2);
  });
});

describe("lookupAdvisories: input guards", () => {
  it("rejects an empty package name", async () => {
    await expect(lookupAdvisories("   ", "1.0.0", "npm", null)).rejects.toThrow();
  });

  it("sends the token only when one is supplied", async () => {
    const spy = vi.spyOn(http, "httpJson").mockResolvedValue([] as never);

    await lookupAdvisories("demo", "1.0.0", "npm", null);
    const anonymous = spy.mock.calls[0]?.[1];
    expect(anonymous?.headers?.authorization).toBeUndefined();

    await lookupAdvisories("demo", "1.0.0", "npm", "ghp_example");
    const authorised = spy.mock.calls[1]?.[1];
    expect(authorised?.headers?.authorization).toBe("Bearer ghp_example");
  });
});

describe("ranking helpers", () => {
  function match(severity: AdvisoryMatch["advisory"]["severity"], score: number): AdvisoryMatch {
    return {
      packageName: "demo",
      installedVersion: "1.0.0",
      advisory: {
        id: `GHSA-${severity}-${score}`,
        cve: null,
        summary: "",
        severity,
        cvssScore: score,
        url: "",
        vulnerableRange: "< 2.0.0",
        firstPatchedVersion: "2.0.0",
        source: "github",
      },
      recommendedVersion: "2.0.0",
      bump: "major",
    };
  }

  it("orders critical before high before moderate", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("high")).toBeGreaterThan(severityRank("moderate"));
    expect(severityRank("low")).toBeGreaterThan(severityRank("unknown"));
  });

  it("sorts worst first", () => {
    const sorted = sortMatches([match("low", 2), match("critical", 9.8), match("moderate", 5)]);
    expect(sorted.map((m) => m.advisory.severity)).toEqual(["critical", "moderate", "low"]);
  });

  it("resolves the highest fix version so one upgrade clears every advisory", () => {
    const matches: AdvisoryMatch[] = [
      { ...match("high", 7), recommendedVersion: "4.17.21" },
      { ...match("critical", 9), recommendedVersion: "4.18.0" },
      { ...match("low", 2), recommendedVersion: "4.17.12" },
    ];
    expect(resolveSafeVersion(matches)).toBe("4.18.0");
  });

  it("returns null when nothing has a published fix", () => {
    expect(resolveSafeVersion([{ ...match("high", 7), recommendedVersion: null }])).toBeNull();
    expect(resolveSafeVersion([])).toBeNull();
  });
});
