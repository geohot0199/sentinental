import { describe, it, expect } from 'vitest';
import {
  WEBMCP_TOOLS_CATALOG,
  registerAllWebMCPTools,
  type WebMCPToolDefinition,
} from '../src/webmcp/index.ts';

/** Tool output is engine-specific JSON; the catalog types it as `unknown`. */
async function runTool(
  name: string,
  input: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const tool = WEBMCP_TOOLS_CATALOG.find((t) => t.name === name);
  expect(tool, `missing tool ${name}`).toBeDefined();
  return (await (tool as WebMCPToolDefinition).execute(input)) as Record<string, unknown>;
}

describe('WebMCP Master Catalog & Registration (W3C Spec Compliance)', () => {
  it('contains all tools across all 5 innovation modules', () => {
    expect(WEBMCP_TOOLS_CATALOG.length).toBeGreaterThanOrEqual(15);

    const modules = new Set(WEBMCP_TOOLS_CATALOG.map(t => t.module));
    expect(modules.has('BreachLab')).toBe(true);
    expect(modules.has('BioSynth')).toBe(true);
    expect(modules.has('ChronoForensic')).toBe(true);
    expect(modules.has('MetaLoop')).toBe(true);
    expect(modules.has('ZkEscrow')).toBe(true);
  });

  it('each tool has valid name, description, inputSchema, and execute handler', () => {
    for (const tool of WEBMCP_TOOLS_CATALOG) {
      expect(tool.name).toMatch(/^[a-z_0-9]+$/);
      expect(tool.description.length).toBeGreaterThan(15);
      expect(tool.inputSchema.type).toBe('object');
      expect(typeof tool.execute).toBe('function');
    }
  });

  it('registers tools with document.modelContext when available according to WebMCP standard', () => {
    const registeredTools: WebMCPToolDefinition[] = [];
    const mockDocument = {
      modelContext: {
        registerTool: (toolDef: unknown) => {
          registeredTools.push(toolDef as WebMCPToolDefinition);
        }
      }
    };

    const result = registerAllWebMCPTools(mockDocument);
    expect(result.registeredCount).toBe(WEBMCP_TOOLS_CATALOG.length);
    expect(registeredTools.length).toBe(WEBMCP_TOOLS_CATALOG.length);
    expect(registeredTools[0]).toHaveProperty('name');
    expect(registeredTools[0]).toHaveProperty('execute');
  });

  it('executes breachlab, biosynth, chrono, metaloop, and zkescrow tools successfully via catalog', async () => {
    const breachRes = await runTool('breachlab_analyze_cve_ast', {
      codeOrManifest: 'const x = eval(req.query.cmd);',
    });
    expect(breachRes.verdict).toBeDefined();

    const bioRes = await runTool('biosynth_mutate_residue', {
      chain: 'A',
      resSeq: 2,
      targetResidue3: 'TRP',
    });
    expect(bioRes.mutatedResidue).toBe('TRP');

    const chronoRes = await runTool('chrono_generate_forensic_dossier', {
      incidentId: 'TEST-CASE-1',
    });
    expect(chronoRes.forensicHash).toBeDefined();

    const metaRes = await runTool('metaloop_inspect_trace_tree', {});
    expect(metaRes.healthScore).toBeDefined();

    const zkRes = await runTool('zkescrow_verify_deliverable_hash', {
      milestoneId: 'M-1',
      submittedContent: 'function patch() {}',
    });
    expect(zkRes.actualSha256).toBeDefined();
  });
});
