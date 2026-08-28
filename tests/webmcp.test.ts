import { describe, it, expect } from 'vitest';
import { WEBMCP_TOOLS_CATALOG, registerAllWebMCPTools } from '../src/webmcp/index.ts';

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
    const registeredTools: any[] = [];
    const mockDocument = {
      modelContext: {
        registerTool: (toolDef: any) => {
          registeredTools.push(toolDef);
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
    // 1. BreachLab
    const breachTool = WEBMCP_TOOLS_CATALOG.find(t => t.name === 'breachlab_analyze_cve_ast');
    const breachRes = await breachTool?.execute({ codeOrManifest: 'const x = eval(req.query.cmd);' });
    expect(breachRes.verdict).toBeDefined();

    // 2. BioSynth
    const bioTool = WEBMCP_TOOLS_CATALOG.find(t => t.name === 'biosynth_mutate_residue');
    const bioRes = await bioTool?.execute({ chain: 'A', resSeq: 2, targetResidue3: 'TRP' });
    expect(bioRes.mutatedResidue).toBe('TRP');

    // 3. ChronoForensic
    const chronoTool = WEBMCP_TOOLS_CATALOG.find(t => t.name === 'chrono_generate_forensic_dossier');
    const chronoRes = await chronoTool?.execute({ incidentId: 'TEST-CASE-1' });
    expect(chronoRes.forensicHash).toBeDefined();

    // 4. MetaLoop
    const metaTool = WEBMCP_TOOLS_CATALOG.find(t => t.name === 'metaloop_inspect_trace_tree');
    const metaRes = await metaTool?.execute({});
    expect(metaRes.healthScore).toBeDefined();

    // 5. ZkEscrow
    const zkTool = WEBMCP_TOOLS_CATALOG.find(t => t.name === 'zkescrow_verify_deliverable_hash');
    const zkRes = await zkTool?.execute({ milestoneId: 'M-1', submittedContent: 'function patch() {}' });
    expect(zkRes.actualSha256).toBeDefined();
  });
});
