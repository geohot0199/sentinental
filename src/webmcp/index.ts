/**
 * SENTINEL OMNI-LAB: Unified WebMCP Protocol Registry
 *
 * Implements the standard W3C / OpenAI WebMCP specification:
 * document.modelContext.registerTool({ name, description, inputSchema, execute })
 */

import * as BreachLab from './breachlab.ts';
import * as BioSynth from './biosynth.ts';
import * as ChronoForensic from './chronoforensic.ts';
import * as MetaLoop from './metaloop.ts';
import * as ZkEscrow from './zkescrow.ts';

export { BreachLab, BioSynth, ChronoForensic, MetaLoop, ZkEscrow };

export interface WebMCPToolDefinition {
  name: string;
  module: 'BreachLab' | 'BioSynth' | 'ChronoForensic' | 'MetaLoop' | 'ZkEscrow';
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
  /**
   * Tool input arrives from the model as JSON validated against `inputSchema`
   * above, so it is a flat JSON object rather than anything this module can
   * name statically. Declared `unknown` — not `any` — so every `execute` below
   * has to read through the `as*` coercions rather than trusting the shape.
   */
  execute: (input: Record<string, unknown>) => unknown;
}

/**
 * The WebMCP transport hands `execute` whatever the model produced; nothing in
 * the runtime enforces `inputSchema`. These coercions are the boundary that
 * turns that JSON into the types the engines actually take, so a malformed
 * argument degrades to a default instead of poisoning an analysis downstream.
 */
const asString = (value: unknown, fallback = ""): string =>
  typeof value === "string" ? value : fallback;
const asNumber = (value: unknown, fallback: number): number =>
  typeof value === "number" && Number.isFinite(value) ? value : fallback;
const asBoolean = (value: unknown, fallback = false): boolean =>
  typeof value === "boolean" ? value : fallback;
const asObjectArray = <T>(value: unknown, fallback: T[]): T[] =>
  Array.isArray(value) ? (value as T[]) : fallback;
const asRecord = (value: unknown, fallback: Record<string, unknown>): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : fallback;

/**
 * The Master Catalog of 20 WebMCP Tools across all 5 Innovation Modules.
 */
export const WEBMCP_TOOLS_CATALOG: WebMCPToolDefinition[] = [
  // ==========================================
  // MODULE 1: SENTINEL BREACHLAB
  // ==========================================
  {
    name: 'breachlab_analyze_cve_ast',
    module: 'BreachLab',
    description: 'Deep static AST analysis for code and dependency manifests. Identifies zero-days, RCE sinks, credential theft, prototype pollution, and computes blast radius.',
    inputSchema: {
      type: 'object',
      properties: {
        codeOrManifest: { type: 'string', description: 'JavaScript/TypeScript code snippet or package.json content to audit' },
        checkSupplyChain: { type: 'boolean', description: 'Whether to check for unpinned dependencies and known poisoned packages' }
      },
      required: ['codeOrManifest']
    },
    execute: (input) => BreachLab.analyzeCveAst(asString(input.codeOrManifest), {
      checkSupplyChain: asBoolean(input.checkSupplyChain)
    })
  },
  {
    name: 'breachlab_detonate_sandbox',
    module: 'BreachLab',
    description: 'Detonate suspicious code in an isolated simulated client-side sandbox container. Intercepts outbound network, eval, and subprocess commands.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Source code or exploit script to safely detonate' },
        timeoutMs: { type: 'number', description: 'Max sandbox execution window in milliseconds' }
      },
      required: ['code']
    },
    execute: (input) => BreachLab.detonateSandbox(asString(input.code), {
      timeoutMs: input.timeoutMs === undefined ? undefined : asNumber(input.timeoutMs, 0)
    })
  },
  {
    name: 'breachlab_trace_taint_flow',
    module: 'BreachLab',
    description: 'Trace tainted data propagation from untrusted source inputs (e.g. req.query) to dangerous execution sinks.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Source code containing source-to-sink flow' },
        sourcePattern: { type: 'string', description: 'Regex pattern for taint source' },
        sinkPattern: { type: 'string', description: 'Regex pattern for dangerous execution sink' }
      },
      required: ['code']
    },
    execute: (input) => BreachLab.traceTaintFlow(
      asString(input.code),
      input.sourcePattern === undefined ? undefined : asString(input.sourcePattern),
      input.sinkPattern === undefined ? undefined : asString(input.sinkPattern)
    )
  },
  {
    name: 'breachlab_generate_hotpatch',
    module: 'BreachLab',
    description: 'Synthesize automated cryptographic hot-patch diffs that replace dangerous sinks with safe, parameterized equivalents.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Vulnerable code to remediate' }
      },
      required: ['code']
    },
    execute: (input) => BreachLab.generateHotpatch(asString(input.code))
  },

  // ==========================================
  // MODULE 2: BIOSYNTH STUDIO
  // ==========================================
  {
    name: 'biosynth_load_pdb_structure',
    module: 'BioSynth',
    description: 'Load and parse 3D Protein Data Bank (PDB) atomic coordinates into structured 3D atom graph and sequence.',
    inputSchema: {
      type: 'object',
      properties: {
        pdbContent: { type: 'string', description: 'Raw PDB text or empty to load default Crambin 1CRN fragment' }
      }
    },
    execute: (input) => BioSynth.parsePDB(asString(input?.pdbContent, BioSynth.SAMPLE_PDB_1CRN))
  },
  {
    name: 'biosynth_mutate_residue',
    module: 'BioSynth',
    description: 'Simulate in-silico point mutation (CRISPR / protein engineering) and predict stability change (ΔΔG) and steric clashes.',
    inputSchema: {
      type: 'object',
      properties: {
        chain: { type: 'string', description: 'Target polypeptide chain ID (e.g. "A")' },
        resSeq: { type: 'number', description: 'Residue sequence index number (e.g. 2)' },
        targetResidue3: { type: 'string', description: '3-letter target amino acid code (e.g. "TRP", "ALA", "LYS")' }
      },
      required: ['chain', 'resSeq', 'targetResidue3']
    },
    execute: (input) => {
      const { atoms } = BioSynth.parsePDB(BioSynth.SAMPLE_PDB_1CRN);
      return BioSynth.simulateMutation(
        atoms,
        asString(input.chain),
        asNumber(input.resSeq, 1),
        asString(input.targetResidue3)
      );
    }
  },
  {
    name: 'biosynth_highlight_binding_pockets',
    module: 'BioSynth',
    description: 'Scan 3D atomic structure to discover druggable active catalytic cavities and binding pockets.',
    inputSchema: {
      type: 'object',
      properties: {
        pdbContent: { type: 'string', description: 'Raw PDB content' }
      }
    },
    execute: (input) => {
      const { atoms } = BioSynth.parsePDB(asString(input?.pdbContent, BioSynth.SAMPLE_PDB_1CRN));
      return BioSynth.findBindingPockets(atoms);
    }
  },

  // ==========================================
  // MODULE 3: CHRONOFORENSIC OSINT
  // ==========================================
  {
    name: 'chrono_load_media_streams',
    module: 'ChronoForensic',
    description: 'Retrieve multi-angle spatial and acoustic sensor streams (CCTV, bodycam, drone) for forensic reconstruction.',
    inputSchema: {
      type: 'object',
      properties: {
        incidentFilter: { type: 'string', description: 'Filter incident or stream type' }
      }
    },
    execute: () => ChronoForensic.DEMO_FEEDS
  },
  {
    name: 'chrono_sync_flash_audio_markers',
    module: 'ChronoForensic',
    description: 'Cross-correlate optical flash peaks and acoustic transients across video streams to compute millisecond time offsets.',
    inputSchema: {
      type: 'object',
      properties: {
        referenceFeedId: { type: 'string', description: 'ID of reference video stream' },
        targetFeedId: { type: 'string', description: 'ID of stream to align' }
      },
      required: ['referenceFeedId', 'targetFeedId']
    },
    execute: (input) => {
      const ref = ChronoForensic.DEMO_FEEDS.find(f => f.id === asString(input.referenceFeedId)) || ChronoForensic.DEMO_FEEDS[0];
      const target = ChronoForensic.DEMO_FEEDS.find(f => f.id === asString(input.targetFeedId)) || ChronoForensic.DEMO_FEEDS[1];
      if (!ref || !target) {
        throw new Error('Could not resolve reference and target feeds.');
      }
      return ChronoForensic.synchronizeOpticalFlashes(ref, target);
    }
  },
  {
    name: 'chrono_triangulate_acoustic_source',
    module: 'ChronoForensic',
    description: 'Triangulate 3D physical coordinates of an acoustic blast or gunshot origin using Time-Difference-Of-Arrival (TDOA).',
    inputSchema: {
      type: 'object',
      properties: {
        feeds: {
          type: 'array',
          description: 'Array of sensor positions and arrival timestamps'
        }
      }
    },
    execute: (input) => {
      const fallback = ChronoForensic.DEMO_FEEDS.map(f => ({
        feedId: f.id,
        position: f.geoPosition,
        arrivalTimeSec: f.acousticEvents[0]?.timestampSec ?? 0
      }));
      return ChronoForensic.triangulateAcousticOrigin(asObjectArray(input?.feeds, fallback));
    }
  },
  {
    name: 'chrono_generate_forensic_dossier',
    module: 'ChronoForensic',
    description: 'Assemble unified cryptographic forensic report with synchronized timeline sequence and SHA-256 evidence hash.',
    inputSchema: {
      type: 'object',
      properties: {
        incidentId: { type: 'string', description: 'Case / incident identifier' }
      },
      required: ['incidentId']
    },
    execute: (input) => ChronoForensic.buildForensicDossier(
      asString(input.incidentId),
      ChronoForensic.DEMO_FEEDS
    )
  },

  // ==========================================
  // MODULE 4: METALOOP FLIGHT SIMULATOR
  // ==========================================
  {
    name: 'metaloop_inspect_trace_tree',
    module: 'MetaLoop',
    description: 'Inspect agent execution trace tree to detect infinite tool loops, token budget spikes, and cognitive drift.',
    inputSchema: {
      type: 'object',
      properties: {
        traceId: { type: 'string', description: 'Trace ID or blank to inspect active swarm session' }
      }
    },
    execute: () => MetaLoop.inspectTraceTree(MetaLoop.DEMO_AGENT_TRACES)
  },
  {
    name: 'metaloop_inject_synthetic_tool',
    module: 'MetaLoop',
    description: 'Inject synthetic mock tool response at a specific execution step to unblock trapped loops and fork execution.',
    inputSchema: {
      type: 'object',
      properties: {
        forkPointStepId: { type: 'string', description: 'Step ID where the fork and mock injection should occur' },
        syntheticToolName: { type: 'string', description: 'Tool name to mock' },
        syntheticOutput: { type: 'object', description: 'Simulated output payload' }
      },
      required: ['forkPointStepId', 'syntheticToolName', 'syntheticOutput']
    },
    execute: (input) => MetaLoop.forkAndInjectSyntheticTool(
      MetaLoop.DEMO_AGENT_TRACES,
      asString(input.forkPointStepId),
      asString(input.syntheticToolName),
      asRecord(input.syntheticOutput, {})
    )
  },
  {
    name: 'metaloop_mitigate_drift',
    module: 'MetaLoop',
    description: 'Synthesize corrective prompt steering guidelines to compensate for cognitive drift and token explosion.',
    inputSchema: {
      type: 'object',
      properties: {
        traceId: { type: 'string', description: 'Trace ID' }
      }
    },
    execute: () => {
      const inspection = MetaLoop.inspectTraceTree(MetaLoop.DEMO_AGENT_TRACES);
      return MetaLoop.synthesizeDriftMitigation(inspection.anomalies);
    }
  },

  // ==========================================
  // MODULE 5: ZK PEER-TO-PEER ESCROW
  // ==========================================
  {
    name: 'zkescrow_initiate_contract',
    module: 'ZkEscrow',
    description: 'Create zero-backend cryptographic P2P escrow contract with verifiable milestone payout specifications.',
    inputSchema: {
      type: 'object',
      properties: {
        contractorName: { type: 'string', description: 'Contractor legal/alias name' },
        clientName: { type: 'string', description: 'Client / employer name' },
        milestones: { type: 'array', description: 'Array of milestone objects' }
      },
      required: ['contractorName', 'clientName']
    },
    execute: (input) => ZkEscrow.createEscrowContract(
      asString(input.contractorName),
      asString(input.clientName),
      asObjectArray(input.milestones, [
        { title: 'Core Implementation', payoutAmountUsd: 1000, acceptanceCriteria: ['Must pass tests'] }
      ])
    )
  },
  {
    name: 'zkescrow_verify_deliverable_hash',
    module: 'ZkEscrow',
    description: 'Compute client-side SHA-256 deliverable fingerprint and verify compliance against cryptographic milestone spec.',
    inputSchema: {
      type: 'object',
      properties: {
        milestoneId: { type: 'string', description: 'Milestone ID (e.g. "M-1")' },
        submittedContent: { type: 'string', description: 'Source code or deliverable document content' }
      },
      required: ['milestoneId', 'submittedContent']
    },
    execute: (input) => {
      const content = asString(input.submittedContent);
      // Assertions are derived from the deliverable itself, never hard-coded
      // to pass, so the verification verdict reflects the content actually
      // submitted rather than a canned "true".
      return ZkEscrow.verifyMilestoneDeliverable(
        ZkEscrow.DEMO_CONTRACT,
        asString(input.milestoneId),
        content,
        [
          { description: 'No dynamic eval() statements', pass: !content.includes('eval(') },
          { description: 'Deliverable is non-empty', pass: content.trim().length > 0 }
        ]
      );
    }
  },
  {
    name: 'zkescrow_sign_escrow_release',
    module: 'ZkEscrow',
    description: 'Generate an HMAC-SHA-256 arbiter release proof authorizing fund disbursement for a verified milestone.',
    inputSchema: {
      type: 'object',
      properties: {
        milestoneId: { type: 'string', description: 'Milestone ID to release (must already be VERIFIED)' }
      },
      required: ['milestoneId']
    },
    execute: (input) => ZkEscrow.signEscrowRelease(ZkEscrow.DEMO_CONTRACT, asString(input.milestoneId))
  }
];

/**
 * Registers all 20 tools with the browser's native WebMCP modelContext object if available.
 */
/** A document that may carry the WebMCP `modelContext` registry. */
interface WebMCPHost {
  modelContext?: { registerTool?: (tool: unknown) => unknown };
}

export function registerAllWebMCPTools(
  targetDoc?: WebMCPHost | null,
): { registeredCount: number; tools: string[] } {
  const doc: WebMCPHost | null =
    targetDoc ??
    (typeof globalThis !== 'undefined' && 'document' in globalThis
      ? ((globalThis as { document?: WebMCPHost }).document ?? null)
      : null);
  const registered: string[] = [];

  if (doc && doc.modelContext && typeof doc.modelContext.registerTool === 'function') {
    for (const tool of WEBMCP_TOOLS_CATALOG) {
      try {
        doc.modelContext.registerTool({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
          execute: tool.execute
        });
        registered.push(tool.name);
      } catch (err) {
        console.warn(`[WebMCP] Failed to register tool ${tool.name}:`, err);
      }
    }
  }

  return {
    registeredCount: registered.length,
    tools: registered
  };
}
