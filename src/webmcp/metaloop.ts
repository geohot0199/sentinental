/**
 * MetaLoop Flight Simulator - Autonomous Agent Swarm Debugger & Cognitive Drift Compensator
 *
 * Implements agent trace tree parsing, hallucination/loop detection,
 * synthetic tool mock injection, state entropy radar, and execution branch forking.
 */

export interface AgentTraceStep {
  stepId: string;
  parentId: string | null;
  agentRole: 'orchestrator' | 'researcher' | 'coder' | 'evaluator';
  actionType: 'thought' | 'tool_call' | 'tool_result' | 'decision';
  toolName?: string;
  toolInput?: Record<string, unknown>;
  toolOutput?: Record<string, unknown>;
  thoughtSummary?: string;
  tokenCost: number;
  entropyScore: number; // 0 to 1 (0 = deterministic, 1 = chaotic drift)
  status: 'SUCCESS' | 'LOOP_DETECTED' | 'HALLUCINATION' | 'DRIFTING' | 'HALTED';
}

export interface DriftAnomaly {
  anomalyType: 'INFINITE_TOOL_LOOP' | 'TOKEN_EXPLOSION' | 'ENTROPY_DIVERGENCE' | 'CONTEXT_DEGRADATION';
  severity: 'WARNING' | 'CRITICAL';
  affectedStepIds: string[];
  description: string;
  recommendedMitigation: string;
}

export interface TraceInspectionResult {
  totalSteps: number;
  totalTokens: number;
  healthScore: number; // 0 to 100
  anomalies: DriftAnomaly[];
  steps: AgentTraceStep[];
  activeBranchId: string;
}

export interface ForkBranchResult {
  originalBranchId: string;
  newBranchId: string;
  forkPointStepId: string;
  syntheticInjectionApplied: boolean;
  forkedSteps: AgentTraceStep[];
  recoveryStatus: 'HEALTHY' | 'RESOLVED';
}

/**
 * Analyzes agent trace sequence and detects cognitive loops, drift, and token spikes.
 */
export function inspectTraceTree(steps: AgentTraceStep[]): TraceInspectionResult {
  const anomalies: DriftAnomaly[] = [];
  let totalTokens = 0;

  // 1. Check for infinite tool loops (same tool called >= 3 times consecutively with similar inputs)
  const toolSequence: { stepId: string; toolName: string; inputHash: string }[] = [];

  steps.forEach(step => {
    totalTokens += step.tokenCost;
    if (step.actionType === 'tool_call' && step.toolName) {
      const inputHash = JSON.stringify(step.toolInput || {});
      toolSequence.push({ stepId: step.stepId, toolName: step.toolName, inputHash });
    }
  });

  // Detect repetitive patterns
  for (let i = 2; i < toolSequence.length; i++) {
    const s1 = toolSequence[i - 2];
    const s2 = toolSequence[i - 1];
    const s3 = toolSequence[i];

    if (s1 && s2 && s3 && s1.toolName === s2.toolName && s2.toolName === s3.toolName && s1.inputHash === s3.inputHash) {
      anomalies.push({
        anomalyType: 'INFINITE_TOOL_LOOP',
        severity: 'CRITICAL',
        affectedStepIds: [s1.stepId, s2.stepId, s3.stepId],
        description: `Agent is trapped calling tool "${s3.toolName}" repeatedly with identical parameters without state progress.`,
        recommendedMitigation: 'Inject synthetic cache response or inject corrective steering prompt.'
      });
      break;
    }
  }

  // 2. Check for token explosion
  const highTokenSteps = steps.filter(s => s.tokenCost > 3500);
  if (highTokenSteps.length > 0) {
    anomalies.push({
      anomalyType: 'TOKEN_EXPLOSION',
      severity: 'WARNING',
      affectedStepIds: highTokenSteps.map(s => s.stepId),
      description: `${highTokenSteps.length} step(s) exceeded the nominal 3500 token budget threshold.`,
      recommendedMitigation: 'Summarize conversation context window and prune past tool output buffers.'
    });
  }

  // 3. Check for Entropy Divergence (chaotic hallucination drift)
  const driftingSteps = steps.filter(s => s.entropyScore > 0.75);
  if (driftingSteps.length > 1) {
    anomalies.push({
      anomalyType: 'ENTROPY_DIVERGENCE',
      severity: 'WARNING',
      affectedStepIds: driftingSteps.map(s => s.stepId),
      description: 'Elevated entropy score detected indicating wandering cognitive focus.',
      recommendedMitigation: 'Anchor agent to primary goal using schema-guided constraint prompt.'
    });
  }

  // Calculate Health Score
  let health = 100;
  anomalies.forEach(a => {
    health -= (a.severity === 'CRITICAL' ? 35 : 15);
  });
  health = Math.max(10, Math.min(100, health));

  return {
    totalSteps: steps.length,
    totalTokens,
    healthScore: health,
    anomalies,
    steps,
    activeBranchId: 'branch_main'
  };
}

/**
 * Injects a synthetic tool response to unblock a trapped agent loop and forks execution.
 */
export function forkAndInjectSyntheticTool(
  steps: AgentTraceStep[],
  forkPointStepId: string,
  syntheticToolName: string,
  syntheticOutput: Record<string, unknown>
): ForkBranchResult {
  const forkIdx = steps.findIndex(s => s.stepId === forkPointStepId);
  if (forkIdx === -1) {
    throw new Error(`Fork point step ${forkPointStepId} not found in trace.`);
  }

  // Duplicate up to fork point
  const forkedSteps = steps.slice(0, forkIdx + 1).map(s => ({ ...s }));

  // Inject synthetic step
  const injectedStepId = `step_syn_${Date.now().toString(36)}`;
  const injectedStep: AgentTraceStep = {
    stepId: injectedStepId,
    parentId: forkPointStepId,
    agentRole: 'evaluator',
    actionType: 'tool_result',
    toolName: syntheticToolName,
    toolOutput: syntheticOutput,
    thoughtSummary: `[SYNTHETIC INJECTION] Flight controller forced state transition with simulated output.`,
    tokenCost: 45,
    entropyScore: 0.1,
    status: 'SUCCESS'
  };

  forkedSteps.push(injectedStep);

  // Resume healthy state
  const resumedStep: AgentTraceStep = {
    stepId: `step_resumed_${Date.now().toString(36)}`,
    parentId: injectedStepId,
    agentRole: 'orchestrator',
    actionType: 'decision',
    thoughtSummary: `Received synthetic resolution. Proceeding to target execution without hallucination loop.`,
    tokenCost: 120,
    entropyScore: 0.15,
    status: 'SUCCESS'
  };

  forkedSteps.push(resumedStep);

  return {
    originalBranchId: 'branch_main',
    newBranchId: `branch_fork_${Date.now().toString(36)}`,
    forkPointStepId,
    syntheticInjectionApplied: true,
    forkedSteps,
    recoveryStatus: 'RESOLVED'
  };
}

/**
 * Generates automated cognitive drift mitigation prompt guidelines.
 */
export function synthesizeDriftMitigation(anomalies: DriftAnomaly[]): { systemPatch: string; recoveryAction: string } {
  if (anomalies.length === 0) {
    return {
      systemPatch: 'Agent state is operating within nominal safety and convergence margins.',
      recoveryAction: 'NO_ACTION_REQUIRED'
    };
  }

  const guidelines: string[] = [];
  if (anomalies.some(a => a.anomalyType === 'INFINITE_TOOL_LOOP')) {
    guidelines.push('STRICT_RULE: Do not invoke the same tool with identical parameters if previous output did not change the workspace state.');
  }
  if (anomalies.some(a => a.anomalyType === 'TOKEN_EXPLOSION')) {
    guidelines.push('STRICT_RULE: Compress multi-line stdout into succinct 3-bullet summaries before feeding back to context.');
  }
  if (anomalies.some(a => a.anomalyType === 'ENTROPY_DIVERGENCE')) {
    guidelines.push('STRICT_RULE: Re-evaluate step against original user acceptance criteria before choosing next action.');
  }

  return {
    systemPatch: `[COGNITIVE COMPENSATOR ACTIVE]\n${guidelines.join('\n')}`,
    recoveryAction: 'APPLY_SYSTEM_GUIDANCE_AND_RESET_BUDGET'
  };
}

/**
 * Built-in Demo Agent Traces (Trapped loop scenario)
 */
export const DEMO_AGENT_TRACES: AgentTraceStep[] = [
  {
    stepId: 'step_1',
    parentId: null,
    agentRole: 'orchestrator',
    actionType: 'thought',
    thoughtSummary: 'User requested triage of vulnerability CVE-2026-4109 in lodash template.',
    tokenCost: 250,
    entropyScore: 0.2,
    status: 'SUCCESS'
  },
  {
    stepId: 'step_2',
    parentId: 'step_1',
    agentRole: 'researcher',
    actionType: 'tool_call',
    toolName: 'search_nvd_database',
    toolInput: { cve: 'CVE-2026-4109' },
    tokenCost: 1200,
    entropyScore: 0.35,
    status: 'SUCCESS'
  },
  {
    stepId: 'step_3',
    parentId: 'step_2',
    agentRole: 'researcher',
    actionType: 'tool_call',
    toolName: 'search_nvd_database',
    toolInput: { cve: 'CVE-2026-4109' },
    tokenCost: 1400,
    entropyScore: 0.65,
    status: 'DRIFTING'
  },
  {
    stepId: 'step_4',
    parentId: 'step_3',
    agentRole: 'researcher',
    actionType: 'tool_call',
    toolName: 'search_nvd_database',
    toolInput: { cve: 'CVE-2026-4109' },
    tokenCost: 1600,
    entropyScore: 0.88,
    status: 'LOOP_DETECTED'
  }
];
