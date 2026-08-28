import { describe, it, expect } from 'vitest';
import {
  inspectTraceTree,
  forkAndInjectSyntheticTool,
  synthesizeDriftMitigation,
  DEMO_AGENT_TRACES
} from '../src/webmcp/metaloop.ts';

describe('MetaLoop Flight Simulator Engine (Module 4)', () => {
  it('detects infinite tool calling loops and calculates health score degradation', () => {
    const inspection = inspectTraceTree(DEMO_AGENT_TRACES);
    expect(inspection.totalSteps).toBe(4);
    expect(inspection.anomalies.some(a => a.anomalyType === 'INFINITE_TOOL_LOOP')).toBe(true);
    expect(inspection.healthScore).toBeLessThan(80);
  });

  it('forks execution branch and injects synthetic tool response to unblock loop', () => {
    const syntheticOutput = { status: 'CACHE_RESOLVED', patchAvailable: true, safeVersion: '4.17.22' };
    const forkResult = forkAndInjectSyntheticTool(DEMO_AGENT_TRACES, 'step_2', 'search_nvd_database', syntheticOutput);

    expect(forkResult.syntheticInjectionApplied).toBe(true);
    expect(forkResult.forkedSteps.length).toBe(4); // step_1, step_2, synthetic injection, resumed step
    expect(forkResult.recoveryStatus).toBe('RESOLVED');
    expect(forkResult.forkedSteps.some(s => s.toolName === 'search_nvd_database' && s.actionType === 'tool_result')).toBe(true);
  });

  it('synthesizes actionable cognitive drift mitigation instructions', () => {
    const inspection = inspectTraceTree(DEMO_AGENT_TRACES);
    const mitigation = synthesizeDriftMitigation(inspection.anomalies);

    expect(mitigation.systemPatch).toContain('STRICT_RULE');
    expect(mitigation.recoveryAction).toBe('APPLY_SYSTEM_GUIDANCE_AND_RESET_BUDGET');
  });
});
