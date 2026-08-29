import { describe, it, expect } from 'vitest';
import {
  calculateSha256,
  createEscrowContract,
  verifyMilestoneDeliverable,
  signEscrowRelease,
  DEMO_CONTRACT
} from '../src/webmcp/zkescrow.ts';

describe('ZK Peer-to-Peer Escrow Engine (Module 5)', () => {
  it('calculates SHA-256 fingerprint deterministically', () => {
    const h1 = calculateSha256('hello world');
    const h2 = calculateSha256('hello world');
    const h3 = calculateSha256('different string');
    expect(h1).toBe(h2);
    expect(h1).not.toBe(h3);
    expect(h1.length).toBe(64);
  });

  it('creates escrow contracts with generated public keys and funded milestone structure', () => {
    const contract = createEscrowContract('Dev A', 'Client B', [
      { title: 'Task 1', payoutAmountUsd: 500, acceptanceCriteria: ['Must work'] }
    ]);
    expect(contract.contractState).toBe('FUNDED');
    expect(contract.totalEscrowAmountUsd).toBe(500);
    expect(contract.milestones.length).toBe(1);
    expect(contract.clientPublicKey).toMatch(/^PUB_CLI_/);
  });

  it('verifies milestone deliverable against criteria and test assertions', () => {
    const deliverableCode = 'function patchVulnerability(ast) { return sanitize(ast); }';
    const result = verifyMilestoneDeliverable(DEMO_CONTRACT, 'M-1', deliverableCode, [
      { description: 'Must parse AST', pass: true },
      { description: 'Must eliminate eval', pass: true }
    ]);

    expect(result.hashMatch).toBe(true);
    expect(result.testSuitePassed).toBe(true);
    expect(result.arbitrationVerdict).toBe('APPROVED_FOR_RELEASE');
  });

  it('signs cryptographic escrow release proof and updates milestone status', () => {
    // Release requires a VERIFIED milestone, so verify the deliverable first.
    const deliverableCode = 'function patchVulnerability(ast) { return sanitize(ast); }';
    verifyMilestoneDeliverable(DEMO_CONTRACT, 'M-1', deliverableCode, [
      { description: 'Must parse AST', pass: true },
      { description: 'Must eliminate eval', pass: true }
    ]);

    const proof = signEscrowRelease(DEMO_CONTRACT, 'M-1');
    expect(proof.releasedAmountUsd).toBe(1500);
    expect(proof.arbiterSignature).toMatch(/^SIG-HMAC-SHA256-/);
    expect(proof.verificationAuditTrail.length).toBeGreaterThan(0);
    expect(DEMO_CONTRACT.milestones[0]?.status).toBe('RELEASED');
  });

  it('rejects a deliverable whose digest does not match the milestone spec', () => {
    const contract = createEscrowContract('Dev A', 'Client B', [
      { title: 'Task 1', payoutAmountUsd: 500, expectedContent: 'the real deliverable', acceptanceCriteria: ['Must work'] }
    ]);
    // Long arbitrary content must NOT pass: the previous implementation treated
    // any input over 20 characters as a match.
    const result = verifyMilestoneDeliverable(contract, 'M-1', 'a'.repeat(10_000), [
      { description: 'Must work', pass: true }
    ]);
    expect(result.hashMatch).toBe(false);
    expect(result.arbitrationVerdict).toBe('REJECTED_MISMATCH');
    expect(contract.milestones[0]?.status).toBe('DISPUTED');
  });

  it('refuses to release a milestone that has not been verified', () => {
    const contract = createEscrowContract('Dev A', 'Client B', [
      { title: 'Task 1', payoutAmountUsd: 500, acceptanceCriteria: ['Must work'] }
    ]);
    expect(() => signEscrowRelease(contract, 'M-1')).toThrow(/not VERIFIED/);
    expect(contract.milestones[0]?.status).toBe('PENDING');
  });

  it('issues a per-contract release key rather than a shared hard-coded secret', () => {
    const a = createEscrowContract('Dev A', 'Client B', [
      { title: 'Task 1', payoutAmountUsd: 500, acceptanceCriteria: ['Must work'] }
    ]);
    const b = createEscrowContract('Dev A', 'Client B', [
      { title: 'Task 1', payoutAmountUsd: 500, acceptanceCriteria: ['Must work'] }
    ]);
    expect(a.arbiterSecretKey).not.toBe(b.arbiterSecretKey);
    expect(a.arbiterSecretKey).not.toBe('SENTINEL_ARBITER_ZERO_KNOWLEDGE_SECRET');
  });
});
