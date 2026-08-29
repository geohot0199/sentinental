import { describe, it, expect } from 'vitest';
import {
  synchronizeOpticalFlashes,
  triangulateAcousticOrigin,
  buildForensicDossier,
  DEMO_FEEDS
} from '../src/webmcp/chronoforensic.ts';

describe('ChronoForensic OSINT Engine (Module 3)', () => {
  it('synchronizes optical flash timestamps and calculates millisecond offsets', () => {
    const f0 = DEMO_FEEDS[0];
    const f1 = DEMO_FEEDS[1];
    expect(f0).toBeDefined();
    expect(f1).toBeDefined();
    if (!f0 || !f1) return;

    const sync = synchronizeOpticalFlashes(f0, f1);
    expect(sync.referenceFeedId).toBe(f0.id);
    expect(sync.targetFeedId).toBe(f1.id);
    expect(typeof sync.calculatedOffsetMs).toBe('number');
    expect(sync.confidenceScore).toBeGreaterThan(0.5);
  });

  it('triangulates 3D acoustic origin from 3 sensor feeds with TDOA', () => {
    const feedsForTriangulation = DEMO_FEEDS.map(f => ({
      feedId: f.id,
      position: f.geoPosition,
      arrivalTimeSec: f.acousticEvents[0]?.timestampSec ?? 0
    }));

    const result = triangulateAcousticOrigin(feedsForTriangulation);
    expect(result.sensorCount).toBe(3);
    expect(result.estimatedSourceLocation).toHaveProperty('x');
    expect(result.estimatedSourceLocation).toHaveProperty('y');
    expect(result.estimatedSourceLocation).toHaveProperty('z');
    expect(result.confidenceRadiusMeters).toBeGreaterThan(0);
  });

  it('builds a complete cryptographic forensic dossier across multi-angle streams', () => {
    const dossier = buildForensicDossier('INCIDENT-2026-X09', DEMO_FEEDS);
    expect(dossier.incidentId).toBe('INCIDENT-2026-X09');
    expect(dossier.synchronizedFeeds.length).toBe(3);
    expect(dossier.timelineSequence.length).toBeGreaterThan(0);
    // Real SHA-256 hex digest over the canonical dossier payload.
    expect(dossier.forensicHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces a different evidence hash when the evidence changes', () => {
    const a = buildForensicDossier('INCIDENT-2026-X09', DEMO_FEEDS);
    // Shifting an arrival time changes the triangulated origin, which must
    // change the dossier's integrity hash.
    const mutated = DEMO_FEEDS.map((f, i) => ({
      ...f,
      acousticEvents: f.acousticEvents.map((e) => ({ ...e, timestampSec: e.timestampSec + i }))
    }));
    const b = buildForensicDossier('INCIDENT-2026-X09', mutated);
    expect(a.forensicHash).not.toBe(b.forensicHash);
  });
});
