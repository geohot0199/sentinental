import { describe, it, expect } from 'vitest';
import {
  parsePDB,
  distance3D,
  simulateMutation,
  findBindingPockets,
  SAMPLE_PDB_1CRN,
  AMINO_ACIDS
} from '../src/webmcp/biosynth.ts';

describe('BioSynth Studio Engine (Module 2)', () => {
  it('parses PDB coordinate data and extracts atoms and sequence', () => {
    const { atoms, sequence } = parsePDB(SAMPLE_PDB_1CRN);
    expect(atoms.length).toBe(25);
    expect(sequence.length).toBe(5);
    expect(sequence[0]).toEqual({ chain: 'A', seq: 1, name: 'THR' });
    expect(sequence[4]).toEqual({ chain: 'A', seq: 5, name: 'SER' });
  });

  it('calculates 3D Euclidean distances accurately', () => {
    const p1 = { x: 0, y: 0, z: 0 };
    const p2 = { x: 3, y: 4, z: 0 };
    expect(distance3D(p1, p2)).toBe(5);
  });

  it('simulates point mutation and computes steric clashes and energy changes', () => {
    const { atoms } = parsePDB(SAMPLE_PDB_1CRN);
    // Mutate THR 2 to bulky TRP (Tryptophan)
    const result = simulateMutation(atoms, 'A', 2, 'TRP');
    expect(result.originalResidue).toBe('THR');
    expect(result.mutatedResidue).toBe('TRP');
    expect(typeof result.deltaDeltaG).toBe('number');
    expect(result.recommendation).toBeDefined();
  });

  it('identifies candidate binding pockets and cavity centers', () => {
    const { atoms } = parsePDB(SAMPLE_PDB_1CRN);
    const pockets = findBindingPockets(atoms);
    expect(Array.isArray(pockets)).toBe(true);
    if (pockets.length > 0) {
      const p0 = pockets[0];
      expect(p0).toBeDefined();
      expect(p0?.druggabilityScore).toBeGreaterThan(0);
      expect(p0?.center).toHaveProperty('x');
    }
  });

  it('contains valid canonical amino acid registry', () => {
    expect(AMINO_ACIDS['ALA']?.code1).toBe('A');
    expect(AMINO_ACIDS['CYS']?.charge).toBe(0);
    expect(AMINO_ACIDS['ARG']?.charge).toBe(1);
    expect(AMINO_ACIDS['ASP']?.charge).toBe(-1);
  });
});
