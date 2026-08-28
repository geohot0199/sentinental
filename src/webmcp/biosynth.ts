/**
 * BioSynth Studio - In-Browser 3D Molecular CAD & Protein Engineering Engine
 *
 * Implements PDB atomic structure parsing, in-silico point mutagenesis,
 * steric clash calculation, van der Waals overlap analysis, and binding pocket detection.
 */

export interface Atom {
  serial: number;
  name: string;
  resName: string;
  chain: string;
  resSeq: number;
  x: number;
  y: number;
  z: number;
  occupancy: number;
  tempFactor: number;
  element: string;
}

export interface AminoAcidInfo {
  code1: string;
  code3: string;
  name: string;
  mass: number;
  hydrophobicity: number; // Kyte-Doolittle scale (-4.5 to 4.5)
  charge: number; // -1, 0, +1
  vdwRadius: number; // Angstroms
}

export const AMINO_ACIDS: Record<string, AminoAcidInfo> = {
  ALA: { code1: 'A', code3: 'ALA', name: 'Alanine', mass: 89.1, hydrophobicity: 1.8, charge: 0, vdwRadius: 1.5 },
  ARG: { code1: 'R', code3: 'ARG', name: 'Arginine', mass: 174.2, hydrophobicity: -4.5, charge: 1, vdwRadius: 2.0 },
  ASN: { code1: 'N', code3: 'ASN', name: 'Asparagine', mass: 132.1, hydrophobicity: -3.5, charge: 0, vdwRadius: 1.6 },
  ASP: { code1: 'D', code3: 'ASP', name: 'Aspartic Acid', mass: 133.1, hydrophobicity: -3.5, charge: -1, vdwRadius: 1.6 },
  CYS: { code1: 'C', code3: 'CYS', name: 'Cysteine', mass: 121.2, hydrophobicity: 2.5, charge: 0, vdwRadius: 1.7 },
  GLN: { code1: 'Q', code3: 'GLN', name: 'Glutamine', mass: 146.2, hydrophobicity: -3.5, charge: 0, vdwRadius: 1.7 },
  GLU: { code1: 'E', code3: 'GLU', name: 'Glutamic Acid', mass: 147.1, hydrophobicity: -3.5, charge: -1, vdwRadius: 1.7 },
  GLY: { code1: 'G', code3: 'GLY', name: 'Glycine', mass: 75.1, hydrophobicity: -0.4, charge: 0, vdwRadius: 1.2 },
  HIS: { code1: 'H', code3: 'HIS', name: 'Histidine', mass: 155.2, hydrophobicity: -3.2, charge: 0.1, vdwRadius: 1.8 },
  ILE: { code1: 'I', code3: 'ILE', name: 'Isoleucine', mass: 131.2, hydrophobicity: 4.5, charge: 0, vdwRadius: 1.8 },
  LEU: { code1: 'L', code3: 'LEU', name: 'Leucine', mass: 131.2, hydrophobicity: 3.8, charge: 0, vdwRadius: 1.8 },
  LYS: { code1: 'K', code3: 'LYS', name: 'Lysine', mass: 146.2, hydrophobicity: -3.9, charge: 1, vdwRadius: 1.8 },
  MET: { code1: 'M', code3: 'MET', name: 'Methionine', mass: 149.2, hydrophobicity: 1.9, charge: 0, vdwRadius: 1.8 },
  PHE: { code1: 'F', code3: 'PHE', name: 'Phenylalanine', mass: 165.2, hydrophobicity: 2.8, charge: 0, vdwRadius: 1.9 },
  PRO: { code1: 'P', code3: 'PRO', name: 'Proline', mass: 115.1, hydrophobicity: -1.6, charge: 0, vdwRadius: 1.5 },
  SER: { code1: 'S', code3: 'SER', name: 'Serine', mass: 105.1, hydrophobicity: -0.8, charge: 0, vdwRadius: 1.5 },
  THR: { code1: 'T', code3: 'THR', name: 'Threonine', mass: 119.1, hydrophobicity: -0.7, charge: 0, vdwRadius: 1.6 },
  TRP: { code1: 'W', code3: 'TRP', name: 'Tryptophan', mass: 204.2, hydrophobicity: -0.9, charge: 0, vdwRadius: 2.1 },
  TYR: { code1: 'Y', code3: 'TYR', name: 'Tyrosine', mass: 181.2, hydrophobicity: -1.3, charge: 0, vdwRadius: 1.9 },
  VAL: { code1: 'V', code3: 'VAL', name: 'Valine', mass: 117.1, hydrophobicity: 4.2, charge: 0, vdwRadius: 1.6 }
};

export interface StericClash {
  atom1: string;
  atom2: string;
  residue1: string;
  residue2: string;
  distanceAngstroms: number;
  clashSeverity: 'MILD' | 'SEVERE' | 'CRITICAL';
}

export interface MutationSimulationResult {
  chain: string;
  residueSeq: number;
  originalResidue: string;
  mutatedResidue: string;
  deltaDeltaG: number; // Estimated change in stability in kcal/mol
  deltaHydrophobicity: number;
  deltaCharge: number;
  stericClashes: StericClash[];
  stabilityVerdict: 'STABILIZING' | 'NEUTRAL' | 'DESTABILIZING' | 'HIGH_CLASH_RISK';
  recommendation: string;
}

export interface BindingPocket {
  id: string;
  center: { x: number; y: number; z: number };
  volumeScore: number;
  druggabilityScore: number; // 0 to 1
  liningResidues: { chain: string; seq: number; name: string }[];
  description: string;
}

/**
 * Parses raw PDB string into structured 3D atomic coordinates.
 */
export function parsePDB(pdbContent: string): { atoms: Atom[]; sequence: { chain: string; seq: number; name: string }[] } {
  const lines = pdbContent.split('\n');
  const atoms: Atom[] = [];
  const seqMap = new Map<string, { chain: string; seq: number; name: string }>();

  for (const line of lines) {
    if (line.startsWith('ATOM  ') || line.startsWith('HETATM')) {
      const serial = parseInt(line.substring(6, 11).trim(), 10) || 0;
      const name = line.substring(12, 16).trim();
      const resName = line.substring(17, 20).trim();
      const chain = line.substring(21, 22).trim() || 'A';
      const resSeq = parseInt(line.substring(22, 26).trim(), 10) || 0;
      const x = parseFloat(line.substring(30, 38).trim()) || 0;
      const y = parseFloat(line.substring(38, 46).trim()) || 0;
      const z = parseFloat(line.substring(46, 54).trim()) || 0;
      const occupancy = parseFloat(line.substring(54, 60).trim()) || 1.0;
      const tempFactor = parseFloat(line.substring(60, 66).trim()) || 0.0;
      const defaultElement = name.length > 0 && name[0] ? name[0] : 'C';
      const element = line.substring(76, 78).trim() || defaultElement;

      atoms.push({ serial, name, resName, chain, resSeq, x, y, z, occupancy, tempFactor, element });

      const key = `${chain}:${resSeq}`;
      if (!seqMap.has(key)) {
        seqMap.set(key, { chain, seq: resSeq, name: resName });
      }
    }
  }

  return {
    atoms,
    sequence: Array.from(seqMap.values()).sort((a, b) => a.seq - b.seq)
  };
}

/**
 * Calculates Euclidean 3D distance between two atomic coordinates.
 */
export function distance3D(a: { x: number; y: number; z: number }, b: { x: number; y: number; z: number }): number {
  const dx = a.x - b.x;
  const dy = a.y - b.y;
  const dz = a.z - b.z;
  return Math.sqrt(dx * dx + dy * dy + dz * dz);
}

/**
 * Simulates in-silico amino acid mutation and predicts stability change & steric clashes.
 */
export function simulateMutation(
  atoms: Atom[],
  chain: string,
  resSeq: number,
  targetResidue3: string
): MutationSimulationResult {
  const target = targetResidue3.toUpperCase();
  const targetInfo = AMINO_ACIDS[target] ?? { code1: 'X', code3: target, name: 'Unknown', mass: 100, hydrophobicity: 0, charge: 0, vdwRadius: 1.6 };

  // Find existing residue
  const resAtoms = atoms.filter(a => a.chain === chain && a.resSeq === resSeq);
  const firstResAtom = resAtoms[0];
  const origResName = firstResAtom ? firstResAtom.resName : 'ALA';
  const origInfo = AMINO_ACIDS[origResName] ?? AMINO_ACIDS['ALA']!;

  const deltaHydro = Number((targetInfo.hydrophobicity - origInfo.hydrophobicity).toFixed(2));
  const deltaCharge = Number((targetInfo.charge - origInfo.charge).toFixed(2));

  // Compute neighboring atoms within 5.0 Angstroms of this residue's Alpha Carbon (CA)
  const caAtom = resAtoms.find(a => a.name === 'CA') || firstResAtom;
  const clashes: StericClash[] = [];

  if (caAtom) {
    const neighbors = atoms.filter(a => !(a.chain === chain && a.resSeq === resSeq));
    for (const neighbor of neighbors) {
      const dist = distance3D(caAtom, neighbor);
      const minAllowableDist = targetInfo.vdwRadius + 1.2;

      if (dist < minAllowableDist) {
        let clashSeverity: 'MILD' | 'SEVERE' | 'CRITICAL' = 'MILD';
        if (dist < 1.8) clashSeverity = 'CRITICAL';
        else if (dist < 2.5) clashSeverity = 'SEVERE';

        clashes.push({
          atom1: `${origResName}${resSeq}.CA`,
          atom2: `${neighbor.resName}${neighbor.resSeq}.${neighbor.name}`,
          residue1: `${origResName}${resSeq}`,
          residue2: `${neighbor.resName}${neighbor.resSeq}`,
          distanceAngstroms: Number(dist.toFixed(2)),
          clashSeverity
        });
      }
    }
  }

  let ddG = 0;
  if (clashes.some(c => c.clashSeverity === 'CRITICAL')) {
    ddG += 4.5;
  } else if (clashes.some(c => c.clashSeverity === 'SEVERE')) {
    ddG += 2.2;
  } else if (clashes.length > 0) {
    ddG += 0.8;
  }

  if (origInfo.hydrophobicity > 2.0 && targetInfo.hydrophobicity < 0) {
    ddG += 1.8;
  } else if (origInfo.hydrophobicity < 0 && targetInfo.hydrophobicity > 2.0 && clashes.length === 0) {
    ddG -= 1.2;
  }

  if (Math.abs(deltaCharge) > 0 && clashes.length > 0) {
    ddG += 0.9;
  }

  const finalDdG = Number(ddG.toFixed(2));

  let stabilityVerdict: MutationSimulationResult['stabilityVerdict'] = 'NEUTRAL';
  if (clashes.some(c => c.clashSeverity === 'CRITICAL') || finalDdG >= 3.0) {
    stabilityVerdict = 'HIGH_CLASH_RISK';
  } else if (finalDdG > 1.0) {
    stabilityVerdict = 'DESTABILIZING';
  } else if (finalDdG < -0.5) {
    stabilityVerdict = 'STABILIZING';
  }

  let recommendation = `Mutation ${origResName}${resSeq} -> ${target} predicted ${stabilityVerdict.toLowerCase().replace(/_/g, ' ')} (ΔΔG: ${finalDdG} kcal/mol).`;
  if (stabilityVerdict === 'HIGH_CLASH_RISK') {
    recommendation += ` Critical steric overlap with ${clashes[0]?.residue2}. Consider smaller sidechain like ALA or SER.`;
  } else if (stabilityVerdict === 'STABILIZING') {
    recommendation += ` Favorable energy gain and improved packing without steric clashes.`;
  }

  return {
    chain,
    residueSeq: resSeq,
    originalResidue: origResName,
    mutatedResidue: target,
    deltaDeltaG: finalDdG,
    deltaHydrophobicity: deltaHydro,
    deltaCharge: deltaCharge,
    stericClashes: clashes.slice(0, 5),
    stabilityVerdict,
    recommendation
  };
}

/**
 * Scans 3D protein structure to discover druggable active binding pockets.
 */
export function findBindingPockets(atoms: Atom[]): BindingPocket[] {
  if (atoms.length === 0) return [];

  const caAtoms = atoms.filter(a => a.name === 'CA');
  const pockets: BindingPocket[] = [];

  const step = Math.max(1, Math.floor(caAtoms.length / 4));
  for (let i = 0; i < caAtoms.length; i += step) {
    const centerAtom = caAtoms[i];
    if (!centerAtom) continue;

    const neighbors = caAtoms.filter(a => distance3D(centerAtom, a) < 9.0);
    
    if (neighbors.length >= 3) {
      const hydrophobicCount = neighbors.filter(a => {
        const info = AMINO_ACIDS[a.resName];
        return info && info.hydrophobicity > 0.5;
      }).length;

      const druggability = Number(Math.min(0.98, (hydrophobicCount / neighbors.length) * 0.9 + 0.1).toFixed(2));
      const pocketId = `Pocket-${pockets.length + 1}`;

      pockets.push({
        id: pocketId,
        center: {
          x: Number(centerAtom.x.toFixed(2)),
          y: Number(centerAtom.y.toFixed(2)),
          z: Number(centerAtom.z.toFixed(2))
        },
        volumeScore: Math.round(neighbors.length * 48.5),
        druggabilityScore: druggability,
        liningResidues: neighbors.map(n => ({ chain: n.chain, seq: n.resSeq, name: n.resName })),
        description: `Cavity at (${centerAtom.x.toFixed(1)}, ${centerAtom.y.toFixed(1)}, ${centerAtom.z.toFixed(1)}) lined by ${neighbors.length} residues. Druggability score: ${druggability}.`
      });
    }
  }

  return pockets;
}

/**
 * Built-in Synthetic Demo Protein (PDB Sample: 1CRN - Crambin fragment)
 */
export const SAMPLE_PDB_1CRN = `
ATOM      1  N   THR A   1      17.047  14.099   3.625  1.00 13.79           N
ATOM      2  CA  THR A   1      16.967  12.784   4.338  1.00 10.80           C
ATOM      3  C   THR A   1      15.685  12.755   5.133  1.00  9.19           C
ATOM      4  O   THR A   1      15.268  13.825   5.594  1.00  9.85           O
ATOM      5  CB  THR A   1      18.170  12.703   5.337  1.00 13.02           C
ATOM      6  N   THR A   2      15.115  11.555   5.265  1.00  7.81           N
ATOM      7  CA  THR A   2      13.856  11.469   6.066  1.00  7.51           C
ATOM      8  C   THR A   2      14.164  10.785   7.379  1.00  6.11           C
ATOM      9  O   THR A   2      14.976   9.873   7.447  1.00  6.88           O
ATOM     10  CB  THR A   2      12.732  10.711   5.261  1.00  8.03           C
ATOM     11  N   CYS A   3      13.488  11.241   8.417  1.00  5.24           N
ATOM     12  CA  CYS A   3      13.660  10.708   9.757  1.00  5.39           C
ATOM     13  C   CYS A   3      12.691   9.571  10.011  1.00  4.76           C
ATOM     14  O   CYS A   3      11.758   9.407   9.238  1.00  6.13           O
ATOM     15  CB  CYS A   3      13.535  11.839  10.776  1.00  6.15           C
ATOM     16  N   PRO A   4      12.871   8.766  11.082  1.00  4.80           N
ATOM     17  CA  PRO A   4      11.979   7.643  11.396  1.00  5.04           C
ATOM     18  C   PRO A   4      10.518   8.067  11.455  1.00  4.90           C
ATOM     19  O   PRO A   4      10.155   9.083  10.884  1.00  6.09           O
ATOM     20  CB  PRO A   4      12.518   7.086  12.721  1.00  5.94           C
ATOM     21  N   SER A   5       9.697   7.288  12.164  1.00  4.55           N
ATOM     22  CA  SER A   5       8.286   7.550  12.302  1.00  5.07           C
ATOM     23  C   SER A   5       8.016   7.933  13.754  1.00  4.47           C
ATOM     24  O   SER A   5       8.802   7.620  14.636  1.00  5.18           O
ATOM     25  CB  SER A   5       7.530   6.284  11.905  1.00  6.51           C
`.trim();
