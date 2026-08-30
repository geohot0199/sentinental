/**
 * Live scan page.
 *
 * Talks to the SENTINEL backend over relative URLs only, so it works
 * unchanged behind any proxy. All rendering goes through `el()`, which sets
 * textContent rather than innerHTML — advisory summaries are upstream data and
 * must never be interpolated as markup.
 */
import { $, el, fill, fmt, toast, boot } from './ui.js';

boot();

/* ------------------------------------------------------------------ state */

/** @type {EventSource | null} */
let stream = null;
let startedAt = 0;
let elapsedTimer = 0;
let currentScanId = null;

const SAMPLE_MANIFEST = {
  name: 'vulnerable-sample',
  version: '1.0.0',
  dependencies: {
    lodash: '4.17.11',
    minimist: '1.2.0',
    axios: '0.21.0',
    'node-fetch': '2.6.0',
    handlebars: '4.0.0',
  },
  devDependencies: {
    vitest: '^1.0.0',
  },
};

const OWN_MANIFEST = {
  name: 'sentinel-strike-team',
  version: '1.0.0',
  dependencies: {
    '@hono/node-server': '^1.13.7',
    '@modelcontextprotocol/sdk': '^1.0.4',
    hono: '^4.6.14',
    zod: '^3.24.1',
  },
};

/* ------------------------------------------------------------------ utils */

/** Fetch JSON, turning a non-2xx into a thrown Error carrying the server text. */
async function api(path, init) {
  const response = await fetch(path, init);
  const text = await response.text();
  let body = null;
  try {
    body = text.length > 0 ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!response.ok) {
    const message = body?.error ?? `${response.status} ${response.statusText}`;
    const error = new Error(message);
    error.remedy = body?.remedy ?? null;
    throw error;
  }
  return body;
}

/** Severity as a status level: fill and weight only, never colour. */
function severityLevel(severity) {
  if (severity === 'critical') return 'alert';
  if (severity === 'high') return 'warn';
  return 'ok';
}

function setStatus(text, level) {
  const node = $('#scanStatus');
  node.dataset.level = level;
  fill(node, [el('span', { class: 'dot' }), text]);
}

function log(line) {
  const out = $('#streamOut');
  out.textContent += `${line}\n`;
  out.scrollTop = out.scrollHeight;
}

function stopElapsed() {
  if (elapsedTimer !== 0) {
    clearInterval(elapsedTimer);
    elapsedTimer = 0;
  }
}

function tickElapsed() {
  stopElapsed();
  elapsedTimer = setInterval(() => {
    $('#mElapsed').textContent = `${((Date.now() - startedAt) / 1000).toFixed(1)}s`;
  }, 100);
}

function closeStream() {
  if (stream !== null) {
    stream.close();
    stream = null;
  }
  stopElapsed();
  $('#cancelScan').hidden = true;
  $('#runScan').disabled = false;
}

/* ------------------------------------------------------------------ modes */

function setMode(mode) {
  const isRepo = mode === 'repo';
  $('#repoPane').hidden = !isRepo;
  $('#manifestPane').hidden = isRepo;
  $('#modeTag').textContent = isRepo ? 'repository' : 'manifest';
  $('#modeRepo').setAttribute('aria-pressed', String(isRepo));
  $('#modeManifest').setAttribute('aria-pressed', String(!isRepo));
  $('#modeRepo').classList.toggle('btn-primary', isRepo);
  $('#modeManifest').classList.toggle('btn-primary', !isRepo);
}

/* --------------------------------------------------------------- rendering */

function renderFindings(findings) {
  const body = $('#findingsBody');
  if (findings.length === 0) {
    fill(body, [
      el('tr', {}, [
        el('td', { colspan: '8', class: 'dim' }, 'No known advisories. This tree is clean.'),
      ]),
    ]);
    return;
  }

  fill(
    body,
    findings.map((f) =>
      el('tr', {}, [
        el('td', { class: 'mono nowrap' }, f.packageName),
        el('td', { class: 'mono nowrap' }, f.installedVersion),
        el('td', {}, [
          el('span', { class: 'status', 'data-level': severityLevel(f.severity) }, f.severity),
        ]),
        el('td', { class: 'mono' }, f.cvssScore == null ? '—' : fmt.num(f.cvssScore, 1)),
        el('td', { class: 'mono nowrap' }, [
          el('a', { href: f.url, target: '_blank', rel: 'noopener noreferrer' }, f.cve ?? f.advisoryId),
        ]),
        el('td', {}, f.summary ?? '—'),
        el('td', { class: 'mono nowrap' }, f.recommendedVersion ?? 'none published'),
        el('td', { class: 'mono' }, f.bump ?? '—'),
      ]),
    ),
  );
}

function renderPlan(plan) {
  const body = $('#planBody');
  const entries = Array.isArray(plan) ? plan : [];
  $('#planTag').textContent = `${entries.length} upgrade${entries.length === 1 ? '' : 's'}`;

  if (entries.length === 0) {
    fill(body, [el('tr', {}, [el('td', { colspan: '5', class: 'dim' }, 'Nothing to upgrade.')])]);
    return;
  }

  fill(
    body,
    entries.map((p) =>
      el('tr', {}, [
        el('td', { class: 'mono nowrap' }, p.packageName),
        el('td', { class: 'mono nowrap' }, p.installedVersion),
        el('td', { class: 'mono nowrap' }, p.targetVersion ?? '—'),
        el('td', { class: 'mono' }, p.bump ?? '—'),
        el('td', { class: 'mono' }, String(p.advisoryCount)),
      ]),
    ),
  );
}

function renderPatch(patch, scanId) {
  const out = $('#patchOut');
  const link = $('#downloadPatch');
  if (patch === null || typeof patch.content !== 'string') {
    out.textContent = '';
    link.setAttribute('aria-disabled', 'true');
    return;
  }
  out.textContent = patch.content;
  link.href = `/api/scans/${encodeURIComponent(scanId)}/patch`;
  link.removeAttribute('aria-disabled');
}

async function renderResult(scanId) {
  const data = await api(`/api/scans/${encodeURIComponent(scanId)}`);
  const { scan, findings, plan, patch } = data;

  $('#mDeps').textContent = String(scan.dependencyCount ?? 0);
  $('#mFindings').textContent = String(scan.findingCount ?? 0);
  $('#mWorst').textContent = scan.worstSeverity ?? 'none';

  renderFindings(findings);
  renderPlan(plan);
  renderPatch(patch, scanId);
  $('#results').hidden = false;
  void loadHistory();
}

/* ---------------------------------------------------------------- history */

async function loadHistory() {
  let scans = [];
  try {
    const data = await api('/api/scans?limit=8');
    scans = data.scans ?? [];
  } catch {
    return; // The status pill already communicates a dead backend.
  }

  $('#historyTag').textContent = `${scans.length} stored`;
  const body = $('#historyBody');

  if (scans.length === 0) {
    fill(body, [el('tr', {}, [el('td', { colspan: '4', class: 'dim' }, 'No scans yet.')])]);
    return;
  }

  fill(
    body,
    scans.map((s) =>
      el('tr', {}, [
        el('td', { class: 'mono' }, fmt.clip(s.target, 28)),
        el('td', { class: 'mono' }, String(s.findingCount ?? 0)),
        el('td', { class: 'mono' }, s.worstSeverity ?? '—'),
        el('td', { class: 'nowrap' }, [
          el(
            'button',
            {
              class: 'btn btn-sm',
              type: 'button',
              onclick: () => {
                currentScanId = s.id;
                void renderResult(s.id).then(() => {
                  $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
                });
              },
            },
            'View',
          ),
          ' ',
          el(
            'button',
            {
              class: 'btn btn-sm',
              type: 'button',
              onclick: () => {
                void api(`/api/scans/${encodeURIComponent(s.id)}`, { method: 'DELETE' })
                  .then(() => {
                    if (currentScanId === s.id) $('#results').hidden = true;
                    toast('Scan deleted.');
                    return loadHistory();
                  })
                  .catch((error) => toast(error.message));
              },
            },
            'Delete',
          ),
        ]),
      ]),
    ),
  );
}

/* ------------------------------------------------------------------- scan */

function watch(scanId) {
  currentScanId = scanId;
  startedAt = Date.now();
  tickElapsed();

  stream = new EventSource(`/api/scans/${encodeURIComponent(scanId)}/events`);

  stream.addEventListener('progress', (event) => {
    const data = JSON.parse(event.data);
    log(`[${data.stage.padEnd(9)}] ${data.message}`);

    // Coarse but honest progress: the stages are known and ordered.
    const weights = { start: 5, inventory: 20, triage: 60, progress: 70, plan: 85, patch: 95 };
    const width = weights[data.stage] ?? Number($('#scanMeter').style.width.replace('%', ''));
    $('#scanMeter').style.width = `${width}%`;

    if (data.stage === 'triage') setStatus('triaging', 'warn');
  });

  stream.addEventListener('end', (event) => {
    const data = JSON.parse(event.data);
    $('#scanMeter').style.width = '100%';
    closeStream();

    if (data.status === 'failed') {
      setStatus('failed', 'alert');
      toast('The scan failed. See the stream for details.');
      void loadHistory();
      return;
    }
    setStatus('complete', 'ok');
    renderResult(scanId).catch((error) => toast(error.message));
  });

  stream.onerror = () => {
    // EventSource retries on its own; only give up once the socket is closed.
    if (stream !== null && stream.readyState === EventSource.CLOSED) {
      closeStream();
      setStatus('disconnected', 'alert');
      log('[error    ] Stream closed unexpectedly.');
    }
  };
}

async function runScan() {
  closeStream();
  $('#runScan').disabled = true;
  $('#results').hidden = true;
  $('#streamOut').textContent = '';
  $('#scanMeter').style.width = '0%';
  $('#mDeps').textContent = '—';
  $('#mFindings').textContent = '—';
  $('#mWorst').textContent = '—';
  $('#mElapsed').textContent = '0.0s';
  setStatus('queued', 'warn');

  const isRepo = !$('#repoPane').hidden;
  const payload = isRepo
    ? { repo: $('#repoInput').value.trim() }
    : { manifest: $('#manifestInput').value.trim() };

  try {
    const created = await api('/api/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    log(`[queued   ] ${created.target} (${created.source})`);
    $('#cancelScan').hidden = false;
    watch(created.id);
  } catch (error) {
    closeStream();
    setStatus('rejected', 'alert');
    log(`[error    ] ${error.message}`);
    if (error.remedy) log(`[hint     ] ${error.remedy}`);
    toast(error.message);
  }
}

/* ------------------------------------------------------------------- init */

async function loadStatus() {
  const pill = $('#backendStatus');
  try {
    const status = await api('/api/status');
    pill.dataset.level = 'ok';
    fill(pill, [el('span', { class: 'dot' }), status.github ? 'backend live' : 'backend (no token)']);
    if (!status.github) {
      $('#repoHelp').textContent =
        'This server has no GitHub token, so repository scanning is disabled. Paste a package.json instead.';
      $('#modeRepo').disabled = true;
    }
  } catch {
    pill.dataset.level = 'alert';
    fill(pill, [el('span', { class: 'dot' }), 'backend offline']);
    log('[error    ] No backend. Start it with: npm run app');
  }
}

function init() {
  $('#manifestInput').value = JSON.stringify(SAMPLE_MANIFEST, null, 2);
  setMode('manifest');

  $('#modeManifest').addEventListener('click', () => setMode('manifest'));
  $('#modeRepo').addEventListener('click', () => setMode('repo'));
  $('#runScan').addEventListener('click', () => void runScan());
  $('#cancelScan').addEventListener('click', () => {
    closeStream();
    setStatus('detached', 'warn');
    log('[client   ] Stopped watching. The scan continues on the server.');
  });

  $('#loadVulnerable').addEventListener('click', () => {
    $('#manifestInput').value = JSON.stringify(SAMPLE_MANIFEST, null, 2);
    toast('Loaded a manifest with known CVEs.');
  });
  $('#loadOwn').addEventListener('click', () => {
    $('#manifestInput').value = JSON.stringify(OWN_MANIFEST, null, 2);
    toast("Loaded SENTINEL's own dependencies.");
  });

  $('#copyPatch').addEventListener('click', () => {
    const text = $('#patchOut').textContent;
    if (text.length === 0) {
      toast('Run a scan first.');
      return;
    }
    void navigator.clipboard
      .writeText(text)
      .then(() => toast('Patched manifest copied.'))
      .catch(() => toast('Clipboard was blocked.'));
  });

  void loadStatus();
  void loadHistory();
}

init();
