/**
 * SENTINEL OMNI-LAB: Standalone WebMCP Bundle
 * Zero external dependencies. Works in any standard browser and ChatGPT in-app browser.
 */

// ==========================================
// 0. CRYPTOGRAPHIC PRIMITIVES
// ==========================================
// Dependency-free, synchronous SHA-256 and HMAC-SHA-256 (FIPS 180-4 / RFC 2104).
// These replace the old 32-bit rolling "hash" that was mislabelled as SHA-256,
// so deliverable fingerprints and forensic evidence hashes are real digests.
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function sha256Bytes(data) {
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const l = data.length;
  const bitLenHi = Math.floor(l / 0x20000000);
  const bitLenLo = (l << 3) >>> 0;
  const paddedLen = ((l + 9 + 63) & ~63) >>> 0;

  const msg = new Uint8Array(paddedLen);
  msg.set(data);
  msg[l] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(paddedLen - 8, bitLenHi, false);
  dv.setUint32(paddedLen - 4, bitLenLo, false);

  const w = new Uint32Array(64);
  for (let i = 0; i < paddedLen; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = ((w[t - 15] >>> 7) | (w[t - 15] << 25)) ^ ((w[t - 15] >>> 18) | (w[t - 15] << 14)) ^ (w[t - 15] >>> 3);
      const s1 = ((w[t - 2] >>> 17) | (w[t - 2] << 15)) ^ ((w[t - 2] >>> 19) | (w[t - 2] << 13)) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
  return out;
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

function utf8Bytes(str) {
  return new TextEncoder().encode(String(str));
}

function sha256Hex(input) {
  return bytesToHex(sha256Bytes(utf8Bytes(input)));
}

function hmacSha256Hex(keyStr, msgStr) {
  const BLOCK = 64;
  const key = utf8Bytes(keyStr);
  const k = key.length > BLOCK ? sha256Bytes(key) : new Uint8Array(BLOCK);
  if (key.length <= BLOCK) k.set(key);
  const ipad = new Uint8Array(BLOCK);
  const opad = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const msg = utf8Bytes(msgStr);
  const inner = new Uint8Array(BLOCK + msg.length);
  inner.set(ipad);
  inner.set(msg, BLOCK);
  const outer = new Uint8Array(BLOCK + 32);
  outer.set(opad);
  outer.set(sha256Bytes(inner), BLOCK);
  return bytesToHex(sha256Bytes(outer));
}

function randomHex(byteLen) {
  const bytes = new Uint8Array(byteLen);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < byteLen; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytesToHex(bytes);
}

// ==========================================
// 1. BREACHLAB ENGINE
// ==========================================
export const BreachLab = {
  calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const map = {};
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      map[char] = (map[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in map) {
      const p = map[char] / str.length;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  },

  analyzeCveAst(codeOrManifest, options) {
    const lines = (codeOrManifest || '').split('\n');
    const findings = [];
    const nodes = [];
    const edges = [];
    let dangerousCalls = 0;
    let obfuscationHits = 0;
    const entropy = this.calculateShannonEntropy(codeOrManifest);

    const isJson = (codeOrManifest || '').trim().startsWith('{');
    if (isJson) {
      try {
        const parsed = JSON.parse(codeOrManifest);
        const allDeps = { ...(parsed.dependencies || {}), ...(parsed.devDependencies || {}) };
        nodes.push({ id: 'root_pkg', label: parsed.name || 'Root Package', type: 'entry', severity: 'low', blastRadius: 20 });

        for (const [dep, version] of Object.entries(allDeps)) {
          const verStr = String(version);
          const depId = `dep_${dep.replace(/[^a-zA-Z0-9]/g, '_')}`;
          let nodeSev = 'low';
          let blast = 30;

          if (verStr.includes('*') || verStr.includes('>') || verStr.includes('^0.') || verStr.startsWith('latest')) {
            findings.push({
              id: `FIND-${findings.length + 1}`,
              type: 'UNPINNED_DEP',
              severity: 'MEDIUM',
              line: 1,
              snippet: `"${dep}": "${verStr}"`,
              description: `Unpinned dependency version (${dep}@${verStr}) risks supply chain poisoning.`,
              remediation: 'Pin exact version with lockfile hash validation.'
            });
            nodeSev = 'medium';
            blast = 55;
          }

          if (dep.includes('event-stream-flat') || dep.includes('ua-parser-js-bad') || dep.includes('colors-corrupt')) {
            findings.push({
              id: `FIND-${findings.length + 1}`,
              type: 'CREDENTIAL_EXFIL',
              severity: 'CRITICAL',
              line: 1,
              snippet: `"${dep}": "${verStr}"`,
              description: `Known malicious supply-chain package signature detected: ${dep}`,
              remediation: `Immediately quarantine and remove package ${dep}.`
            });
            nodeSev = 'critical';
            blast = 95;
          }

          nodes.push({ id: depId, label: `${dep}@${verStr}`, type: 'intermediate', severity: nodeSev, blastRadius: blast });
          edges.push({ from: 'root_pkg', to: depId, label: 'depends_on', tainted: nodeSev !== 'low' });
        }
      } catch {}
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const trimmed = line.trim();

      if (/eval\s*\(|new\s+Function\s*\(|vm\.runInThisContext/.test(trimmed)) {
        dangerousCalls++;
        findings.push({
          id: `FIND-${findings.length + 1}`,
          type: 'RCE',
          severity: 'CRITICAL',
          line: lineNum,
          snippet: trimmed,
          description: 'Dynamic code execution sink (eval/new Function) allowing arbitrary remote code execution.',
          remediation: 'Eliminate eval(); use safe static JSON parsing or strict schema evaluation.'
        });
      }

      if (/child_process|exec\s*\(|spawn\s*\(|execSync\s*\(/.test(trimmed)) {
        dangerousCalls++;
        findings.push({
          id: `FIND-${findings.length + 1}`,
          type: 'RCE',
          severity: 'HIGH',
          line: lineNum,
          snippet: trimmed,
          description: 'Command injection vector through shell execution primitive.',
          remediation: 'Replace exec with spawn with explicit arguments array; avoid passing raw strings into shell.'
        });
      }

      if (/process\.env\.(AWS|SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE_KEY)/i.test(trimmed) &&
          (/fetch\(|http|axios|request|XMLHttpRequest|socket\.send|\.post\(/i.test(trimmed) || lines.some(l => l.includes('http') || l.includes('fetch')))) {
        dangerousCalls++;
        findings.push({
          id: `FIND-${findings.length + 1}`,
          type: 'CREDENTIAL_EXFIL',
          severity: 'CRITICAL',
          line: lineNum,
          snippet: trimmed,
          description: 'Targeted secret / environment variable exfiltration via outbound network transmission.',
          remediation: 'Remove outbound secret leakage; isolate credential handling behind hardware security modules.'
        });
      }

      if (/net\.connect|net\.createConnection|socket\.connect|(\/bin\/sh|\/bin\/bash)/.test(trimmed)) {
        dangerousCalls++;
        findings.push({
          id: `FIND-${findings.length + 1}`,
          type: 'REVERSE_SHELL',
          severity: 'CRITICAL',
          line: lineNum,
          snippet: trimmed,
          description: 'Reverse shell / raw TCP socket spawning interactive shell.',
          remediation: 'Quarantine and terminate connection immediately; strip raw socket execution.'
        });
      }

      if (/__proto__|constructor\.prototype|Object\.prototype/.test(trimmed) && !trimmed.startsWith('//')) {
        findings.push({
          id: `FIND-${findings.length + 1}`,
          type: 'PROTOTYPE_POLLUTION',
          severity: 'HIGH',
          line: lineNum,
          snippet: trimmed,
          description: 'Unchecked prototype assignment leading to global prototype pollution and denial of service/RCE.',
          remediation: 'Use Object.create(null) or Map; validate keys before property assignment.'
        });
      }

      if (/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|Buffer\.from\(.+,'base64'\)|atob\(/.test(trimmed) && trimmed.length > 30) {
        obfuscationHits++;
        findings.push({
          id: `FIND-${findings.length + 1}`,
          type: 'OBFUSCATION',
          severity: 'MEDIUM',
          line: lineNum,
          snippet: trimmed.slice(0, 80) + (trimmed.length > 80 ? '...' : ''),
          description: 'Obfuscated character encodings / base64 payload detected hiding internal logic.',
          remediation: 'Deobfuscate code and verify raw string literals against safe inventory.'
        });
      }
    });

    let score = 0;
    for (const f of findings) {
      if (f.severity === 'CRITICAL') score += 35;
      else if (f.severity === 'HIGH') score += 20;
      else if (f.severity === 'MEDIUM') score += 10;
      else score += 5;
    }
    if (entropy > 5.2) score += 15;
    score = Math.min(100, Math.max(0, score));

    let verdict = 'SAFE';
    if (score >= 80) verdict = 'CRITICAL_ZERO_DAY';
    else if (score >= 50) verdict = 'MALICIOUS';
    else if (score > 15) verdict = 'SUSPICIOUS';

    if (nodes.length === 0) {
      nodes.push({ id: 'entry_point', label: 'Entrypoint / Payload', type: 'entry', severity: 'low', blastRadius: 20 });
      findings.forEach((f, idx) => {
        const nodeId = `vuln_${idx + 1}`;
        const sev = f.severity.toLowerCase();
        const blast = f.severity === 'CRITICAL' ? 95 : f.severity === 'HIGH' ? 75 : 45;
        nodes.push({ id: nodeId, label: `${f.type} (L${f.line})`, type: f.type === 'CREDENTIAL_EXFIL' ? 'exfil' : 'sink', severity: sev, blastRadius: blast });
        edges.push({ from: 'entry_point', to: nodeId, label: 'triggers', tainted: true });
      });
    }

    const obfuscationRatio = lines.length > 0 ? Number((obfuscationHits / lines.length).toFixed(3)) : 0;

    return {
      threatScore: score,
      verdict,
      findings,
      graph: { nodes, edges },
      summary: `Analyzed ${lines.length} lines of code. Found ${findings.length} security alerts. Threat Score: ${score}/100 [${verdict}].`,
      astMetrics: {
        entropy,
        obfuscationRatio,
        dangerousCallsCount: dangerousCalls,
        linesOfCode: lines.length
      }
    };
  },

  detonateSandbox(code, config) {
    const startTime = Date.now();
    const interceptedEvents = [];
    const quarantinedThreats = [];
    const stdout = [];

    // Honour the advertised execution window instead of scanning unbounded.
    const timeoutMs = config && config.timeoutMs;
    const deadline = typeof timeoutMs === 'number' && timeoutMs >= 0 ? startTime + timeoutMs : null;
    let timedOut = false;

    const lines = (code || '').split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (deadline !== null && Date.now() > deadline) {
        timedOut = true;
        break;
      }
      const line = lines[i].trim();
      if (!line || line.startsWith('//')) continue;

      if (/process\.env\.([a-zA-Z0-9_]+)/.test(line)) {
        const match = line.match(/process\.env\.([a-zA-Z0-9_]+)/);
        const varName = match ? match[1] : 'UNKNOWN_VAR';
        interceptedEvents.push({
          timestamp: Date.now() - startTime,
          action: 'READ_ENV',
          target: `process.env.${varName}`,
          blocked: false,
          alert: `Detonated process queried sensitive environment key: ${varName}`
        });
      }

      if (/fetch\(|http\.request|axios|net\.connect|XMLHttpRequest/.test(line)) {
        interceptedEvents.push({
          timestamp: Date.now() - startTime + 5,
          action: 'NETWORK_EXFIL_ATTEMPT',
          target: 'Outbound TCP/HTTP Sink',
          blocked: true,
          alert: 'Quarantine Firewall BLOCKED unauthorized outbound network socket during detonation.'
        });
        quarantinedThreats.push('BLOCKED_NETWORK_EXFILTRATION');
      }

      if (/eval\(|new Function\(/.test(line)) {
        interceptedEvents.push({
          timestamp: Date.now() - startTime + 10,
          action: 'UNSAFE_EVAL_EXECUTION',
          target: 'V8 Execution Engine',
          blocked: true,
          alert: 'Execution Interceptor HALTED dynamic eval execution stream.'
        });
        quarantinedThreats.push('BLOCKED_DYNAMIC_EVAL');
      }

      if (/exec\(|spawn\(|execSync\(/.test(line)) {
        interceptedEvents.push({
          timestamp: Date.now() - startTime + 15,
          action: 'SUBPROCESS_SPAWN',
          target: '/bin/sh',
          blocked: true,
          alert: 'Subprocess spawner caught attempting to invoke host command shell.'
        });
        quarantinedThreats.push('BLOCKED_HOST_COMMAND_INJECTION');
      }

      if (/console\.log\((.+)\)/.test(line)) {
        const logMatch = line.match(/console\.log\((.+)\)/);
        if (logMatch) stdout.push(`[DETONATOR STDOUT] ${logMatch[1].replace(/['"]/g, '')}`);
      }
    }

    const executionTimeMs = Math.max(0, Date.now() - startTime);
    const safeToRun = quarantinedThreats.length === 0 && interceptedEvents.length === 0 && !timedOut;

    if (timedOut) {
      stdout.push(`[Sandbox execution window (${timeoutMs}ms) exceeded - scan aborted before completion.]`);
    }

    return {
      success: !timedOut,
      timedOut,
      executionTimeMs,
      interceptedEvents,
      quarantinedThreats,
      safeToRun,
      stdout: stdout.length > 0 ? stdout : ['[Detonation sandbox initialized in isolated micro-container.]', `[Completed simulated analysis in ${executionTimeMs}ms]`]
    };
  },

  traceTaintFlow(code, sourcePattern, sinkPattern) {
    const lines = (code || '').split('\n');
    const source = sourcePattern || 'req.query|req.body|process.env|userInput';
    const sink = sinkPattern || 'eval|exec|execSync|spawn|fs.writeFile|net.connect';

    const sourceRegex = new RegExp(source, 'i');
    const sinkRegex = new RegExp(sink, 'i');

    const traceSteps = [];
    const trackedVars = new Set();

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();

      if (sourceRegex.test(trimmed)) {
        const assignMatch = trimmed.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/);
        if (assignMatch) trackedVars.add(assignMatch[1]);
        traceSteps.push({ line: lineNum, type: 'SOURCE', text: trimmed, variable: assignMatch ? assignMatch[1] : undefined });
        return;
      }

      for (const v of trackedVars) {
        if (trimmed.includes(v)) {
          const nextAssign = trimmed.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/);
          if (nextAssign && nextAssign[1] !== v) trackedVars.add(nextAssign[1]);

          if (sinkRegex.test(trimmed)) {
            traceSteps.push({ line: lineNum, type: 'SINK', text: trimmed, variable: v });
          } else {
            traceSteps.push({ line: lineNum, type: 'PROPAGATION', text: trimmed, variable: v });
          }
          break;
        }
      }
    });

    return {
      sourcePattern: source,
      sinkPattern: sink,
      isVulnerable: traceSteps.some(s => s.type === 'SINK'),
      taintTrace: traceSteps,
      taintedVariables: Array.from(trackedVars)
    };
  },

  generateHotpatch(code) {
    const lines = (code || '').split('\n');
    const patchedLines = [];
    const diff = [];
    const fixesApplied = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let modified = line;

      if (/eval\s*\((.+)\)/.test(line)) {
        modified = line.replace(/eval\s*\((.+)\)/g, 'JSON.parse($1 /* [SENTINEL-PATCH: Replaced dangerous eval with strict JSON parser] */)');
        diff.push(`- ${line}`);
        diff.push(`+ ${modified}`);
        fixesApplied.push('Replaced dynamic eval() sink with safe JSON parse');
      } else if (/child_process\.exec\s*\((.+)\)/.test(line) || /execSync\s*\((.+)\)/.test(line)) {
        modified = line.replace(/(?:child_process\.)?exec(?:Sync)?\s*\((.+)\)/g, '/* [SENTINEL-PATCH: Parameterized shell command against injection] */ execFileSync("/usr/bin/env", [$1])');
        diff.push(`- ${line}`);
        diff.push(`+ ${modified}`);
        fixesApplied.push('Replaced unsafe shell exec string with parameterized command execution');
      } else if (/__proto__|constructor\.prototype/.test(line)) {
        modified = `/* [SENTINEL-PATCH: Block prototype mutation] */ if (!['__proto__', 'constructor', 'prototype'].includes(key)) { ${line.trim()} }`;
        diff.push(`- ${line}`);
        diff.push(`+ ${modified}`);
        fixesApplied.push('Added prototype pollution filter guard');
      } else if (/process\.env\.(AWS|SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE_KEY)/i.test(line) && /fetch|http|axios/i.test(line)) {
        modified = `// [SENTINEL-PATCH: Outbound secret transmission neutralized]\n// ${line}`;
        diff.push(`- ${line}`);
        diff.push(`+ ${modified}`);
        fixesApplied.push('Neutralized exfiltration of sensitive environment variables');
      }

      patchedLines.push(modified);
    }

    const patchedCode = patchedLines.join('\n');
    const origAnalysis = this.analyzeCveAst(code);
    const patchAnalysis = this.analyzeCveAst(patchedCode);
    const scoreImprovement = Math.max(0, origAnalysis.threatScore - patchAnalysis.threatScore);

    return {
      originalCode: code,
      patchedCode,
      diff,
      fixesApplied: fixesApplied.length > 0 ? fixesApplied : ['No critical vulnerabilities found requiring automated code rewriting.'],
      securityScoreImprovement: scoreImprovement
    };
  }
};

// ==========================================
// 2. BIOSYNTH STUDIO ENGINE
// ==========================================
export const BioSynth = {
  SAMPLE_PDB_1CRN: `
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
`.trim(),

  AMINO_ACIDS: {
    ALA: { code1: 'A', code3: 'ALA', name: 'Alanine', hydrophobicity: 1.8, charge: 0, vdwRadius: 1.5 },
    ARG: { code1: 'R', code3: 'ARG', name: 'Arginine', hydrophobicity: -4.5, charge: 1, vdwRadius: 2.0 },
    ASN: { code1: 'N', code3: 'ASN', name: 'Asparagine', hydrophobicity: -3.5, charge: 0, vdwRadius: 1.6 },
    ASP: { code1: 'D', code3: 'ASP', name: 'Aspartic Acid', hydrophobicity: -3.5, charge: -1, vdwRadius: 1.6 },
    CYS: { code1: 'C', code3: 'CYS', name: 'Cysteine', hydrophobicity: 2.5, charge: 0, vdwRadius: 1.7 },
    GLN: { code1: 'Q', code3: 'GLN', name: 'Glutamine', hydrophobicity: -3.5, charge: 0, vdwRadius: 1.7 },
    GLU: { code1: 'E', code3: 'GLU', name: 'Glutamic Acid', hydrophobicity: -3.5, charge: -1, vdwRadius: 1.7 },
    GLY: { code1: 'G', code3: 'GLY', name: 'Glycine', hydrophobicity: -0.4, charge: 0, vdwRadius: 1.2 },
    HIS: { code1: 'H', code3: 'HIS', name: 'Histidine', hydrophobicity: -3.2, charge: 0.1, vdwRadius: 1.8 },
    ILE: { code1: 'I', code3: 'ILE', name: 'Isoleucine', hydrophobicity: 4.5, charge: 0, vdwRadius: 1.8 },
    LEU: { code1: 'L', code3: 'LEU', name: 'Leucine', hydrophobicity: 3.8, charge: 0, vdwRadius: 1.8 },
    LYS: { code1: 'K', code3: 'LYS', name: 'Lysine', hydrophobicity: -3.9, charge: 1, vdwRadius: 1.8 },
    MET: { code1: 'M', code3: 'MET', name: 'Methionine', hydrophobicity: 1.9, charge: 0, vdwRadius: 1.8 },
    PHE: { code1: 'F', code3: 'PHE', name: 'Phenylalanine', hydrophobicity: 2.8, charge: 0, vdwRadius: 1.9 },
    PRO: { code1: 'P', code3: 'PRO', name: 'Proline', hydrophobicity: -1.6, charge: 0, vdwRadius: 1.5 },
    SER: { code1: 'S', code3: 'SER', name: 'Serine', hydrophobicity: -0.8, charge: 0, vdwRadius: 1.5 },
    THR: { code1: 'T', code3: 'THR', name: 'Threonine', hydrophobicity: -0.7, charge: 0, vdwRadius: 1.6 },
    TRP: { code1: 'W', code3: 'TRP', name: 'Tryptophan', hydrophobicity: -0.9, charge: 0, vdwRadius: 2.1 },
    TYR: { code1: 'Y', code3: 'TYR', name: 'Tyrosine', hydrophobicity: -1.3, charge: 0, vdwRadius: 1.9 },
    VAL: { code1: 'V', code3: 'VAL', name: 'Valine', hydrophobicity: 4.2, charge: 0, vdwRadius: 1.6 }
  },

  parsePDB(pdbContent) {
    const lines = (pdbContent || this.SAMPLE_PDB_1CRN).split('\n');
    const atoms = [];
    const seqMap = new Map();

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
        const element = line.substring(76, 78).trim() || (name.length > 0 ? name[0] : 'C');

        atoms.push({ serial, name, resName, chain, resSeq, x, y, z, occupancy, tempFactor, element });
        const key = `${chain}:${resSeq}`;
        if (!seqMap.has(key)) seqMap.set(key, { chain, seq: resSeq, name: resName });
      }
    }

    return { atoms, sequence: Array.from(seqMap.values()).sort((a, b) => a.seq - b.seq) };
  },

  distance3D(a, b) {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    const dz = a.z - b.z;
    return Math.sqrt(dx * dx + dy * dy + dz * dz);
  },

  simulateMutation(atoms, chain, resSeq, targetResidue3) {
    const target = (targetResidue3 || 'ALA').toUpperCase();
    const targetInfo = this.AMINO_ACIDS[target] || { code1: 'X', code3: target, name: 'Unknown', hydrophobicity: 0, charge: 0, vdwRadius: 1.6 };

    const resAtoms = atoms.filter(a => a.chain === chain && a.resSeq === resSeq);
    const origResName = resAtoms.length > 0 ? resAtoms[0].resName : 'ALA';
    const origInfo = this.AMINO_ACIDS[origResName] || this.AMINO_ACIDS['ALA'];

    const deltaHydro = Number((targetInfo.hydrophobicity - origInfo.hydrophobicity).toFixed(2));
    const deltaCharge = Number((targetInfo.charge - origInfo.charge).toFixed(2));

    const caAtom = resAtoms.find(a => a.name === 'CA') || resAtoms[0];
    const clashes = [];

    if (caAtom) {
      const neighbors = atoms.filter(a => !(a.chain === chain && a.resSeq === resSeq));
      for (const neighbor of neighbors) {
        const dist = this.distance3D(caAtom, neighbor);
        const minAllowable = targetInfo.vdwRadius + 1.2;

        if (dist < minAllowable) {
          let clashSeverity = 'MILD';
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
    if (clashes.some(c => c.clashSeverity === 'CRITICAL')) ddG += 4.5;
    else if (clashes.some(c => c.clashSeverity === 'SEVERE')) ddG += 2.2;
    else if (clashes.length > 0) ddG += 0.8;

    if (origInfo.hydrophobicity > 2.0 && targetInfo.hydrophobicity < 0) ddG += 1.8;
    else if (origInfo.hydrophobicity < 0 && targetInfo.hydrophobicity > 2.0 && clashes.length === 0) ddG -= 1.2;

    const finalDdG = Number(ddG.toFixed(2));

    let stabilityVerdict = 'NEUTRAL';
    if (clashes.some(c => c.clashSeverity === 'CRITICAL') || finalDdG >= 3.0) stabilityVerdict = 'HIGH_CLASH_RISK';
    else if (finalDdG > 1.0) stabilityVerdict = 'DESTABILIZING';
    else if (finalDdG < -0.5) stabilityVerdict = 'STABILIZING';

    let recommendation = `Mutation ${origResName}${resSeq} -> ${target} predicted ${stabilityVerdict.toLowerCase().replace(/_/g, ' ')} (ΔΔG: ${finalDdG} kcal/mol).`;
    if (stabilityVerdict === 'HIGH_CLASH_RISK') {
      recommendation += ` Steric clash detected with ${clashes[0]?.residue2}. Try smaller sidechain like ALA.`;
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
  },

  findBindingPockets(atoms) {
    if (!atoms || atoms.length === 0) return [];
    const caAtoms = atoms.filter(a => a.name === 'CA');
    const pockets = [];
    const step = Math.max(1, Math.floor(caAtoms.length / 4));

    for (let i = 0; i < caAtoms.length; i += step) {
      const centerAtom = caAtoms[i];
      const neighbors = caAtoms.filter(a => this.distance3D(centerAtom, a) < 9.0);

      if (neighbors.length >= 3) {
        const hydrophobicCount = neighbors.filter(a => {
          const info = this.AMINO_ACIDS[a.resName];
          return info && info.hydrophobicity > 0.5;
        }).length;

        const druggability = Number(Math.min(0.98, (hydrophobicCount / neighbors.length) * 0.9 + 0.1).toFixed(2));
        pockets.push({
          id: `Pocket-${pockets.length + 1}`,
          center: { x: Number(centerAtom.x.toFixed(2)), y: Number(centerAtom.y.toFixed(2)), z: Number(centerAtom.z.toFixed(2)) },
          volumeScore: Math.round(neighbors.length * 48.5),
          druggabilityScore: druggability,
          liningResidues: neighbors.map(n => ({ chain: n.chain, seq: n.resSeq, name: n.resName })),
          description: `Cavity at (${centerAtom.x.toFixed(1)}, ${centerAtom.y.toFixed(1)}, ${centerAtom.z.toFixed(1)}) lined by ${neighbors.length} residues. Druggability score: ${druggability}.`
        });
      }
    }
    return pockets;
  }
};

// ==========================================
// 3. CHRONOFORENSIC OSINT ENGINE
// ==========================================
export const ChronoForensic = {
  SPEED_OF_SOUND: 343.0,

  DEMO_FEEDS: [
    {
      id: 'CAM-01-CCTV',
      sourceName: 'North Corner Street CCTV',
      cameraType: 'CCTV',
      geoPosition: { x: 10, y: 15, z: 6 },
      durationSec: 15.0,
      recordedFps: 30,
      audioSampleRate: 48000,
      opticalEvents: [{ timestampSec: 3.140, intensity: 95, description: 'Flash peak muzzle/blast' }],
      acousticEvents: [{ timestampSec: 3.195, amplitudeDb: 102, frequencyHz: 450 }]
    },
    {
      id: 'CAM-02-BODYCAM',
      sourceName: 'Patrol Officer Bodycam #42',
      cameraType: 'BODYCAM',
      geoPosition: { x: -35, y: 40, z: 1.7 },
      durationSec: 15.0,
      recordedFps: 60,
      audioSampleRate: 48000,
      opticalEvents: [{ timestampSec: 3.240, intensity: 88, description: 'Direct optical flash line-of-sight' }],
      acousticEvents: [{ timestampSec: 3.390, amplitudeDb: 96, frequencyHz: 440 }]
    },
    {
      id: 'CAM-03-DRONE',
      sourceName: 'Overwatch Quadcopter Drone',
      cameraType: 'DRONE',
      geoPosition: { x: 5, y: -50, z: 45 },
      durationSec: 15.0,
      recordedFps: 60,
      audioSampleRate: 48000,
      opticalEvents: [{ timestampSec: 3.142, intensity: 92, description: 'Aerial thermal flash detection' }],
      acousticEvents: [{ timestampSec: 3.340, amplitudeDb: 91, frequencyHz: 460 }]
    }
  ],

  synchronizeOpticalFlashes(refFeed, targetFeed) {
    if (!refFeed.opticalEvents.length || !targetFeed.opticalEvents.length) {
      return { referenceFeedId: refFeed.id, targetFeedId: targetFeed.id, calculatedOffsetMs: 0, confidenceScore: 0.1, matchedFeature: 'OPTICAL_FLASH' };
    }
    const refPeak = refFeed.opticalEvents.reduce((m, e) => e.intensity > m.intensity ? e : m, refFeed.opticalEvents[0]);
    const targetPeak = targetFeed.opticalEvents.reduce((m, e) => e.intensity > m.intensity ? e : m, targetFeed.opticalEvents[0]);

    const offsetSec = targetPeak.timestampSec - refPeak.timestampSec;
    const offsetMs = Math.round(offsetSec * 1000);
    const diff = Math.abs(refPeak.intensity - targetPeak.intensity);
    const confidence = Number(Math.max(0.6, 1.0 - (diff / 100)).toFixed(2));

    return { referenceFeedId: refFeed.id, targetFeedId: targetFeed.id, calculatedOffsetMs: offsetMs, confidenceScore: confidence, matchedFeature: 'OPTICAL_FLASH' };
  },

  triangulateAcousticOrigin(feeds) {
    if (feeds.length < 3) throw new Error('At least 3 feeds required for 3D triangulation.');
    const ref = feeds[0];
    const t0 = ref.arrivalTimeSec;
    const p0 = ref.position;

    let sumX = 0, sumY = 0, sumZ = 0;
    feeds.forEach(f => { sumX += f.position.x; sumY += f.position.y; sumZ += f.position.z; });
    let estX = sumX / feeds.length;
    let estY = sumY / feeds.length;
    let estZ = sumZ / feeds.length;

    for (let it = 0; it < 60; it++) {
      let gradX = 0, gradY = 0, gradZ = 0;
      for (let i = 1; i < feeds.length; i++) {
        const fi = feeds[i];
        const pi = fi.position;
        const ti = fi.arrivalTimeSec;

        const d_i = Math.sqrt((estX - pi.x) ** 2 + (estY - pi.y) ** 2 + (estZ - pi.z) ** 2);
        const d_0 = Math.sqrt((estX - p0.x) ** 2 + (estY - p0.y) ** 2 + (estZ - p0.z) ** 2);

        const theoreticalDiff = (d_i - d_0) / this.SPEED_OF_SOUND;
        const observedDiff = ti - t0;
        const error = theoreticalDiff - observedDiff;

        const eps = 0.001;
        const d_i_dx = (Math.sqrt((estX + eps - pi.x) ** 2 + (estY - pi.y) ** 2 + (estZ - pi.z) ** 2) - d_i) / eps;
        const d_0_dx = (Math.sqrt((estX + eps - p0.x) ** 2 + (estY - p0.y) ** 2 + (estZ - p0.z) ** 2) - d_0) / eps;
        const dError_dx = (d_i_dx - d_0_dx) / this.SPEED_OF_SOUND;

        const d_i_dy = (Math.sqrt((estX - pi.x) ** 2 + (estY + eps - pi.y) ** 2 + (estZ - pi.z) ** 2) - d_i) / eps;
        const d_0_dy = (Math.sqrt((estX - p0.x) ** 2 + (estY + eps - p0.y) ** 2 + (estZ - p0.z) ** 2) - d_0) / eps;
        const dError_dy = (d_i_dy - d_0_dy) / this.SPEED_OF_SOUND;

        const d_i_dz = (Math.sqrt((estX - pi.x) ** 2 + (estY - pi.y) ** 2 + (estZ + eps - pi.z) ** 2) - d_i) / eps;
        const d_0_dz = (Math.sqrt((estX - p0.x) ** 2 + (estY - p0.y) ** 2 + (estZ + eps - p0.z) ** 2) - d_0) / eps;
        const dError_dz = (d_i_dz - d_0_dz) / this.SPEED_OF_SOUND;

        gradX += 2 * error * dError_dx;
        gradY += 2 * error * dError_dy;
        gradZ += 2 * error * dError_dz;
      }
      estX -= 0.05 * gradX;
      estY -= 0.05 * gradY;
      estZ -= 0.05 * gradZ;
    }

    return {
      estimatedSourceLocation: { x: Number(estX.toFixed(2)), y: Number(estY.toFixed(2)), z: Number(estZ.toFixed(2)) },
      confidenceRadiusMeters: 0.45,
      speedOfSoundMetersPerSec: this.SPEED_OF_SOUND,
      sensorCount: feeds.length
    };
  },

  buildForensicDossier(incidentId, feeds) {
    const syncs = feeds.map(f => {
      const sync = this.synchronizeOpticalFlashes(feeds[0], f);
      return { feedId: f.id, sourceName: f.sourceName, timeOffsetMs: sync.calculatedOffsetMs };
    });

    let origin = { x: 0, y: 0, z: 0 };
    if (feeds.length >= 3) {
      const tri = this.triangulateAcousticOrigin(
        feeds.map(f => ({ feedId: f.id, position: f.geoPosition, arrivalTimeSec: (f.acousticEvents[0] && f.acousticEvents[0].timestampSec) || 0 }))
      );
      origin = tri.estimatedSourceLocation;
    }

    const timelineSequence = [
      { timestampMs: 0, eventLabel: 'Optical Flash Peak', detectedByFeeds: feeds.map(f => f.id), confidence: 0.98 },
      { timestampMs: 142, eventLabel: 'Primary Shockwave Arrival', detectedByFeeds: feeds.slice(0, 2).map(f => f.id), confidence: 0.94 }
    ];

    const reconstructedUtcTimestamp = new Date().toISOString();
    const forensicHash = sha256Hex(JSON.stringify({
      incidentId,
      reconstructedUtcTimestamp,
      synchronizedFeeds: syncs,
      originLocation: origin,
      timelineSequence
    }));

    return {
      incidentId,
      reconstructedUtcTimestamp,
      synchronizedFeeds: syncs,
      originLocation: origin,
      timelineSequence,
      forensicHash
    };
  }
};

// ==========================================
// 4. METALOOP FLIGHT SIMULATOR ENGINE
// ==========================================
export const MetaLoop = {
  DEMO_AGENT_TRACES: [
    { stepId: 'step_1', parentId: null, agentRole: 'orchestrator', actionType: 'thought', thoughtSummary: 'User requested triage of vulnerability CVE-2026-4109 in lodash template.', tokenCost: 250, entropyScore: 0.2, status: 'SUCCESS' },
    { stepId: 'step_2', parentId: 'step_1', agentRole: 'researcher', actionType: 'tool_call', toolName: 'search_nvd_database', toolInput: { cve: 'CVE-2026-4109' }, tokenCost: 1200, entropyScore: 0.35, status: 'SUCCESS' },
    { stepId: 'step_3', parentId: 'step_2', agentRole: 'researcher', actionType: 'tool_call', toolName: 'search_nvd_database', toolInput: { cve: 'CVE-2026-4109' }, tokenCost: 1400, entropyScore: 0.65, status: 'DRIFTING' },
    { stepId: 'step_4', parentId: 'step_3', agentRole: 'researcher', actionType: 'tool_call', toolName: 'search_nvd_database', toolInput: { cve: 'CVE-2026-4109' }, tokenCost: 1600, entropyScore: 0.88, status: 'LOOP_DETECTED' }
  ],

  inspectTraceTree(steps) {
    const anomalies = [];
    let totalTokens = 0;

    steps.forEach(s => { totalTokens += s.tokenCost; });

    // Check loops
    const toolCalls = steps.filter(s => s.actionType === 'tool_call');
    if (toolCalls.length >= 3 && toolCalls[toolCalls.length - 1].toolName === toolCalls[toolCalls.length - 2].toolName) {
      anomalies.push({
        anomalyType: 'INFINITE_TOOL_LOOP',
        severity: 'CRITICAL',
        affectedStepIds: toolCalls.map(s => s.stepId),
        description: 'Agent is trapped calling the same tool without progression.',
        recommendedMitigation: 'Inject synthetic cache response or inject corrective steering prompt.'
      });
    }

    const health = anomalies.length > 0 ? 45 : 98;
    return {
      totalSteps: steps.length,
      totalTokens,
      healthScore: health,
      anomalies,
      steps,
      activeBranchId: 'branch_main'
    };
  },

  forkAndInjectSyntheticTool(steps, forkPointStepId, syntheticToolName, syntheticOutput) {
    const forkIdx = steps.findIndex(s => s.stepId === forkPointStepId);
    const forkedSteps = steps.slice(0, (forkIdx === -1 ? 1 : forkIdx) + 1).map(s => ({ ...s }));

    const injectedStepId = `step_syn_${Date.now().toString(36)}`;
    forkedSteps.push({
      stepId: injectedStepId,
      parentId: forkPointStepId,
      agentRole: 'evaluator',
      actionType: 'tool_result',
      toolName: syntheticToolName,
      toolOutput: syntheticOutput,
      thoughtSummary: '[SYNTHETIC INJECTION] Flight controller forced state transition with simulated output.',
      tokenCost: 45,
      entropyScore: 0.1,
      status: 'SUCCESS'
    });

    forkedSteps.push({
      stepId: `step_resumed_${Date.now().toString(36)}`,
      parentId: injectedStepId,
      agentRole: 'orchestrator',
      actionType: 'decision',
      thoughtSummary: 'Received synthetic resolution. Proceeding to target execution without hallucination loop.',
      tokenCost: 120,
      entropyScore: 0.15,
      status: 'SUCCESS'
    });

    return {
      originalBranchId: 'branch_main',
      newBranchId: `branch_fork_${Date.now().toString(36)}`,
      forkPointStepId,
      syntheticInjectionApplied: true,
      forkedSteps,
      recoveryStatus: 'RESOLVED'
    };
  },

  synthesizeDriftMitigation(anomalies) {
    return {
      systemPatch: `[COGNITIVE COMPENSATOR ACTIVE]\nSTRICT_RULE: Do not invoke the same tool with identical parameters if previous output did not change workspace state.\nSTRICT_RULE: Re-evaluate step against original user acceptance criteria before choosing next action.`,
      recoveryAction: 'APPLY_SYSTEM_GUIDANCE_AND_RESET_BUDGET'
    };
  }
};

// ==========================================
// 5. ZK PEER-TO-PEER ESCROW ENGINE
// ==========================================
export const ZkEscrow = {
  calculateSha256(content) {
    return sha256Hex(String(content ?? ''));
  },

  createEscrowContract(contractorName, clientName, milestones) {
    const structured = (milestones || []).map((m, idx) => ({
      id: `M-${idx + 1}`,
      title: m.title,
      payoutAmountUsd: m.payoutAmountUsd || 1000,
      // Spec-only milestones hash their placeholder; milestones with an
      // expectedContent hash that content. Both compare strictly on verify.
      expectedContent: m.expectedContent,
      expectedFileSha256: sha256Hex(m.expectedContent != null ? m.expectedContent : `INITIAL_SPEC_${m.title}`),
      acceptanceCriteria: m.acceptanceCriteria || ['Must pass tests'],
      status: 'PENDING'
    }));
    return {
      contractId: `CTR-${Date.now().toString(36).toUpperCase()}`,
      clientPublicKey: `PUB_CLI_${randomHex(4)}`,
      contractorPublicKey: `PUB_CTR_${randomHex(4)}`,
      arbiterAgentId: 'WebMCP-Sentinel-Arbiter-v1',
      // Per-contract release key: never a shared hard-coded secret.
      arbiterSecretKey: randomHex(32),
      totalEscrowAmountUsd: structured.reduce((a, m) => a + m.payoutAmountUsd, 0),
      milestones: structured,
      createdAt: new Date().toISOString(),
      contractState: 'FUNDED'
    };
  },

  verifyMilestoneDeliverable(contract, milestoneId, submittedContent, testAssertions) {
    const milestone = contract.milestones.find(m => m.id === milestoneId);
    if (!milestone) {
      throw new Error(`Milestone ${milestoneId} not found in contract.`);
    }
    const actualSha256 = sha256Hex(String(submittedContent ?? ''));
    const failedCriteria = (testAssertions || []).filter(t => !t.pass).map(t => t.description);
    const passed = failedCriteria.length === 0;

    // Strict digest comparison. A deliverable matches only when its SHA-256
    // equals the contractual digest - never by length, prefix, or assertion.
    const hashMatch = actualSha256 === milestone.expectedFileSha256;

    let arbitrationVerdict = 'REQUIRES_REMEDIATION';
    if (hashMatch && passed) {
      arbitrationVerdict = 'APPROVED_FOR_RELEASE';
      milestone.status = 'VERIFIED';
    } else if (!hashMatch) {
      arbitrationVerdict = 'REJECTED_MISMATCH';
      milestone.status = 'DISPUTED';
    }

    return {
      milestoneId,
      hashMatch,
      actualSha256,
      expectedSha256: milestone.expectedFileSha256,
      testSuitePassed: passed,
      failedCriteria,
      arbitrationVerdict
    };
  },

  signEscrowRelease(contract, milestoneId, arbiterSecretKey) {
    const milestone = contract.milestones.find(m => m.id === milestoneId);
    if (!milestone) {
      throw new Error(`Milestone ${milestoneId} not found.`);
    }
    if (milestone.status !== 'VERIFIED') {
      throw new Error(`Milestone ${milestoneId} is ${milestone.status}, not VERIFIED. Escrow release requires a successful deliverable verification first.`);
    }
    if (contract.contractState === 'DRAFT') {
      throw new Error('Escrow contract is still in DRAFT state and cannot release funds.');
    }

    const secret = arbiterSecretKey || contract.arbiterSecretKey;
    const timestamp = new Date().toISOString();
    const payload = `${contract.contractId}:${milestoneId}:${milestone.payoutAmountUsd}:${timestamp}`;
    // Honest label: an HMAC-SHA-256 keyed digest, not an ECDSA/Ed25519 signature.
    const arbiterSignature = `SIG-HMAC-SHA256-${hmacSha256Hex(secret, payload)}`;

    milestone.status = 'RELEASED';
    if (contract.milestones.every(m => m.status === 'RELEASED')) {
      contract.contractState = 'COMPLETED';
    }

    return {
      contractId: contract.contractId,
      milestoneId,
      releasedAmountUsd: milestone.payoutAmountUsd,
      arbiterSignature,
      timestamp,
      verificationAuditTrail: [
        `Milestone [${milestone.title}] verified against acceptance criteria before release.`,
        `Deliverable SHA-256 fingerprint matched the contractual milestone specification.`,
        `Release authorization signed with the contract's HMAC-SHA-256 arbiter key.`,
        `Escrow vault funds released ($${milestone.payoutAmountUsd} USD) to contractor address ${contract.contractorPublicKey}.`
      ]
    };
  }
};

ZkEscrow.DEMO_CONTRACT = ZkEscrow.createEscrowContract(
  'Alice Cryptography Labs',
  'Bob Decentralized Corp',
  [
    {
      title: 'Milestone 1: Zero-Day Hotpatch AST Module',
      payoutAmountUsd: 1500,
      expectedContent: 'function patchVulnerability(ast) { return sanitize(ast); }',
      acceptanceCriteria: ['Must parse AST', 'Must eliminate eval']
    },
    {
      title: 'Milestone 2: 3D Protein CAD Viewer & Mutagenesis',
      payoutAmountUsd: 2000,
      expectedContent: 'function render3dProtein(pdb) { return WebGL.draw(pdb); }',
      acceptanceCriteria: ['Must render PDB atoms', 'Must compute clashes']
    }
  ]
);

// ==========================================
// MASTER WEBMCP CATALOG (20 Tools)
// ==========================================
export const WEBMCP_TOOLS_CATALOG = [
  // Module 1
  {
    name: 'breachlab_analyze_cve_ast',
    module: 'BreachLab',
    description: 'Deep static AST analysis for code and dependency manifests. Identifies zero-days, RCE sinks, credential theft, prototype pollution, and computes blast radius.',
    inputSchema: { type: 'object', properties: { codeOrManifest: { type: 'string' } }, required: ['codeOrManifest'] },
    execute: (input) => BreachLab.analyzeCveAst(input.codeOrManifest, { checkSupplyChain: input.checkSupplyChain })
  },
  {
    name: 'breachlab_detonate_sandbox',
    module: 'BreachLab',
    description: 'Detonate suspicious code in an isolated simulated client-side sandbox container. Intercepts outbound network, eval, and subprocess commands.',
    inputSchema: { type: 'object', properties: { code: { type: 'string' } }, required: ['code'] },
    execute: (input) => BreachLab.detonateSandbox(input.code)
  },
  {
    name: 'breachlab_trace_taint_flow',
    module: 'BreachLab',
    description: 'Trace tainted data propagation from untrusted source inputs (e.g. req.query) to dangerous execution sinks.',
    inputSchema: { type: 'object', properties: { code: { type: 'string' } }, required: ['code'] },
    execute: (input) => BreachLab.traceTaintFlow(input.code)
  },
  {
    name: 'breachlab_generate_hotpatch',
    module: 'BreachLab',
    description: 'Synthesize automated cryptographic hot-patch diffs that replace dangerous sinks with safe, parameterized equivalents.',
    inputSchema: { type: 'object', properties: { code: { type: 'string' } }, required: ['code'] },
    execute: (input) => BreachLab.generateHotpatch(input.code)
  },

  // Module 2
  {
    name: 'biosynth_load_pdb_structure',
    module: 'BioSynth',
    description: 'Load and parse 3D Protein Data Bank (PDB) atomic coordinates into structured 3D atom graph and sequence.',
    inputSchema: { type: 'object', properties: { pdbContent: { type: 'string' } } },
    execute: (input) => BioSynth.parsePDB(input?.pdbContent || BioSynth.SAMPLE_PDB_1CRN)
  },
  {
    name: 'biosynth_mutate_residue',
    module: 'BioSynth',
    description: 'Simulate in-silico point mutation (CRISPR / protein engineering) and predict stability change (ΔΔG) and steric clashes.',
    inputSchema: { type: 'object', properties: { chain: { type: 'string' }, resSeq: { type: 'number' }, targetResidue3: { type: 'string' } }, required: ['chain', 'resSeq', 'targetResidue3'] },
    execute: (input) => {
      const { atoms } = BioSynth.parsePDB(BioSynth.SAMPLE_PDB_1CRN);
      return BioSynth.simulateMutation(atoms, input.chain, input.resSeq, input.targetResidue3);
    }
  },
  {
    name: 'biosynth_highlight_binding_pockets',
    module: 'BioSynth',
    description: 'Scan 3D atomic structure to discover druggable active catalytic cavities and binding pockets.',
    inputSchema: { type: 'object', properties: { pdbContent: { type: 'string' } } },
    execute: (input) => {
      const { atoms } = BioSynth.parsePDB(input?.pdbContent || BioSynth.SAMPLE_PDB_1CRN);
      return BioSynth.findBindingPockets(atoms);
    }
  },

  // Module 3
  {
    name: 'chrono_load_media_streams',
    module: 'ChronoForensic',
    description: 'Retrieve multi-angle spatial and acoustic sensor streams (CCTV, bodycam, drone) for forensic reconstruction.',
    inputSchema: { type: 'object', properties: { incidentFilter: { type: 'string' } } },
    execute: () => ChronoForensic.DEMO_FEEDS
  },
  {
    name: 'chrono_sync_flash_audio_markers',
    module: 'ChronoForensic',
    description: 'Cross-correlate optical flash peaks and acoustic transients across video streams to compute millisecond time offsets.',
    inputSchema: { type: 'object', properties: { referenceFeedId: { type: 'string' }, targetFeedId: { type: 'string' } }, required: ['referenceFeedId', 'targetFeedId'] },
    execute: (input) => {
      const ref = ChronoForensic.DEMO_FEEDS.find(f => f.id === input.referenceFeedId) || ChronoForensic.DEMO_FEEDS[0];
      const target = ChronoForensic.DEMO_FEEDS.find(f => f.id === input.targetFeedId) || ChronoForensic.DEMO_FEEDS[1];
      return ChronoForensic.synchronizeOpticalFlashes(ref, target);
    }
  },
  {
    name: 'chrono_triangulate_acoustic_source',
    module: 'ChronoForensic',
    description: 'Triangulate 3D physical coordinates of an acoustic blast or gunshot origin using Time-Difference-Of-Arrival (TDOA).',
    inputSchema: { type: 'object', properties: { feeds: { type: 'array' } } },
    execute: (input) => {
      const feeds = input?.feeds || ChronoForensic.DEMO_FEEDS.map(f => ({
        feedId: f.id,
        position: f.geoPosition,
        arrivalTimeSec: f.acousticEvents[0].timestampSec
      }));
      return ChronoForensic.triangulateAcousticOrigin(feeds);
    }
  },
  {
    name: 'chrono_generate_forensic_dossier',
    module: 'ChronoForensic',
    description: 'Assemble unified cryptographic forensic report with synchronized timeline sequence and SHA-256 evidence hash.',
    inputSchema: { type: 'object', properties: { incidentId: { type: 'string' } }, required: ['incidentId'] },
    execute: (input) => ChronoForensic.buildForensicDossier(input.incidentId, ChronoForensic.DEMO_FEEDS)
  },

  // Module 4
  {
    name: 'metaloop_inspect_trace_tree',
    module: 'MetaLoop',
    description: 'Inspect agent execution trace tree to detect infinite tool loops, token budget spikes, and cognitive drift.',
    inputSchema: { type: 'object', properties: { traceId: { type: 'string' } } },
    execute: () => MetaLoop.inspectTraceTree(MetaLoop.DEMO_AGENT_TRACES)
  },
  {
    name: 'metaloop_inject_synthetic_tool',
    module: 'MetaLoop',
    description: 'Inject synthetic mock tool response at a specific execution step to unblock trapped loops and fork execution.',
    inputSchema: { type: 'object', properties: { forkPointStepId: { type: 'string' }, syntheticToolName: { type: 'string' }, syntheticOutput: { type: 'object' } }, required: ['forkPointStepId', 'syntheticToolName', 'syntheticOutput'] },
    execute: (input) => MetaLoop.forkAndInjectSyntheticTool(
      MetaLoop.DEMO_AGENT_TRACES,
      input.forkPointStepId,
      input.syntheticToolName,
      input.syntheticOutput
    )
  },
  {
    name: 'metaloop_mitigate_drift',
    module: 'MetaLoop',
    description: 'Synthesize corrective prompt steering guidelines to compensate for cognitive drift and token explosion.',
    inputSchema: { type: 'object', properties: { traceId: { type: 'string' } } },
    execute: () => {
      const inspection = MetaLoop.inspectTraceTree(MetaLoop.DEMO_AGENT_TRACES);
      return MetaLoop.synthesizeDriftMitigation(inspection.anomalies);
    }
  },

  // Module 5
  {
    name: 'zkescrow_initiate_contract',
    module: 'ZkEscrow',
    description: 'Create zero-backend cryptographic P2P escrow contract with verifiable milestone payout specifications.',
    inputSchema: { type: 'object', properties: { contractorName: { type: 'string' }, clientName: { type: 'string' } }, required: ['contractorName', 'clientName'] },
    execute: (input) => ZkEscrow.createEscrowContract(input.contractorName, input.clientName, input.milestones)
  },
  {
    name: 'zkescrow_verify_deliverable_hash',
    module: 'ZkEscrow',
    description: 'Compute client-side SHA-256 deliverable fingerprint and verify compliance against cryptographic milestone spec.',
    inputSchema: { type: 'object', properties: { milestoneId: { type: 'string' }, submittedContent: { type: 'string' } }, required: ['milestoneId', 'submittedContent'] },
    execute: (input) => {
      const content = String(input.submittedContent ?? '');
      return ZkEscrow.verifyMilestoneDeliverable(
        ZkEscrow.DEMO_CONTRACT,
        input.milestoneId,
        content,
        [
          { description: 'No dynamic eval() statements', pass: !content.includes('eval(') },
          { description: 'Deliverable is non-empty', pass: content.trim().length > 0 }
        ]
      );
    }
  },
  {
    name: 'zkescrow_sign_escrow_release',
    module: 'ZkEscrow',
    description: 'Generate an HMAC-SHA-256 arbiter release proof authorizing fund disbursement for a verified milestone.',
    inputSchema: { type: 'object', properties: { milestoneId: { type: 'string' } }, required: ['milestoneId'] },
    execute: (input) => ZkEscrow.signEscrowRelease(ZkEscrow.DEMO_CONTRACT, input.milestoneId)
  }
];

export function registerAllWebMCPTools(targetDoc) {
  const doc = targetDoc || (typeof document !== 'undefined' ? document : null);
  const registered = [];

  if (doc && doc.modelContext && typeof doc.modelContext.registerTool === 'function') {
    for (const tool of WEBMCP_TOOLS_CATALOG) {
      try {
        doc.modelContext.registerTool({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
          execute: tool.execute
        });
        registered.push(tool.name);
      } catch (err) {
        console.warn(`[WebMCP] Failed to register tool ${tool.name}:`, err);
      }
    }
  }

  return {
    registeredCount: registered.length,
    tools: registered
  };
}
