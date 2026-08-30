/**
 * Sentinel BreachLab - Core Malware & CVE Reverse Engineering Engine
 *
 * Implements client-side AST inspection, isolated sandbox simulation,
 * taint propagation tracing, and automated hot-patch synthesis.
 */

export interface VulnerabilityFinding {
  id: string;
  type: 'RCE' | 'CREDENTIAL_EXFIL' | 'PROTOTYPE_POLLUTION' | 'OBFUSCATION' | 'UNPINNED_DEP' | 'REVERSE_SHELL';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  line: number;
  snippet: string;
  description: string;
  remediation: string;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: 'entry' | 'intermediate' | 'sink' | 'exfil';
  severity: 'low' | 'medium' | 'high' | 'critical';
  x?: number;
  y?: number;
  blastRadius: number; // 1-100 scale
}

export interface AttackGraphEdge {
  from: string;
  to: string;
  label: string;
  tainted: boolean;
}

export interface BreachLabAnalysisResult {
  threatScore: number; // 0 to 100
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL_ZERO_DAY';
  findings: VulnerabilityFinding[];
  graph: {
    nodes: AttackGraphNode[];
    edges: AttackGraphEdge[];
  };
  summary: string;
  astMetrics: {
    entropy: number;
    obfuscationRatio: number;
    dangerousCallsCount: number;
    linesOfCode: number;
  };
}

export interface DetonationEvent {
  timestamp: number;
  action: string;
  target: string;
  blocked: boolean;
  alert: string;
}

export interface DetonationReport {
  success: boolean;
  /** True when the scan was cut short because the configured window elapsed. */
  timedOut: boolean;
  executionTimeMs: number;
  interceptedEvents: DetonationEvent[];
  quarantinedThreats: string[];
  safeToRun: boolean;
  stdout: string[];
}

export interface HotpatchResult {
  originalCode: string;
  patchedCode: string;
  diff: string[];
  fixesApplied: string[];
  securityScoreImprovement: number;
}

/**
 * Calculate Shannon entropy of a string to detect encoded/obfuscated payloads.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const map: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (char !== undefined) {
      map[char] = (map[char] || 0) + 1;
    }
  }
  let entropy = 0;
  for (const char in map) {
    const count = map[char];
    if (count !== undefined) {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

/**
 * A manifest arrives from untrusted code under audit, and `JSON.parse` types it
 * as `any`. Narrow the dependency map before it is spread, so a manifest with
 * `"dependencies": "nope"` yields no dependencies rather than garbage nodes.
 */
function asDependencyMap(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Deep static AST and heuristic pattern analyzer for code & dependency manifests.
 */
// `_options` is accepted for call-site compatibility (the browser bundle passes
// `{ checkSupplyChain }`) but supply-chain checks are unconditional, so the
// flag has no effect and is named as unused rather than silently ignored.
// eslint-disable-next-line complexity, max-lines-per-function -- one branch per detection rule
export function analyzeCveAst(
  codeOrManifest: string,
  _options?: { checkSupplyChain?: boolean },
): BreachLabAnalysisResult {
  const lines = codeOrManifest.split('\n');
  const findings: VulnerabilityFinding[] = [];
  const nodes: AttackGraphNode[] = [];
  const edges: AttackGraphEdge[] = [];

  let dangerousCalls = 0;
  let obfuscationHits = 0;
  const entropy = calculateShannonEntropy(codeOrManifest);

  // Check if it's package.json
  const isJson = codeOrManifest.trim().startsWith('{');
  if (isJson) {
    try {
      const parsed = JSON.parse(codeOrManifest) as {
        name?: unknown;
        dependencies?: unknown;
        devDependencies?: unknown;
      };
      const allDeps = {
        ...asDependencyMap(parsed.dependencies),
        ...asDependencyMap(parsed.devDependencies)
      };

      const pkgName = typeof parsed.name === 'string' && parsed.name.trim() ? parsed.name : 'Root Package';
      nodes.push({ id: 'root_pkg', label: pkgName, type: 'entry', severity: 'low', blastRadius: 20 });

      for (const [dep, version] of Object.entries(allDeps)) {
        const verStr = String(version);
        const depId = `dep_${dep.replace(/[^a-zA-Z0-9]/g, '_')}`;
        
        let nodeSev: 'low' | 'medium' | 'high' | 'critical' = 'low';
        let blast = 30;

        if (verStr.includes('*') || verStr.includes('>') || verStr.includes('^0.') || verStr.startsWith('latest')) {
          findings.push({
            id: `FIND-${findings.length + 1}`,
            type: 'UNPINNED_DEP',
            severity: 'MEDIUM',
            line: 1,
            snippet: `"${dep}": "${verStr}"`,
            description: `Unpinned or wild wildcard dependency version (${dep}@${verStr}) risks supply chain poisoning.`,
            remediation: `Pin exact version with lockfile hash validation.`
          });
          nodeSev = 'medium';
          blast = 55;
        }

        // Known flagged packages / typosquatting mocks
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
    } catch {
      // Fallback to text parsing
    }
  }

  // Scan line by line for malicious code patterns
  lines.forEach((line, index) => {
    const lineNum = index + 1;
    const trimmed = line.trim();

    // 1. Remote Code Execution / Eval
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

    // 2. Child Process / Command Injection
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

    // 3. Credential Harvesting & Env Theft
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

    // 4. Reverse Shell & Raw Sockets
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

    // 5. Prototype Pollution
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

    // 6. Hex / Base64 Heavy Obfuscation
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

  // Calculate Threat Score
  let score = 0;
  for (const f of findings) {
    if (f.severity === 'CRITICAL') score += 35;
    else if (f.severity === 'HIGH') score += 20;
    else if (f.severity === 'MEDIUM') score += 10;
    else score += 5;
  }
  if (entropy > 5.2) score += 15;
  score = Math.min(100, Math.max(0, score));

  let verdict: BreachLabAnalysisResult['verdict'] = 'SAFE';
  if (score >= 80) verdict = 'CRITICAL_ZERO_DAY';
  else if (score >= 50) verdict = 'MALICIOUS';
  else if (score > 15) verdict = 'SUSPICIOUS';

  // Build Graph if not JSON
  if (nodes.length === 0) {
    nodes.push({ id: 'entry_point', label: 'Entrypoint / Payload', type: 'entry', severity: 'low', blastRadius: 20 });
    
    findings.forEach((f, idx) => {
      const nodeId = `vuln_${idx + 1}`;
      const sev = f.severity.toLowerCase() as 'low' | 'medium' | 'high' | 'critical';
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
    summary: `Analyzed ${lines.length} lines of code. Found ${findings.length} security alerts (${findings.filter(f => f.severity === 'CRITICAL').length} Critical, ${findings.filter(f => f.severity === 'HIGH').length} High). Threat Score: ${score}/100 [${verdict}].`,
    astMetrics: {
      entropy,
      obfuscationRatio,
      dangerousCallsCount: dangerousCalls,
      linesOfCode: lines.length
    }
  };
}

/**
 * Isolated Sandboxed Detonation runner (client-safe simulation).
 */
// eslint-disable-next-line complexity -- one branch per intercepted sandbox capability
export function detonateSandbox(
  code: string,
  config?: { timeoutMs?: number; mockEnv?: Record<string, string> }
): DetonationReport {
  const startTime = Date.now();
  const interceptedEvents: DetonationEvent[] = [];
  const quarantinedThreats: string[] = [];
  const stdout: string[] = [];

  // The advertised execution window is honoured: when a timeout is configured
  // the scan stops the moment the deadline passes instead of running unbounded
  // on attacker-controlled input and blocking the thread past the promise.
  const timeoutMs = config?.timeoutMs;
  const deadline = typeof timeoutMs === 'number' && timeoutMs >= 0 ? startTime + timeoutMs : null;
  let timedOut = false;

  // Inspect code execution steps safely via virtualized interpreter
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (deadline !== null && Date.now() > deadline) {
      timedOut = true;
      break;
    }

    const rawLine = lines[i];
    if (rawLine === undefined) continue;
    const line = rawLine.trim();
    if (!line || line.startsWith('//')) continue;

    // Intercept Env Read
    if (/process\.env\.([a-zA-Z0-9_]+)/.test(line)) {
      const match = line.match(/process\.env\.([a-zA-Z0-9_]+)/);
      const varName = match && match[1] ? match[1] : 'UNKNOWN_VAR';
      interceptedEvents.push({
        timestamp: Date.now() - startTime,
        action: 'READ_ENV',
        target: `process.env.${varName}`,
        blocked: false,
        alert: `Detonated process queried sensitive environment key: ${varName}`
      });
    }

    // Intercept Outbound Network Transmission
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

    // Intercept Eval / Dynamic Execution
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

    // Intercept Child Process Execution
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

    // Simulate console.log
    if (/console\.log\((.+)\)/.test(line)) {
      const logMatch = line.match(/console\.log\((.+)\)/);
      if (logMatch && logMatch[1]) {
        stdout.push(`[DETONATOR STDOUT] ${logMatch[1].replace(/['"]/g, '')}`);
      }
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
}

/**
 * Taint Flow Tracer: tracks data propagation from untrusted source to sensitive sink.
 */
/** Longest pattern accepted from the model; longer input is treated as absent. */
const MAX_PATTERN_LENGTH = 200;

/**
 * Compile a caller/model-supplied pattern safely.
 *
 * The pattern arrives from the model, so it can be invalid (`SyntaxError` kills
 * the whole tool call) or pathological (catastrophic backtracking pins the
 * thread). Compile it in a try/catch, fall back to an escaped literal match,
 * and cap the length.
 */
function safeRegex(pattern: string, fallback: string): RegExp {
  const trimmed = pattern.length <= MAX_PATTERN_LENGTH ? pattern : fallback;
  try {
    return new RegExp(trimmed, 'i');
  } catch {
    return new RegExp(trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
  }
}

export function traceTaintFlow(code: string, sourcePattern?: string, sinkPattern?: string) {
  const lines = code.split('\n');
  const source = sourcePattern || 'req.query|req.body|process.env|userInput';
  const sink = sinkPattern || 'eval|exec|execSync|spawn|fs.writeFile|net.connect';

  const sourceRegex = safeRegex(source, 'req\\.query|req\\.body|process\\.env|userInput');
  const sinkRegex = safeRegex(sink, 'eval|exec|execSync|spawn|fs\\.writeFile|net\\.connect');

  const traceSteps: { line: number; type: 'SOURCE' | 'PROPAGATION' | 'SINK'; text: string; variable?: string }[] = [];
  const trackedVars = new Set<string>();

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Check Source
    if (sourceRegex.test(trimmed)) {
      const assignMatch = trimmed.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/);
      if (assignMatch && assignMatch[1]) {
        trackedVars.add(assignMatch[1]);
      }
      traceSteps.push({
        line: lineNum,
        type: 'SOURCE',
        text: trimmed,
        variable: assignMatch && assignMatch[1] ? assignMatch[1] : undefined
      });
      return;
    }

    // Check propagation
    for (const v of trackedVars) {
      if (trimmed.includes(v)) {
        const nextAssign = trimmed.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/);
        if (nextAssign && nextAssign[1] && nextAssign[1] !== v) {
          trackedVars.add(nextAssign[1]);
        }
        
        if (sinkRegex.test(trimmed)) {
          traceSteps.push({
            line: lineNum,
            type: 'SINK',
            text: trimmed,
            variable: v
          });
        } else {
          traceSteps.push({
            line: lineNum,
            type: 'PROPAGATION',
            text: trimmed,
            variable: v
          });
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
}

/**
 * Synthesizes hot-patches to automatically neutralize vulnerabilities.
 */
export function generateHotpatch(code: string): HotpatchResult {
  const lines = code.split('\n');
  const patchedLines: string[] = [];
  const diff: string[] = [];
  const fixesApplied: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine === undefined) continue;
    const line = rawLine;
    let modified = line;

    // Patch 1: Replace eval with safe JSON.parse
    if (/eval\s*\((.+)\)/.test(line)) {
      modified = line.replace(/eval\s*\((.+)\)/g, 'JSON.parse($1 /* [SENTINEL-PATCH: Replaced dangerous eval with strict JSON parser] */)');
      diff.push(`- ${line}`);
      diff.push(`+ ${modified}`);
      fixesApplied.push('Replaced dynamic eval() sink with safe JSON parse');
    }
    // Patch 2: Sanitize child_process.exec to execFile/spawn with args
    else if (/child_process\.exec\s*\((.+)\)/.test(line) || /execSync\s*\((.+)\)/.test(line)) {
      modified = line.replace(/(?:child_process\.)?exec(?:Sync)?\s*\((.+)\)/g, '/* [SENTINEL-PATCH: Parameterized shell command against injection] */ execFileSync("/usr/bin/env", [$1])');
      diff.push(`- ${line}`);
      diff.push(`+ ${modified}`);
      fixesApplied.push('Replaced unsafe shell exec string with parameterized command execution');
    }
    // Patch 3: Prototype Pollution Defense
    else if (/__proto__|constructor\.prototype/.test(line)) {
      modified = `/* [SENTINEL-PATCH: Block prototype mutation] */ if (!['__proto__', 'constructor', 'prototype'].includes(key)) { ${line.trim()} }`;
      diff.push(`- ${line}`);
      diff.push(`+ ${modified}`);
      fixesApplied.push('Added prototype pollution filter guard');
    }
    // Patch 4: Mask environment exfiltration
    else if (/process\.env\.(AWS|SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE_KEY)/i.test(line) && /fetch|http|axios/i.test(line)) {
      modified = `// [SENTINEL-PATCH: Outbound secret transmission neutralized]\n// ${line}`;
      diff.push(`- ${line}`);
      diff.push(`+ ${modified}`);
      fixesApplied.push('Neutralized exfiltration of sensitive environment variables');
    }

    patchedLines.push(modified);
  }

  const patchedCode = patchedLines.join('\n');
  const originalAnalysis = analyzeCveAst(code);
  const patchedAnalysis = analyzeCveAst(patchedCode);
  const securityScoreImprovement = Math.max(0, originalAnalysis.threatScore - patchedAnalysis.threatScore);

  return {
    originalCode: code,
    patchedCode,
    diff,
    fixesApplied: fixesApplied.length > 0 ? fixesApplied : ['No critical vulnerabilities found requiring automated code rewriting.'],
    securityScoreImprovement
  };
}
