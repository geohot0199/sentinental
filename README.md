<div align="center">

# SENTINEL OMNI-LAB

**The World's First 5-in-1 Agent-Native Frontier Operating System built on the W3C / OpenAI WebMCP Standard.**

*Built for the WebMCP Challenge by OpenAI, Google Chrome, Cloudflare, Vercel, Shopify, Render, and Netlify.*

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/Tests-136%20Passed-10b981.svg)]()
[![WebMCP Standard](https://img.shields.io/badge/WebMCP-20%20Tools%20Registered-00f2fe.svg)]()

</div>

---

## 🌟 What is SENTINEL OMNI-LAB?

**SENTINEL OMNI-LAB** is an agent-native frontier workspace that reimagines the open web when humans and browser-based AI agents collaborate side-by-side using **WebMCP (Web Model Context Protocol)**.

Instead of an AI agent struggling to scrape or guess its way through web interfaces, Sentinel Omni-Lab directly exposes **20 structured client-side tools** via `document.modelContext.registerTool({...})`. These tools operate browser-native primitives—including **WebGL 3D rendering, isolated Web Worker sandboxing, Web Audio / acoustic TDOA multilateration, AST parsing, and zero-backend WebCrypto encryption**.

---

## 🚀 The 5 Breakthrough Innovation Laboratories

SENTINEL OMNI-LAB combines 5 domain-defining modules into one unified web application:

### 🛡️ Module 1: Sentinel BreachLab (Zero-Day Supply-Chain War Room)
* **What it does:** Real-time in-browser reverse-engineering laboratory for zero-day exploits, malicious npm packages, and supply-chain attacks.
* **Client-Side Capabilities:**
  * Static AST security inspection & Shannon entropy calculation.
  * Isolated simulated micro-sandbox detonation in Web Workers (intercepts credential reads, blocked socket connections, dangerous `eval()`).
  * Live interactive Canvas Attack Graph visualizing CVE blast radius and tainted data propagation.
  * Automated cryptographic hot-patch synthesis.
* **WebMCP Tools:** `breachlab_analyze_cve_ast`, `breachlab_detonate_sandbox`, `breachlab_trace_taint_flow`, `breachlab_generate_hotpatch`.

### 🧬 Module 2: BioSynth Studio (In-Browser 3D Molecular CAD & Protein Co-Pilot)
* **What it does:** 3D crystallographic engineering and in-silico CRISPR/protein design studio.
* **Client-Side Capabilities:**
  * PDB (Protein Data Bank) 3D coordinate parser and interactive WebGL canvas renderer.
  * In-silico point mutagenesis simulator calculating thermodynamic folding stability ($\Delta\Delta G$) and charge perturbations.
  * 3D steric clash and van der Waals overlap analysis engine.
  * Active catalytic binding cavity & druggability scanner.
* **WebMCP Tools:** `biosynth_load_pdb_structure`, `biosynth_mutate_residue`, `biosynth_highlight_binding_pockets`.

### ⏱️ Module 3: ChronoForensic OSINT (Multi-Angle Acoustic & Spatial Reconstructor)
* **What it does:** Incident forensic reconstruction synchronizing unaligned drone feeds, officer bodycams, and CCTV feeds.
* **Client-Side Capabilities:**
  * Optical flash peak cross-correlation for sub-millisecond timeline alignment.
  * 3D acoustic Time-Difference-Of-Arrival (TDOA) spherical multilateration based on speed of sound ($343\text{ m/s}$).
  * Interactive 2D/3D sensor placement map and shockwave propagation visualizer.
  * Unified cryptographic forensic dossier generation with SHA-256 evidence chain.
* **WebMCP Tools:** `chrono_load_media_streams`, `chrono_sync_flash_audio_markers`, `chrono_triangulate_acoustic_source`, `chrono_generate_forensic_dossier`.

### 🛸 Module 4: MetaLoop Flight Simulator (Autonomous Swarm Debugger & Cognitive Drift Compensator)
* **What it does:** An interactive flight cockpit for debugging multi-agent swarms, tool calling loops, and cognitive hallucinations.
* **Client-Side Capabilities:**
  * Agent execution trace tree parser and visual node graph.
  * Trapped loop, token explosion, and entropy divergence anomaly detector.
  * Synthetic tool mock injector allowing the flight controller to fork execution into a healthy recovery branch.
  * Automated cognitive drift compensation guideline generator.
* **WebMCP Tools:** `metaloop_inspect_trace_tree`, `metaloop_inject_synthetic_tool`, `metaloop_mitigate_drift`.

### 🔐 Module 5: ZK Peer-to-Peer Escrow (Zero-Backend WebCrypto Dispute Arbiter)
* **What it does:** A 100% serverless, zero-backend cryptographic milestone arbitration platform.
* **Client-Side Capabilities:**
  * WebCrypto ECDSA and SHA-256 deliverable fingerprinting.
  * In-browser client-side acceptance test suite verification.
  * Zero-knowledge cryptographic escrow release signature authorization.
* **WebMCP Tools:** `zkescrow_initiate_contract`, `zkescrow_verify_deliverable_hash`, `zkescrow_sign_escrow_release`.

---

## 🛠️ WebMCP Implementation Details (W3C Specification)

SENTINEL OMNI-LAB adheres directly to the official WebMCP standard:

```javascript
// Registering tools with the browser's modelContext
document.modelContext.registerTool({
  name: "breachlab_analyze_cve_ast",
  description: "Deep static AST analysis for code and dependency manifests",
  inputSchema: {
    type: "object",
    properties: {
      codeOrManifest: { type: "string" },
      checkSupplyChain: { type: "boolean" }
    },
    required: ["codeOrManifest"]
  },
  execute: async (input) => {
    return BreachLab.analyzeCveAst(input.codeOrManifest, { checkSupplyChain: input.checkSupplyChain });
  }
});
```

When accessed in **ChatGPT’s in-app browser** or **Google Chrome with `#enable-webmcp-testing`**, all 20 tools are automatically registered and accessible to browser agents. For standard browsers, a built-in interactive **WebMCP Agent Cockpit** is integrated directly into the UI.

---

## 💻 Quickstart & Local Development

### 1. Prerequisites
- Node.js >= 22.14

### 2. Install & Run
```bash
# Install dependencies
npm install

# Run all unit and integration tests (136 tests passing)
npm test

# Run TypeScript typecheck
npm run typecheck

# Start local WebMCP development server (port 4321)
npm run site:dev
```

Open your browser to `http://localhost:4321` to access the full Sentinel Omni-Lab suite!

---

## 🏆 Devpost Submission Information

* **Category:** WebMCP Challenge (OpenAI / Google Chrome / Cloudflare / Vercel / Shopify / Render / Netlify)
* **Live URL:** Can be hosted on GitHub Pages, Cloudflare Pages, Vercel, Netlify, or ChatGPT Sites.
* **License:** [MIT License Detectable at Root](LICENSE)
* **Test Suite:** 13 test suites, 136 tests passed, 0 security vulnerabilities detected.
