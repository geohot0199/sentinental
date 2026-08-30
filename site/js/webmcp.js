/* =============================================================================
   SENTINEL — WebMCP bridge.

   Installs `document.modelContext` when the browser does not ship one yet, then
   registers the OMNI-LAB tool catalog against it. This is the same registry the
   in-repo console uses (`src/web/public/webmcp-bundle.js`), so a real WebMCP
   agent and the on-page cockpit call identical code.
   ========================================================================== */

import {
  BreachLab,
  BioSynth,
  ChronoForensic,
  MetaLoop,
  ZkEscrow,
  WEBMCP_TOOLS_CATALOG,
  registerAllWebMCPTools,
} from './engines.js';

export { BreachLab, BioSynth, ChronoForensic, MetaLoop, ZkEscrow, WEBMCP_TOOLS_CATALOG };

/**
 * Provide a spec-shaped `document.modelContext` polyfill.
 *
 * A browser that already implements the W3C/OpenAI proposal keeps its own
 * implementation; we only fill the gap so the page is agent-callable today.
 */
function ensureModelContext() {
  if (document.modelContext && typeof document.modelContext.registerTool === 'function') {
    return { polyfilled: false, context: document.modelContext };
  }

  const tools = new Map();
  const context = {
    registerTool(definition) {
      if (!definition || typeof definition.name !== 'string') {
        throw new TypeError('registerTool requires a named tool definition.');
      }
      tools.set(definition.name, definition);
      return { unregister: () => tools.delete(definition.name) };
    },
    getTools() {
      return Array.from(tools.values());
    },
    async invokeTool(name, input) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`Unknown WebMCP tool: ${name}`);
      return tool.execute(input ?? {});
    },
  };

  Object.defineProperty(document, 'modelContext', {
    value: context,
    configurable: true,
    writable: false,
  });
  return { polyfilled: true, context };
}

const { polyfilled } = ensureModelContext();
const registration = registerAllWebMCPTools(document);

export const webmcp = {
  /** True when this page supplied the polyfill rather than the browser. */
  polyfilled,
  registeredCount: registration.registeredCount,
  toolNames: registration.tools,
  catalog: WEBMCP_TOOLS_CATALOG,
  /** Invoke a registered tool by name; always resolves through modelContext. */
  invoke: (name, input) => document.modelContext.invokeTool(name, input),
  /** Tools belonging to one OMNI-LAB module. */
  byModule: (module) => WEBMCP_TOOLS_CATALOG.filter((t) => t.module === module),
};
