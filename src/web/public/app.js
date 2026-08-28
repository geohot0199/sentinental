/**
 * SENTINEL console front end.
 *
 * Plain ES modules, no framework and no build step: the whole point of this
 * project is the harness, and a stranger cloning the repo should be able to
 * read the UI without installing a toolchain.
 *
 * Everything rendered here is inserted as textContent, never innerHTML, because
 * the content is model output and tool results.
 */

const el = (id) => document.getElementById(id);

const streamEl = el("stream");
const emptyEl = el("empty");
const inputEl = el("input");
const sendBtn = el("send");
const cancelBtn = el("cancel");
const statusEl = el("turn-status");
const toolListEl = el("tool-list");
const subagentListEl = el("subagent-list");
const capabilitiesEl = el("capabilities");
const overlayEl = el("approval-overlay");
const approvalBodyEl = el("approval-body");
const approveBtn = el("approve");
const denyBtn = el("deny");
const suggestionsEl = el("suggestions");

const state = {
  sessionId: null,
  eventSource: null,
  busy: false,
  pendingApprovals: [],
  toolCalls: new Map(),
  subagents: new Set(),
  activeGateMarker: null,
  status: null,
};

// ------------------------------------------------------------------ helpers

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = `status-${kind}`;
}

function clearEmpty() {
  if (emptyEl.isConnected) emptyEl.remove();
}

function atBottom() {
  return streamEl.scrollHeight - streamEl.scrollTop - streamEl.clientHeight < 90;
}

/** Only auto-scroll when the operator is already at the bottom. */
function append(node) {
  clearEmpty();
  const stick = atBottom();
  node.classList.add("event");
  streamEl.appendChild(node);
  if (stick) streamEl.scrollTop = streamEl.scrollHeight;
}

function line(kind, glyph, build) {
  const row = document.createElement("div");
  row.className = `line ${kind}`;
  const g = document.createElement("span");
  g.className = "glyph";
  g.textContent = glyph;
  const body = document.createElement("span");
  body.className = "body";
  build(body);
  row.append(g, body);
  return row;
}

function truncate(text, max = 150) {
  const collapsed = String(text).replace(/\s+/g, " ").trim();
  return collapsed.length > max ? `${collapsed.slice(0, max - 1)}…` : collapsed;
}

function stringify(value) {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

const DESTRUCTIVE = new Set(["open_pull_request", "merge_pull_request"]);

// ------------------------------------------------------------- side panels

function recordTool(toolCallId, toolName) {
  const item = document.createElement("li");
  item.textContent = toolName;
  if (DESTRUCTIVE.has(toolName)) item.classList.add("destructive");
  const placeholder = toolListEl.querySelector("li.muted");
  if (placeholder) placeholder.remove();
  toolListEl.appendChild(item);
  state.toolCalls.set(toolCallId, { item, toolName });
}

function completeTool(toolCallId) {
  const entry = state.toolCalls.get(toolCallId);
  if (entry && !entry.item.classList.contains("destructive")) {
    entry.item.classList.add("done");
  }
}

function recordSubagent(name) {
  if (state.subagents.has(name)) return;
  state.subagents.add(name);
  const placeholder = subagentListEl.querySelector("li.muted");
  if (placeholder) placeholder.remove();
  const item = document.createElement("li");
  item.textContent = name;
  subagentListEl.appendChild(item);
}

// ------------------------------------------------------------- transcript

function renderUser(text) {
  const node = document.createElement("div");
  node.className = "msg-user";
  node.textContent = text.replace(/^> /, "");
  append(node);
}

function renderAgent(text, threadId) {
  const node = document.createElement("div");
  node.className = "msg-agent";
  if (threadId && threadId !== "main" && threadId !== "user") {
    const tag = document.createElement("span");
    tag.className = "thread-tag";
    tag.textContent = `subagent ${threadId}`;
    node.appendChild(tag);
  }
  const body = document.createElement("div");
  body.textContent = text;
  node.appendChild(body);
  append(node);
}

/** A visible, permanent mark in the transcript where the agent stopped. */
function renderGateMarker(names) {
  const node = document.createElement("div");
  node.className = "gate-marker";
  node.textContent = `⏸  Paused for human approval — ${names.join(", ")}`;
  append(node);
  state.activeGateMarker = node;
}

function resolveGateMarker(approved) {
  if (!state.activeGateMarker) return;
  state.activeGateMarker.classList.add("resolved", approved ? "approved" : "denied");
  state.activeGateMarker.textContent = approved
    ? "✓  Approved by the operator — the agent resumed."
    : "✗  Denied by the operator — the agent was told to stop.";
  state.activeGateMarker = null;
}

// ------------------------------------------------------------- approvals

function showApprovals(approvals) {
  state.pendingApprovals = approvals;
  approvalBodyEl.replaceChildren();

  for (const approval of approvals) {
    const card = document.createElement("div");
    card.className = "approval-item";

    const header = document.createElement("header");
    header.textContent = approval.toolName;
    card.appendChild(header);

    const args = document.createElement("div");
    args.className = "args";
    const entries =
      approval.args && typeof approval.args === "object" && !Array.isArray(approval.args)
        ? Object.entries(approval.args)
        : [["arguments", approval.args]];

    if (entries.length === 0) {
      const note = document.createElement("div");
      note.className = "arg-row";
      note.textContent = "No arguments.";
      args.appendChild(note);
    }

    for (const [key, value] of entries) {
      const row = document.createElement("div");
      row.className = "arg-row";
      const k = document.createElement("div");
      k.className = "k";
      k.textContent = key;
      const v = document.createElement("div");
      v.className = "v";
      v.textContent = stringify(value);
      row.append(k, v);
      args.appendChild(row);
    }

    card.appendChild(args);
    approvalBodyEl.appendChild(card);
  }

  overlayEl.hidden = false;
  setStatus("Waiting for your decision", "waiting");
  // Focus Deny, not Approve: the safe option should be the one an accidental
  // Enter keypress hits.
  denyBtn.focus();
}

async function respond(approved) {
  const decisions = state.pendingApprovals.map((approval) => ({
    toolCallId: approval.toolCallId,
    threadId: approval.threadId,
    approved,
  }));
  overlayEl.hidden = true;
  approveBtn.disabled = true;
  denyBtn.disabled = true;
  resolveGateMarker(approved);
  setStatus(approved ? "Resuming…" : "Denied, wrapping up…", "running");

  try {
    const response = await fetch(`/api/session/${state.sessionId}/approval`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ decisions }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error ?? `HTTP ${response.status}`);
    }
  } catch (error) {
    append(line("error", "✖", (b) => (b.textContent = `Approval failed: ${error.message}`)));
    setStatus("Error", "error");
  } finally {
    state.pendingApprovals = [];
    approveBtn.disabled = false;
    denyBtn.disabled = false;
  }
}

approveBtn.addEventListener("click", () => respond(true));
denyBtn.addEventListener("click", () => respond(false));

// Escape denies. Refusing an irreversible action is the safe default, and it
// must never be possible to dismiss this dialog without a decision.
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !overlayEl.hidden) {
    event.preventDefault();
    respond(false);
  }
});

// -------------------------------------------------------------- streaming

function handleEvent(event) {
  switch (event.kind) {
    case "turn-start":
      setStatus("Agent running", "running");
      state.busy = true;
      cancelBtn.hidden = false;
      break;

    case "assistant":
      if (event.threadId === "user") renderUser(event.text);
      else renderAgent(event.text, event.threadId);
      break;

    case "thinking":
      append(line("thinking", "◦", (b) => (b.textContent = truncate(event.text, 200))));
      break;

    case "tool-call": {
      recordTool(event.toolCallId, event.toolName);
      append(
        line("tool", "→", (b) => {
          const name = document.createElement("span");
          name.className = "name";
          name.textContent = event.toolName;
          const args = document.createElement("span");
          args.textContent = ` ${truncate(stringify(event.args), 130)}`;
          b.append(name, args);
        }),
      );
      break;
    }

    case "tool-result":
      completeTool(event.toolCallId);
      append(
        line("result", "←", (b) => {
          b.textContent = truncate(event.text.split("\n")[0] ?? "", 150);
        }),
      );
      break;

    case "subagent":
      recordSubagent(event.name);
      append(line("subagent", "⑂", (b) => (b.textContent = `subagent ${event.name} started`)));
      break;

    case "sandbox":
      append(line("sandbox", "▣", (b) => (b.textContent = event.detail)));
      break;

    case "approval-required":
      renderGateMarker(event.approvals.map((a) => a.toolName));
      showApprovals(event.approvals);
      break;

    case "mcp-auth-required":
      append(
        line("error", "!", (b) => (b.textContent = `${event.server} needs authorisation.`)),
      );
      break;

    case "turn-done":
      state.busy = false;
      cancelBtn.hidden = true;
      sendBtn.disabled = false;
      inputEl.disabled = false;
      if (overlayEl.hidden) {
        setStatus(event.status === "error" ? "Turn failed" : "Idle", event.status === "error" ? "error" : "done");
      }
      append(line("done", "▪", (b) => (b.textContent = `turn ${event.status}`)));
      break;

    case "error":
      append(line("error", "✖", (b) => (b.textContent = event.message)));
      setStatus("Error", "error");
      state.busy = false;
      sendBtn.disabled = false;
      inputEl.disabled = false;
      cancelBtn.hidden = true;
      break;

    default:
      break;
  }
}

function connectStream(sessionId) {
  if (state.eventSource) state.eventSource.close();
  const source = new EventSource(`/api/session/${sessionId}/stream`);
  state.eventSource = source;

  source.addEventListener("agent", (message) => {
    try {
      handleEvent(JSON.parse(message.data));
    } catch {
      // A frame we cannot parse must not kill the stream.
    }
  });

  source.addEventListener("error", () => {
    // EventSource reconnects on its own; surface it without tearing down state.
    if (!state.busy) setStatus("Reconnecting…", "waiting");
  });
}

// ---------------------------------------------------------------- actions

async function send() {
  const message = inputEl.value.trim();
  if (message.length === 0 || state.busy || state.sessionId === null) return;

  inputEl.value = "";
  inputEl.disabled = true;
  sendBtn.disabled = true;
  setStatus("Starting…", "running");

  try {
    const response = await fetch(`/api/session/${state.sessionId}/message`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error ?? `HTTP ${response.status}`);
    }
  } catch (error) {
    append(line("error", "✖", (b) => (b.textContent = error.message)));
    setStatus("Error", "error");
    inputEl.disabled = false;
    sendBtn.disabled = false;
  }
}

sendBtn.addEventListener("click", send);

inputEl.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    send();
  }
});

cancelBtn.addEventListener("click", async () => {
  if (state.sessionId === null) return;
  await fetch(`/api/session/${state.sessionId}/cancel`, { method: "POST" });
  setStatus("Cancelling…", "waiting");
});

// ----------------------------------------------------------------- boot

function renderCapabilities(status) {
  capabilitiesEl.replaceChildren();
  const chips = [
    { label: status.model ?? "no model", on: Boolean(status.model), bad: !status.model },
    { label: `sandbox ${status.sandbox ? "on" : "off"}`, on: status.sandbox },
    { label: `github ${status.github ? "on" : "off"}`, on: status.github },
    {
      label: status.remoteWrites ? "writes armed" : "read-only",
      on: !status.remoteWrites,
    },
  ];
  for (const chip of chips) {
    const node = document.createElement("span");
    node.className = `chip ${chip.bad ? "bad" : chip.on ? "on" : "off"}`;
    const dot = document.createElement("span");
    dot.className = "dot";
    const text = document.createElement("span");
    text.textContent = chip.label;
    node.append(dot, text);
    capabilitiesEl.appendChild(node);
  }
}

function renderSuggestions(targetRepo) {
  const repo = targetRepo ?? "owner/repo";
  const ideas = [
    `Triage the dependencies in ${repo} and tell me what is actually exploitable.`,
    `Scan ${repo}, then prepare a patch for every critical and high advisory.`,
    `Which dependencies in ${repo} have no published fix?`,
  ];
  for (const idea of ideas) {
    const button = document.createElement("button");
    button.className = "suggestion";
    button.type = "button";
    button.textContent = idea;
    button.addEventListener("click", () => {
      inputEl.value = idea;
      inputEl.focus();
    });
    suggestionsEl.appendChild(button);
  }
}

async function boot() {
  setStatus("Connecting…", "waiting");
  let status;
  try {
    status = await (await fetch("/api/status")).json();
  } catch {
    setStatus("Server unreachable", "error");
    return;
  }
  state.status = status;
  renderCapabilities(status);
  renderSuggestions(status.targetRepo);

  if (!status.ready) {
    clearEmpty();
    append(
      line("error", "✖", (b) => (b.textContent = status.error ?? "The harness is not ready.")),
    );
    setStatus("Not ready", "error");
    sendBtn.disabled = true;
    inputEl.disabled = true;
    return;
  }

  for (const warning of status.warnings ?? []) {
    append(line("thinking", "!", (b) => (b.textContent = warning)));
  }

  try {
    const response = await fetch("/api/session", { method: "POST" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`);
    state.sessionId = body.sessionId;
    connectStream(body.sessionId);
    setStatus("Idle", "done");
    inputEl.focus();
  } catch (error) {
    append(line("error", "✖", (b) => (b.textContent = `Could not start a session: ${error.message}`)));
    setStatus("Error", "error");
    sendBtn.disabled = true;
  }
}

boot();
