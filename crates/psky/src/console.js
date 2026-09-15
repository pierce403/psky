"use strict";

// Tokens stay in this closure. Server values enter the DOM as text, never HTML.
(() => {
  const byId = id => document.getElementById(id);
  const state = {
    token: "", connected: false, connecting: false, refreshing: false,
    saving: false, submitting: false, generation: 0, revision: null,
    settings: null, dirty: false, stale: false, latestStatus: null,
    logs: [], cursor: 0, operation: null, timer: null, instanceId: null,
  };
  const fields = {
    node_name: "setting-node-name", network: "setting-network",
    test_fid: "setting-fid", request_timeout_ms: "setting-timeout",
    max_response_bytes: "setting-max-bytes", max_block_delay_seconds: "setting-max-delay",
    admin_bind: "setting-admin-bind", public_bind: "setting-public-bind",
  };
  function setText(id, value) { byId(id).textContent = value; }
  function badge(text, tone = "neutral") {
    const item = document.createElement("span");
    item.className = `badge ${tone}`;
    item.textContent = text;
    return item;
  }
  function notice(message, tone = "") {
    setText("notice", message);
    byId("notice").className = `notice ${tone}`;
  }
  function configNotice(message, tone = "") {
    setText("config-notice", message);
    byId("config-notice").className = `subtle ${tone}`;
  }
  function connection(label, tone) {
    setText("connection-state", label);
    byId("connection-state").className = `badge ${tone}`;
  }
  function time(value) {
    if (value === null || value === undefined) return "Not recorded";
    const date = typeof value === "number" ? new Date(value < 1e12 ? value * 1000 : value) : new Date(value);
    return Number.isNaN(date.getTime()) ? "Not recorded" : date.toLocaleString();
  }
  function duration(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return "Unknown";
    if (seconds < 60) return `${Math.floor(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`;
    return `${Math.floor(seconds / 86400)}d ${Math.floor(seconds % 86400 / 3600)}h`;
  }
  function operationName(kind) {
    return ({ preflight: "Peer check", reconstruct: "Reconstruction" })[kind] || kind || "Operation";
  }
  function emptyRow(target, message) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.className = "empty-state";
    cell.textContent = message;
    row.append(cell);
    target.replaceChildren(row);
  }
  function addCell(row, value) {
    const cell = document.createElement("td");
    if (value instanceof Node) cell.append(value);
    else cell.textContent = value === null || value === undefined ? "Unknown" : String(value);
    row.append(cell);
  }
  function updateControls() {
    const busy = state.submitting || Boolean(state.operation);
    byId("connect").disabled = state.connecting;
    byId("refresh").disabled = !state.connected || state.refreshing;
    byId("disconnect").hidden = !state.connected;
    byId("connection-panel").hidden = state.connected;
    byId("config-fields").disabled = !state.connected || state.saving || !state.settings;
    byId("save-config").disabled = !state.connected || state.saving || !state.dirty || state.stale || busy;
    byId("reload-config").disabled = !state.connected || state.saving;
    byId("preflight").disabled = !state.connected || busy || state.saving || !state.settings?.endpoints.length;
    byId("reconstruct").disabled = !state.connected || busy || state.saving;
    setText("save-config", state.saving ? "Saving…" : "Save settings");
    setText("preflight", state.submitting === "preflight" ? "Starting…" : "Check nodes");
    setText("reconstruct", state.submitting === "reconstruct" ? "Starting…" : "Run offline reconstruction");
  }

  async function api(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(`/admin/${path}`, {
        method: options.method || "GET",
        headers: { Authorization: `Bearer ${state.token}`, ...(options.body ? { "Content-Type": "application/json" } : {}) },
        ...(options.body ? { body: JSON.stringify(options.body) } : {}),
        signal: controller.signal, credentials: "omit", cache: "no-store", redirect: "error",
      });
      const result = await response.json();
      if (!response.ok) {
        const error = new Error(result.message || `Request failed (${response.status}).`);
        error.status = response.status;
        error.code = result.error;
        throw error;
      }
      return result;
    } catch (error) {
      if (error.name === "AbortError") throw new Error("The node did not respond within 12 seconds. Check its process and listener.");
      if (error instanceof TypeError) throw new Error("Could not reach the node. Check its process and listener.");
      throw error;
    } finally { clearTimeout(timeout); }
  }
  function disconnect(message = "Disconnected. Your token has been cleared from this tab.", tone = "") {
    clearTimeout(state.timer);
    state.generation++;
    Object.assign(state, { token: "", connected: false, connecting: false, refreshing: false, saving: false, submitting: false });
    byId("token").value = "";
    connection("Disconnected", "neutral");
    notice(`${message}${state.latestStatus ? " Displayed status is stale." : ""}`, tone);
    updateControls();
  }
  function markFailure(error) {
    if (error.status === 401 || error.status === 403) {
      disconnect(error.status === 401 ? "Authentication failed. Enter the current admin token." : "This origin is not allowed. Open the console using its loopback address.", "error");
      return;
    }
    connection("Status stale", "warning");
    notice(error.message, "error");
  }

  // Polling never overwrites this form. Only explicit reloads and saves do so.
  function renderConfig(config, preserveEdits = false) {
    const keepDraft = preserveEdits && state.dirty;
    state.settings = config.settings;
    if (keepDraft) {
      // Reauthentication must not discard a draft or move its compare-and-swap revision.
      state.stale = config.revision !== state.revision;
      setText("config-revision", state.stale ? `Editing ${state.revision} · saved ${config.revision}` : `Revision ${state.revision}`);
      configNotice(state.stale ? "Unsaved changes preserved. The saved configuration changed; reload before saving." : "Unsaved changes preserved.", state.stale ? "error" : "");
    } else {
      state.revision = config.revision;
      state.dirty = false;
      state.stale = false;
      for (const [key, id] of Object.entries(fields)) byId(id).value = config.settings[key] ?? "";
      byId("setting-endpoints").value = config.settings.endpoints.join("\n");
      byId("setting-fixture").checked = config.settings.serve_fixture;
      setText("config-revision", `Revision ${config.revision}`);
      configNotice("Saved configuration loaded.");
    }
    byId("config-stale").hidden = !state.stale;
    byId("restart-warning").hidden = !config.restart_required;
    setText("active-admin", config.active_listeners?.admin_bind || "Not reported");
    setText("active-public", config.active_listeners?.public_bind || "Not reported");
    renderPeers(state.latestStatus?.preflight);
    updateControls();
  }
  function fieldNumber(id, optional = false) {
    const raw = byId(id).value.trim();
    if (optional && raw === "") return null;
    const number = Number(raw);
    if (!raw || !Number.isSafeInteger(number) || number < 0) throw new Error("Numeric settings must be whole numbers within the supported range.");
    return number;
  }
  function readConfig() {
    return {
      node_name: byId("setting-node-name").value.trim(),
      endpoints: byId("setting-endpoints").value.split(/\r?\n/).map(item => item.trim()).filter(Boolean),
      network: byId("setting-network").value,
      test_fid: fieldNumber("setting-fid", true),
      request_timeout_ms: fieldNumber("setting-timeout"),
      max_response_bytes: fieldNumber("setting-max-bytes"),
      max_block_delay_seconds: fieldNumber("setting-max-delay"),
      serve_fixture: byId("setting-fixture").checked,
      admin_bind: byId("setting-admin-bind").value.trim(),
      public_bind: byId("setting-public-bind").value.trim(),
    };
  }

  function peerMetric(list, title, value) {
    const item = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = title;
    description.textContent = value;
    item.append(term, description);
    list.append(item);
  }
  function renderPeers(report) {
    const nodes = report?.nodes || (state.settings?.endpoints || []).map(endpoint => ({ endpoint }));
    const fragment = document.createDocumentFragment();
    if (!nodes.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = state.settings ? "Add Hypersnap endpoints in Configuration to begin." : "Connect to load the configured endpoints.";
      fragment.append(empty);
    }
    for (const node of nodes) {
      const card = document.createElement("article");
      card.className = "peer-card";
      const heading = document.createElement("div");
      heading.className = "peer-heading";
      const endpoint = document.createElement("h3");
      endpoint.className = "peer-endpoint";
      endpoint.textContent = node.endpoint;
      const info = node.info;
      const failures = (node.requests || []).filter(request => request.failure);
      const mismatch = node.protocol === "incompatible" || node.network === "incompatible";
      let label = !report ? "Unchecked" : !info ? "Info unavailable" : mismatch ? "Mismatch" : "Health unconfirmed";
      let tone = !report ? "neutral" : !info || mismatch ? "error" : "neutral";
      if (info && node.freshness === "lagging") { label = "Lagging"; tone = "warning"; }
      if (node.peer_unique === false) { label = "Duplicate peer"; tone = "warning"; }
      if (node.healthy === true) { label = "Checks passed"; tone = "success"; }
      heading.append(endpoint, badge(label, tone));
      card.append(heading);
      const facts = document.createElement("dl");
      facts.className = "peer-facts";
      peerMetric(facts, "Version", info?.version || "Unknown");
      peerMetric(facts, "Data shards", info?.num_shards === undefined ? "Unknown" : String(info.num_shards));
      const shards = info?.shard_infos || [];
      const delays = shards.map(shard => shard.block_delay_seconds).filter(Number.isFinite);
      peerMetric(facts, "Largest reported delay", delays.length ? duration(Math.max(...delays)) : "Unknown");
      peerMetric(facts, "Network", node.observed_network || "Unconfirmed");
      card.append(facts);
      const identity = document.createElement("p");
      identity.className = "peer-identity";
      identity.textContent = `Peer ID: ${info?.peer_id || "Not reported"}`;
      card.append(identity);
      const checked = document.createElement("p");
      checked.className = "peer-note";
      checked.textContent = report ? `Checked ${time(state.latestStatus?.last_check_at)} · Freshness: ${node.freshness || "unknown"}` : "No check in this process.";
      card.append(checked);
      if (shards.length) {
        const shardText = document.createElement("p");
        shardText.className = "peer-note";
        shardText.textContent = shards.map(shard => `Shard ${shard.shard_id}: height ${shard.max_height}, delay ${duration(shard.block_delay_seconds)}`).join(" · ");
        card.append(shardText);
      }
      if (failures.length) {
        const note = document.createElement("p");
        note.className = "peer-note";
        note.textContent = failures.map(request => `${request.route}: ${request.failure}`).join(" · ");
        card.append(note);
      }
      fragment.append(card);
    }
    byId("peers").replaceChildren(fragment);
    setText("peer-count", state.settings ? String(state.settings.endpoints.length) : "Not loaded");
    const responding = (report?.nodes || []).filter(node => node.info).length;
    setText("peer-summary", report ? `${responding} of ${report.nodes.length} returned node info` : "Run a read-only check");
    setText("preflight-evidence", report ? JSON.stringify(report, null, 2) : "No peer check yet.");
  }
  function renderStatus(status) {
    const restarted = Boolean(state.instanceId && status.instance_id && status.instance_id !== state.instanceId);
    if (restarted) {
      state.logs = [];
      state.cursor = 0;
      state.stale = true;
      byId("config-stale").hidden = false;
      configNotice("The node restarted. Reload its saved configuration before making changes.", "error");
      renderLogs();
    }
    state.instanceId = status.instance_id || state.instanceId;
    // An older in-flight poll can finish after a successful save.
    if (!restarted && state.revision !== null && status.config_revision < state.revision) return false;
    state.latestStatus = status;
    state.operation = status.active_operation || (status.operation_running ? { kind: "operation", status: "running" } : null);
    setText("node-title", status.node_name || state.settings?.node_name || "Node overview");
    setText("node-version", status.version ? `v${status.version} · ${status.mode || "preflight-and-offline-lab"}` : status.mode || "Preflight and reconstruction lab");
    setText("uptime", duration(status.uptime_seconds));
    setText("storage-gate", status.storage_gate || "Live account writes are unavailable. The reconstruction lab uses public test fixtures.");
    setText("account-binding", status.account_binding || "Not implemented");
    setText("signer", status.signer || "Public fixture key only");
    setText("operation-state", state.operation ? operationName(state.operation.kind) : "Idle");
    setText("operation-detail", state.operation ? "Running on the node" : "No operation running");
    const checkAge = status.last_check_at ? Math.max(0, Date.now() / 1000 - status.last_check_at) : null;
    setText("last-check", checkAge === null ? "Never" : checkAge < 5 ? "Just now" : `${duration(checkAge)} ago`);
    byId("last-check").title = status.last_check_at ? time(status.last_check_at) : "";
    setText("check-summary", status.preflight ? "Observed health, not a durability proof" : "No live observations yet");
    byId("restart-warning").hidden = !status.restart_required;
    if (state.revision !== null && status.config_revision !== undefined && status.config_revision !== state.revision) {
      state.stale = true;
      byId("config-stale").hidden = false;
      configNotice("A newer configuration is saved on the node. Reload to continue.", "error");
    }
    byId("preflight-stale").hidden = !status.preflight || status.preflight_config_revision === status.config_revision;
    renderPeers(status.preflight);
    const lab = status.lab;
    const labRevision = status.lab_config_revision === null || status.lab_config_revision === undefined ? "" : ` Configuration revision ${status.lab_config_revision}.`;
    setText("lab-summary", lab ? lab.error ? `The last offline reconstruction failed. Check operation events.${labRevision}` : `${lab.exports_checked ?? "Unknown number of"} exports checked using the public fixture key.${labRevision} Live reconstruction remains unproven.` : "No lab result in this process.");
    setText("lab-evidence", lab ? JSON.stringify(lab, null, 2) : "No reconstruction yet.");
    updateControls();
    return restarted;
  }
  function renderOperations(result) {
    const target = byId("operations");
    const operations = [...(result.active ? [result.active] : []), ...(result.recent || [])];
    const seen = new Set();
    const fragment = document.createDocumentFragment();
    for (const operation of operations) {
      if (seen.has(operation.id)) continue;
      seen.add(operation.id);
      const row = document.createElement("tr");
      const kind = document.createElement("span");
      kind.textContent = operationName(operation.kind);
      kind.title = `Operation ${operation.id}, configuration ${operation.config_revision}`;
      addCell(row, kind);
      addCell(row, badge(operation.status || "Unknown", operation.status === "failed" ? "error" : operation.status === "succeeded" ? "success" : "neutral"));
      addCell(row, time(operation.started_at));
      addCell(row, operation.error || (operation.finished_at ? `Finished ${time(operation.finished_at)}` : "In progress"));
      fragment.append(row);
    }
    if (fragment.childNodes.length) target.replaceChildren(fragment);
    else emptyRow(target, "No operations in this process.");
  }
  function renderLogs() {
    const target = byId("logs");
    const filter = byId("log-filter").value;
    const fragment = document.createDocumentFragment();
    for (const entry of [...state.logs].reverse()) {
      const level = String(entry.level || "info").toLowerCase();
      if (filter === "error" && level !== "error") continue;
      if (filter === "warn" && !["warn", "warning", "error"].includes(level)) continue;
      const row = document.createElement("tr");
      addCell(row, time(entry.timestamp));
      addCell(row, badge(level, level === "error" ? "error" : ["warn", "warning"].includes(level) ? "warning" : "neutral"));
      addCell(row, entry.event);
      addCell(row, entry.message);
      fragment.append(row);
    }
    if (fragment.childNodes.length) target.replaceChildren(fragment);
    else emptyRow(target, state.logs.length ? "No events match this filter." : "No events in this process.");
    setText("log-count", `${state.logs.length} events`);
  }
  function appendLogs(result) {
    const known = new Set(state.logs.map(entry => entry.sequence));
    for (const entry of result.entries || []) if (!known.has(entry.sequence)) state.logs.push(entry);
    if (state.logs.length > 200) state.logs.splice(0, state.logs.length - 200);
    state.cursor = result.next_cursor ?? state.cursor;
    byId("logs-truncated").hidden = !result.truncated && !result.dropped_before && state.logs.length < 200;
    renderLogs();
  }

  function scheduleRefresh() {
    clearTimeout(state.timer);
    if (state.connected) state.timer = setTimeout(() => {
      if (document.visibilityState === "visible") refresh();
      else scheduleRefresh();
    }, 5000);
  }
  async function refresh(manual = false) {
    if (!state.connected || state.refreshing) return;
    state.refreshing = true;
    const generation = state.generation;
    updateControls();
    try {
      const results = await Promise.allSettled([api("status"), api("operations"), api(`logs?after=${state.cursor}&limit=100`)]);
      if (generation !== state.generation) return;
      const restarted = results[0].status === "fulfilled" && renderStatus(results[0].value);
      if (results[1].status === "fulfilled") renderOperations(results[1].value);
      // The concurrent log request used the previous process's cursor.
      if (results[2].status === "fulfilled" && !restarted) appendLogs(results[2].value);
      const failures = results.filter(result => result.status === "rejected");
      if (failures.length) markFailure(failures.find(result => [401, 403].includes(result.reason.status))?.reason || failures[0].reason);
      else {
        connection("Connected", "success");
        if (manual || byId("notice").classList.contains("error")) notice(`Status updated ${new Date().toLocaleTimeString()}.`);
      }
    } finally {
      if (generation === state.generation) { state.refreshing = false; updateControls(); scheduleRefresh(); }
    }
  }
  byId("connection-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (state.connecting) return;
    const token = byId("token").value.trim();
    if (!token) return;
    state.token = token;
    byId("token").value = "";
    state.connecting = true;
    state.generation++;
    const generation = state.generation;
    updateControls();
    notice("Connecting to the local node…");
    try {
      const [status, config] = await Promise.all([api("status"), api("config")]);
      if (generation !== state.generation) return;
      state.connected = true;
      state.logs = [];
      state.cursor = 0;
      state.instanceId = null;
      renderConfig(config, true);
      renderStatus(status);
      connection("Connected", "success");
      notice("Connected. Status refreshes every 5 seconds while this tab is visible.", "success");
      await refresh();
    } catch (error) {
      if (generation !== state.generation) return;
      disconnect(error.message, "error");
    } finally {
      if (generation === state.generation) { state.connecting = false; updateControls(); }
    }
  });
  byId("disconnect").addEventListener("click", () => disconnect());
  byId("refresh").addEventListener("click", () => refresh(true));
  byId("log-filter").addEventListener("change", renderLogs);
  byId("config-form").addEventListener("input", () => {
    state.dirty = true;
    if (!state.stale) configNotice("Unsaved changes.");
    updateControls();
  });
  byId("reload-config").addEventListener("click", async () => {
    if (state.dirty && !window.confirm("Discard unsaved edits and reload the saved configuration?")) return;
    const generation = state.generation;
    state.saving = true;
    updateControls();
    try {
      const config = await api("config");
      if (generation === state.generation) renderConfig(config);
    } catch (error) {
      if (generation === state.generation) { configNotice(error.message, "error"); if ([401, 403].includes(error.status)) markFailure(error); }
    } finally {
      if (generation === state.generation) { state.saving = false; updateControls(); }
    }
  });
  byId("config-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (!state.connected || state.saving || state.stale || !state.dirty) return;
    const generation = state.generation;
    state.saving = true;
    updateControls();
    try {
      const settings = readConfig();
      const config = await api("config", { method: "PUT", body: { expected_revision: state.revision, settings } });
      if (generation !== state.generation) return;
      renderConfig(config);
      configNotice(config.restart_required ? "Saved. Restart the node process to apply listener changes." : "Saved. Settings are active.", "success");
      await refresh();
    } catch (error) {
      if (generation !== state.generation) return;
      if (error.status === 409 && error.code !== "Busy") { state.stale = true; byId("config-stale").hidden = false; }
      configNotice(error.message, "error");
      if ([401, 403].includes(error.status)) markFailure(error);
    } finally {
      if (generation === state.generation) { state.saving = false; updateControls(); }
    }
  });
  async function run(kind) {
    if (!state.connected || state.operation || state.submitting) return;
    const generation = state.generation;
    state.submitting = kind;
    updateControls();
    notice(`Starting ${operationName(kind).toLowerCase()}…`);
    try {
      const operation = await api(kind, { method: "POST" });
      if (generation !== state.generation) return;
      state.operation = operation;
      notice(`${operationName(kind)} accepted. Follow progress in Activity.`);
      await refresh();
    } catch (error) {
      if (generation !== state.generation) return;
      if ([401, 403].includes(error.status)) markFailure(error);
      else { await refresh(); notice(error.message, "error"); }
    } finally {
      if (generation === state.generation) { state.submitting = false; updateControls(); }
    }
  }
  byId("preflight").addEventListener("click", () => run("preflight"));
  byId("reconstruct").addEventListener("click", () => run("reconstruct"));
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refresh(); });
  window.addEventListener("beforeunload", event => { if (state.dirty) { event.preventDefault(); event.returnValue = ""; } });
})();
