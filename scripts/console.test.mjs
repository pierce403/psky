// State-machine tests for the real console script. This is a small DOM/fetch
// fixture, not a browser or a layout/accessibility test; browser smoke is separate.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../crates/psky/src/console.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../crates/psky/src/console.html", import.meta.url), "utf8");
const clone = value => structuredClone(value);

class Element {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.childNodes = [];
    this.handlers = new Map();
    this.className = "";
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this._value = "";
    this._text = "";
    this.classList = { contains: name => this.className.split(/\s+/).includes(name) };
  }
  get value() { return this._value; }
  set value(value) { this._value = String(value); }
  get textContent() { return this._text + this.childNodes.map(child => child.textContent).join(""); }
  set textContent(value) { this._text = String(value); this.childNodes = []; }
  set innerHTML(_) { throw new Error("Unsafe HTML sink used"); }
  set outerHTML(_) { throw new Error("Unsafe HTML sink used"); }
  insertAdjacentHTML() { throw new Error("Unsafe HTML sink used"); }
  append(...nodes) {
    for (const node of nodes) {
      if (node.tagName === "#fragment") this.childNodes.push(...node.childNodes.splice(0));
      else this.childNodes.push(node);
    }
  }
  replaceChildren(...nodes) { this._text = ""; this.childNodes = []; this.append(...nodes); }
  addEventListener(type, handler) {
    if (!this.handlers.has(type)) this.handlers.set(type, []);
    this.handlers.get(type).push(handler);
  }
  async emit(type) {
    for (const handler of this.handlers.get(type) || []) {
      await handler({ preventDefault() {}, target: this });
    }
  }
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fixture() {
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
  const get = id => {
    assert.ok(elements.has(id), `Console references missing HTML element #${id}`);
    return elements.get(id);
  };
  get("log-filter").value = "all";
  const requests = [];
  const createdTags = [];
  const timers = new Map();
  let nextTimer = 0;
  const storage = new Proxy({}, { get() { throw new Error("Browser storage used"); }, set() { throw new Error("Browser storage used"); } });
  const document = new Element("#document");
  Object.assign(document, {
    visibilityState: "visible",
    getElementById: get,
    createElement: tag => { createdTags.push(tag); return new Element(tag); },
    createDocumentFragment: () => new Element("#fragment"),
  });
  Object.defineProperty(document, "cookie", {
    get() { throw new Error("Cookie storage used"); },
    set() { throw new Error("Cookie storage used"); },
  });
  const settings = {
    node_name: "Node A", network: "mainnet", endpoints: ["https://node.example"],
    test_fid: 8531, request_timeout_ms: 5000, max_response_bytes: 262144,
    max_block_delay_seconds: 30, admin_bind: "127.0.0.1:8788",
    public_bind: "127.0.0.1:8787", serve_fixture: false,
  };
  const server = {
    config: {
      revision: 1, settings, restart_required: false,
      active_listeners: { admin_bind: settings.admin_bind, public_bind: settings.public_bind },
    },
    status: {
      api_version: 1, instance_id: "instance-a", config_revision: 1,
      node_name: "Node A", version: "0.1.0", uptime_seconds: 10,
      active_operation: null, operation_running: false, restart_required: false,
      preflight: null, preflight_config_revision: null, last_check_at: null,
      lab: null, lab_config_revision: null,
    },
    operations: { active: null, recent: [] },
    logs: [],
    intercept: null,
    respond(request) {
      const url = new URL(request.path, "http://127.0.0.1:8788");
      if (url.pathname === "/admin/status") return clone(this.status);
      if (url.pathname === "/admin/operations") return clone(this.operations);
      if (url.pathname === "/admin/logs") {
        const after = Number(url.searchParams.get("after"));
        const entries = this.logs.filter(entry => entry.sequence > after).slice(0, 100);
        return { entries: clone(entries), next_cursor: entries.at(-1)?.sequence ?? this.logs.at(-1)?.sequence ?? 0, dropped_before: 0, truncated: false };
      }
      if (url.pathname === "/admin/config" && request.options.method === "GET") return clone(this.config);
      if (url.pathname === "/admin/config" && request.options.method === "PUT") {
        const input = JSON.parse(request.options.body);
        assert.equal(input.expected_revision, this.config.revision, "Save must use the loaded revision");
        this.config = { ...this.config, revision: this.config.revision + 1, settings: input.settings };
        this.status = { ...this.status, config_revision: this.config.revision, node_name: input.settings.node_name };
        return clone(this.config);
      }
      throw new Error(`Unexpected fixture request: ${request.options.method} ${request.path}`);
    },
  };
  const window = new Element("#window");
  window.confirm = () => true;
  window.localStorage = storage;
  window.sessionStorage = storage;
  const context = vm.createContext({
    document, window, Node: Element, AbortController, localStorage: storage, sessionStorage: storage,
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(path, options) {
      const request = { path, options };
      requests.push(request);
      const intercepted = server.intercept?.(request);
      const body = await (intercepted === undefined ? server.respond(request) : intercepted);
      return { ok: true, status: 200, async json() { return clone(body); } };
    },
  });
  vm.runInContext(source, context, { filename: "console.js" });
  return {
    get, server, requests, createdTags, timers,
    async connect(token = "ab".repeat(32)) {
      get("token").value = token;
      await get("connection-form").emit("submit");
      assert.equal(get("connection-state").textContent, "Connected");
    },
    async editName(value) { get("setting-node-name").value = value; await get("config-form").emit("input"); },
    refresh() { return get("refresh").emit("click"); },
    allText() { return [...elements.values()].map(element => element.textContent).join("\n"); },
  };
}

test("token leaves the input, is sent only as a bearer header, and disconnect stops requests", async () => {
  const app = fixture();
  const token = "12".repeat(32);
  await app.connect(token);
  assert.equal(app.get("token").value, "");
  assert.ok(!app.allText().includes(token));
  assert.ok(app.requests.length >= 5);
  for (const { path, options } of app.requests) {
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    assert.ok(!path.includes(token));
    assert.equal(options.credentials, "omit");
    assert.equal(options.redirect, "error");
    assert.equal(options.cache, "no-store");
  }
  await app.editName("Draft survives reauthentication");
  await app.get("disconnect").emit("click");
  const previousRequests = app.requests.length;
  await app.refresh();
  assert.equal(app.requests.length, previousRequests);
  assert.equal(app.get("token").value, "");
  assert.equal(app.timers.size, 0);
  const replacement = "34".repeat(32);
  await app.connect(replacement);
  assert.ok(app.requests.slice(previousRequests).every(request => request.options.headers.Authorization === `Bearer ${replacement}`));
  assert.equal(app.get("setting-node-name").value, "Draft survives reauthentication");
  assert.equal(app.get("save-config").disabled, false);
  await app.get("config-form").emit("submit");
  assert.equal(app.server.config.settings.node_name, "Draft survives reauthentication");
  assert.equal(app.server.config.revision, 2);
});

test("polling preserves dirty form values and warns when another writer updates settings", async () => {
  const app = fixture();
  await app.connect();
  await app.editName("Unsaved operator edit");
  await app.refresh();
  assert.equal(app.get("setting-node-name").value, "Unsaved operator edit");
  assert.equal(app.get("save-config").disabled, false);
  app.server.status.config_revision = 2;
  app.server.status.node_name = "Saved by another agent";
  await app.refresh();
  assert.equal(app.get("setting-node-name").value, "Unsaved operator edit");
  assert.equal(app.get("config-stale").hidden, false);
  assert.equal(app.get("save-config").disabled, true);
  assert.equal(app.requests.filter(request => request.path === "/admin/config").length, 1, "A poll must not reload the form");
});

test("an old status response after successful save cannot invalidate the new revision", async () => {
  const app = fixture();
  await app.connect();
  await app.editName("Saved new name");
  const oldStatus = clone(app.server.status);
  const pending = deferred();
  let held = false;
  app.server.intercept = request => {
    if (request.path === "/admin/status" && !held) { held = true; return pending.promise; }
  };
  const polling = app.refresh();
  assert.ok(held);
  await app.get("config-form").emit("submit");
  assert.equal(app.server.config.revision, 2);
  assert.equal(app.get("config-revision").textContent, "Revision 2");
  pending.resolve(oldStatus);
  await polling;
  assert.equal(app.get("config-stale").hidden, true);
  assert.equal(app.get("setting-node-name").value, "Saved new name");
  await app.editName("Next edit");
  assert.equal(app.get("save-config").disabled, false);
});

test("disconnect prevents an in-flight poll from updating the UI or rescheduling", async () => {
  const app = fixture();
  await app.connect();
  const pending = deferred();
  app.server.intercept = request => request.path === "/admin/status" ? pending.promise : undefined;
  const polling = app.refresh();
  await app.get("disconnect").emit("click");
  pending.resolve({ ...app.server.status, node_name: "Late response must be ignored" });
  await polling;
  assert.equal(app.get("node-title").textContent, "Node A");
  assert.equal(app.get("connection-state").textContent, "Disconnected");
  assert.equal(app.get("refresh").disabled, true);
  assert.equal(app.timers.size, 0);
});

test("a new process instance resets log cursors and does not mix old process events", async () => {
  const app = fixture();
  app.server.logs = [{ sequence: 50, timestamp: 1, level: "info", event: "old_event", message: "Old process message" }];
  await app.connect();
  assert.match(app.get("logs").textContent, /Old process message/);
  app.server.status.instance_id = "instance-b";
  app.server.logs = [{ sequence: 1, timestamp: 2, level: "info", event: "new_event", message: "New process message" }];
  await app.refresh();
  assert.equal(app.get("log-count").textContent, "0 events");
  assert.ok(!app.get("logs").textContent.includes("Old process message"));
  assert.equal(app.get("config-stale").hidden, false);
  await app.refresh();
  const logRequests = app.requests.filter(request => request.path.startsWith("/admin/logs?"));
  assert.match(logRequests.at(-2).path, /after=50&/);
  assert.match(logRequests.at(-1).path, /after=0&/);
  assert.equal(app.get("log-count").textContent, "1 events");
  assert.match(app.get("logs").textContent, /New process message/);
  assert.ok(!app.get("logs").textContent.includes("Old process message"));
});

test("hostile response strings remain literal text and never reach an HTML sink", async () => {
  const app = fixture();
  const hostile = '<img src=x onerror="globalThis.compromised=true">';
  app.server.status.node_name = hostile;
  app.server.status.account_binding = hostile;
  app.server.status.preflight = { nodes: [{ endpoint: hostile, requests: [{ route: hostile, failure: hostile }] }] };
  app.server.logs = [{ sequence: 1, timestamp: 1, level: "error", event: hostile, message: hostile }];
  app.server.operations.recent = [{ id: 1, kind: hostile, status: "failed", started_at: 1, finished_at: 2, error: hostile, config_revision: 1 }];
  await app.connect();
  assert.equal(app.get("node-title").textContent, hostile);
  assert.ok(app.get("peers").textContent.includes(hostile));
  assert.ok(app.get("logs").textContent.includes(hostile));
  assert.ok(app.get("operations").textContent.includes(hostile));
  assert.ok(app.createdTags.every(tag => !["img", "script", "iframe"].includes(tag)));
});
