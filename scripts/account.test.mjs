// Exercises the real account script with a tiny DOM/fetch fixture. These are
// state and secret-handling tests, not browser layout or Farcaster proof tests.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../crates/psky/src/account.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../crates/psky/src/account.html", import.meta.url), "utf8");
const flush = async () => { for (let index = 0; index < 5; index += 1) await new Promise(resolve => setImmediate(resolve)); };
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

class Element {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.childNodes = [];
    this.handlers = new Map();
    this.attributes = new Map();
    this._text = "";
    this.value = "";
    this.type = "";
    this.hidden = false;
    this.disabled = false;
  }
  get textContent() { return this._text + this.childNodes.map(child => child.textContent).join(""); }
  set textContent(value) { this._text = String(value); this.childNodes = []; }
  set innerHTML(_) { throw new Error("Unsafe HTML sink"); }
  set outerHTML(_) { throw new Error("Unsafe HTML sink"); }
  insertAdjacentHTML() { throw new Error("Unsafe HTML sink"); }
  append(...children) { this.childNodes.push(...children); }
  replaceChildren(...children) { this._text = ""; this.childNodes = children; }
  setAttribute(key, value) { this.attributes.set(key, String(value)); }
  getAttribute(key) { return this.attributes.get(key) ?? null; }
  removeAttribute(key) { this.attributes.delete(key); if (key === "href" || key === "src") delete this[key]; }
  addEventListener(type, handler) { if (!this.handlers.has(type)) this.handlers.set(type, []); this.handlers.get(type).push(handler); }
  async emit(type, extra = {}) { for (const handler of this.handlers.get(type) || []) await handler({ preventDefault() {}, target: this, ...extra }); }
  focus() { this.focused = true; }
  select() { this.selected = true; }
}

function fixture() {
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
  const get = id => { assert.ok(elements.has(id), `Script references missing HTML element #${id}`); return elements.get(id); };
  get("new-password").type = "password";
  const timers = new Map();
  let timerId = 0;
  const requests = [];
  const clipboard = [];
  const document = new Element("#document");
  document.getElementById = get;
  document.createElement = tag => new Element(tag);
  const storage = new Proxy({}, { get() { throw new Error("Secret browser storage used"); }, set() { throw new Error("Secret browser storage used"); } });
  Object.defineProperty(document, "cookie", { get() { throw new Error("Cookies used"); }, set() { throw new Error("Cookies used"); } });
  const window = new Element("#window");
  window.location = { origin: "http://localhost:8787" };
  window.confirm = () => true;
  window.localStorage = storage;
  window.sessionStorage = storage;
  const navigator = { clipboard: { async writeText(value) { clipboard.push(value); } } };
  const server = {
    enabled: true,
    passwords: [],
    complete: false,
    grantExpiresAt: undefined,
    intercept: null,
    start: { request_id: "request-1", poll_token: "poll-secret", auth_url: "https://farcaster.xyz/~/siwf?nonce=fixture", expires_at: Math.floor(Date.now() / 1000) + 300 },
    respond({ path, options }) {
      if (path === "/account/status") return { enabled: this.enabled, service_url: "http://localhost:8787", handle: "psky.test", bound: false, storage_ready: false, signer_ready: false };
      if (path === "/account/login" && options.method === "POST") return this.start;
      if (path === "/account/login/request-1") {
        assert.equal(options.headers.Authorization, "Bearer poll-secret");
        return this.complete ? { status: "complete", account_token: "account-secret", fid: 8531, handle: "psky.test", service_url: "http://localhost:8787", expires_at: this.grantExpiresAt } : { status: "pending" };
      }
      if (path === "/account/passwords") {
        assert.equal(options.headers.Authorization, "Bearer account-secret");
        if (options.method === "GET") return { passwords: this.passwords };
        const { name } = JSON.parse(options.body);
        if (options.method === "POST") {
          this.passwords.push({ name, created_at: 1_789_000_000 });
          return { name, password: "generated-secret-once", handle: "psky.test", service_url: "http://localhost:8787" };
        }
        if (options.method === "DELETE") { this.passwords = this.passwords.filter(item => item.name !== name); return {}; }
      }
      throw new Error(`Unexpected request ${options.method} ${path}`);
    },
  };
  const context = vm.createContext({
    document, window, navigator, URL, AbortController, TypeError,
    localStorage: storage, sessionStorage: storage,
    console: new Proxy({}, { get() { throw new Error("Console logging used"); } }),
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(path, options) {
      const request = { path, options };
      requests.push(request);
      const response = await (server.intercept?.(request) ?? server.respond(request));
      const status = response.__status ?? 200;
      const body = response.__status ? response.body : response;
      return { ok: status >= 200 && status < 300, status, async json() { return structuredClone(body); } };
    },
  });
  vm.runInContext(source, context, { filename: "account.js" });
  return {
    get, window, navigator, timers, requests, server, clipboard,
    ready: flush,
    async poll() {
      const entry = [...timers].find(([, timer]) => timer.delay === 3000);
      assert.ok(entry, "A 3-second poll must be scheduled");
      timers.delete(entry[0]);
      await entry[1].callback();
      await flush();
    },
    async connect() { await flush(); await get("login").emit("click"); server.complete = true; await this.poll(); },
    async create(name = "My phone") { get("password-name").value = name; await get("password-form").emit("submit"); },
  };
}

test("status enables configured login without claiming social readiness", async () => {
  const f = fixture();
  await f.ready();
  assert.equal(f.get("login").disabled, false);
  assert.equal(f.get("service-url").textContent, "http://localhost:8787");
  assert.match(html, /Feeds and posting are not ready/);
  assert.match(html, /does not approve a publishing signer/);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].options.cache, "no-store");
  assert.equal(f.requests[0].options.credentials, "omit");
  assert.equal(f.requests[0].options.redirect, "error");
});

test("disabled nodes explain the configuration gate", async () => {
  const f = fixture();
  await f.ready();
  f.server.enabled = false;
  await f.window.emit("pagehide");
  await f.window.emit("pageshow", { persisted: true });
  await f.ready();
  assert.equal(f.get("login").disabled, true);
  assert.match(f.get("notice").textContent, /not enabled/);
});

test("pending sign-in polls with bearer token only and handles trusted QR data", async () => {
  const f = fixture();
  await f.ready();
  f.server.start.qr_data_url = "data:image/svg+xml;base64,PHN2Zy8+";
  await f.get("login").emit("click");
  assert.equal(f.get("login-pending").hidden, false);
  assert.equal(f.get("login-qr").src, f.server.start.qr_data_url);
  assert.equal(f.get("login-qr").hidden, false);
  await f.poll();
  const request = f.requests.at(-1);
  assert.equal(request.path, "/account/login/request-1");
  assert.ok(!request.path.includes("secret"));
  assert.equal(request.options.headers.Authorization, "Bearer poll-secret");
  assert.equal(f.get("password-panel").hidden, true);
});

test("unsafe auth and QR URLs are rejected without adding DOM sinks", async () => {
  for (const [field, value] of [["auth_url", "javascript:alert(1)"], ["auth_url", "https://user:password@example.com"], ["qr_data_url", "https://other.example/track.svg"], ["qr_data_url", "data:text/html;base64,PHN2Zy8+"]]) {
    const f = fixture();
    await f.ready();
    f.server.start[field] = value;
    await f.get("login").emit("click");
    assert.match(f.get("notice").textContent, /invalid/);
    assert.equal(f.get("login-link").href, undefined);
    assert.equal(f.get("login-qr").src, undefined);
    assert.ok(![...f.timers.values()].some(timer => timer.delay === 3000));
  }
});

test("a completed proof unlocks password creation, reveal, copy, and revoke", async () => {
  const f = fixture();
  await f.connect();
  assert.equal(f.get("password-panel").hidden, false);
  assert.equal(f.get("identity-handle").textContent, "psky.test");
  assert.equal(f.get("identity-fid").textContent, "FID 8531");
  await f.create();
  assert.equal(f.get("password-result").hidden, false);
  assert.equal(f.get("new-password").type, "password");
  assert.equal(f.get("new-password").value, "generated-secret-once");
  assert.equal(f.get("result-handle").textContent, "psky.test");
  await f.get("reveal-password").emit("click");
  assert.equal(f.get("new-password").type, "text");
  assert.equal(f.get("reveal-password").getAttribute("aria-pressed"), "true");
  await f.get("copy-password").emit("click");
  assert.deepEqual(f.clipboard, ["generated-secret-once"]);
  const revoke = f.get("password-list").childNodes[0].childNodes[1];
  await revoke.emit("click");
  assert.equal(f.server.passwords.length, 0);
  assert.equal(f.get("new-password").value, "");
  assert.equal(f.get("password-result").hidden, true);
});

test("clipboard denial provides a manual selection fallback", async () => {
  const f = fixture();
  await f.connect();
  await f.create();
  f.navigator.clipboard.writeText = async () => { throw new Error("denied"); };
  await f.get("copy-password").emit("click");
  assert.equal(f.get("new-password").focused, true);
  assert.equal(f.get("new-password").selected, true);
  assert.match(f.get("copy-notice").textContent, /manually/);
});

test("disconnect and pagehide erase every displayed secret and stop polling", async () => {
  for (const event of ["disconnect", "pagehide"]) {
    const f = fixture();
    await f.connect();
    await f.create();
    if (event === "disconnect") await f.get("disconnect").emit("click");
    else await f.window.emit("pagehide");
    assert.equal(f.get("new-password").value, "");
    assert.equal(f.get("password-panel").hidden, true);
    assert.equal(f.get("identity").hidden, true);
    assert.equal(f.get("login-link").href, undefined);
    assert.equal(f.get("login-qr").src, undefined);
    assert.equal(f.timers.size, 0);
    assert.equal(f.server.passwords.length, 1, "Disconnect must not revoke app passwords");
  }
});

test("late password responses cannot reveal secrets after disconnect", async () => {
  const f = fixture();
  await f.connect();
  const pending = deferred();
  f.server.intercept = request => request.options.method === "POST" ? pending.promise : undefined;
  const creation = f.create();
  await flush();
  await f.get("disconnect").emit("click");
  pending.resolve({ name: "My phone", password: "late-secret", handle: "psky.test", service_url: "http://localhost:8787" });
  await creation;
  assert.equal(f.get("new-password").value, "");
  assert.equal(f.get("password-panel").hidden, true);
});

test("late login responses cannot reconnect a canceled sign-in", async () => {
  const f = fixture();
  await f.ready();
  await f.get("login").emit("click");
  const pending = deferred();
  f.server.intercept = request => request.path === "/account/login/request-1" ? pending.promise : undefined;
  const polling = f.poll();
  await flush();
  await f.get("disconnect").emit("click");
  pending.resolve({ status: "complete", account_token: "late-account", fid: 8531 });
  await polling;
  assert.equal(f.get("password-panel").hidden, true);
  assert.equal(f.get("identity").hidden, true);
  assert.equal(f.timers.size, 0);
});

test("a pending start request can be canceled before the relay responds", async () => {
  const f = fixture();
  await f.ready();
  const pending = deferred();
  f.server.intercept = request => request.path === "/account/login" ? pending.promise : undefined;
  const starting = f.get("login").emit("click");
  await flush();
  assert.equal(f.get("disconnect").hidden, false);
  assert.equal(f.get("disconnect").textContent, "Cancel sign-in");
  await f.get("disconnect").emit("click");
  pending.resolve(f.server.start);
  await starting;
  assert.equal(f.get("login-link").href, undefined);
  assert.equal(f.get("login-pending").hidden, true);
  assert.equal(f.timers.size, 0);
});

test("the advertised grant expiry clears local access and one-time passwords", async () => {
  const f = fixture();
  f.server.grantExpiresAt = Math.floor(Date.now() / 1000) + 600;
  await f.connect();
  await f.create();
  const timer = [...f.timers.values()].find(item => item.delay > 500000);
  assert.ok(timer, "Grant expiry must have a local timer");
  await timer.callback();
  assert.equal(f.get("new-password").value, "");
  assert.equal(f.get("password-panel").hidden, true);
  assert.match(f.get("notice").textContent, /Account access expired/);
});

test("expired or revoked account grants clear passwords and require new proof", async () => {
  const f = fixture();
  await f.connect();
  await f.create();
  f.server.intercept = request => request.path === "/account/passwords" ? { __status: 401, body: { error: "Unauthorized", message: "Expired" } } : undefined;
  await f.get("refresh-passwords").emit("click");
  await flush();
  assert.equal(f.get("new-password").value, "");
  assert.equal(f.get("password-panel").hidden, true);
  assert.match(f.get("notice").textContent, /Sign in with Farcaster again/);
});

test("older password lists cannot overwrite a newer revocation result", async () => {
  const f = fixture();
  await f.connect();
  await f.create();
  const pending = deferred();
  let interceptNext = true;
  f.server.intercept = request => {
    if (request.path === "/account/passwords" && request.options.method === "GET" && interceptNext) { interceptNext = false; return pending.promise; }
  };
  const oldRefresh = f.get("refresh-passwords").emit("click");
  await flush();
  await f.get("password-list").childNodes[0].childNodes[1].emit("click");
  pending.resolve({ passwords: [{ name: "old stale entry", created_at: 1_789_000_000 }] });
  await oldRefresh;
  await flush();
  assert.match(f.get("password-list").textContent, /No app passwords/);
});

test("password labels are text, and revocation requires confirmation", async () => {
  const f = fixture();
  await f.connect();
  await f.create("<img src=x onerror=alert(1)>");
  assert.match(f.get("password-list").textContent, /<img src=x onerror=alert\(1\)>/);
  f.window.confirm = () => false;
  const before = f.requests.length;
  await f.get("password-list").childNodes[0].childNodes[1].emit("click");
  assert.equal(f.requests.length, before);
  assert.equal(f.server.passwords.length, 1);
});

test("invalid and expired challenges do not start polling", async () => {
  const f = fixture();
  await f.ready();
  f.server.start.expires_at = Math.floor(Date.now() / 1000) - 1;
  await f.get("login").emit("click");
  assert.match(f.get("notice").textContent, /expired/);
  assert.ok(![...f.timers.values()].some(timer => timer.delay === 3000));
});

test("invalid password names are rejected before sending a credential request", async () => {
  const f = fixture();
  await f.connect();
  const before = f.requests.length;
  for (const name of ["", "x".repeat(65), "My phone\nSecond line", "電話"]) {
    await f.create(name);
    assert.equal(f.requests.length, before);
    assert.match(f.get("password-notice").textContent, /1 to 64/);
  }
});
