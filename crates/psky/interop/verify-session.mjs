/**
 * Exercise the same password-session implementation used by the stock client.
 * Input is one JSON object on stdin: {service, identifier, password, did}.
 * Credentials never enter command arguments, environment variables, or logs.
 * This test creates and deletes sessions but does not publish or change content.
 * Success proves the credential handshake, not AppView or federation readiness.
 */
import assert from "node:assert/strict";
import { PasswordSession } from "@atproto/lex-password-session";

let stage = "input";
let activeSession;

async function readInput() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 16 * 1024) throw new Error("Input limit");
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  let input;
  try {
    input = JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
  assert(input && typeof input === "object" && !Array.isArray(input));
  assert.deepEqual(Object.keys(input).sort(), ["did", "identifier", "password", "service"]);
  for (const field of ["did", "identifier", "password", "service"]) {
    assert.equal(typeof input[field], "string");
    assert(input[field].length > 0 && input[field].length <= 2048);
  }
  const url = new URL(input.service);
  assert(!url.username && !url.password && !url.search && !url.hash && url.pathname === "/");
  assert(url.protocol === "https:" || (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)));
  input.service = url.origin;
  return input;
}

async function safeFetch(url, init = {}) {
  const timeout = AbortSignal.timeout(15_000);
  const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
  return fetch(url, { ...init, signal, redirect: "error" });
}

async function readJson(response) {
  assert(response.headers.get("content-type")?.startsWith("application/json"));
  const reader = response.body?.getReader();
  assert(reader);
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      assert(size <= 32 * 1024);
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } finally {
    await reader.cancel().catch(() => {});
  }
}

async function raw(service, method, nsid, token) {
  return safeFetch(`${service}/xrpc/${nsid}`, {
    method,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

async function assertRejected(response) {
  assert([400, 401, 403].includes(response.status));
  const body = await readJson(response);
  assert(["InvalidToken", "ExpiredToken", "AuthenticationRequired"].includes(body.error));
}

try {
  const input = await readInput();
  stage = "describeServer";
  const description = await raw(input.service, "GET", "com.atproto.server.describeServer");
  assert(description.ok);
  const server = await readJson(description);
  assert.equal(typeof server.did, "string");
  assert(server.did.startsWith("did:"));
  assert(Array.isArray(server.availableUserDomains));

  const options = {
    ...input,
    fetch: safeFetch,
    // LoginForm sends an empty factor when email 2FA is not in use.
    authFactorToken: "",
    allowTakendown: true,
  };
  delete options.did;
  stage = "login";
  activeSession = await PasswordSession.login(options);
  assert.equal(activeSession.did, input.did);
  assert.equal(typeof activeSession.handle, "string");
  assert.equal(activeSession.session.active, true);

  stage = "getSession";
  const current = await activeSession.fetchHandler("/xrpc/com.atproto.server.getSession", { method: "GET" });
  assert(current.ok);
  assert.equal((await readJson(current)).did, input.did);

  stage = "refresh";
  const oldRefresh = activeSession.session.refreshJwt;
  const oldAccess = activeSession.session.accessJwt;
  await activeSession.refresh();
  assert.notEqual(activeSession.session.refreshJwt, oldRefresh);
  assert.notEqual(activeSession.session.accessJwt, oldAccess);
  assert.equal(activeSession.did, input.did);

  stage = "refresh replay rejection";
  await assertRejected(await raw(input.service, "POST", "com.atproto.server.refreshSession", oldRefresh));

  stage = "logout";
  const access = activeSession.session.accessJwt;
  const refresh = activeSession.session.refreshJwt;
  await activeSession.logout();
  assert.equal(activeSession.destroyed, true);
  activeSession = undefined;
  await assertRejected(await raw(input.service, "GET", "com.atproto.server.getSession", access));
  await assertRejected(await raw(input.service, "POST", "com.atproto.server.refreshSession", refresh));

  stage = "password reuse after logout";
  activeSession = await PasswordSession.login(options);
  assert.equal(activeSession.did, input.did);
  await activeSession.logout();
  assert.equal(activeSession.destroyed, true);
  activeSession = undefined;
  input.password = "";
  options.password = "";
  process.stdout.write("Session compatibility passed: describe, login, session, refresh, replay rejection, logout, password reuse.\n");
} catch {
  // Never print the thrown SDK error: it may retain request/credential data.
  process.stderr.write(`Session compatibility failed during ${stage}.\n`);
  process.exitCode = 1;
} finally {
  if (activeSession && !activeSession.destroyed) {
    try {
      await activeSession.logout();
    } catch {
      process.stderr.write("Session cleanup failed; revoke the dedicated test password.\n");
      process.exitCode = 1;
    }
  }
}
