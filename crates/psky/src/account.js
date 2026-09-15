/* Account grants and generated passwords live only in this closure and the DOM.
 * Every request belongs to a generation so late responses cannot reconnect a
 * disconnected tab or reveal credentials after account access was cleared. */
(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const stale = Symbol("stale request");
  const controllers = new Set();
  let generation = 0;
  let enabled = false;
  let grant = "";
  let challenge = null;
  let pollTimer = null;
  let grantTimer = null;
  let busy = false;
  let starting = false;
  let revealedName = "";
  let listVersion = 0;

  function notice(message, kind = "", id = "notice") {
    $(id).textContent = message;
    $(id).className = `notice ${kind}`;
  }

  function clearPassword() {
    $("new-password").value = "";
    $("new-password").type = "password";
    $("reveal-password").textContent = "Show";
    $("reveal-password").setAttribute("aria-pressed", "false");
    $("password-result").hidden = true;
    $("copy-notice").textContent = "";
    $("result-service-url").textContent = "";
    $("result-handle").textContent = "";
    revealedName = "";
  }

  function renderActions() {
    $("login").hidden = Boolean(grant || challenge);
    $("login").disabled = !enabled || busy;
    $("disconnect").hidden = !(grant || challenge || starting);
    $("disconnect").textContent = challenge || starting ? "Cancel sign-in" : "Disconnect";
    $("password-panel").hidden = !grant;
    $("create-password").disabled = !grant || busy;
    $("password-name").disabled = !grant || busy;
    $("refresh-passwords").disabled = !grant || busy;
  }

  function clearAccess() {
    generation += 1;
    listVersion += 1;
    for (const controller of controllers) controller.abort();
    controllers.clear();
    clearTimeout(pollTimer);
    clearTimeout(grantTimer);
    pollTimer = null;
    grantTimer = null;
    grant = "";
    challenge = null;
    busy = false;
    starting = false;
    clearPassword();
    $("password-name").value = "";
    $("password-list").replaceChildren();
    $("identity").hidden = true;
    $("identity-handle").textContent = "";
    $("identity-fid").textContent = "";
    $("login-pending").hidden = true;
    $("login-link").removeAttribute("href");
    $("login-qr").removeAttribute("src");
    $("login-qr").hidden = true;
    notice("", "", "password-notice");
    renderActions();
  }

  async function request(path, { method = "GET", token = "", body } = {}, epoch = generation) {
    const controller = new AbortController();
    controllers.add(controller);
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      const headers = { Accept: "application/json" };
      if (token) headers.Authorization = `Bearer ${token}`;
      if (body !== undefined) headers["Content-Type"] = "application/json";
      const response = await fetch(path, {
        method, headers, body: body === undefined ? undefined : JSON.stringify(body),
        cache: "no-store", credentials: "omit", redirect: "error", signal: controller.signal,
      });
      if (epoch !== generation) throw stale;
      let data;
      try { data = await response.json(); }
      catch { throw new Error("The node returned an unreadable response."); }
      if (epoch !== generation) throw stale;
      if (!response.ok) {
        const error = new Error(typeof data.message === "string" ? data.message.slice(0, 300) : "The node could not complete this request.");
        error.status = response.status;
        throw error;
      }
      return data;
    } catch (error) {
      if (epoch !== generation) throw stale;
      if (error.name === "AbortError" || error instanceof TypeError) throw new Error("Cannot reach the node. Check the connection and retry.");
      throw error;
    } finally {
      clearTimeout(timeout);
      controllers.delete(controller);
    }
  }

  function safeAuthUrl(value) {
    const url = new URL(value);
    if (!["https:", "farcaster:"].includes(url.protocol) || url.username || url.password) throw new Error("The node returned an invalid Farcaster sign-in link.");
    return url.href;
  }

  function safeQrUrl(value) {
    if (typeof value !== "string" || value.length > 500000 || !/^data:image\/svg\+xml;base64,[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error("The node returned an invalid QR code image.");
    return value;
  }

  async function loadStatus() {
    const epoch = generation;
    busy = true;
    enabled = false;
    $("retry-status").hidden = true;
    renderActions();
    notice("Checking this node...");
    try {
      const data = await request("/account/status", {}, epoch);
      enabled = data.enabled === true;
      $("service-url").textContent = data.service_url || "Not configured";
      $("node-handle").textContent = data.handle || "Not configured";
      notice(enabled ? "Ready to verify your Farcaster identity." : "Account sign-in is not enabled. Configure it in the node's management console.");
    } catch (error) {
      if (error === stale) return;
      notice(error.message, "error");
      $("retry-status").hidden = false;
    } finally {
      if (epoch === generation) { busy = false; renderActions(); }
    }
  }

  async function startLogin() {
    if (!enabled || busy || grant || challenge) return;
    clearAccess();
    const epoch = generation;
    busy = true;
    starting = true;
    renderActions();
    notice("Creating a Farcaster sign-in request...");
    try {
      const data = await request("/account/login", { method: "POST", body: {} }, epoch);
      if (typeof data.request_id !== "string" || !data.request_id || typeof data.poll_token !== "string" || !data.poll_token || !Number.isFinite(data.expires_at) || data.expires_at <= Date.now() / 1000) throw new Error("The node returned an invalid or expired sign-in request.");
      const authUrl = safeAuthUrl(data.auth_url);
      const qrUrl = data.qr_data_url ? safeQrUrl(data.qr_data_url) : "";
      challenge = { id: data.request_id, token: data.poll_token, expires: data.expires_at };
      $("login-link").href = authUrl;
      if (qrUrl) { $("login-qr").src = qrUrl; $("login-qr").hidden = false; }
      $("login-pending").hidden = false;
      notice("Open Farcaster and approve sign-in for this node.");
      schedulePoll(epoch);
    } catch (error) {
      if (error !== stale) notice(error.message, "error");
    } finally {
      if (epoch === generation) { busy = false; starting = false; renderActions(); }
    }
  }

  function schedulePoll(epoch) {
    if (!challenge || epoch !== generation) return;
    const remaining = Math.max(0, Math.ceil(challenge.expires - Date.now() / 1000));
    $("login-expiry").textContent = `Waiting for approval. Expires in ${Math.ceil(remaining / 60)} min.`;
    pollTimer = setTimeout(() => pollLogin(epoch), 3000);
  }

  async function pollLogin(epoch) {
    if (!challenge || epoch !== generation) return;
    if (Date.now() / 1000 >= challenge.expires) {
      clearAccess();
      notice("This sign-in request expired. Start again to get a new one.", "error");
      return;
    }
    try {
      const data = await request(`/account/login/${encodeURIComponent(challenge.id)}`, { token: challenge.token }, epoch);
      if (data.status === "pending") { schedulePoll(epoch); return; }
      if (data.status !== "complete" || typeof data.account_token !== "string" || !data.account_token) throw new Error("The node returned an invalid sign-in result.");
      grant = data.account_token;
      challenge = null;
      if (Number.isFinite(data.expires_at)) {
        const remaining = data.expires_at * 1000 - Date.now();
        if (remaining <= 0) {
          clearAccess();
          notice("Account access expired. Sign in with Farcaster again.", "error");
          return;
        }
        grantTimer = setTimeout(() => {
          if (epoch !== generation) return;
          clearAccess();
          notice("Account access expired. Sign in with Farcaster again.", "error");
        }, Math.min(remaining, 2147483647));
      }
      $("login-pending").hidden = true;
      $("login-link").removeAttribute("href");
      $("login-qr").removeAttribute("src");
      $("identity").hidden = false;
      $("identity-handle").textContent = data.handle || "Farcaster account";
      $("identity-fid").textContent = `FID ${data.fid ?? "verified"}`;
      if (data.service_url) $("service-url").textContent = data.service_url;
      if (data.handle) $("node-handle").textContent = data.handle;
      notice("Identity verified. Create or manage your app passwords below.", "success");
      renderActions();
      await loadPasswords(epoch);
    } catch (error) {
      if (error === stale) return;
      if (error.status && error.status < 500 && error.status !== 429) {
        clearAccess();
        notice(error.message, "error");
      } else {
        notice(`${error.message} Retrying while this request is valid.`, "error");
        schedulePoll(epoch);
      }
    }
  }

  function passwordError(error) {
    if (error === stale) return;
    if (error.status === 401 || error.status === 403) {
      clearAccess();
      notice("Account access expired or was revoked. Sign in with Farcaster again.", "error");
    } else notice(error.message, "error", "password-notice");
  }

  function renderPasswords(passwords) {
    const rows = [];
    for (const password of passwords) {
      if (typeof password.name !== "string") continue;
      const row = document.createElement("li");
      const detail = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = password.name;
      const date = document.createElement("small");
      const created = new Date(password.created_at * 1000);
      date.textContent = Number.isNaN(created.getTime()) ? "Creation time unavailable" : `Created ${created.toLocaleString()}`;
      detail.append(name, date);
      if (password.revoked) {
        const state = document.createElement("span");
        state.className = "subtle";
        state.textContent = "Revoked";
        row.append(detail, state);
      } else {
        const revoke = document.createElement("button");
        revoke.type = "button";
        revoke.className = "secondary";
        revoke.textContent = "Revoke";
        revoke.setAttribute("aria-label", `Revoke password for ${password.name}`);
        revoke.addEventListener("click", () => revokePassword(password.name, revoke));
        row.append(detail, revoke);
      }
      rows.push(row);
    }
    if (!rows.length) {
      const row = document.createElement("li");
      row.className = "empty-state";
      row.textContent = "No app passwords yet.";
      rows.push(row);
    }
    $("password-list").replaceChildren(...rows);
  }

  async function loadPasswords(epoch = generation) {
    if (!grant) return;
    const version = ++listVersion;
    try {
      const data = await request("/account/passwords", { token: grant }, epoch);
      if (version !== listVersion) return;
      if (!Array.isArray(data.passwords)) throw new Error("The node returned an invalid password list.");
      renderPasswords(data.passwords);
    } catch (error) { if (version === listVersion) passwordError(error); }
  }

  async function createPassword(event) {
    event.preventDefault();
    if (!grant || busy) return;
    const name = $("password-name").value.trim();
    if (!/^[\x20-\x7e]{1,64}$/.test(name)) { notice("Use 1 to 64 basic Latin letters, numbers, spaces, or punctuation.", "error", "password-notice"); return; }
    const epoch = generation;
    busy = true;
    clearPassword();
    renderActions();
    notice("Creating password...", "", "password-notice");
    try {
      const data = await request("/account/passwords", { method: "POST", token: grant, body: { name } }, epoch);
      if (typeof data.password !== "string" || !data.password || typeof data.handle !== "string" || typeof data.service_url !== "string") throw new Error("The node returned an invalid password response. Revoke this entry and try again.");
      $("new-password").value = data.password;
      revealedName = data.name || name;
      $("result-handle").textContent = data.handle;
      $("result-service-url").textContent = data.service_url;
      $("password-result").hidden = false;
      $("password-name").value = "";
      notice("Password created. Save it before leaving this tab.", "success", "password-notice");
      await loadPasswords(epoch);
    } catch (error) { passwordError(error); }
    finally { if (epoch === generation) { busy = false; renderActions(); } }
  }

  async function revokePassword(name, button) {
    if (!grant || busy || !window.confirm(`Revoke the password for ${name}? Apps using it will need to sign in again.`)) return;
    const epoch = generation;
    busy = true;
    button.disabled = true;
    renderActions();
    try {
      await request("/account/passwords", { method: "DELETE", token: grant, body: { name } }, epoch);
      if (revealedName === name) clearPassword();
      notice(`Password for ${name} revoked.`, "success", "password-notice");
      await loadPasswords(epoch);
    } catch (error) { passwordError(error); }
    finally { if (epoch === generation) { busy = false; button.disabled = false; renderActions(); } }
  }

  $("login").addEventListener("click", startLogin);
  $("retry-status").addEventListener("click", loadStatus);
  $("disconnect").addEventListener("click", () => { clearAccess(); notice("Disconnected. App passwords remain active until revoked."); });
  $("password-form").addEventListener("submit", createPassword);
  $("refresh-passwords").addEventListener("click", () => loadPasswords());
  $("dismiss-password").addEventListener("click", clearPassword);
  $("reveal-password").addEventListener("click", () => {
    const show = $("new-password").type === "password";
    $("new-password").type = show ? "text" : "password";
    $("reveal-password").textContent = show ? "Hide" : "Show";
    $("reveal-password").setAttribute("aria-pressed", String(show));
  });
  $("copy-password").addEventListener("click", async () => {
    if (!$("new-password").value) return;
    const epoch = generation;
    const name = revealedName;
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText($("new-password").value);
      if (epoch === generation && name === revealedName) $("copy-notice").textContent = "Copied. Clear your clipboard after saving it securely.";
    } catch {
      if (epoch !== generation || name !== revealedName) return;
      $("new-password").focus();
      $("new-password").select();
      $("copy-notice").textContent = "Clipboard unavailable. Use Show, then select and copy the password manually.";
    }
  });
  window.addEventListener("pagehide", clearAccess);
  window.addEventListener("pageshow", event => { if (event.persisted) loadStatus(); });
  loadStatus();
})();
