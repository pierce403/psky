"use strict";
const buttons = document.querySelectorAll("button");
async function run(action, method) {
  const notice = document.getElementById("notice");
  const token = document.getElementById("token").value.trim();
  if (!token) { notice.textContent = "Enter the admin token first."; return; }
  buttons.forEach(button => button.disabled = true);
  notice.textContent = "Running...";
  try {
    const response = await fetch(`/admin/${action}`, {
      method, headers: { Authorization: `Bearer ${token}` }, credentials: "omit", cache: "no-store"
    });
    const result = await response.json();
    document.getElementById("result").textContent = JSON.stringify(result, null, 2);
    notice.textContent = response.ok ? "Complete. See the evidence scope in the result." : `Failed: ${result.message || response.status}`;
  } catch (_) {
    notice.textContent = "Could not reach the local node.";
  } finally {
    buttons.forEach(button => button.disabled = false);
  }
}
document.getElementById("status").addEventListener("click", () => run("status", "GET"));
document.getElementById("preflight").addEventListener("click", () => run("preflight", "POST"));
document.getElementById("reconstruct").addEventListener("click", () => run("reconstruct", "POST"));
