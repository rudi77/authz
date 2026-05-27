// Minimal admin SPA. No build step, no framework — just fetch + DOM.
//
// Two auth modes:
//   1. Session cookie (preferred) — set by /oauth/callback after SSO login;
//      the SPA reads the CSRF token from /admin/session and echoes it on
//      every mutating call. Cookies are HttpOnly so JS never touches them.
//   2. X-API-Key (developer mode) — kept in sessionStorage by default;
//      optionally localStorage. Hidden behind a toggle so an SSO-enabled
//      service doesn't tempt operators to paste keys into the browser.

const STORAGE_KEY = "authz.adminKey";
const REMEMBER_KEY = "authz.rememberKey";

const remembered = localStorage.getItem(REMEMBER_KEY) === "true";
let apiKey =
  (remembered ? localStorage.getItem(STORAGE_KEY) : sessionStorage.getItem(STORAGE_KEY)) || "";

let session = null; // { authenticated, kind, csrf_token, ... } from /admin/session

const apiKeyInput = document.getElementById("api-key");
const rememberCheckbox = document.getElementById("remember-key");
const apiKeyPanel = document.getElementById("api-key-panel");
const devToggle = document.getElementById("dev-mode-toggle");
const sessionInfo = document.getElementById("session-info");
const signinBtn = document.getElementById("signin-btn");
const signoutBtn = document.getElementById("signout-btn");
apiKeyInput.value = apiKey;
rememberCheckbox.checked = remembered;

function persistKey(value, remember) {
  if (remember) {
    localStorage.setItem(STORAGE_KEY, value);
    localStorage.setItem(REMEMBER_KEY, "true");
    sessionStorage.removeItem(STORAGE_KEY);
  } else {
    sessionStorage.setItem(STORAGE_KEY, value);
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(REMEMBER_KEY);
  }
}

document.getElementById("save-key").addEventListener("click", () => {
  apiKey = apiKeyInput.value.trim();
  persistKey(apiKey, rememberCheckbox.checked);
  refreshAll();
});

rememberCheckbox.addEventListener("change", () => {
  // Re-persist the current value into the storage the user just chose.
  if (apiKey) persistKey(apiKey, rememberCheckbox.checked);
});

devToggle.addEventListener("click", () => {
  apiKeyPanel.hidden = !apiKeyPanel.hidden;
});

signinBtn.addEventListener("click", () => {
  // The redirect target is the current admin URL so the callback bounces back.
  const ret = encodeURIComponent("/admin/");
  window.location.href = `/oauth/login?return_to=${ret}`;
});

signoutBtn.addEventListener("click", async () => {
  try {
    await fetch("/oauth/logout", { method: "POST", credentials: "include" });
  } catch {}
  session = null;
  await loadSession();
});

async function loadSession() {
  // Try the session probe — works whether we have a cookie, an X-API-Key,
  // or neither. 401 here just means "not logged in", not an error.
  const headers = { Accept: "application/json" };
  if (apiKey) headers["X-API-Key"] = apiKey;
  try {
    const resp = await fetch("/admin/session", {
      headers,
      credentials: "include",
    });
    if (resp.status === 401) {
      session = null;
    } else if (resp.ok) {
      session = await resp.json();
    }
  } catch {
    session = null;
  }
  renderSessionInfo();
}

function renderSessionInfo() {
  if (session && session.kind === "session") {
    sessionInfo.textContent = session.email
      ? `signed in as ${session.email}`
      : `signed in as ${session.subject}`;
    signinBtn.hidden = true;
    signoutBtn.hidden = false;
  } else if (session && session.kind === "apikey") {
    sessionInfo.textContent = "using API key";
    signinBtn.hidden = false;
    signoutBtn.hidden = true;
  } else if (session && session.kind === "token") {
    sessionInfo.textContent = "using bearer token";
    signinBtn.hidden = false;
    signoutBtn.hidden = true;
  } else {
    sessionInfo.textContent = "not signed in";
    signinBtn.hidden = false;
    signoutBtn.hidden = true;
  }
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("tab--active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("panel--active"));
    tab.classList.add("tab--active");
    const target = document.getElementById(`panel-${tab.dataset.tab}`);
    target.classList.add("panel--active");
    if (tab.dataset.tab === "tenants") loadTenants();
    if (tab.dataset.tab === "applications") loadApplications();
    if (tab.dataset.tab === "api-keys") loadApiKeys();
  });
});

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...(options.headers || {}),
  };
  // Session principal: send CSRF token on mutating calls and include cookies.
  // Otherwise fall back to X-API-Key.
  const mutating =
    options.method && options.method.toUpperCase() !== "GET" && options.method.toUpperCase() !== "HEAD";
  if (session && session.kind === "session") {
    if (mutating && session.csrf_token) {
      headers["X-CSRF-Token"] = session.csrf_token;
    }
  } else if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }
  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "include",
  });
  if (response.status === 204) return null;
  if (response.status >= 400) {
    let detail;
    try { detail = await response.json(); } catch { detail = await response.text(); }
    throw new Error(`HTTP ${response.status}: ${JSON.stringify(detail)}`);
  }
  return response.json();
}

// ---------------- Tenants ----------------

async function loadTenants() {
  // The service has no list-tenants endpoint yet; show what we can fetch
  // by slug from local cache and rely on /healthz to confirm readiness.
  const tbody = document.querySelector("#table-tenants tbody");
  tbody.innerHTML = "";
  const cached = JSON.parse(localStorage.getItem("authz.tenants") || "[]");
  for (const t of cached) addTenantRow(t);
}

function addTenantRow(tenant) {
  const tbody = document.querySelector("#table-tenants tbody");
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${tenant.slug}</td>
    <td>${tenant.name}</td>
    <td><span class="pill pill--ok">${tenant.status}</span></td>
    <td><code>${tenant.id}</code></td>`;
  tbody.appendChild(tr);
}

document.getElementById("form-tenant").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const tenant = await api("/v1/tenants", {
      method: "POST",
      body: JSON.stringify({ slug: fd.get("slug"), name: fd.get("name") }),
    });
    const cached = JSON.parse(localStorage.getItem("authz.tenants") || "[]");
    cached.push(tenant);
    localStorage.setItem("authz.tenants", JSON.stringify(cached));
    addTenantRow(tenant);
    e.target.reset();
  } catch (err) { alert(err.message); }
});

// ---------------- Applications ----------------

async function loadApplications() {
  const tbody = document.querySelector("#table-applications tbody");
  tbody.innerHTML = "";
  const cached = JSON.parse(localStorage.getItem("authz.applications") || "[]");
  for (const a of cached) addApplicationRow(a);
}

function addApplicationRow(app) {
  const tbody = document.querySelector("#table-applications tbody");
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${app.slug}</td>
    <td>${app.name}</td>
    <td><span class="pill pill--ok">${app.status}</span></td>
    <td><code>${app.id}</code></td>`;
  tbody.appendChild(tr);
}

document.getElementById("form-application").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const app = await api("/v1/applications", {
      method: "POST",
      body: JSON.stringify({ slug: fd.get("slug"), name: fd.get("name") }),
    });
    const cached = JSON.parse(localStorage.getItem("authz.applications") || "[]");
    cached.push(app);
    localStorage.setItem("authz.applications", JSON.stringify(cached));
    addApplicationRow(app);
    e.target.reset();
  } catch (err) { alert(err.message); }
});

// ---------------- API keys ----------------

async function loadApiKeys() {
  try {
    const keys = await api("/v1/api-keys");
    const tbody = document.querySelector("#table-api-keys tbody");
    tbody.innerHTML = "";
    for (const k of keys) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${k.name}</td>
        <td><code>${k.key_prefix}…</code></td>
        <td>${(k.scopes || []).join(", ")}</td>
        <td><span class="pill pill--${k.status === "active" ? "ok" : "err"}">${k.status}</span></td>
        <td>${k.last_used_at || "—"}</td>
        <td>
          <button data-action="rotate" data-id="${k.id}">Rotate</button>
          <button data-action="revoke" data-id="${k.id}">Revoke</button>
        </td>`;
      tbody.appendChild(tr);
    }
    document.querySelectorAll('#table-api-keys [data-action="rotate"]').forEach((b) =>
      b.addEventListener("click", () => rotateKey(b.dataset.id)),
    );
    document.querySelectorAll('#table-api-keys [data-action="revoke"]').forEach((b) =>
      b.addEventListener("click", () => revokeKey(b.dataset.id)),
    );
  } catch (err) {
    console.warn("api keys load failed", err);
  }
}

async function rotateKey(keyId) {
  try {
    const created = await api(`/v1/api-keys/${keyId}/rotate`, { method: "POST" });
    showSecret("new-key-banner", "new-key-text", created.key);
    await loadApiKeys();
  } catch (err) { alert(err.message); }
}

async function revokeKey(keyId) {
  if (!confirm("Revoke key? Calls using it will fail immediately.")) return;
  try {
    await api(`/v1/api-keys/${keyId}`, { method: "DELETE" });
    await loadApiKeys();
  } catch (err) { alert(err.message); }
}

document.getElementById("form-api-key").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const created = await api("/v1/api-keys", {
      method: "POST",
      body: JSON.stringify({ name: fd.get("name"), scopes: [fd.get("scopes")] }),
    });
    showSecret("new-key-banner", "new-key-text", created.key);
    await loadApiKeys();
    e.target.reset();
  } catch (err) { alert(err.message); }
});

// ---------------- Invitations ----------------

document.getElementById("form-invitation").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const tenant = fd.get("tenant_id");
  const body = { email: fd.get("email") };
  if (fd.get("application_id")) body.application_id = fd.get("application_id");
  if (fd.get("roles")) {
    body.roles = fd.get("roles").split(",").map((s) => s.trim()).filter(Boolean);
  }
  try {
    const created = await api(`/v1/tenants/${tenant}/invitations`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    showSecret("invite-banner", "invite-token-text", created.token);
    e.target.reset();
  } catch (err) { alert(err.message); }
});

// ---------------- Decision probe ----------------

document.getElementById("form-decision").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const subject = { type: fd.get("subject_type") };
  if (fd.get("user_id")) subject.user_id = fd.get("user_id");
  if (fd.get("agent_id")) subject.agent_id = fd.get("agent_id");
  try {
    const result = await api("/v1/authorize", {
      method: "POST",
      body: JSON.stringify({
        tenant_id: fd.get("tenant_id"),
        application_id: fd.get("application_id"),
        subject,
        resource: fd.get("resource"),
        action: fd.get("action"),
      }),
    });
    document.getElementById("decision-output").textContent = JSON.stringify(result, null, 2);
  } catch (err) {
    document.getElementById("decision-output").textContent = err.message;
  }
});

// ---------------- Helpers ----------------

function showSecret(bannerId, codeId, secret) {
  const banner = document.getElementById(bannerId);
  document.getElementById(codeId).textContent = secret;
  banner.classList.remove("banner--hidden");
}

async function refreshAll() {
  await loadSession();
  await Promise.all([
    healthCheck(),
    loadTenants(),
    loadApplications(),
    loadApiKeys(),
  ]);
}

async function healthCheck() {
  const pill = document.getElementById("status-pill");
  const versionLabel = document.getElementById("service-version");
  try {
    const root = await fetch("/").then((r) => r.json());
    versionLabel.textContent = root.version || "?";
    const health = await fetch("/healthz").then((r) => r.json());
    if (health.status === "ok") {
      pill.textContent = "ok";
      pill.className = "pill pill--ok";
    } else {
      pill.textContent = "degraded";
      pill.className = "pill pill--err";
    }
  } catch {
    pill.textContent = "unreachable";
    pill.className = "pill pill--err";
  }
}

refreshAll();
