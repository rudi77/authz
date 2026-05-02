// Minimal admin SPA. No build step, no framework — just fetch + DOM.
//
// The API key lives in localStorage so a refresh doesn't lose it. All API
// calls flow through one ``api`` helper that injects the X-API-Key header.

const STORAGE_KEY = "authz.adminKey";
let apiKey = localStorage.getItem(STORAGE_KEY) || "";

document.getElementById("api-key").value = apiKey;
document.getElementById("save-key").addEventListener("click", () => {
  apiKey = document.getElementById("api-key").value.trim();
  localStorage.setItem(STORAGE_KEY, apiKey);
  refreshAll();
});

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
  if (apiKey) headers["X-API-Key"] = apiKey;
  const response = await fetch(path, { ...options, headers });
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
