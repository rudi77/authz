// Admin SPA for the authz service. No build step, no framework — fetch + DOM.
//
// Two auth modes:
//   1. Session cookie (preferred) — set by /oauth/callback after SSO login;
//      the SPA reads the CSRF token from /admin/session and echoes it on
//      every mutating call. Cookies are HttpOnly so JS never touches them.
//   2. X-API-Key (developer mode) — kept in sessionStorage by default;
//      optionally localStorage. Hidden behind a toggle so an SSO-enabled
//      service doesn't tempt operators to paste keys into the browser.
//
// Every server-provided string is rendered through `el()` / textContent —
// never interpolated into innerHTML — so stored names can't inject markup.

const STORAGE_KEY = "authz.adminKey";
const REMEMBER_KEY = "authz.rememberKey";
const CTX_KEY = "authz.adminContext";

const $ = (sel) => document.querySelector(sel);

function storageGet(store, key) {
  try { return store.getItem(key); } catch { return null; }
}
function storageSet(store, key, value) {
  try { value === null ? store.removeItem(key) : store.setItem(key, value); } catch {}
}

const remembered = storageGet(localStorage, REMEMBER_KEY) === "true";
let apiKey =
  (remembered ? storageGet(localStorage, STORAGE_KEY) : storageGet(sessionStorage, STORAGE_KEY)) || "";
let session = null; // { authenticated, kind, csrf_token, ... } from /admin/session
let oidcEnabled = false; // advertised by GET / when admin SSO is configured

const state = {
  tenants: [],
  applications: [],
  users: [],
  roles: [],
  permissions: [],
  agents: [],
  tenantId: "",
  appId: "",
  editingRole: null,
};

try {
  const saved = JSON.parse(storageGet(localStorage, CTX_KEY) || "{}");
  state.tenantId = saved.tenantId || "";
  state.appId = saved.appId || "";
} catch {}

// ---------------------------------------------------------------- helpers

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(node.dataset, v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const pill = (text, ok) =>
  el("span", { class: `pill pill--${ok === undefined ? "unknown" : ok ? "ok" : "err"}` }, text);
const code = (text) => el("code", {}, text ?? "—");
const fmtDate = (v) => (v ? new Date(v).toLocaleString() : "—");
const splitList = (v) => (v || "").split(",").map((s) => s.trim()).filter(Boolean);

function fillTable(selector, rows, emptyText = "Nothing here yet.") {
  const table = $(selector);
  const tbody = table.querySelector("tbody");
  const cols = table.querySelectorAll("thead th").length;
  tbody.replaceChildren();
  if (!rows.length) {
    tbody.append(el("tr", {}, el("td", { colspan: cols, class: "empty" }, emptyText)));
    return;
  }
  for (const cells of rows) tbody.append(el("tr", {}, cells.map((c) => el("td", {}, c))));
}

let toastTimer;
function toast(message, kind = "ok") {
  const t = $("#toast");
  t.textContent = message;
  t.className = `toast toast--${kind}`;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, kind === "err" ? 8000 : 3000);
}

function showSecret(bannerId, codeId, secret) {
  document.getElementById(codeId).textContent = secret;
  document.getElementById(bannerId).classList.remove("banner--hidden");
}

class ApiError extends Error {
  constructor(status, detail) {
    super(`HTTP ${status}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", Accept: "application/json" };
  const method = (options.method || "GET").toUpperCase();
  const mutating = method !== "GET" && method !== "HEAD";
  if (session && session.kind === "session") {
    if (mutating && session.csrf_token) headers["X-CSRF-Token"] = session.csrf_token;
  } else if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }
  const response = await fetch(path, {
    method,
    headers,
    credentials: "include",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (response.status === 204) return null;
  if (response.status >= 400) {
    let detail;
    try { detail = await response.json(); } catch { detail = await response.text(); }
    throw new ApiError(response.status, detail?.detail ?? detail);
  }
  return response.json();
}

// Wrap a form submit / click handler: report errors as a toast.
const guarded = (fn) => async (event) => {
  if (event && event.preventDefault) event.preventDefault();
  try { await fn(event); } catch (err) { toast(err.message, "err"); }
};

function requireCtx(which) {
  if ((which === "tenant" || which === "both") && !state.tenantId) {
    throw new Error("Select a tenant at the top first.");
  }
  if ((which === "app" || which === "both") && !state.appId) {
    throw new Error("Select an application at the top first.");
  }
}

const tenantById = (id) => state.tenants.find((t) => t.id === id);
const appById = (id) => state.applications.find((a) => a.id === id);
const userLabel = (id) => {
  const u = state.users.find((x) => x.id === id);
  return u ? u.email || u.display_name || u.id : id;
};

// ---------------------------------------------------------------- session

const apiKeyInput = $("#api-key");
const rememberCheckbox = $("#remember-key");
apiKeyInput.value = apiKey;
rememberCheckbox.checked = remembered;

function persistKey(value, remember) {
  if (remember) {
    storageSet(localStorage, STORAGE_KEY, value);
    storageSet(localStorage, REMEMBER_KEY, "true");
    storageSet(sessionStorage, STORAGE_KEY, null);
  } else {
    storageSet(sessionStorage, STORAGE_KEY, value);
    storageSet(localStorage, STORAGE_KEY, null);
    storageSet(localStorage, REMEMBER_KEY, null);
  }
}

$("#save-key").addEventListener("click", () => {
  apiKey = apiKeyInput.value.trim();
  persistKey(apiKey, rememberCheckbox.checked);
  boot();
});
rememberCheckbox.addEventListener("change", () => {
  if (apiKey) persistKey(apiKey, rememberCheckbox.checked);
});
$("#dev-mode-toggle").addEventListener("click", () => {
  $("#api-key-panel").hidden = !$("#api-key-panel").hidden;
});
$("#signin-btn").addEventListener("click", () => {
  window.location.href = `/oauth/login?return_to=${encodeURIComponent("/admin/")}`;
});
$("#signout-btn").addEventListener("click", async () => {
  try { await fetch("/oauth/logout", { method: "POST", credentials: "include" }); } catch {}
  session = null;
  await loadSession();
});

async function loadSession() {
  const headers = { Accept: "application/json" };
  if (apiKey) headers["X-API-Key"] = apiKey;
  try {
    const resp = await fetch("/admin/session", { headers, credentials: "include" });
    session = resp.ok ? await resp.json() : null;
  } catch {
    session = null;
  }
  const info = $("#session-info");
  const signedIn = session && session.kind === "session";
  if (signedIn) info.textContent = `signed in as ${session.email || session.subject}`;
  else if (session && session.kind === "token") info.textContent = "using bearer token";
  else if (apiKey) info.textContent = "using API key";
  else info.textContent = "no credentials (dev mode only)";
  $("#signin-btn").hidden = signedIn || !oidcEnabled;
  $("#signout-btn").hidden = !signedIn;
}

// ---------------------------------------------------------------- navigation

const loaders = {
  dashboard: loadDashboard,
  tenants: loadTenantsPanel,
  applications: loadApplicationsPanel,
  permissions: loadPermissions,
  roles: loadRoles,
  users: () => loadUsers(),
  memberships: loadMemberships,
  agents: loadAgents,
  invitations: loadInvitations,
  features: loadFeatures,
  probe: loadProbe,
  audit: () => loadAudit(),
  "api-keys": loadApiKeys,
  oauth: loadOAuth,
};
let currentPanel = "dashboard";

function showPanel(name) {
  currentPanel = name;
  document.querySelectorAll(".nav-item").forEach((b) =>
    b.classList.toggle("nav-item--active", b.dataset.panel === name),
  );
  document.querySelectorAll(".panel").forEach((p) =>
    p.classList.toggle("panel--active", p.id === `panel-${name}`),
  );
  if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
  refreshCurrent();
}

async function refreshCurrent() {
  try { await loaders[currentPanel]?.(); } catch (err) { toast(err.message, "err"); }
}

document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => showPanel(b.dataset.panel)),
);

// ---------------------------------------------------------------- context

function renderContextLabels() {
  const t = tenantById(state.tenantId);
  const a = appById(state.appId);
  document.querySelectorAll("[data-ctx]").forEach((node) => {
    const parts = [];
    if (node.dataset.ctx !== "app") parts.push(t ? `tenant ${t.slug}` : "no tenant selected");
    if (node.dataset.ctx !== "tenant") parts.push(a ? `app ${a.slug}` : "no application selected");
    node.textContent = `· ${parts.join(" · ")}`;
  });
}

function renderContextSelectors() {
  const fill = (select, items, selected) => {
    select.replaceChildren(
      el("option", { value: "" }, "— select —"),
      ...items.map((i) =>
        el("option", { value: i.id, selected: i.id === selected }, `${i.slug} — ${i.name}`),
      ),
    );
  };
  if (!tenantById(state.tenantId)) state.tenantId = state.tenants[0]?.id || "";
  if (!appById(state.appId)) state.appId = state.applications[0]?.id || "";
  fill($("#ctx-tenant"), state.tenants, state.tenantId);
  fill($("#ctx-app"), state.applications, state.appId);
  renderContextLabels();
}

function saveContext() {
  storageSet(localStorage, CTX_KEY, JSON.stringify({ tenantId: state.tenantId, appId: state.appId }));
  renderContextLabels();
  state.editingRole = null;
  refreshCurrent();
}
$("#ctx-tenant").addEventListener("change", (e) => { state.tenantId = e.target.value; saveContext(); });
$("#ctx-app").addEventListener("change", (e) => { state.appId = e.target.value; saveContext(); });

async function loadCatalog() {
  [state.tenants, state.applications] = await Promise.all([
    api("/v1/tenants?page_size=500"),
    api("/v1/applications?page_size=500"),
  ]);
  renderContextSelectors();
}

// ---------------------------------------------------------------- dashboard

async function loadDashboard() {
  const cards = $("#dash-cards");
  const card = (label, value, panel) =>
    el("button", { class: "card", type: "button", onclick: () => showPanel(panel) },
      el("span", { class: "card-value" }, value), el("span", { class: "card-label" }, label));
  const [users, keys, denies] = await Promise.all([
    api("/v1/users?page_size=500").catch(() => []),
    api("/v1/api-keys").catch(() => []),
    api("/v1/audit?decision=deny&page_size=500").catch(() => []),
  ]);
  cards.replaceChildren(
    card("Tenants", state.tenants.length, "tenants"),
    card("Applications", state.applications.length, "applications"),
    card("Users", users.length, "users"),
    card("Active API keys", keys.filter((k) => k.status === "active").length, "api-keys"),
    card("Recent denies", denies.length, "audit"),
  );
}

// ---------------------------------------------------------------- tenants

function statusToggle(kind, item, reload) {
  const active = item.status === "active";
  return el("button", {
    type: "button",
    class: active ? "btn-danger btn-small" : "btn-secondary btn-small",
    onclick: guarded(async () => {
      if (active && !confirm(`Suspend ${kind} "${item.slug}"? Every decision for it will be denied.`)) return;
      await api(`/v1/${kind === "tenant" ? "tenants" : "applications"}/${item.id}`, {
        method: "PATCH",
        body: { status: active ? "suspended" : "active" },
      });
      toast(`${kind} ${item.slug} ${active ? "suspended" : "activated"}`);
      await loadCatalog();
      await reload();
    }),
  }, active ? "Suspend" : "Activate");
}

async function loadTenantsPanel() {
  await loadCatalog();
  fillTable("#table-tenants", state.tenants.map((t) => [
    t.slug, t.name, pill(t.status, t.status === "active"), code(t.id),
    statusToggle("tenant", t, loadTenantsPanel),
  ]));
  if (state.tenantId) {
    const mappings = await api(`/v1/tenants/${state.tenantId}/mappings`);
    fillTable("#table-mappings", mappings.map((m) => [m.provider, m.issuer, code(m.external_tenant_id)]),
      "No IdP mappings for this tenant.");
  } else {
    fillTable("#table-mappings", [], "Select a tenant.");
  }
}

$("#form-tenant").addEventListener("submit", guarded(async (e) => {
  const fd = new FormData(e.target);
  const tenant = await api("/v1/tenants", {
    method: "POST", body: { slug: fd.get("slug"), name: fd.get("name") },
  });
  state.tenantId = tenant.id;
  e.target.reset();
  toast(`Tenant ${tenant.slug} created`);
  saveContext();
}));

$("#form-mapping").addEventListener("submit", guarded(async (e) => {
  requireCtx("tenant");
  const fd = new FormData(e.target);
  await api(`/v1/tenants/${state.tenantId}/mappings`, {
    method: "POST",
    body: {
      provider: fd.get("provider"),
      issuer: fd.get("issuer"),
      external_tenant_id: fd.get("external_tenant_id"),
    },
  });
  e.target.reset();
  toast("Mapping added");
  await loadTenantsPanel();
}));

// ---------------------------------------------------------------- applications

async function loadApplicationsPanel() {
  await loadCatalog();
  fillTable("#table-applications", state.applications.map((a) => [
    a.slug, a.name, pill(a.status, a.status === "active"), code(a.id),
    statusToggle("application", a, loadApplicationsPanel),
  ]));
}

$("#form-application").addEventListener("submit", guarded(async (e) => {
  const fd = new FormData(e.target);
  const app = await api("/v1/applications", {
    method: "POST", body: { slug: fd.get("slug"), name: fd.get("name") },
  });
  state.appId = app.id;
  e.target.reset();
  toast(`Application ${app.slug} created`);
  await loadCatalog();
  saveContext();
}));

// ---------------------------------------------------------------- permissions

async function fetchPermissions() {
  state.permissions = state.appId ? await api(`/v1/applications/${state.appId}/permissions`) : [];
  return state.permissions;
}

async function loadPermissions() {
  if (!state.appId) return fillTable("#table-permissions", [], "Select an application.");
  const perms = await fetchPermissions();
  fillTable("#table-permissions",
    perms.map((p) => [code(p.name), p.resource, p.action, p.description || ""]),
    "No permissions defined for this application.");
}

$("#form-permission").addEventListener("submit", guarded(async (e) => {
  requireCtx("app");
  const fd = new FormData(e.target);
  const name = fd.get("name").trim();
  if (!name.includes(".")) throw new Error("Permission names look like resource.action");
  await api(`/v1/applications/${state.appId}/permissions`, {
    method: "POST", body: { name, description: fd.get("description") || null },
  });
  e.target.reset();
  toast(`Permission ${name} added`);
  await loadPermissions();
}));

// ---------------------------------------------------------------- roles

async function fetchRoles() {
  state.roles = state.appId ? await api(`/v1/applications/${state.appId}/roles`) : [];
  $("#role-names").replaceChildren(...state.roles.map((r) => el("option", { value: r.name })));
  return state.roles;
}

async function loadRoles() {
  if (!state.appId) {
    $("#role-editor").hidden = true;
    return fillTable("#table-roles", [], "Select an application.");
  }
  const roles = await fetchRoles();
  fillTable("#table-roles", roles.map((r) => [
    el("strong", {}, r.name), r.scope, r.description || "",
    el("button", { type: "button", class: "btn-secondary btn-small", onclick: guarded(() => openRoleEditor(r)) },
      "Permissions"),
  ]), "No roles defined for this application.");
  if (state.editingRole) await openRoleEditor(state.editingRole);
  else $("#role-editor").hidden = true;
}

async function openRoleEditor(role) {
  state.editingRole = role;
  const [perms, current] = await Promise.all([
    fetchPermissions(),
    api(`/v1/roles/${role.id}/permissions`),
  ]);
  const granted = new Set(current.permissions);
  $("#role-editor-name").textContent = role.name;
  const list = $("#role-editor-list");
  list.replaceChildren(
    ...(perms.length
      ? perms.map((p) => el("label", {},
          el("input", { type: "checkbox", value: p.name, checked: granted.has(p.name) }),
          code(p.name)))
      : [el("p", { class: "hint" }, "Define permissions for this application first.")]),
  );
  $("#role-editor").hidden = false;
}

$("#role-editor-save").addEventListener("click", guarded(async () => {
  const role = state.editingRole;
  if (!role) return;
  const names = [...document.querySelectorAll("#role-editor-list input:checked")].map((i) => i.value);
  await api(`/v1/roles/${role.id}/permissions`, { method: "PUT", body: { permissions: names } });
  toast(`Saved ${names.length} permission(s) on ${role.name}`);
}));

$("#form-role").addEventListener("submit", guarded(async (e) => {
  requireCtx("app");
  const fd = new FormData(e.target);
  const scope = fd.get("scope");
  const body = { name: fd.get("name"), scope, description: fd.get("description") || null };
  if (scope === "tenant") {
    requireCtx("tenant");
    body.tenant_id = state.tenantId;
  }
  const role = await api(`/v1/applications/${state.appId}/roles`, { method: "POST", body });
  e.target.reset();
  toast(`Role ${role.name} created`);
  state.editingRole = role;
  await loadRoles();
}));

// ---------------------------------------------------------------- users

async function fetchUsers(q = "") {
  const qs = q ? `&q=${encodeURIComponent(q)}` : "";
  state.users = await api(`/v1/users?page_size=500${qs}`);
  return state.users;
}

function fillUserSelect(select, includeEmpty = false) {
  const current = select.value;
  select.replaceChildren(
    ...(includeEmpty ? [el("option", { value: "" }, "— user —")] : []),
    ...state.users.map((u) =>
      el("option", { value: u.id, selected: u.id === current }, u.email || u.display_name || u.id)),
  );
  if (!state.users.length && !includeEmpty) {
    select.append(el("option", { value: "" }, "no users yet — add one under Users"));
  }
}

async function loadUsers(q = "") {
  const users = await fetchUsers(q);
  fillTable("#table-users", users.map((u) => [
    u.email || "—", u.display_name || "—",
    el("div", {}, u.identities.map((i) => el("div", { class: "small" }, `${i.provider}: ${i.subject}`))),
    pill(u.status, u.status === "active"), code(u.id),
  ]), q ? "No users match." : "No users yet.");
}

$("#form-user").addEventListener("submit", guarded(async (e) => {
  const fd = new FormData(e.target);
  const body = Object.fromEntries([...fd.entries()].filter(([, v]) => v !== ""));
  const user = await api("/v1/users", { method: "POST", body });
  e.target.reset();
  toast(`User ${user.email || user.id} ready`);
  await loadUsers();
}));

$("#form-user-search").addEventListener("submit", guarded(async (e) => {
  await loadUsers(new FormData(e.target).get("q"));
}));

// ---------------------------------------------------------------- memberships

async function loadMemberships() {
  await Promise.all([fetchUsers(), fetchRoles()]);
  fillUserSelect($("#membership-user"));
  if (!state.tenantId) return fillTable("#table-memberships", [], "Select a tenant.");
  const rows = await api(`/v1/tenants/${state.tenantId}/memberships?page_size=500`);
  fillTable("#table-memberships", rows.map((m) => {
    const rolesInput = el("input", { value: m.roles.join(", "), list: "role-names", class: "inline-input" });
    const active = m.status === "active";
    return [
      userLabel(m.user_id),
      m.application_id ? appById(m.application_id)?.slug || m.application_id : "(all)",
      rolesInput,
      pill(m.status, active),
      el("span", { class: "actions" },
        el("button", {
          type: "button", class: "btn-small",
          onclick: guarded(async () => {
            await api(`/v1/memberships/${m.id}`, { method: "PATCH", body: { roles: splitList(rolesInput.value) } });
            toast("Roles updated");
            await loadMemberships();
          }),
        }, "Save roles"),
        el("button", {
          type: "button", class: active ? "btn-danger btn-small" : "btn-secondary btn-small",
          onclick: guarded(async () => {
            await api(`/v1/memberships/${m.id}`, {
              method: "PATCH", body: { status: active ? "suspended" : "active" },
            });
            await loadMemberships();
          }),
        }, active ? "Suspend" : "Activate")),
    ];
  }), "No memberships in this tenant.");
}

$("#form-membership").addEventListener("submit", guarded(async (e) => {
  requireCtx("both");
  const fd = new FormData(e.target);
  if (!fd.get("user_id")) throw new Error("Pick a user (add one under Users first).");
  await api(`/v1/tenants/${state.tenantId}/memberships`, {
    method: "POST",
    body: { user_id: fd.get("user_id"), application_id: state.appId, roles: splitList(fd.get("roles")) },
  });
  e.target.reset();
  toast("Membership granted");
  await loadMemberships();
}));

// ---------------------------------------------------------------- agents

async function fetchAgents() {
  state.agents = state.tenantId && state.appId
    ? await api(`/v1/tenants/${state.tenantId}/applications/${state.appId}/agents`)
    : [];
  return state.agents;
}

async function loadAgents() {
  if (!state.tenantId || !state.appId) return fillTable("#table-agents", [], "Select a tenant and an application.");
  const [agents] = await Promise.all([fetchAgents(), fetchRoles()]);
  const roleSets = await Promise.all(agents.map((a) => api(`/v1/agents/${a.id}/roles`)));
  fillTable("#table-agents", agents.map((a, i) => {
    const rolesInput = el("input", { value: roleSets[i].roles.join(", "), list: "role-names", class: "inline-input" });
    return [
      el("strong", {}, a.name), a.role || "—", rolesInput, pill(a.status, a.status === "active"), code(a.id),
      el("button", {
        type: "button", class: "btn-small",
        onclick: guarded(async () => {
          await api(`/v1/agents/${a.id}/roles`, { method: "PUT", body: { roles: splitList(rolesInput.value) } });
          toast(`Roles of ${a.name} updated`);
          await loadAgents();
        }),
      }, "Save roles"),
    ];
  }), "No agents registered.");
}

$("#form-agent").addEventListener("submit", guarded(async (e) => {
  requireCtx("both");
  const fd = new FormData(e.target);
  const agent = await api(`/v1/tenants/${state.tenantId}/applications/${state.appId}/agents`, {
    method: "POST", body: { name: fd.get("name"), role: fd.get("role") || "" },
  });
  e.target.reset();
  toast(`Agent ${agent.name} registered — assign roles in the table`);
  await loadAgents();
}));

// ---------------------------------------------------------------- invitations

async function loadInvitations() {
  await fetchRoles();
  if (!state.tenantId) return fillTable("#table-invitations", [], "Select a tenant.");
  const rows = await api(`/v1/tenants/${state.tenantId}/invitations`);
  fillTable("#table-invitations", rows.map((i) => [
    i.email, i.roles.join(", ") || "—", pill(i.status, i.status === "pending" ? undefined : i.status === "accepted"),
    fmtDate(i.expires_at),
    i.status === "pending"
      ? el("button", {
          type: "button", class: "btn-danger btn-small",
          onclick: guarded(async () => {
            if (!confirm(`Revoke invitation for ${i.email}?`)) return;
            await api(`/v1/invitations/${i.id}`, { method: "DELETE" });
            await loadInvitations();
          }),
        }, "Revoke")
      : "",
  ]), "No invitations.");
}

$("#form-invitation").addEventListener("submit", guarded(async (e) => {
  requireCtx("tenant");
  const fd = new FormData(e.target);
  const body = {
    email: fd.get("email"),
    roles: splitList(fd.get("roles")),
    ttl_days: Number(fd.get("ttl_days") || 7),
  };
  if (state.appId) body.application_id = state.appId;
  const created = await api(`/v1/tenants/${state.tenantId}/invitations`, { method: "POST", body });
  showSecret("invite-banner", "invite-token-text", created.token);
  e.target.reset();
  await loadInvitations();
}));

// ---------------------------------------------------------------- feature mask & flags

async function loadFeatures() {
  if (!state.tenantId || !state.appId) {
    $("#mask-list").replaceChildren(el("p", { class: "hint" }, "Select a tenant and an application."));
    return fillTable("#table-flags", [], "Select a tenant and an application.");
  }
  const [perms, mask, tenantFlags, appFlags] = await Promise.all([
    fetchPermissions(),
    api(`/v1/tenants/${state.tenantId}/applications/${state.appId}/permission-mask`),
    api(`/v1/tenants/${state.tenantId}/feature-flags`),
    api(`/v1/tenants/${state.tenantId}/feature-flags?application_id=${state.appId}`),
  ]);
  const masked = new Set(mask.permissions);
  $("#mask-list").replaceChildren(
    ...(perms.length
      ? perms.map((p) => el("label", {},
          el("input", { type: "checkbox", value: p.name, checked: masked.has(p.name) }), code(p.name)))
      : [el("p", { class: "hint" }, "This application has no permissions yet.")]),
  );
  const flagRows = (scope, flags) =>
    Object.entries(flags).map(([k, v]) => [scope, code(k), code(JSON.stringify(v))]);
  fillTable("#table-flags", [
    ...flagRows("tenant", tenantFlags.flags),
    ...flagRows(appById(state.appId)?.slug || "application", appFlags.flags),
  ], "No feature flags set.");
}

$("#mask-save").addEventListener("click", guarded(async () => {
  requireCtx("both");
  const names = [...document.querySelectorAll("#mask-list input:checked")].map((i) => i.value);
  await api(`/v1/tenants/${state.tenantId}/applications/${state.appId}/permission-mask`, {
    method: "PUT", body: { permissions: names },
  });
  toast(names.length ? `Mask saved (${names.length} permission(s) enabled)` : "Mask cleared — all permissions allowed");
}));

$("#form-flag").addEventListener("submit", guarded(async (e) => {
  requireCtx("tenant");
  const fd = new FormData(e.target);
  let value;
  try { value = JSON.parse(fd.get("value")); } catch { value = fd.get("value"); }
  const body = { key: fd.get("key"), value };
  if (fd.get("app_scoped")) {
    requireCtx("app");
    body.application_id = state.appId;
  }
  await api(`/v1/tenants/${state.tenantId}/feature-flags`, { method: "PUT", body });
  e.target.reset();
  e.target.querySelector("[name=app_scoped]").checked = true;
  toast("Flag saved");
  await loadFeatures();
}));

// ---------------------------------------------------------------- decision probe

async function loadProbe() {
  await Promise.all([fetchUsers(), fetchAgents()]);
  fillUserSelect($("#probe-user"), true);
  const agentSelect = $("#probe-agent");
  const current = agentSelect.value;
  agentSelect.replaceChildren(
    el("option", { value: "" }, "— agent —"),
    ...state.agents.map((a) => el("option", { value: a.id, selected: a.id === current }, a.name)),
  );
}

$("#form-decision").addEventListener("submit", guarded(async (e) => {
  requireCtx("both");
  const fd = new FormData(e.target);
  const mode = e.submitter?.value || "authorize";
  const subject = { type: fd.get("subject_type") };
  if (fd.get("user_id")) subject.user_id = fd.get("user_id");
  if (fd.get("agent_id")) subject.agent_id = fd.get("agent_id");
  const base = { tenant_id: state.tenantId, application_id: state.appId, subject };
  const verdict = $("#decision-verdict");
  const out = $("#decision-output");
  try {
    if (mode === "effective") {
      const result = await api("/v1/effective-permissions", { method: "POST", body: base });
      verdict.replaceChildren(el("p", {}, `${result.permissions.length} effective permission(s)`));
      out.textContent = JSON.stringify(result, null, 2);
    } else {
      if (!fd.get("resource") || !fd.get("action")) throw new Error("Resource and action are required.");
      const result = await api("/v1/authorize", {
        method: "POST", body: { ...base, resource: fd.get("resource"), action: fd.get("action") },
      });
      verdict.replaceChildren(el("p", { class: "verdict" },
        pill(result.allowed ? "ALLOW" : "DENY", result.allowed), " ", code(result.required_permission),
        " — ", result.reason));
      out.textContent = JSON.stringify(result, null, 2);
    }
  } catch (err) {
    verdict.replaceChildren();
    out.textContent = err.message;
  }
}));

// ---------------------------------------------------------------- audit

async function loadAudit() {
  const form = $("#form-audit");
  const fd = new FormData(form);
  const params = new URLSearchParams({ page_size: "200" });
  if (fd.get("decision")) params.set("decision", fd.get("decision"));
  if (fd.get("only_tenant") && state.tenantId) params.set("tenant_id", state.tenantId);
  const rows = await api(`/v1/audit?${params}`);
  fillTable("#table-audit", rows.map((r) => [
    fmtDate(r.created_at),
    pill(r.decision, r.decision === "allow"),
    code(`${r.resource}.${r.action}`),
    r.reason || "—",
    r.agent_id ? `agent ${r.agent_id.slice(0, 8)}… for ${userLabel(r.user_id)}` : userLabel(r.user_id) || "—",
  ]), "No audit entries.");
}
$("#form-audit").addEventListener("submit", guarded(loadAudit));

// ---------------------------------------------------------------- API keys

async function loadApiKeys() {
  const keys = await api("/v1/api-keys");
  fillTable("#table-api-keys", keys.map((k) => [
    k.name, code(`${k.key_prefix}…`), (k.scopes || []).join(", "),
    pill(k.status, k.status === "active"), fmtDate(k.last_used_at),
    k.status === "active"
      ? el("span", { class: "actions" },
          el("button", {
            type: "button", class: "btn-secondary btn-small",
            onclick: guarded(async () => {
              const created = await api(`/v1/api-keys/${k.id}/rotate`, { method: "POST" });
              showSecret("new-key-banner", "new-key-text", created.key);
              await loadApiKeys();
            }),
          }, "Rotate"),
          el("button", {
            type: "button", class: "btn-danger btn-small",
            onclick: guarded(async () => {
              if (!confirm("Revoke key? Calls using it will fail immediately.")) return;
              await api(`/v1/api-keys/${k.id}`, { method: "DELETE" });
              await loadApiKeys();
            }),
          }, "Revoke"))
      : "",
  ]), "No stored API keys (bootstrap keys from AUTHZ_API_KEYS are not listed).");
}

$("#form-api-key").addEventListener("submit", guarded(async (e) => {
  const fd = new FormData(e.target);
  const body = { name: fd.get("name"), scopes: [fd.get("scopes")] };
  if (fd.get("scopes") === "tenant") {
    requireCtx("tenant");
    body.scopes = [`tenant:${state.tenantId}`];
    body.tenant_id = state.tenantId;
  }
  const created = await api("/v1/api-keys", { method: "POST", body });
  showSecret("new-key-banner", "new-key-text", created.key);
  e.target.reset();
  await loadApiKeys();
}));

// ---------------------------------------------------------------- OAuth

async function loadOAuth() {
  let clients;
  try {
    clients = await api("/v1/oauth/clients");
  } catch (err) {
    if (err.status === 404) {
      $("#oauth-disabled").hidden = false;
      $("#oauth-enabled").hidden = true;
      return;
    }
    throw err;
  }
  $("#oauth-disabled").hidden = true;
  $("#oauth-enabled").hidden = false;
  fillTable("#table-oauth-clients", clients.map((c) => [
    c.name, code(c.client_id), c.scopes.join(", "), pill(c.status, c.status === "active"),
    fmtDate(c.last_used_at),
    c.status === "active"
      ? el("span", { class: "actions" },
          el("button", {
            type: "button", class: "btn-secondary btn-small",
            onclick: guarded(async () => {
              const created = await api(`/v1/oauth/clients/${c.client_id}/rotate`, { method: "POST" });
              showSecret("oauth-secret-banner", "oauth-secret-text", created.client_secret);
              await loadOAuth();
            }),
          }, "Rotate secret"),
          el("button", {
            type: "button", class: "btn-danger btn-small",
            onclick: guarded(async () => {
              if (!confirm(`Revoke client ${c.name}?`)) return;
              await api(`/v1/oauth/clients/${c.client_id}`, { method: "DELETE" });
              await loadOAuth();
            }),
          }, "Revoke"))
      : "",
  ]), "No OAuth clients.");
  const keys = await api("/v1/oauth/signing-keys");
  fillTable("#table-signing-keys", keys.map((k) => [code(k.kid), k.alg, pill(k.status, k.status === "active"), fmtDate(k.created_at)]),
    "No signing keys yet.");
}

$("#form-oauth-client").addEventListener("submit", guarded(async (e) => {
  const fd = new FormData(e.target);
  const created = await api("/v1/oauth/clients", {
    method: "POST", body: { name: fd.get("name"), scopes: [fd.get("scopes")] },
  });
  showSecret("oauth-secret-banner", "oauth-secret-text", `${created.client_id} / ${created.client_secret}`);
  e.target.reset();
  await loadOAuth();
}));

$("#rotate-signing-key").addEventListener("click", guarded(async () => {
  if (!confirm("Rotate the token signing key? The old key stays published for verification.")) return;
  await api("/v1/oauth/signing-keys/rotate", { method: "POST" });
  toast("Signing key rotated");
  await loadOAuth();
}));

// ---------------------------------------------------------------- boot

async function healthCheck() {
  const statusPill = $("#status-pill");
  try {
    const root = await fetch("/").then((r) => r.json());
    $("#service-version").textContent = root.version || "?";
    oidcEnabled = (root.endpoints || []).includes("/oauth/login");
    const health = await fetch("/healthz").then((r) => r.json());
    const ok = health.status === "ok";
    statusPill.textContent = ok ? "healthy" : "degraded";
    statusPill.className = `pill pill--${ok ? "ok" : "err"}`;
  } catch {
    statusPill.textContent = "unreachable";
    statusPill.className = "pill pill--err";
  }
}

async function boot() {
  await healthCheck();
  await loadSession();
  try {
    await loadCatalog();
    if (apiKey) $("#api-key-panel").hidden = true;
  } catch (err) {
    if (err.status === 401 || err.status === 403) {
      $("#api-key-panel").hidden = false;
      toast("Not authorized — sign in with SSO or paste an admin API key.", "err");
      return;
    }
    toast(err.message, "err");
  }
  const fromHash = location.hash.replace("#", "");
  showPanel(loaders[fromHash] ? fromHash : currentPanel);
}

boot();
