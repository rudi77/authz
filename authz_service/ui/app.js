// AuthZ admin console. No build step, no framework — fetch + DOM.
//
// Two auth modes:
//   1. Session cookie (preferred) — set by /oauth/callback after SSO login;
//      the SPA reads the CSRF token from /admin/session and echoes it on
//      every mutating call. Cookies are HttpOnly so JS never touches them.
//   2. X-API-Key — entered on the sign-in screen, kept in sessionStorage
//      by default (optionally localStorage).
//
// Every server-provided string is rendered through `el()` / textContent —
// never interpolated into innerHTML — so stored names can't inject markup.

const STORAGE_KEY = "authz.adminKey";
const REMEMBER_KEY = "authz.rememberKey";
const CTX_KEY = "authz.adminContext";

const root = document.getElementById("root");

// ===================================================================== storage

function storageGet(store, key) {
  try { return store.getItem(key); } catch { return null; }
}
function storageSet(store, key, value) {
  try { value === null ? store.removeItem(key) : store.setItem(key, value); } catch {}
}
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
function forgetKey() {
  storageSet(sessionStorage, STORAGE_KEY, null);
  storageSet(localStorage, STORAGE_KEY, null);
  storageSet(localStorage, REMEMBER_KEY, null);
}

const remembered = storageGet(localStorage, REMEMBER_KEY) === "true";
let apiKey =
  (remembered ? storageGet(localStorage, STORAGE_KEY) : storageGet(sessionStorage, STORAGE_KEY)) || "";
let session = null; // { kind, csrf_token, email, subject } from /admin/session
let oidcEnabled = false;
let serviceVersion = "?";
let healthy = null;

const state = {
  tenants: [],
  applications: [],
  users: [],
  roles: [],
  permissions: [],
  agents: [],
  tenantId: "",
  appId: "",
};
try {
  const saved = JSON.parse(storageGet(localStorage, CTX_KEY) || "{}");
  state.tenantId = saved.tenantId || "";
  state.appId = saved.appId || "";
} catch {}

// ===================================================================== DOM helpers

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k === "value") node.value = v;
    else if (k === "checked") node.checked = Boolean(v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false || c === "") continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const ICONS = {
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
  dashboard: '<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>',
  building: '<rect width="16" height="20" x="4" y="2" rx="2"/><path d="M9 22v-4h6v4"/><path d="M8 6h.01M16 6h.01M12 6h.01M12 10h.01M12 14h.01M16 10h.01M16 14h.01M8 10h.01M8 14h.01"/>',
  box: '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
  permission: '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5"/>',
  layers: '<path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/><path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65"/><path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  userCheck: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/>',
  bot: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2M20 14h2M15 13v2M9 13v2"/>',
  mail: '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
  ticket: '<path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z"/><path d="M13 5v2M13 17v2M13 11v2"/>',
  toggle: '<rect width="20" height="12" x="2" y="6" rx="6"/><circle cx="16" cy="12" r="2"/>',
  scale: '<path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="M7 21h10M12 3v18M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  lock: '<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  plus: '<path d="M5 12h14M12 5v14"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  copy: '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
  chevrons: '<path d="m7 15 5 5 5-5M7 9l5-5 5 5"/>',
  refresh: '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
  trash: '<path d="M3 6h18M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>',
  pencil: '<path d="M21.17 6.81a1 1 0 0 0-3.99-3.99L3.84 16.17a2 2 0 0 0-.5.83l-1.32 4.35a.5.5 0 0 0 .62.62l4.35-1.32a2 2 0 0 0 .83-.5z"/>',
  pause: '<rect x="14" y="4" width="4" height="16" rx="1"/><rect x="6" y="4" width="4" height="16" rx="1"/>',
  play: '<polygon points="6 3 20 12 6 21 6 3"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  rotate: '<path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/>',
  power: '<path d="M12 2v10M18.4 6.6a9 9 0 1 1-12.77.04"/>',
  book: '<path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  flag: '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/>',
  arrow: '<path d="M5 12h14M12 5l7 7-7 7"/>',
  sso: '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3"/>',
};

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = ICONS[name] || ""; // static, trusted markup only
  return svg;
}

function btn(label, { variant = "", iconName, onClick, small, block, type = "button", title, disabled } = {}) {
  const cls = ["btn", variant && `btn-${variant}`, small && "btn-sm", block && "btn-block", !label && "btn-icon"]
    .filter(Boolean).join(" ");
  return el("button", { type, class: cls, onclick: onClick, title: title || undefined, "aria-label": title || undefined, disabled },
    iconName && icon(iconName), label);
}
const iconBtn = (iconName, title, onClick, danger = false) =>
  el("button", {
    type: "button", class: `btn btn-ghost btn-sm btn-icon${danger ? " danger" : ""}`,
    title, "aria-label": title, onclick: onClick,
  }, icon(iconName));

function badge(text, tone = "", { dot = false, mono = false } = {}) {
  return el("span", { class: `badge ${tone}${mono ? " mono" : ""}` }, dot && el("span", { class: "bdot" }), text);
}
function statusBadge(status) {
  const tone = { active: "green", accepted: "green", pending: "amber", suspended: "red",
    revoked: "red", expired: "", retiring: "amber", disabled: "red" }[status] ?? "";
  return badge(status, tone, { dot: true });
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el("textarea", {}, text);
    document.body.append(ta);
    ta.select();
    try { document.execCommand("copy"); } catch {}
    ta.remove();
  }
  toast("Copied to clipboard");
}

function idChip(id, len = 8) {
  if (!id) return el("span", { class: "muted" }, "—");
  return el("span", { class: "id-chip", title: id },
    id.length > len ? `${id.slice(0, len)}…` : id,
    el("button", { type: "button", title: "Copy", "aria-label": "Copy id", onclick: () => copyText(id) }, icon("copy")));
}

function hue(seed) {
  let h = 0;
  for (const ch of String(seed)) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return h;
}
function avatar(seed, label, square = false) {
  const initials = String(label || "?").replace(/[^A-Za-z0-9 ._@-]/g, "").split(/[ ._@-]+/)
    .filter(Boolean).slice(0, 2).map((s) => s[0].toUpperCase()).join("") || "?";
  return el("span", { class: `avatar${square ? " square" : ""}`, style: `background:hsl(${hue(seed)} 55% 48%)` }, initials);
}

function relTime(value) {
  if (!value) return "—";
  const d = new Date(value);
  const diff = (d.getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  const fmt = (n, unit) => {
    const v = Math.round(n);
    return diff >= 0 ? `in ${v} ${unit}${v === 1 ? "" : "s"}` : `${v} ${unit}${v === 1 ? "" : "s"} ago`;
  };
  if (abs < 60) return diff >= 0 ? "in a moment" : "just now";
  if (abs < 3600) return fmt(abs / 60, "minute");
  if (abs < 86400) return fmt(abs / 3600, "hour");
  if (abs < 86400 * 30) return fmt(abs / 86400, "day");
  return d.toLocaleDateString();
}
const timeCell = (value) => el("span", { title: value ? new Date(value).toLocaleString() : "" }, relTime(value));

function pageHeader(title, subtitle, ...actions) {
  return el("div", { class: "page-head" },
    el("div", {}, el("h1", {}, title), subtitle && el("p", { class: "page-sub" }, subtitle)),
    actions.length ? el("div", { class: "page-actions" }, actions) : null);
}

function card({ title, subtitle, actions = [], body, foot, toolbar } = {}) {
  return el("section", { class: "card" },
    title && el("div", { class: "card-head" },
      el("div", {}, el("h2", {}, title), subtitle && el("p", {}, subtitle)),
      el("div", { class: "spacer" }), actions),
    toolbar,
    body,
    foot && el("div", { class: "card-foot" }, foot));
}

function emptyState(iconName, title, text, action) {
  return el("div", { class: "empty" },
    el("div", { class: "empty-icon" }, icon(iconName)),
    el("h3", {}, title),
    text && el("p", {}, text),
    action);
}

function table(columns, rows, empty) {
  if (!rows.length) return empty;
  return el("div", { class: "table-wrap" }, el("table", { class: "table" },
    el("thead", {}, el("tr", {}, columns.map((c) => el("th", { class: c.shrink ? "shrink" : "" }, c.label)))),
    el("tbody", {}, rows.map((row) => el("tr", {},
      columns.map((c) => el("td", { class: c.shrink ? "shrink" : "" }, c.render(row))))))));
}

function nameCell(seed, main, sub, square = false) {
  return el("div", { class: "cell-stack" }, avatar(seed, main, square),
    el("div", {}, el("div", { class: "cell-main" }, main), sub && el("div", { class: "cell-sub" }, sub)));
}

// ===================================================================== toasts

function toast(message, kind = "ok") {
  const node = el("div", { class: `toast ${kind}`, role: "status" },
    el("span", { class: "ticon" }, icon(kind === "ok" ? "check" : "x")),
    el("div", {}, message));
  document.getElementById("toasts").append(node);
  setTimeout(() => node.remove(), kind === "err" ? 7000 : 3200);
}

// ===================================================================== forms & modals

function input(name, { placeholder, required, type = "text", value, mono, min, max, autocomplete = "off", list } = {}) {
  return el("input", { class: `input${mono ? " mono" : ""}`, name, placeholder, required, type, value, min, max, autocomplete, list });
}
function selectEl(name, options, value, { required } = {}) {
  return el("select", { class: "select", name, required },
    options.map((o) => el("option", { value: o.value, selected: o.value === value }, o.label)));
}
function field(label, control, help) {
  return el("div", { class: "field" }, el("label", {}, label), control, help && el("div", { class: "help" }, help));
}

/** Checkbox list. items: [{ value, title, desc, checked }]. Grouped by text before the last dot when `group`. */
function checklist(name, items, { group = false, emptyText = "Nothing to choose from." } = {}) {
  const box = el("div", { class: "checklist" });
  if (!items.length) {
    box.append(el("div", { class: "checklist-empty" }, emptyText));
    return box;
  }
  let lastGroup = null;
  for (const it of items) {
    if (group) {
      const g = it.value.includes(".") ? it.value.slice(0, it.value.lastIndexOf(".")) : "other";
      if (g !== lastGroup) {
        box.append(el("div", { class: "group-title" }, g));
        lastGroup = g;
      }
    }
    box.append(el("label", { class: "check-row" },
      el("input", { type: "checkbox", name, value: it.value, checked: it.checked }),
      el("div", {}, el("div", { class: "title" }, it.title ?? it.value), it.desc && el("div", { class: "desc" }, it.desc))));
  }
  return box;
}

function modal({ title, description, body, submitLabel = "Save", danger = false, wide = false,
  iconName, onSubmit, cancelLabel = "Cancel", hideCancel = false }) {
  return new Promise((resolve) => {
    const err = el("div", { class: "modal-error", hidden: true });
    const submit = el("button", { type: "submit", class: `btn ${danger ? "btn-danger" : "btn-primary"}` }, submitLabel);
    const cancel = hideCancel ? null : btn(cancelLabel, { onClick: () => close(null) });
    const form = el("form", { novalidate: false },
      el("div", { class: "modal-head" },
        iconName && el("div", { class: `modal-icon ${danger ? "danger" : "ok"}` }, icon(iconName)),
        el("div", {}, el("h2", {}, title), description && el("p", {}, description)),
        el("button", { type: "button", class: "btn btn-ghost btn-sm btn-icon modal-close", "aria-label": "Close", onclick: () => close(null) }, icon("x"))),
      body && el("div", { class: "modal-body" }, body),
      el("div", { class: "modal-foot" }, err, cancel, submit));
    const dlg = el("dialog", { class: `modal${wide ? " wide" : ""}` }, form);
    let closed = false;
    function close(v) {
      if (closed) return;
      closed = true;
      dlg.close();
      dlg.remove();
      resolve(v);
    }
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.hidden = true;
      submit.disabled = true;
      try {
        const result = onSubmit ? await onSubmit(new FormData(form), form) : true;
        close(result === undefined ? true : result);
      } catch (x) {
        err.replaceChildren(icon("alert"), el("span", {}, x.message));
        err.hidden = false;
      } finally {
        submit.disabled = false;
      }
    });
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(null); });
    document.body.append(dlg);
    dlg.showModal();
    const first = form.querySelector(".modal-body input:not([type=checkbox]), .modal-body select, .modal-body textarea");
    (first || submit).focus();
  });
}

async function confirmAction(title, text, { confirmLabel = "Confirm", danger = true } = {}) {
  return Boolean(await modal({ title, description: text, submitLabel: confirmLabel, danger, iconName: danger ? "alert" : "info" }));
}

function showSecret({ title, description, secret, note }) {
  return modal({
    title, description, iconName: "check", submitLabel: "Done", hideCancel: true,
    body: el("div", {},
      el("div", { class: "callout" }, icon("alert"),
        el("div", {}, note || "This value is shown only once. Copy it now and store it securely.")),
      el("div", { class: "secret" }, el("code", {}, secret),
        btn("", { variant: "ghost", small: true, iconName: "copy", title: "Copy", onClick: () => copyText(secret) }))),
  });
}

// ===================================================================== API

class ApiError extends Error {
  constructor(status, detail) {
    super(humanError(status, detail));
    this.status = status;
    this.detail = detail;
  }
}

function humanError(status, detail) {
  if (detail && typeof detail === "object") {
    const code = detail.error || detail.reason;
    const extra = detail.permissions ? `: ${detail.permissions.join(", ")}` : detail.hint ? ` — ${detail.hint}` : "";
    if (code) return `${String(code).replaceAll("_", " ")}${extra}`;
    if (Array.isArray(detail)) return detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
    return JSON.stringify(detail);
  }
  if (status === 401) return "Not signed in";
  if (status === 403) return "Not allowed";
  return detail ? String(detail) : `Request failed (${status})`;
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", Accept: "application/json", ...(options.headers || {}) };
  const method = (options.method || "GET").toUpperCase();
  const mutating = method !== "GET" && method !== "HEAD";
  if (session && session.kind === "session") {
    if (mutating && session.csrf_token) headers["X-CSRF-Token"] = session.csrf_token;
  } else if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }
  const response = await fetch(path, {
    method, headers, credentials: "include",
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

const splitList = (v) => (v || "").split(",").map((s) => s.trim()).filter(Boolean);
const tenantById = (id) => state.tenants.find((t) => t.id === id);
const appById = (id) => state.applications.find((a) => a.id === id);
const userById = (id) => state.users.find((u) => u.id === id);
const userLabel = (id) => {
  const u = userById(id);
  return u ? u.display_name || u.email || u.id : id ? `${id.slice(0, 8)}…` : "—";
};
const agentLabel = (id) => state.agents.find((a) => a.id === id)?.name || (id ? `${id.slice(0, 8)}…` : "—");

async function fetchCatalog() {
  [state.tenants, state.applications] = await Promise.all([
    api("/v1/tenants?page_size=500"),
    api("/v1/applications?page_size=500"),
  ]);
  if (!tenantById(state.tenantId)) state.tenantId = state.tenants[0]?.id || "";
  if (!appById(state.appId)) state.appId = state.applications[0]?.id || "";
}
async function fetchUsers(q = "") {
  state.users = await api(`/v1/users?page_size=500${q ? `&q=${encodeURIComponent(q)}` : ""}`);
  return state.users;
}
async function fetchPermissions(appId = state.appId) {
  const perms = appId ? await api(`/v1/applications/${appId}/permissions`) : [];
  if (appId === state.appId) state.permissions = perms;
  return perms;
}
async function fetchRoles(appId = state.appId) {
  const roles = appId ? await api(`/v1/applications/${appId}/roles`) : [];
  if (appId === state.appId) state.roles = roles;
  return roles;
}
async function fetchAgents() {
  state.agents = state.tenantId && state.appId
    ? await api(`/v1/tenants/${state.tenantId}/applications/${state.appId}/agents`)
    : [];
  return state.agents;
}
const permDesc = (name) => state.permissions.find((p) => p.name === name)?.description;

// ===================================================================== session / boot

async function healthCheck() {
  try {
    const info = await fetch("/").then((r) => r.json());
    serviceVersion = info.version || "?";
    oidcEnabled = (info.endpoints || []).includes("/oauth/login");
    const health = await fetch("/healthz").then((r) => r.json());
    healthy = health.status === "ok";
  } catch {
    healthy = false;
  }
}

async function loadSession() {
  const headers = { Accept: "application/json" };
  if (apiKey) headers["X-API-Key"] = apiKey;
  try {
    const resp = await fetch("/admin/session", { headers, credentials: "include" });
    session = resp.ok ? await resp.json() : null;
  } catch {
    session = null;
  }
}

async function boot() {
  root.replaceChildren(el("div", { class: "loading" }, el("div", { class: "spinner" })));
  await healthCheck();
  await loadSession();
  try {
    await fetchCatalog();
  } catch (err) {
    if (err.status === 401 || err.status === 403) return renderLogin(apiKey ? "That key was rejected or lacks the admin scope." : "");
    renderLogin(err.message);
    return;
  }
  renderShell();
}

function renderLogin(error = "") {
  const keyInput = input("key", { placeholder: "Paste an admin API key", type: "password", mono: true, required: true });
  const remember = el("input", { type: "checkbox", name: "remember", checked: remembered });
  const form = el("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      apiKey = keyInput.value.trim();
      persistKey(apiKey, remember.checked);
      await boot();
    },
  },
  field("API key", keyInput),
  el("label", { class: "check", style: "margin-bottom:18px" }, remember, "Remember on this device"),
  btn("Sign in", { variant: "primary", type: "submit", iconName: "arrow", block: true }));

  root.replaceChildren(el("div", { class: "login" }, el("div", { class: "login-card" },
    el("div", { class: "brand-logo" }, icon("shield")),
    el("h1", {}, "Sign in to AuthZ"),
    el("p", {}, "Manage tenants, roles, agents and delegations."),
    oidcEnabled && [
      btn("Continue with SSO", {
        variant: "primary", iconName: "sso", block: true,
        onClick: () => { window.location.href = `/oauth/login?return_to=${encodeURIComponent("/admin/")}`; },
      }),
      el("div", { class: "divider" }, "or use an API key"),
    ],
    form,
    error && el("p", { class: "login-error" }, error),
    el("p", { class: "login-foot" },
      "Keys are kept in this tab only unless you choose to remember them. ",
      oidcEnabled ? "SSO keeps credentials out of the browser entirely." : "Configure admin OIDC to enable SSO.",
      " ", el("a", { href: "https://github.com/rudi77/authz/blob/main/SECURITY.md", target: "_blank", rel: "noopener" }, "Security notes")))));
  keyInput.focus();
}

async function signOut() {
  if (session && session.kind === "session") {
    try {
      await fetch("/oauth/logout", {
        method: "POST", credentials: "include",
        headers: session.csrf_token ? { "X-CSRF-Token": session.csrf_token } : {},
      });
    } catch {}
  }
  session = null;
  apiKey = "";
  forgetKey();
  renderLogin();
}

// ===================================================================== shell

const NAV = [
  { group: null, items: [["dashboard", "Overview", "dashboard"]] },
  { group: "Catalog", items: [
    ["tenants", "Tenants", "building"],
    ["applications", "Applications", "box"],
    ["permissions", "Permissions", "permission"],
    ["roles", "Roles", "layers"],
  ] },
  { group: "Identities", items: [
    ["users", "Users", "users"],
    ["memberships", "Memberships", "userCheck"],
    ["agents", "Agents", "bot"],
    ["invitations", "Invitations", "mail"],
  ] },
  { group: "Agent access", items: [
    ["delegations", "Delegations", "ticket"],
    ["features", "Feature controls", "toggle"],
  ] },
  { group: "Decisions", items: [
    ["probe", "Decision probe", "scale"],
    ["audit", "Audit log", "list"],
  ] },
  { group: "Credentials", items: [
    ["api-keys", "API keys", "key"],
    ["oauth", "OAuth clients", "lock"],
  ] },
];

let content;
let currentPage = "dashboard";

function ctxSelect(label, items, value, onChange, square) {
  const current = items.find((i) => i.id === value);
  const sel = el("select", { "aria-label": label, onchange: (e) => onChange(e.target.value) },
    items.length ? items.map((i) => el("option", { value: i.id, selected: i.id === value }, `${i.name} (${i.slug})`))
      : el("option", { value: "" }, `No ${label.toLowerCase()}s yet`));
  return el("label", { class: "ctx-select" },
    current ? avatar(current.id, current.name, square) : el("span", { class: "ctx-avatar", style: "background:var(--text-3)" }, "?"),
    el("span", {}, el("span", { class: "ctx-label" }, label),
      el("span", { class: "ctx-value" }, current ? current.name : `Create ${label === "Application" ? "an" : "a"} ${label.toLowerCase()}`)),
    el("span", { class: "ctx-chevron" }, icon("chevrons")),
    sel);
}

function renderTopbar() {
  const who = session && session.kind === "session"
    ? session.email || session.subject
    : apiKey ? "API key" : "Dev mode (no auth)";
  return el("header", { class: "topbar" },
    el("div", { class: "ctx" },
      ctxSelect("Tenant", state.tenants, state.tenantId, (v) => setContext({ tenantId: v }), true),
      el("span", { class: "ctx-sep" }, "/"),
      ctxSelect("Application", state.applications, state.appId, (v) => setContext({ appId: v }), true)),
    el("div", { class: "topbar-right" },
      el("span", { class: "health", title: `Service ${healthy ? "healthy" : "unreachable or degraded"}` },
        el("span", { class: `dot ${healthy ? "ok" : healthy === false ? "err" : ""}` }), healthy ? "Healthy" : "Degraded"),
      el("span", { class: "who" }, who,
        (apiKey || session?.kind === "session") && iconBtn("logout", "Sign out", signOut))));
}

function renderShell() {
  const nav = el("nav", { class: "nav" });
  for (const section of NAV) {
    if (section.group) nav.append(el("div", { class: "nav-group" }, section.group));
    for (const [id, label, ic] of section.items) {
      nav.append(el("button", { class: "nav-item", dataset: { page: id }, onclick: () => go(id) }, icon(ic), label));
    }
  }
  content = el("div", { class: "content" });
  root.replaceChildren(el("div", { class: "app" },
    el("aside", { class: "sidebar" },
      el("div", { class: "brand" }, el("div", { class: "brand-logo" }, icon("shield")),
        el("div", { class: "brand-text" }, el("div", { class: "brand-name" }, "AuthZ"), el("div", { class: "brand-sub" }, "Authorization console"))),
      nav,
      el("div", { class: "sidebar-foot" },
        el("span", {}, `Service v${serviceVersion}`),
        el("a", { href: "/docs", target: "_blank", rel: "noopener" }, "API reference ↗"))),
    el("div", { class: "main" }, el("div", { id: "topbar-slot" }, renderTopbar()), content)));
  const fromHash = location.hash.replace("#", "");
  go(PAGES[fromHash] ? fromHash : currentPage, { replace: true });
}

function refreshTopbar() {
  document.getElementById("topbar-slot")?.replaceChildren(renderTopbar());
}

function setContext(patch) {
  Object.assign(state, patch);
  storageSet(localStorage, CTX_KEY, JSON.stringify({ tenantId: state.tenantId, appId: state.appId }));
  refreshTopbar();
  render();
}

function go(page, { replace = false } = {}) {
  currentPage = page;
  if (location.hash !== `#${page}`) {
    if (replace) history.replaceState(null, "", `#${page}`);
    else history.pushState(null, "", `#${page}`);
  }
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.page === page));
  render();
}
window.addEventListener("popstate", () => {
  const p = location.hash.replace("#", "");
  if (PAGES[p] && content) go(p, { replace: true });
});

let renderSeq = 0;
async function render() {
  const seq = ++renderSeq;
  const page = PAGES[currentPage];
  content.replaceChildren(el("div", { class: "loading" }, el("div", { class: "spinner" })));
  try {
    const node = await page();
    if (seq === renderSeq) content.replaceChildren(node);
  } catch (err) {
    if (seq !== renderSeq) return;
    if (err.status === 401) return renderLogin("Your session ended. Sign in again.");
    content.replaceChildren(card({ body: emptyState("alert", "Something went wrong", err.message,
      btn("Try again", { iconName: "refresh", onClick: render })) }));
  }
}

/** Guard for pages that need a tenant and/or application selected. */
function needContext(kind, title, subtitle) {
  const missingTenant = (kind === "tenant" || kind === "both") && !state.tenantId;
  const missingApp = (kind === "app" || kind === "both") && !state.appId;
  if (!missingTenant && !missingApp) return null;
  const what = missingTenant ? "a tenant" : "an application";
  return el("div", {}, pageHeader(title, subtitle), card({
    body: emptyState(missingTenant ? "building" : "box", `Create ${what} first`,
      `This page works inside ${what}. Create one, then pick it in the switcher at the top.`,
      btn(`Go to ${missingTenant ? "Tenants" : "Applications"}`, {
        variant: "primary", iconName: "arrow", onClick: () => go(missingTenant ? "tenants" : "applications"),
      })),
  }));
}

/** Manager of the selected application, if it is managed through the
 * provisioning API. Its permissions, roles, memberships and agents are then
 * read-only here — the service rejects writes from anyone else. */
const managedBy = () => appById(state.appId)?.managed_by || null;
function managedNotice() {
  const by = managedBy();
  return by && el("div", { class: "callout info" }, icon("info"),
    el("div", {}, "Managed by ", el("code", { class: "code-inline" }, by),
      " — read-only here. Changes come from the managing application."));
}

/** Run an action, toast errors, re-render on success. */
const action = (fn) => async () => {
  try { await fn(); } catch (err) { toast(err.message, "err"); }
};

// ===================================================================== pages

const PAGES = {};

// ---------------------------------------------------------------- overview

PAGES.dashboard = async () => {
  const t = tenantById(state.tenantId);
  const a = appById(state.appId);
  const safe = (p) => p.catch(() => []);
  const [users, keys, denies, perms, roles, agents, memberships, grants] = await Promise.all([
    safe(fetchUsers()),
    safe(api("/v1/api-keys")),
    safe(api("/v1/audit?decision=deny&page_size=200")),
    safe(fetchPermissions()),
    safe(fetchRoles()),
    safe(fetchAgents()),
    t ? safe(api(`/v1/tenants/${t.id}/memberships?page_size=500`)) : [],
    t ? safe(api(`/v1/delegations?tenant_id=${t.id}&active_only=true&page_size=500`)) : [],
  ]);
  const stat = (label, value, ic, page, red) =>
    el("button", { class: "stat", type: "button", onclick: () => go(page) },
      el("div", { class: "stat-top" }, label, el("span", { class: "stat-icon" }, icon(ic))),
      el("div", { class: `stat-value${red && value ? " red" : ""}` }, value));

  const steps = [
    [Boolean(t), "Create a tenant", "A customer or organisation.", "tenants"],
    [Boolean(a), "Register an application", "The product whose access you control.", "applications"],
    [perms.length > 0, "Define permissions", "resource.action names such as contracts.read.", "permissions"],
    [roles.length > 0, "Group permissions into roles", "For people and for agents.", "roles"],
    [memberships.length > 0, "Grant a user a role", "Memberships connect users to roles in a tenant.", "memberships"],
    [agents.length > 0, "Register an agent", "Agents only ever get user ∩ agent.", "agents"],
    [grants.length > 0, "Issue a delegation", "Time-boxed, revocable access for one agent run.", "delegations"],
  ];
  const done = steps.filter((s) => s[0]).length;

  return el("div", {},
    pageHeader("Overview", t && a ? `${t.name} · ${a.name}` : "Authorization at a glance."),
    el("div", { class: "stats" },
      stat("Tenants", state.tenants.length, "building", "tenants"),
      stat("Applications", state.applications.length, "box", "applications"),
      stat("Users", users.length, "users", "users"),
      stat("Agents", agents.length, "bot", "agents"),
      stat("Active delegations", grants.length, "ticket", "delegations"),
      stat("Active API keys", keys.filter((k) => k.status === "active").length, "key", "api-keys"),
      stat("Recent denies", denies.length, "alert", "audit", true)),
    el("div", { class: "grid-2" },
      card({
        title: "Setup", subtitle: `${done} of ${steps.length} steps complete for the selected tenant and app`,
        actions: el("div", { class: "progress" }, el("span", { style: `width:${(done / steps.length) * 100}%` })),
        body: el("ul", { class: "steps" }, steps.map(([ok, title, desc, page]) =>
          el("li", { class: `step${ok ? " done" : ""}` },
            el("span", { class: "step-check" }, icon("check")),
            el("div", { class: "step-text" }, el("div", { class: "step-title" }, title), el("div", { class: "step-desc" }, desc)),
            !ok && btn("Open", { small: true, onClick: () => go(page) })))),
      }),
      card({
        title: "Recent denies", subtitle: "Every deny is audited",
        actions: btn("View all", { small: true, variant: "ghost", iconName: "arrow", onClick: () => go("audit") }),
        body: table([
          { label: "Permission", render: (r) => el("code", {}, `${r.resource}.${r.action}`) },
          { label: "Reason", render: (r) => badge(r.reason || "—", "red") },
          { label: "When", render: (r) => timeCell(r.created_at), shrink: true },
        ], denies.slice(0, 6), emptyState("check", "No denies yet", "Denied decisions will show up here.")),
      })));
};

// ---------------------------------------------------------------- tenants

function statusToggle(kind, item) {
  const active = item.status === "active";
  return iconBtn(active ? "pause" : "play", active ? `Suspend ${kind}` : `Activate ${kind}`, action(async () => {
    if (active && !(await confirmAction(`Suspend ${item.name}?`,
      `Every authorization decision for this ${kind} will be denied until it is activated again.`,
      { confirmLabel: "Suspend" }))) return;
    await api(`/v1/${kind === "tenant" ? "tenants" : "applications"}/${item.id}`, {
      method: "PATCH", body: { status: active ? "suspended" : "active" },
    });
    toast(`${item.name} ${active ? "suspended" : "activated"}`);
    await fetchCatalog();
    refreshTopbar();
    render();
  }), active);
}

async function createCatalogItem(kind) {
  const created = await modal({
    title: kind === "tenant" ? "New tenant" : "New application",
    description: kind === "tenant"
      ? "A tenant is a customer or organisation. Permissions are always evaluated inside one."
      : "An application owns its permissions and roles.",
    submitLabel: "Create",
    body: el("div", {},
      field("Name", input("name", { placeholder: kind === "tenant" ? "ACME Corp" : "Contract AI", required: true })),
      field("Slug", input("slug", { placeholder: kind === "tenant" ? "acme" : "contract-ai", required: true, mono: true }),
        "Short, unique, URL-safe identifier. Cannot be changed later.")),
    onSubmit: (fd) => api(kind === "tenant" ? "/v1/tenants" : "/v1/applications", {
      method: "POST", body: { name: fd.get("name"), slug: fd.get("slug").trim() },
    }),
  });
  if (!created) return;
  toast(`${created.name} created`);
  await fetchCatalog();
  setContext(kind === "tenant" ? { tenantId: created.id } : { appId: created.id });
}

PAGES.tenants = async () => {
  await fetchCatalog();
  const t = tenantById(state.tenantId);
  const mappings = t ? await api(`/v1/tenants/${t.id}/mappings`) : [];
  const newBtn = () => btn("New tenant", { variant: "primary", iconName: "plus", onClick: action(() => createCatalogItem("tenant")) });
  return el("div", {},
    pageHeader("Tenants", "Customers or organisations. Suspending a tenant denies every decision inside it.", newBtn()),
    card({
      body: table([
        { label: "Tenant", render: (r) => nameCell(r.id, r.name, r.slug, true) },
        { label: "Status", render: (r) => statusBadge(r.status) },
        { label: "ID", render: (r) => idChip(r.id) },
        { label: "", shrink: true, render: (r) => el("div", { class: "row-actions" },
          r.id !== state.tenantId && btn("Select", { small: true, variant: "ghost", onClick: () => setContext({ tenantId: r.id }) }),
          r.id === state.tenantId && badge("selected", "indigo"),
          statusToggle("tenant", r)) },
      ], state.tenants, emptyState("building", "No tenants yet", "Create the first tenant to start modelling access.", newBtn())),
    }),
    t && card({
      title: "Identity provider mappings",
      subtitle: `Map an IdP tenant (e.g. an Entra tid) to ${t.name} so resolve-context finds it.`,
      actions: btn("Add mapping", { small: true, iconName: "plus", onClick: action(async () => {
        const ok = await modal({
          title: "Add IdP mapping", description: `Requests whose token carries this external tenant id resolve to ${t.name}.`,
          submitLabel: "Add mapping",
          body: el("div", {},
            el("div", { class: "field-row" },
              field("Provider", selectEl("provider", ["entra", "cognito", "gcp", "oidc"].map((v) => ({ value: v, label: v })), "entra")),
              field("External tenant id", input("external_tenant_id", { required: true, mono: true, placeholder: "tid" }))),
            field("Issuer", input("issuer", { required: true, placeholder: "https://login.microsoftonline.com/<tid>/v2.0" }))),
          onSubmit: (fd) => api(`/v1/tenants/${t.id}/mappings`, { method: "POST", body: Object.fromEntries(fd) }),
        });
        if (ok) { toast("Mapping added"); render(); }
      }) }),
      body: table([
        { label: "Provider", render: (m) => badge(m.provider) },
        { label: "Issuer", render: (m) => el("span", { class: "code" }, m.issuer) },
        { label: "External tenant", render: (m) => idChip(m.external_tenant_id, 14) },
      ], mappings, emptyState("link", "No mappings", "Without a mapping, tenants are resolved by explicit id only.")),
    }));
};

// ---------------------------------------------------------------- applications

PAGES.applications = async () => {
  await fetchCatalog();
  const newBtn = () => btn("New application", { variant: "primary", iconName: "plus", onClick: action(() => createCatalogItem("application")) });
  return el("div", {},
    pageHeader("Applications", "Each application owns its permissions and roles.", newBtn()),
    card({
      body: table([
        { label: "Application", render: (r) => nameCell(r.id, r.name, r.slug, true) },
        { label: "Status", render: (r) => el("div", { class: "tags" }, statusBadge(r.status),
          r.managed_by && el("span", { title: `Managed by ${r.managed_by}` }, badge("managed", "indigo"))) },
        { label: "ID", render: (r) => idChip(r.id) },
        { label: "", shrink: true, render: (r) => el("div", { class: "row-actions" },
          r.id !== state.appId && btn("Select", { small: true, variant: "ghost", onClick: () => setContext({ appId: r.id }) }),
          r.id === state.appId && badge("selected", "indigo"),
          statusToggle("application", r)) },
      ], state.applications, emptyState("box", "No applications yet", "Register the product whose access you want to control.", newBtn())),
    }));
};

// ---------------------------------------------------------------- permissions

PAGES.permissions = async () => {
  const guard = needContext("app", "Permissions");
  if (guard) return guard;
  const perms = await fetchPermissions();
  const app = appById(state.appId);
  const ro = Boolean(managedBy());
  const newBtn = () => !ro && btn("New permission", { variant: "primary", iconName: "plus", onClick: action(async () => {
    const ok = await modal({
      title: "New permission", description: `Add a permission to ${app.name}.`, submitLabel: "Create",
      body: el("div", {},
        field("Name", input("name", { placeholder: "contracts.review", required: true, mono: true }),
          "Format resource.action — or namespace.resource.action, e.g. mcp.github.create_issue."),
        field("Description", input("description", { placeholder: "What this allows" }))),
      onSubmit: (fd) => {
        const name = fd.get("name").trim();
        if (!name.includes(".")) throw new Error("Use the form resource.action");
        return api(`/v1/applications/${state.appId}/permissions`, {
          method: "POST", body: { name, description: fd.get("description") || null },
        });
      },
    });
    if (ok) { toast(`Permission ${ok.name} created`); render(); }
  }) });
  return el("div", {},
    pageHeader("Permissions", `Everything ${app.name} can check. Names are matched exactly.`, newBtn()),
    managedNotice(),
    card({
      body: table([
        { label: "Permission", render: (p) => el("div", { class: "tags" },
          el("code", { class: "code-inline" }, p.name),
          p.critical && badge("critical", "amber"),
          p.deprecated && el("span", { title: "No longer in the catalog; counts in no decision" }, badge("deprecated", "red"))) },
        { label: "Resource", render: (p) => p.resource },
        { label: "Action", render: (p) => badge(p.action, "", { mono: true }) },
        { label: "Description", render: (p) => p.description || el("span", { class: "muted" }, "—") },
      ], perms, emptyState("permission", "No permissions yet", "Define what can be checked, e.g. contracts.read.", newBtn())),
    }));
};

// ---------------------------------------------------------------- roles

function permissionChecklist(perms, checked, name = "permissions") {
  return checklist(name, perms.map((p) => ({
    value: p.name, desc: p.description, checked: checked.has(p.name),
  })), { group: true, emptyText: "This application has no permissions yet." });
}

PAGES.roles = async () => {
  const guard = needContext("app", "Roles");
  if (guard) return guard;
  const app = appById(state.appId);
  const [roles, perms] = await Promise.all([fetchRoles(), fetchPermissions()]);
  const rolePerms = await Promise.all(roles.map((r) => api(`/v1/roles/${r.id}/permissions`)));
  const ro = Boolean(managedBy());

  const editPermissions = (role, current) => action(async () => {
    const ok = await modal({
      title: `Permissions of “${role.name}”`, description: "Tick everything this role grants.",
      submitLabel: "Save", wide: true,
      body: permissionChecklist(perms, new Set(current)),
      onSubmit: (fd) => api(`/v1/roles/${role.id}/permissions`, { method: "PUT", body: { permissions: fd.getAll("permissions") } }),
    });
    if (ok) { toast(`${role.name} now grants ${ok.permissions.length} permission(s)`); render(); }
  });

  const newBtn = () => !ro && btn("New role", { variant: "primary", iconName: "plus", onClick: action(async () => {
    const created = await modal({
      title: "New role", description: `Roles bundle permissions of ${app.name}.`, submitLabel: "Create role", wide: true,
      body: el("div", {},
        el("div", { class: "field-row" },
          field("Name", input("name", { placeholder: "reviewer", required: true, mono: true })),
          field("Scope", selectEl("scope", [
            { value: "application", label: "Application — for people" },
            { value: "agent", label: "Agent — for AI agents" },
            { value: "tenant", label: "Tenant — selected tenant only" },
            { value: "platform", label: "Platform" },
          ], "application"))),
        field("Description", input("description", { placeholder: "What this role is for" })),
        el("div", { class: "field" }, el("div", { class: "field-label" }, "Permissions"), permissionChecklist(perms, new Set()))),
      onSubmit: async (fd) => {
        const body = { name: fd.get("name").trim(), scope: fd.get("scope"), description: fd.get("description") || null };
        if (body.scope === "tenant") {
          if (!state.tenantId) throw new Error("Select a tenant first");
          body.tenant_id = state.tenantId;
        }
        const role = await api(`/v1/applications/${state.appId}/roles`, { method: "POST", body });
        const chosen = fd.getAll("permissions");
        if (chosen.length) await api(`/v1/roles/${role.id}/permissions`, { method: "PUT", body: { permissions: chosen } });
        return role;
      },
    });
    if (created) { toast(`Role ${created.name} created`); render(); }
  }) });

  return el("div", {},
    pageHeader("Roles", "Named bundles of permissions, assigned to users (memberships) and agents.", newBtn()),
    managedNotice(),
    card({
      body: table([
        { label: "Role", render: (r) => el("div", {}, el("div", { class: "cell-main" }, r.name), r.description && el("div", { class: "cell-sub" }, r.description)) },
        { label: "Scope", render: (r) => badge(r.scope, r.scope === "agent" ? "indigo" : "") },
        { label: "Permissions", render: (r) => {
          const names = rolePerms[roles.indexOf(r)].permissions;
          if (!names.length) return el("span", { class: "muted" }, "none");
          return el("div", { class: "tags" }, names.slice(0, 4).map((n) => badge(n, "", { mono: true })),
            names.length > 4 && badge(`+${names.length - 4}`));
        } },
        { label: "", shrink: true, render: (r) => !ro && btn("Edit permissions", { small: true, iconName: "pencil",
          onClick: editPermissions(r, rolePerms[roles.indexOf(r)].permissions) }) },
      ], roles, emptyState("layers", "No roles yet", "Create a role for people and one for your agents.", newBtn())),
    }));
};

// ---------------------------------------------------------------- users

async function addUser() {
  const user = await modal({
    title: "Add user",
    description: "Users are normally created on first login. Pre-provision one to grant access before that.",
    submitLabel: "Add user",
    body: el("div", {},
      el("div", { class: "field-row" },
        field("Display name", input("display_name", { placeholder: "Alice Example" })),
        field("Email", input("email", { type: "email", placeholder: "alice@acme.com" }))),
      el("div", { class: "field-row" },
        field("Provider", selectEl("provider", ["entra", "cognito", "gcp", "oidc"].map((v) => ({ value: v, label: v })), "entra")),
        field("Subject", input("subject", { required: true, mono: true, placeholder: "sub / oid claim" }))),
      field("Issuer", input("issuer", { required: true, placeholder: "https://login.microsoftonline.com/<tid>/v2.0" }),
        "Must match the iss claim of the user's tokens.")),
    onSubmit: (fd) => api("/v1/users", {
      method: "POST", body: Object.fromEntries([...fd.entries()].filter(([, v]) => v !== "")),
    }),
  });
  if (user) toast(`${user.display_name || user.email || "User"} added`);
  return user;
}

PAGES.users = async () => {
  const q = PAGES.users.q || "";
  const users = await fetchUsers(q);
  const newBtn = () => btn("Add user", { variant: "primary", iconName: "plus", onClick: action(async () => { if (await addUser()) render(); }) });
  const search = input("q", { placeholder: "Search by name, email or id", value: q });
  search.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { PAGES.users.q = search.value.trim(); render(); }
  });
  return el("div", {},
    pageHeader("Users", "People known to the service, identified by their IdP identity.", newBtn()),
    card({
      toolbar: el("div", { class: "toolbar" }, el("div", { class: "search" }, icon("search"), search),
        q && btn("Clear", { small: true, variant: "ghost", onClick: () => { PAGES.users.q = ""; render(); } })),
      body: table([
        { label: "User", render: (u) => nameCell(u.id, u.display_name || u.email || "Unnamed user", u.display_name ? u.email : null) },
        { label: "Identities", render: (u) => el("div", { class: "tags" }, u.identities.map((i) =>
          el("span", { title: `${i.issuer} · ${i.subject}` }, badge(`${i.provider}: ${i.subject}`, "", { mono: true })))) },
        { label: "Status", render: (u) => statusBadge(u.status) },
        { label: "ID", render: (u) => idChip(u.id) },
      ], users, q ? emptyState("search", "No matches", `No user matches “${q}”.`)
        : emptyState("users", "No users yet", "Users appear after their first login, or add one now.", newBtn())),
    }));
};

// ---------------------------------------------------------------- memberships

function roleChecklist(roles, checked) {
  const items = roles.map((r) => ({ value: r.name, title: r.name, desc: [r.scope !== "application" && `${r.scope} role`, r.description].filter(Boolean).join(" · "), checked: checked.has(r.name) }));
  return checklist("roles", items, { emptyText: "This application has no roles yet — create one under Roles." });
}

PAGES.memberships = async () => {
  const guard = needContext("both", "Memberships");
  if (guard) return guard;
  const t = tenantById(state.tenantId);
  const app = appById(state.appId);
  const [rows, roles] = await Promise.all([
    api(`/v1/tenants/${t.id}/memberships?page_size=500`),
    fetchRoles(),
    fetchUsers(),
  ]);
  const memberships = rows.filter((m) => !m.application_id || m.application_id === state.appId);
  const ro = Boolean(managedBy());

  const grant = action(async () => {
    const taken = new Set(memberships.map((m) => m.user_id));
    const free = state.users.filter((u) => !taken.has(u.id));
    if (!state.users.length) {
      if (await confirmAction("No users yet", "Add a user first, then grant them access.", { confirmLabel: "Add user", danger: false })) {
        if (await addUser()) render();
      }
      return;
    }
    const ok = await modal({
      title: "Grant access", description: `Give a user roles in ${t.name} for ${app.name}.`, submitLabel: "Grant", wide: true,
      body: el("div", {},
        field("User", selectEl("user_id", (free.length ? free : state.users).map((u) => ({ value: u.id, label: u.display_name ? `${u.display_name} — ${u.email || u.id}` : u.email || u.id })), null, { required: true }),
          free.length ? null : "Every user already has a membership here."),
        el("div", { class: "field" }, el("div", { class: "field-label" }, "Roles"), roleChecklist(roles, new Set()))),
      onSubmit: (fd) => api(`/v1/tenants/${t.id}/memberships`, {
        method: "POST", body: { user_id: fd.get("user_id"), application_id: state.appId, roles: fd.getAll("roles") },
      }),
    });
    if (ok) { toast("Access granted"); render(); }
  });

  const editRoles = (m) => action(async () => {
    const ok = await modal({
      title: `Roles of ${userLabel(m.user_id)}`, description: `In ${t.name} · ${app.name}`, submitLabel: "Save", wide: true,
      body: roleChecklist(roles, new Set(m.roles)),
      onSubmit: (fd) => api(`/v1/memberships/${m.id}`, { method: "PATCH", body: { roles: fd.getAll("roles") } }),
    });
    if (ok) { toast("Roles updated"); render(); }
  });
  const toggle = (m) => action(async () => {
    const active = m.status === "active";
    if (active && !(await confirmAction(`Suspend ${userLabel(m.user_id)}?`,
      "The user and every agent acting for them lose access in this tenant.", { confirmLabel: "Suspend" }))) return;
    await api(`/v1/memberships/${m.id}`, { method: "PATCH", body: { status: active ? "suspended" : "active" } });
    toast(active ? "Membership suspended" : "Membership activated");
    render();
  });

  const newBtn = () => !ro && btn("Grant access", { variant: "primary", iconName: "plus", onClick: grant });
  return el("div", {},
    pageHeader("Memberships", `Who has which roles in ${t.name} for ${app.name}.`, newBtn()),
    managedNotice(),
    card({
      body: table([
        { label: "User", render: (m) => {
          const u = userById(m.user_id);
          return nameCell(m.user_id, userLabel(m.user_id), u?.display_name ? u.email : null);
        } },
        { label: "Roles", render: (m) => m.roles.length
          ? el("div", { class: "tags" }, m.roles.map((r) => badge(r, "indigo")))
          : el("span", { class: "muted" }, "no roles") },
        { label: "Scope", render: (m) => m.application_id ? app.name : badge("all applications") },
        { label: "Status", render: (m) => statusBadge(m.status) },
        { label: "", shrink: true, render: (m) => !(ro && m.application_id) && el("div", { class: "row-actions" },
          btn("Edit roles", { small: true, iconName: "pencil", onClick: editRoles(m) }),
          iconBtn(m.status === "active" ? "pause" : "play", m.status === "active" ? "Suspend" : "Activate", toggle(m), m.status === "active")) },
      ], memberships, emptyState("userCheck", "Nobody has access yet", `Grant a user roles in ${t.name}.`, newBtn())),
    }));
};

// ---------------------------------------------------------------- agents

PAGES.agents = async () => {
  const guard = needContext("both", "Agents");
  if (guard) return guard;
  const t = tenantById(state.tenantId);
  const app = appById(state.appId);
  const [agents, roles] = await Promise.all([fetchAgents(), fetchRoles()]);
  const roleSets = await Promise.all(agents.map((a) => api(`/v1/agents/${a.id}/roles`)));
  const ro = Boolean(managedBy());

  const editRoles = (agent, current) => action(async () => {
    const ok = await modal({
      title: `Roles of ${agent.name}`,
      description: "An agent never exceeds the user it acts for — these roles set its ceiling.",
      submitLabel: "Save", wide: true,
      body: roleChecklist(roles, new Set(current)),
      onSubmit: (fd) => api(`/v1/agents/${agent.id}/roles`, { method: "PUT", body: { roles: fd.getAll("roles") } }),
    });
    if (ok) { toast(`Roles of ${agent.name} updated`); render(); }
  });

  const newBtn = () => !ro && btn("Register agent", { variant: "primary", iconName: "plus", onClick: action(async () => {
    const ok = await modal({
      title: "Register agent", description: `An AI agent operating in ${t.name} · ${app.name}.`, submitLabel: "Register", wide: true,
      body: el("div", {},
        el("div", { class: "field-row" },
          field("Name", input("name", { required: true, placeholder: "contract-analyzer" })),
          field("Label", input("role", { placeholder: "e.g. reviewer bot" }), "Free-text, informational only.")),
        el("div", { class: "field" }, el("div", { class: "field-label" }, "Roles"),
          roleChecklist(roles, new Set(roles.filter((r) => r.scope === "agent").map((r) => r.name))),
          el("div", { class: "help" }, "Agent-scoped roles are pre-selected."))),
      onSubmit: async (fd) => {
        const agent = await api(`/v1/tenants/${t.id}/applications/${app.id}/agents`, {
          method: "POST", body: { name: fd.get("name"), role: fd.get("role") || "" },
        });
        await api(`/v1/agents/${agent.id}/roles`, { method: "PUT", body: { roles: fd.getAll("roles") } });
        return agent;
      },
    });
    if (ok) { toast(`${ok.name} registered`); render(); }
  }) });

  return el("div", {},
    pageHeader("Agents", "AI agents act for a user. Effective access is always user ∩ agent ∩ tenant mask.", newBtn()),
    managedNotice(),
    el("div", { class: "callout info" }, icon("info"),
      el("div", {}, "Want a run limited to fewer permissions or a short time window? Issue a ",
        el("a", { href: "#delegations", onclick: (e) => { e.preventDefault(); go("delegations"); } }, "delegation"), ".")),
    card({
      body: table([
        { label: "Agent", render: (a) => nameCell(a.id, a.display_name || a.name, a.display_name ? a.name : a.role || null, true) },
        { label: "Roles", render: (a) => {
          const names = roleSets[agents.indexOf(a)].roles;
          return names.length ? el("div", { class: "tags" }, names.map((r) => badge(r, "indigo"))) : el("span", { class: "muted" }, "no roles");
        } },
        { label: "Status", render: (a) => statusBadge(a.status) },
        { label: "ID", render: (a) => idChip(a.id) },
        { label: "", shrink: true, render: (a) => !ro && btn("Edit roles", { small: true, iconName: "pencil",
          onClick: editRoles(a, roleSets[agents.indexOf(a)].roles) }) },
      ], agents, emptyState("bot", "No agents yet", "Register an agent and give it an agent role.", newBtn())),
    }));
};

// ---------------------------------------------------------------- invitations

PAGES.invitations = async () => {
  const guard = needContext("tenant", "Invitations");
  if (guard) return guard;
  const t = tenantById(state.tenantId);
  const [rows, roles] = await Promise.all([api(`/v1/tenants/${t.id}/invitations`), fetchRoles()]);
  const ro = Boolean(managedBy());

  const newBtn = () => !ro && btn("Invite", { variant: "primary", iconName: "plus", onClick: action(async () => {
    const created = await modal({
      title: "Invite someone", description: `They join ${t.name} with these roles when they accept.`, submitLabel: "Create invitation", wide: true,
      body: el("div", {},
        el("div", { class: "field-row" },
          field("Email", input("email", { type: "email", required: true, placeholder: "bob@acme.com" })),
          field("Valid for", selectEl("ttl_days", [1, 3, 7, 14, 30].map((d) => ({ value: String(d), label: `${d} day${d > 1 ? "s" : ""}` })), "7"))),
        el("div", { class: "field" }, el("div", { class: "field-label" }, "Roles"), roleChecklist(roles, new Set()))),
      onSubmit: (fd) => api(`/v1/tenants/${t.id}/invitations`, {
        method: "POST",
        body: { email: fd.get("email"), roles: fd.getAll("roles"), ttl_days: Number(fd.get("ttl_days")),
          ...(state.appId ? { application_id: state.appId } : {}) },
      }),
    });
    if (!created) return;
    await showSecret({ title: "Invitation created", description: `Send this token to ${created.email} through your own channel.`,
      secret: created.token, note: "The token is shown only once. Your application delivers it (e.g. in an email link)." });
    render();
  }) });

  return el("div", {},
    pageHeader("Invitations", `Pending and past invitations to ${t.name}.`, newBtn()),
    managedNotice(),
    card({
      body: table([
        { label: "Email", render: (i) => nameCell(i.email, i.email, null) },
        { label: "Roles", render: (i) => i.roles.length ? el("div", { class: "tags" }, i.roles.map((r) => badge(r, "indigo"))) : el("span", { class: "muted" }, "—") },
        { label: "Status", render: (i) => statusBadge(i.status) },
        { label: "Expires", render: (i) => timeCell(i.expires_at) },
        { label: "", shrink: true, render: (i) => i.status === "pending" && iconBtn("trash", "Revoke invitation", action(async () => {
          if (!(await confirmAction(`Revoke invitation for ${i.email}?`, "The token stops working immediately.", { confirmLabel: "Revoke" }))) return;
          await api(`/v1/invitations/${i.id}`, { method: "DELETE" });
          toast("Invitation revoked");
          render();
        }), true) },
      ], rows, emptyState("mail", "No invitations", "Invite people by email; they get roles on acceptance.", newBtn())),
    }));
};

// ---------------------------------------------------------------- delegations

async function issueDelegation() {
  const t = tenantById(state.tenantId);
  const app = appById(state.appId);
  await Promise.all([fetchUsers(), fetchAgents(), fetchPermissions()]);
  if (!state.agents.length) throw new Error("Register an agent first");
  if (!state.users.length) throw new Error("Add a user first");
  const userSel = selectEl("user_id", state.users.map((u) => ({ value: u.id, label: u.display_name ? `${u.display_name} — ${u.email || ""}` : u.email || u.id })), null, { required: true });
  const agentSel = selectEl("agent_id", state.agents.map((a) => ({ value: a.id, label: a.name })), null, { required: true });
  const permField = el("div", { class: "field" }, el("div", { class: "field-label" }, "Delegated permissions"),
    el("div", { class: "help" }, "Pre-selected: everything the agent may do for this user (user ∩ agent ∩ tenant mask). Untick to narrow."),
    el("div", { class: "checklist" }, el("div", { class: "checklist-empty" }, "Loading…")));
  // Re-load the delegable set whenever user or agent changes.
  const loadDelegable = async () => {
    const box = permField.querySelector(".checklist");
    box.replaceChildren(el("div", { class: "checklist-empty" }, "Loading…"));
    const result = await api("/v1/effective-permissions", {
      method: "POST",
      body: { tenant_id: t.id, application_id: app.id, subject: { type: "agent", user_id: userSel.value, agent_id: agentSel.value } },
    }).catch((e) => ({ error: e.message, permissions: [] }));
    box.replaceWith(checklist("permissions", result.permissions.map((p) => ({ value: p, desc: permDesc(p), checked: true })),
      { group: true, emptyText: result.error || "Nothing to delegate: this user and agent share no permissions (or one of them is inactive)." }));
  };
  userSel.addEventListener("change", loadDelegable);
  agentSel.addEventListener("change", loadDelegable);

  const pending = modal({
    title: "Issue delegation", wide: true, submitLabel: "Issue grant",
    description: "Lets one agent act for one user — only with the permissions below, until it expires.",
    body: el("div", {},
      el("div", { class: "field-row" }, field("On behalf of", userSel), field("Agent", agentSel)),
      el("div", { class: "field-row" },
        field("Purpose", input("purpose", { placeholder: "Summarise NDA #42" }), "Shown in the audit trail."),
        field("Valid for", selectEl("ttl_seconds", [
          { value: "900", label: "15 minutes" }, { value: "3600", label: "1 hour" },
          { value: "28800", label: "8 hours" }, { value: "86400", label: "24 hours" },
        ], "3600"))),
      permField),
    onSubmit: (fd) => {
      const permissions = fd.getAll("permissions");
      if (!permissions.length) throw new Error("Select at least one permission");
      return api("/v1/delegations", {
        method: "POST",
        body: { tenant_id: t.id, application_id: app.id, user_id: fd.get("user_id"), agent_id: fd.get("agent_id"),
          permissions, ttl_seconds: Number(fd.get("ttl_seconds")), purpose: fd.get("purpose") || null },
      });
    },
  });
  loadDelegable();
  const created = await pending;
  if (!created) return null;
  await showSecret({
    title: "Delegation issued",
    description: `${agentLabel(created.agent_id)} may use ${created.permissions.length} permission(s) for ${userLabel(created.user_id)} until ${new Date(created.expires_at).toLocaleString()}.`,
    secret: created.token,
    note: "Hand this token to the agent runtime. It sends it as the X-Delegation-Token header.",
  });
  return created;
}

PAGES.delegations = async () => {
  const guard = needContext("both", "Delegations");
  if (guard) return guard;
  const t = tenantById(state.tenantId);
  const app = appById(state.appId);
  const showAll = Boolean(PAGES.delegations.showAll);
  await Promise.all([fetchUsers(), fetchAgents(), fetchPermissions()]);
  const params = new URLSearchParams({ tenant_id: t.id, page_size: "300" });
  if (!showAll) params.set("active_only", "true");
  const rows = (await api(`/v1/delegations?${params}`)).filter((g) => g.application_id === app.id);

  const newBtn = () => btn("Issue delegation", { variant: "primary", iconName: "plus", onClick: action(async () => {
    if (await issueDelegation()) render();
  }) });
  const killBtn = btn("Revoke all for an agent", { iconName: "power", onClick: action(async () => {
    if (!state.agents.length) throw new Error("No agents registered");
    const res = await modal({
      title: "Revoke all delegations of an agent", iconName: "power", danger: true, submitLabel: "Revoke all",
      description: "Every active grant of the agent stops working on its next check. Use this if an agent misbehaves.",
      body: field("Agent", selectEl("agent_id", state.agents.map((a) => ({ value: a.id, label: a.name })), null)),
      onSubmit: (fd) => api("/v1/delegations/revoke", { method: "POST", body: { tenant_id: t.id, agent_id: fd.get("agent_id") } }),
    });
    if (res) { toast(`${res.revoked} delegation(s) revoked`); render(); }
  }) });

  const seg = el("div", { class: "segmented" },
    el("button", { type: "button", class: showAll ? "" : "on", onclick: () => { PAGES.delegations.showAll = false; render(); } }, "Active"),
    el("button", { type: "button", class: showAll ? "on" : "", onclick: () => { PAGES.delegations.showAll = true; render(); } }, "All"));

  return el("div", {},
    pageHeader("Delegations",
      "Time-boxed, revocable grants that let an agent act for one user with a subset of permissions: user ∩ agent ∩ mask ∩ grant.",
      killBtn, newBtn()),
    card({
      toolbar: el("div", { class: "toolbar" }, seg, el("span", { class: "muted", style: "margin-left:auto;font-size:12.5px" },
        `${rows.length} grant${rows.length === 1 ? "" : "s"}`)),
      body: table([
        { label: "Agent → user", render: (g) => el("div", { class: "cell-stack" }, avatar(g.agent_id, agentLabel(g.agent_id), true),
          el("div", {}, el("div", { class: "cell-main" }, agentLabel(g.agent_id)), el("div", { class: "cell-sub" }, `for ${userLabel(g.user_id)}`))) },
        { label: "Permissions", render: (g) => el("div", { class: "tags" }, g.permissions.slice(0, 3).map((p) => badge(p, "", { mono: true })),
          g.permissions.length > 3 && badge(`+${g.permissions.length - 3}`)) },
        { label: "Purpose", render: (g) => g.purpose || el("span", { class: "muted" }, "—") },
        { label: "Expires", render: (g) => timeCell(g.expires_at) },
        { label: "Status", render: (g) => statusBadge(g.active ? "active" : g.status === "revoked" ? "revoked" : "expired") },
        { label: "", shrink: true, render: (g) => el("div", { class: "row-actions" }, idChip(g.id, 6),
          g.active && iconBtn("trash", "Revoke", action(async () => {
            if (!(await confirmAction("Revoke this delegation?", "The agent loses it on its next authorization check.", { confirmLabel: "Revoke" }))) return;
            await api(`/v1/delegations/${g.id}`, { method: "DELETE" });
            toast("Delegation revoked");
            render();
          }), true)) },
      ], rows, emptyState("ticket", showAll ? "No delegations yet" : "No active delegations",
        "Issue a grant to give an agent narrowly scoped, expiring access for a single task.", newBtn())),
    }));
};

// ---------------------------------------------------------------- feature controls

PAGES.features = async () => {
  const guard = needContext("both", "Feature controls");
  if (guard) return guard;
  const t = tenantById(state.tenantId);
  const app = appById(state.appId);
  const [perms, mask, tenantFlags, appFlags] = await Promise.all([
    fetchPermissions(),
    api(`/v1/tenants/${t.id}/applications/${app.id}/permission-mask`),
    api(`/v1/tenants/${t.id}/feature-flags`),
    api(`/v1/tenants/${t.id}/feature-flags?application_id=${app.id}`),
  ]);
  const masked = new Set(mask.permissions);
  const maskForm = el("form", {}, permissionChecklist(perms, masked, "mask"));
  const flags = [
    ...Object.entries(tenantFlags.flags).map(([k, v]) => ({ scope: "Tenant-wide", k, v })),
    ...Object.entries(appFlags.flags).map(([k, v]) => ({ scope: app.name, k, v })),
  ];
  return el("div", {},
    pageHeader("Feature controls", `What ${t.name} may use in ${app.name}.`),
    el("div", { class: "grid-2" },
      card({
        title: "Permission mask",
        subtitle: masked.size ? `${masked.size} of ${perms.length} permissions enabled` : "No mask — every permission is enabled",
        body: el("div", { class: "card-body" },
          el("p", { class: "muted", style: "margin:0 0 12px;font-size:13px" },
            "Tick the permissions this tenant has bought. Leaving everything unticked means no restriction. Denies caused by the mask report tenant_feature_disabled."),
          maskForm),
        foot: [
          btn("Clear mask", { onClick: action(async () => {
            await api(`/v1/tenants/${t.id}/applications/${app.id}/permission-mask`, { method: "PUT", body: { permissions: [] } });
            toast("Mask cleared — all permissions allowed");
            render();
          }) }),
          btn("Save mask", { variant: "primary", onClick: action(async () => {
            const names = new FormData(maskForm).getAll("mask");
            await api(`/v1/tenants/${t.id}/applications/${app.id}/permission-mask`, { method: "PUT", body: { permissions: names } });
            toast(names.length ? `Mask saved — ${names.length} permission(s) enabled` : "Mask cleared — all permissions allowed");
            render();
          }) }),
        ],
      }),
      card({
        title: "Feature flags", subtitle: "Arbitrary JSON values your app can read.",
        actions: btn("Set flag", { small: true, iconName: "plus", onClick: action(async () => {
          const ok = await modal({
            title: "Set feature flag", submitLabel: "Save flag",
            body: el("div", {},
              field("Key", input("key", { required: true, mono: true, placeholder: "beta_search" })),
              field("Value", input("value", { required: true, mono: true, placeholder: 'true, 42 or {"limit": 5}' }), "Parsed as JSON; plain text is stored as a string."),
              field("Scope", selectEl("scope", [{ value: "app", label: app.name }, { value: "tenant", label: "Tenant-wide" }], "app"))),
            onSubmit: (fd) => {
              let value;
              try { value = JSON.parse(fd.get("value")); } catch { value = fd.get("value"); }
              return api(`/v1/tenants/${t.id}/feature-flags`, {
                method: "PUT", body: { key: fd.get("key"), value, ...(fd.get("scope") === "app" ? { application_id: app.id } : {}) },
              });
            },
          });
          if (ok) { toast("Flag saved"); render(); }
        }) }),
        body: table([
          { label: "Key", render: (f) => el("code", { class: "code-inline" }, f.k) },
          { label: "Value", render: (f) => el("code", {}, JSON.stringify(f.v)) },
          { label: "Scope", render: (f) => badge(f.scope) },
        ], flags, emptyState("flag", "No flags", "Set a flag to toggle behaviour per tenant.")),
      })));
};

// ---------------------------------------------------------------- decision probe

PAGES.probe = async () => {
  const guard = needContext("both", "Decision probe");
  if (guard) return guard;
  const t = tenantById(state.tenantId);
  const app = appById(state.appId);
  await Promise.all([fetchUsers(), fetchAgents(), fetchPermissions()]);
  const st = PAGES.probe.state || (PAGES.probe.state = { type: "user" });

  const result = el("div", {}, card({ body: emptyState("scale", "Run a check", "Pick a subject and a permission, then check it.") }));
  const userSel = selectEl("user_id", [{ value: "", label: "Select a user…" }, ...state.users.map((u) => ({ value: u.id, label: u.display_name ? `${u.display_name} — ${u.email || ""}` : u.email || u.id }))], st.user_id || "");
  const agentSel = selectEl("agent_id", [{ value: "", label: "Select an agent…" }, ...state.agents.map((a) => ({ value: a.id, label: a.name }))], st.agent_id || "");
  const permInput = input("permission", { placeholder: "contracts.read", mono: true, list: "perm-options", value: st.permission || "" });
  const tokenInput = el("textarea", { class: "input mono", name: "token", placeholder: "Optional: paste a delegation token (eyJ…)", rows: 3 }, st.token || "");
  const agentFields = el("div", { class: "field-group" }, field("Agent", agentSel), field("Delegation token", tokenInput, "Narrows the decision to that grant."));
  const userField = field(st.type === "agent" ? "On behalf of user" : "User", userSel);
  agentFields.hidden = st.type !== "agent";
  const seg = el("div", { class: "segmented" });
  const setType = (type) => {
    st.type = type;
    agentFields.hidden = type !== "agent";
    userField.querySelector("label").textContent = type === "agent" ? "On behalf of user" : "User";
    seg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.type === type));
  };
  for (const [type, label] of [["user", "User"], ["agent", "Agent for user"]]) {
    seg.append(el("button", { type: "button", dataset: { type }, class: st.type === type ? "on" : "", onclick: () => setType(type) }, label));
  }

  const run = async (mode) => {
    Object.assign(st, { user_id: userSel.value, agent_id: agentSel.value, permission: permInput.value.trim(), token: tokenInput.value.trim() });
    const subject = { type: st.type };
    if (st.user_id) subject.user_id = st.user_id;
    if (st.type === "agent" && st.agent_id) subject.agent_id = st.agent_id;
    const headers = st.type === "agent" && st.token ? { "X-Delegation-Token": st.token } : {};
    const base = { tenant_id: t.id, application_id: app.id, subject };
    try {
      if (mode === "effective") {
        const r = await api("/v1/effective-permissions", { method: "POST", body: base, headers });
        result.replaceChildren(card({
          title: "Effective permissions", subtitle: `${r.permissions.length} permission(s) right now`,
          body: el("div", {}, el("div", { class: "card-body" }, r.permissions.length
            ? el("div", { class: "tags" }, r.permissions.map((p) => badge(p, "green", { mono: true })))
            : el("span", { class: "muted" }, "Nothing — this subject cannot do anything here.")),
          el("pre", { class: "json" }, JSON.stringify(r, null, 2))),
        }));
        return;
      }
      const perm = st.permission;
      if (!perm.includes(".")) throw new Error("Enter a permission like contracts.read");
      const cut = perm.lastIndexOf(".");
      const r = await api("/v1/authorize", {
        method: "POST", headers, body: { ...base, resource: perm.slice(0, cut), action: perm.slice(cut + 1) },
      });
      result.replaceChildren(el("section", { class: "card" },
        el("div", { class: "card-body" }, el("div", { class: `verdict ${r.allowed ? "allow" : "deny"}` },
          el("div", { class: "verdict-icon" }, icon(r.allowed ? "check" : "x")),
          el("div", {},
            el("div", { class: "verdict-title" }, r.allowed ? "Allowed" : "Denied"),
            el("div", { class: "verdict-meta" },
              el("div", {}, "Permission ", el("code", { class: "code-inline" }, r.required_permission)),
              el("div", {}, "Reason ", badge(r.reason, r.allowed ? "green" : "red")))))),
        el("pre", { class: "json" }, JSON.stringify(r, null, 2))));
    } catch (err) {
      result.replaceChildren(card({ body: emptyState("alert", "Request failed", err.message) }));
    }
  };

  return el("div", {},
    pageHeader("Decision probe", `Ask the engine exactly what an app or agent would ask — in ${t.name} · ${app.name}.`),
    el("datalist", { id: "perm-options" }, state.permissions.map((p) => el("option", { value: p.name }))),
    el("div", { class: "grid-2" },
      card({
        title: "Request",
        body: el("div", { class: "card-body" },
          el("div", { class: "field" }, el("div", { class: "field-label" }, "Subject"), seg),
          userField,
          agentFields,
          field("Permission", permInput, "resource.action — suggestions come from this application.")),
        foot: [
          btn("Effective permissions", { onClick: () => run("effective") }),
          btn("Check permission", { variant: "primary", iconName: "scale", onClick: () => run("authorize") }),
        ],
      }),
      result));
};

// ---------------------------------------------------------------- audit

PAGES.audit = async () => {
  const f = PAGES.audit.filter || (PAGES.audit.filter = { decision: "", tenantOnly: true });
  const params = new URLSearchParams({ page_size: "200" });
  if (f.decision) params.set("decision", f.decision);
  if (f.tenantOnly && state.tenantId) params.set("tenant_id", state.tenantId);
  const [rows] = await Promise.all([api(`/v1/audit?${params}`), fetchUsers().catch(() => []), fetchAgents().catch(() => [])]);
  const seg = el("div", { class: "segmented" }, [["", "All"], ["deny", "Denied"], ["allow", "Allowed"]].map(([v, label]) =>
    el("button", { type: "button", class: f.decision === v ? "on" : "", onclick: () => { f.decision = v; render(); } }, label)));
  const scope = el("label", { class: "check" }, el("input", { type: "checkbox", checked: f.tenantOnly,
    onchange: (e) => { f.tenantOnly = e.target.checked; render(); } }), "Selected tenant only");
  return el("div", {},
    pageHeader("Audit log", "Every deny is recorded. Allows are recorded when AUTHZ_AUDIT_ALL=true.",
      btn("Refresh", { iconName: "refresh", onClick: render })),
    card({
      toolbar: el("div", { class: "toolbar" }, seg, scope),
      body: table([
        { label: "Decision", render: (r) => badge(r.decision === "allow" ? "Allowed" : "Denied", r.decision === "allow" ? "green" : "red", { dot: true }) },
        { label: "Permission", render: (r) => el("code", { class: "code-inline" }, `${r.resource}.${r.action}`) },
        { label: "Reason", render: (r) => r.reason ? badge(r.reason) : "—" },
        { label: "Subject", render: (r) => el("div", {},
          el("div", { class: "cell-main" }, r.agent_id ? agentLabel(r.agent_id) : userLabel(r.user_id)),
          r.agent_id && el("div", { class: "cell-sub" }, `agent for ${userLabel(r.user_id)}`),
          r.request?.delegation_id && el("div", { class: "cell-sub" }, `via delegation ${r.request.delegation_id.slice(0, 8)}…`)) },
        { label: "When", shrink: true, render: (r) => timeCell(r.created_at) },
      ], rows, emptyState("list", "No entries", "Nothing matches these filters yet.")),
    }));
};

// ---------------------------------------------------------------- API keys

PAGES["api-keys"] = async () => {
  const keys = await api("/v1/api-keys");
  const newBtn = () => btn("Create key", { variant: "primary", iconName: "plus", onClick: action(async () => {
    const t = tenantById(state.tenantId);
    const created = await modal({
      title: "Create API key", submitLabel: "Create key",
      description: "Creating the first stored key ends dev mode: from then on every call needs a key.",
      body: el("div", {},
        field("Name", input("name", { required: true, placeholder: "agent-runtime-prod" })),
        field("Scope", selectEl("scope", [
          { value: "runtime", label: "runtime — decision endpoints only (for apps and agents)" },
          { value: "admin", label: "admin — full management access" },
          ...(t ? [{ value: "tenant", label: `tenant — runtime + management of ${t.name} only` }] : []),
        ], "runtime"))),
      onSubmit: (fd) => {
        const scope = fd.get("scope");
        const body = { name: fd.get("name"), scopes: [scope] };
        if (scope === "tenant") Object.assign(body, { scopes: [`tenant:${t.id}`], tenant_id: t.id });
        return api("/v1/api-keys", { method: "POST", body });
      },
    });
    if (!created) return;
    await showSecret({ title: "API key created", description: created.name, secret: created.key });
    render();
  }) });
  return el("div", {},
    pageHeader("API keys", "Hashed, scoped keys for services. Bootstrap keys from AUTHZ_API_KEYS are not listed.", newBtn()),
    card({
      body: table([
        { label: "Name", render: (k) => el("div", {}, el("div", { class: "cell-main" }, k.name), el("div", { class: "cell-sub" }, el("code", {}, `${k.key_prefix}…`))) },
        { label: "Scopes", render: (k) => el("div", { class: "tags" }, (k.scopes || []).map((s) => badge(s, s === "admin" ? "amber" : "indigo"))) },
        { label: "Status", render: (k) => statusBadge(k.status) },
        { label: "Last used", render: (k) => k.last_used_at ? timeCell(k.last_used_at) : el("span", { class: "muted" }, "never") },
        { label: "", shrink: true, render: (k) => k.status === "active" && el("div", { class: "row-actions" },
          iconBtn("rotate", "Rotate", action(async () => {
            if (!(await confirmAction(`Rotate ${k.name}?`, "A new key with the same scopes is created. Revoke the old one once callers have switched.", { confirmLabel: "Rotate", danger: false }))) return;
            const created = await api(`/v1/api-keys/${k.id}/rotate`, { method: "POST" });
            await showSecret({ title: "Key rotated", description: `New key for ${k.name}`, secret: created.key });
            render();
          })),
          iconBtn("trash", "Revoke", action(async () => {
            if (!(await confirmAction(`Revoke ${k.name}?`, "Calls using this key fail immediately.", { confirmLabel: "Revoke" }))) return;
            await api(`/v1/api-keys/${k.id}`, { method: "DELETE" });
            toast("Key revoked");
            render();
          }), true)) },
      ], keys, emptyState("key", "No stored keys", "Create a runtime key for your app or agent runtime.", newBtn())),
    }));
};

// ---------------------------------------------------------------- OAuth

PAGES.oauth = async () => {
  let clients;
  try {
    clients = await api("/v1/oauth/clients");
  } catch (err) {
    if (err.status !== 404) throw err;
    return el("div", {}, pageHeader("OAuth clients", "client_credentials clients for the built-in authorization server."),
      card({ body: emptyState("lock", "Authorization server is disabled",
        "Set AUTHZ_OAUTH_AS_ENABLED=true and AUTHZ_OAUTH_ISSUER to issue OAuth tokens for your services.") }));
  }
  const keys = await api("/v1/oauth/signing-keys");
  const newBtn = () => btn("Register client", { variant: "primary", iconName: "plus", onClick: action(async () => {
    const created = await modal({
      title: "Register OAuth client", submitLabel: "Register",
      body: el("div", {},
        field("Name", input("name", { required: true, placeholder: "billing-service" })),
        field("Scope", selectEl("scope", [{ value: "runtime", label: "runtime" }, { value: "admin", label: "admin" }], "runtime"))),
      onSubmit: (fd) => api("/v1/oauth/clients", { method: "POST", body: { name: fd.get("name"), scopes: [fd.get("scope")] } }),
    });
    if (!created) return;
    await showSecret({ title: "Client registered", description: `client_id: ${created.client_id}`, secret: created.client_secret });
    render();
  }) });
  return el("div", {},
    pageHeader("OAuth clients", "Services exchange their secret at /oauth/token for short-lived JWTs.", newBtn()),
    card({
      body: table([
        { label: "Client", render: (c) => el("div", {}, el("div", { class: "cell-main" }, c.name), el("div", { class: "cell-sub" }, el("code", {}, c.client_id))) },
        { label: "Scopes", render: (c) => el("div", { class: "tags" }, c.scopes.map((s) => badge(s, "indigo"))) },
        { label: "Status", render: (c) => statusBadge(c.status) },
        { label: "Last used", render: (c) => c.last_used_at ? timeCell(c.last_used_at) : el("span", { class: "muted" }, "never") },
        { label: "", shrink: true, render: (c) => c.status === "active" && el("div", { class: "row-actions" },
          iconBtn("rotate", "Rotate secret", action(async () => {
            const created = await api(`/v1/oauth/clients/${c.client_id}/rotate`, { method: "POST" });
            await showSecret({ title: "Secret rotated", description: c.name, secret: created.client_secret });
            render();
          })),
          iconBtn("trash", "Revoke", action(async () => {
            if (!(await confirmAction(`Revoke ${c.name}?`, "Token requests with this client fail immediately.", { confirmLabel: "Revoke" }))) return;
            await api(`/v1/oauth/clients/${c.client_id}`, { method: "DELETE" });
            toast("Client revoked");
            render();
          }), true)) },
      ], clients, emptyState("lock", "No clients", "Register a client for each service that needs tokens.", newBtn())),
    }),
    card({
      title: "Signing keys", subtitle: "Also used for delegation grants. Retiring keys stay published until tokens expire.",
      actions: btn("Rotate", { small: true, iconName: "rotate", onClick: action(async () => {
        if (!(await confirmAction("Rotate the signing key?", "New tokens use a new key; the old one keeps verifying until it is pruned.", { confirmLabel: "Rotate", danger: false }))) return;
        await api("/v1/oauth/signing-keys/rotate", { method: "POST" });
        toast("Signing key rotated");
        render();
      }) }),
      body: table([
        { label: "Key id", render: (k) => idChip(k.kid, 16) },
        { label: "Algorithm", render: (k) => badge(k.alg, "", { mono: true }) },
        { label: "Status", render: (k) => statusBadge(k.status) },
        { label: "Created", render: (k) => timeCell(k.created_at) },
      ], keys, emptyState("key", "No signing keys yet", "A key is created on first use (SQLite) or with `authz oauth signing-key generate`.")),
    }));
};

boot();
