// bounty/lib/setup.js — logika murni untuk wizard `bounty setup`.
// Tanpa I/O dan tanpa prompt: hanya transformasi data agar mudah di-tes.
// Driver interaktif (readline) ada di bounty/bin/bounty.mjs.
import { NINE_ROUTER_BASE } from "./provider.js";

/** Buat slug aman untuk nama file dari nama/host program. */
export function slugify(name) {
  const s = String(name ?? "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .replace(/-+/g, "-");
  return s || "program";
}

/** Normalkan input host: buang skema, path, port diabaikan? (port disimpan). */
export function normalizeHost(input) {
  return String(input ?? "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
}

// Template scope: pemetaan ke daftar path Allowed.
export const SCOPE_TEMPLATES = {
  all: { label: "Seluruh situs", allowed: ["/"], denied: [] },
  api: { label: "API saja", allowed: ["/api/"], denied: [] },
  custom: { label: "Custom (tentukan path sendiri)", allowed: [], denied: [] },
};

/** Terima "1"/"2"/"3" atau "all"/"api"/"custom" -> {key,label,allowed,denied}. */
export function scopeTemplate(choice) {
  const map = { "1": "all", all: "all", "2": "api", api: "api", "3": "custom", custom: "custom" };
  const key = map[String(choice ?? "").trim().toLowerCase()];
  if (!key) return null;
  return { key, ...SCOPE_TEMPLATES[key] };
}

/** Base URL default per tipe provider. */
export function defaultProviderBase(type) {
  return String(type ?? "").toLowerCase() === "anthropic" ? "https://api.anthropic.com" : NINE_ROUTER_BASE;
}

/** Filter daftar model (substring, case-insensitive). Kosong -> semua. */
export function filterModels(models, query) {
  const list = Array.isArray(models) ? models : [];
  const q = String(query ?? "").trim().toLowerCase();
  if (!q) return list;
  return list.filter((m) => String(m).toLowerCase().includes(q));
}

/**
 * Markdown program yang kompatibel dengan parseProgram (scope.js).
 * Allowed/Denied kosong -> baris tetap ditulis dengan nilai kosong.
 */
export function buildProgramMarkdown({ name, host, allowed = ["/"], denied = [], budget = 5, rate = 10, roles = ["low", "high"] } = {}) {
  const lines = [
    `# ${String(name ?? "").trim() || "Program"}`,
    "",
    `Scope: ${String(host ?? "").trim()}`,
    `Allowed: ${(allowed ?? []).join(", ")}`,
    `Denied: ${(denied ?? []).join(", ")}`,
    `Budget: ${budget}`,
    `Rate: ${rate}`,
    `Roles: ${(roles ?? []).join(", ")}`,
    "",
    "Dibuat oleh `bounty setup`. Pastikan target punya program resmi dan kamu",
    "diizinkan mengujinya. Scope gate fail-closed — target di luar scope ditolak.",
    "",
  ];
  return lines.join("\n");
}

/**
 * URL contoh yang DIJAMIN in-scope untuk verifikasi (host + path Allowed
 * pertama). Dipakai agar langkah verifikasi tidak kontradiksi dengan
 * template (mis. "API saja" -> https://host/api/, bukan https://host/).
 */
export function exampleTargetFor(host, allowed = ["/"]) {
  const h = normalizeHost(host);
  const first = (Array.isArray(allowed) && allowed.length > 0 && allowed[0]) ? String(allowed[0]) : "/";
  const path = first.startsWith("/") ? first : `/${first}`;
  return `https://${h}${path}`;
}

export default {
  slugify,
  normalizeHost,
  SCOPE_TEMPLATES,
  scopeTemplate,
  defaultProviderBase,
  filterModels,
  buildProgramMarkdown,
  exampleTargetFor,
};
