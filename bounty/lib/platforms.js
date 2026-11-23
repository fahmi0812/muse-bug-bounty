// bounty/lib/platforms.js — integrasi READ-ONLY HackerOne + Bugcrowd.
// TIDAK ada auto-submit, TIDAK ada pembayaran/deposit, TIDAK ada pengiriman
// laporan ke platform. Yang dilakukan modul ini hanya:
//   (1) baca scope program, (2) cari laporan publik (cek duplikat),
//   (3) buat DRAF laporan Markdown (dikirim manual oleh manusia).
// Token HANYA dari env (HACKERONE_TOKEN / HACKERONE_USERNAME /
// BUGCROWD_TOKEN) — tidak pernah di-hardcode, tidak pernah di-log.
//
// Status bentuk API (dicek 2026-11-23, docs resmi):
// - HackerOne scope: TERVERIFIK. Hacker API pakai HTTP Basic
//   (username + token sebagai password). Scope dibaca dari
//   GET /v1/hackers/programs/{handle} (structured_scopes tertanam di
//   respons) dengan fallback GET /v1/programs/{id}/structured_scopes.
//   Bentuk atribut: {asset_identifier, asset_type, max_severity,
//   eligible_for_bounty}. Sumber: api.hackerone.com (Resources > Programs).
// - HackerOne hacktivity: BEST-EFFORT. Tidak ada endpoint REST publik
//   resmi yang terdokumentasi untuk pencarian laporan (MCP
//   search_hacktivity memakai query Lucene, tapi HTTP di baliknya tidak
//   didokumentasikan). Implementasi memakai feed publik
//   https://hackerone.com/hacktivity.json?query=... dengan parsing
//   toleran; bila bentuk respons berubah, fungsi mengembalikan {error}.
// - Bugcrowd scope: BEST-EFFORT. Docs resmi (docs.bugcrowd.com):
//   base https://api.bugcrowd.com, auth "Authorization: Token
//   USERNAME:PASSWORD", Accept "application/vnd.bugcrowd+json", JSON:API,
//   program di /programs/{uuid}, target lewat
//   ?include=current_brief.target_groups.targets. Handle diperlakukan
//   sebagai UUID dulu; bila 404, fallback daftar /programs lalu cocokkan
//   field `code`. Bentuk filter code tidak terverifikasi.
// - Bugcrowd hacktivity: TIDAK DIDUKUNG — Bugcrowd tidak punya pencarian
//   laporan publik seperti hacktivity; cek duplikat manual di UI.
import { loadProgramFile } from "./scope.js";

const TIMEOUT_MS = 15000;

export const PLATFORMS = ["hackerone", "bugcrowd"];

// --- token (env saja) -------------------------------------------------------
function tokenFor(platform, env = process.env) {
  if (platform === "hackerone") {
    const token = String(env.HACKERONE_TOKEN ?? "").trim();
    if (!token) return { error: "token belum diset (HACKERONE_TOKEN)" };
    const username = String(env.HACKERONE_USERNAME ?? "").trim();
    if (!username) return { error: "token belum diset (HACKERONE_USERNAME)" };
    return { auth: `Basic ${Buffer.from(`${username}:${token}`).toString("base64")}` };
  }
  if (platform === "bugcrowd") {
    const token = String(env.BUGCROWD_TOKEN ?? "").trim();
    if (!token) return { error: "token belum diset (BUGCROWD_TOKEN)" };
    // Token Bugcrowd berbentuk "username:password" (lihat docs/platforms.md).
    return { auth: `Token ${token}` };
  }
  return { error: `platform tidak dikenal (${PLATFORMS.join(" | ")})` };
}

// --- HTTP helper ------------------------------------------------------------
async function apiGet(url, { headers = {}, fetchFn = globalThis.fetch } = {}) {
  let res;
  try {
    res = await fetchFn(url, {
      method: "GET",
      headers: { Accept: "application/json", ...headers },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    return { error: `gagal menghubungi ${new URL(url).host}: ${err.message}` };
  }
  if (!res.ok) return { error: `HTTP ${res.status} dari ${new URL(url).host}`, status: res.status };
  try {
    return { data: await res.json() };
  } catch {
    return { error: "respons bukan JSON" };
  }
}

// --- HackerOne --------------------------------------------------------------
// Bentuk respons program (JSON:API): data.relationships.structured_scopes.data
// atau data.attributes.structured_scopes — tiap item:
//   { attributes: { asset_identifier, asset_type, max_severity,
//                   eligible_for_bounty } }
function parseHackerOneScopes(json) {
  const data = json?.data ?? {};
  const rel = data.relationships?.structured_scopes?.data
    ?? data.attributes?.structured_scopes?.data
    ?? data.structured_scopes?.data
    ?? [];
  const assets = [];
  for (const item of rel) {
    const a = item?.attributes ?? item ?? {};
    const identifier = String(a.asset_identifier ?? a.identifier ?? "").trim();
    if (!identifier) continue;
    assets.push({
      type: String(a.asset_type ?? a.type ?? "URL").toLowerCase(),
      identifier,
      eligible: a.eligible_for_bounty !== false,
      maxSeverity: String(a.max_severity ?? "").toLowerCase() || undefined,
    });
  }
  return { assets, programId: data.id ? String(data.id) : undefined };
}

async function hackerOneScope(handle, { fetchFn, env }) {
  const tok = tokenFor("hackerone", env);
  if (tok.error) return tok;
  const base = "https://api.hackerone.com/v1";
  const first = await apiGet(`${base}/hackers/programs/${encodeURIComponent(handle)}`, {
    headers: { Authorization: tok.auth },
    fetchFn,
  });
  if (first.error) return first;
  const parsed = parseHackerOneScopes(first.data);
  if (parsed.assets.length > 0 || !parsed.programId) {
    return { platform: "hackerone", handle, assets: parsed.assets };
  }
  // Scope tidak tertanam — ambil lewat endpoint structured_scopes.
  const second = await apiGet(`${base}/programs/${encodeURIComponent(parsed.programId)}/structured_scopes`, {
    headers: { Authorization: tok.auth },
    fetchFn,
  });
  if (second.error) return second;
  const scopes = Array.isArray(second.data?.data) ? second.data.data : [];
  const assets = [];
  for (const item of scopes) {
    const a = item?.attributes ?? {};
    const identifier = String(a.asset_identifier ?? "").trim();
    if (!identifier) continue;
    assets.push({
      type: String(a.asset_type ?? "URL").toLowerCase(),
      identifier,
      eligible: a.eligible_for_bounty !== false,
      maxSeverity: String(a.max_severity ?? "").toLowerCase() || undefined,
    });
  }
  return { platform: "hackerone", handle, assets };
}

// --- Bugcrowd (best-effort, lihat header) -----------------------------------
// Bentuk JSON:API: data.attributes.current_brief.target_groups[].targets[]
// (tiap target {name}) atau resources `included` bertipe "target".
function parseBugcrowdTargets(json) {
  const data = Array.isArray(json?.data) ? json.data[0] : json?.data;
  if (!data) return [];
  const names = new Set();
  const groups = data.attributes?.current_brief?.target_groups ?? [];
  for (const g of groups) {
    for (const t of g?.targets ?? []) {
      const name = String(t?.name ?? "").trim();
      if (name) names.add(name);
    }
  }
  for (const inc of json?.included ?? []) {
    if (inc?.type === "target") {
      const name = String(inc?.attributes?.name ?? "").trim();
      if (name) names.add(name);
    }
  }
  return [...names].map((identifier) => ({ type: "url", identifier, eligible: true }));
}

async function bugcrowdScope(handle, { fetchFn, env }) {
  const tok = tokenFor("bugcrowd", env);
  if (tok.error) return tok;
  const headers = { Authorization: tok.auth, Accept: "application/vnd.bugcrowd+json" };
  const include = "include=current_brief.target_groups.targets&fields[program]=code&fields[target]=name";
  const direct = await apiGet(`https://api.bugcrowd.com/programs/${encodeURIComponent(handle)}?${include}`, { headers, fetchFn });
  if (!direct.error) {
    return { platform: "bugcrowd", handle, assets: parseBugcrowdTargets(direct.data) };
  }
  if (direct.status !== 404) return direct;
  // Handle mungkin `code`, bukan UUID — cocokkan dari daftar program.
  const list = await apiGet(`https://api.bugcrowd.com/programs?page[limit]=100&fields[program]=code`, { headers, fetchFn });
  if (list.error) return list;
  const match = (Array.isArray(list.data?.data) ? list.data.data : []).find(
    (p) => String(p?.attributes?.code ?? "").toLowerCase() === String(handle).toLowerCase()
  );
  if (!match) return { error: `program Bugcrowd tidak ditemukan: ${handle}`, status: 404 };
  const again = await apiGet(`https://api.bugcrowd.com/programs/${encodeURIComponent(match.id)}?${include}`, { headers, fetchFn });
  if (again.error) return again;
  return { platform: "bugcrowd", handle, assets: parseBugcrowdTargets(again.data) };
}

// --- API publik -------------------------------------------------------------
export async function getProgramScope(platform, handle, { fetchFn = globalThis.fetch, env = process.env } = {}) {
  if (!PLATFORMS.includes(platform)) return { error: `platform tidak dikenal (${PLATFORMS.join(" | ")})` };
  if (!handle) return { error: "handle program wajib diisi" };
  if (platform === "hackerone") return hackerOneScope(handle, { fetchFn, env });
  return bugcrowdScope(handle, { fetchFn, env });
}

// Cari laporan publik HackerOne (cek duplikat SEBELUM menulis draf).
// Best-effort: endpoint feed publik, bentuk respons bisa berubah.
// Mengembalikan {results: [{title, url, state}]} atau {error}.
export async function searchHacktivity(platform, query, { fetchFn = globalThis.fetch } = {}) {
  if (platform !== "hackerone") {
    return { error: "Bugcrowd tidak punya pencarian laporan publik; cek duplikat manual di UI Bugcrowd" };
  }
  if (!query) return { error: "query pencarian wajib diisi" };
  const url = `https://hackerone.com/hacktivity.json?query=${encodeURIComponent(query)}`;
  const res = await apiGet(url, { fetchFn });
  if (res.error) return res;
  const raw = res.data;
  const list = Array.isArray(raw) ? raw : raw?.reports ?? raw?.data ?? raw?.results ?? [];
  if (!Array.isArray(list)) {
    return { error: "format hacktivity tidak dikenali (endpoint best-effort, mungkin berubah)" };
  }
  const results = [];
  for (const r of list.slice(0, 25)) {
    const title = String(r?.title ?? r?.attributes?.title ?? "").trim();
    const id = r?.id ?? r?.attributes?.id;
    const url2 = r?.url ?? (id ? `https://hackerone.com/reports/${id}` : "");
    if (!title && !url2) continue;
    results.push({
      title: title || "(tanpa judul)",
      url: url2,
      state: String(r?.state ?? r?.attributes?.state ?? r?.substate ?? "").toLowerCase() || "disclosed",
    });
  }
  return { results };
}

// --- Draf laporan (murni, tidak mengirim apa pun) ---------------------------
// finding: {title, endpoint, vulnClass, cwe, severity, evidence, steps}
export function draftReport(finding = {}) {
  const title = String(finding.title ?? finding.vulnClass ?? "Temuan keamanan").trim();
  const endpoint = String(finding.endpoint ?? "-").trim();
  const vulnClass = String(finding.vulnClass ?? "-").trim();
  const cwe = String(finding.cwe ?? "-").trim();
  const severity = String(finding.severity ?? "medium").trim();
  const evidence = String(finding.evidence ?? "-").trim();
  const steps = String(finding.steps ?? "1. (isi langkah reproduksi dengan akun test sendiri)\n2. Amati respons yang menyimpang dari perilaku normal.").trim();
  return [
    "# DRAFT — belum dikirim, kirim manual setelah review",
    "",
    "> Draf ini dibuat otomatis oleh muse-bug-bounty untuk ditinjau manusia.",
    "> JANGAN kirim apa adanya: verifikasi dulu temuannya, lengkapi bukti,",
    "> lalu kirim manual lewat UI platform. Modul ini TIDAK pernah mengirim",
    "> laporan, dan TIDAK ada jalur auto-submit di repo ini.",
    "",
    `## Summary — ${title}`,
    "",
    `- Endpoint: \`${endpoint}\``,
    `- Kelas: ${vulnClass}`,
    `- CWE: ${cwe}`,
    `- Severity: ${severity}`,
    "",
    "## Steps to Reproduce",
    "",
    steps,
    "",
    "## Impact",
    "",
    `(isi dampak nyata dari temuan ini — data apa yang bocor / aksi apa yang bisa dilakukan penyerang.)`,
    "",
    "## Evidence",
    "",
    evidence,
    "",
    "## Remediation",
    "",
    `(isi perbaikan yang disarankan — validasi input, otorisasi, dan sebagainya.)`,
    "",
  ].join("\n");
}

// --- Bandingkan scope platform vs programs/<nama>.md (tanpa menulis) --------
function normHost(h) {
  return String(h ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0].replace(/^\*\./, "");
}

export async function syncScopeToProgram(platform, handle, programFile, { fetchFn = globalThis.fetch, env = process.env } = {}) {
  const scope = await getProgramScope(platform, handle, { fetchFn, env });
  if (scope.error) return scope;
  let program;
  try {
    program = typeof programFile === "string" ? loadProgramFile(programFile) : programFile;
  } catch (err) {
    return { error: `gagal membaca file program: ${err.message}` };
  }
  // Allowed lokal berupa host (Scope:) atau path (Allowed: /api/) — untuk
  // perbandingan scope, hanya entri berbentuk host yang dipakai; path
  // diabaikan karena scope platform bicara soal aset/host.
  const localHosts = new Set((program?.allowedHosts ?? []).map(normHost).filter(Boolean));
  const remote = new Set(scope.assets.map((a) => normHost(a.identifier)).filter(Boolean));
  const added = [...remote].filter((h) => !localHosts.has(h)).sort();
  const removed = [...localHosts].filter((h) => !remote.has(h)).sort();
  const unchanged = [...remote].filter((h) => localHosts.has(h)).sort();
  return { platform, handle, added, removed, unchanged };
}

export default { getProgramScope, searchHacktivity, draftReport, syncScopeToProgram, PLATFORMS };
