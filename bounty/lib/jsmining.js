// bounty/lib/jsmining.js — JS mining: jsluice + sourcemapper (P0-4).
// Menggali endpoint + secret dari bundle JavaScript target in-scope,
// lalu mengubahnya menjadi kandidat (status candidate) untuk store.
// BUKAN klaim vuln: endpoint = enumerasi (low), secret = kandidat yang
// wajib diverifikasi manual.
//
// Tool:
// - jsluice (BishopFox, go install github.com/BishopFox/jsluice/cmd/jsluice@latest):
//   mode `urls` dan `secrets`, output JSONL. Flag terverifikasi dari README
//   upstream: `jsluice <mode> [flags] [file...]`, `-o json` (output JSON),
//   `-u/--unique` (satu URL sekali per file), `-R/--resolve-paths <base>`
//   (selesaikan path relatif terhadap URL dasar), `-S/--include-source`.
//   Input boleh file lokal, URL http(s), atau stdin (`-`).
// - sourcemapper (denandz, go install github.com/denandz/sourcemapper@latest):
//   `-url <map>` (file .map langsung) atau `-jsurl <js url>` (cari
//   sourceMappingURL di JS), `-output <dir>` WAJIB. Menulis ulang source
//   asli ke direktori output.
// - getJS (003random) TIDAK di-wrap di sini: daftar URL JS didapat dari
//   katana (runner recon) atau dari URL JS yang sudah diketahui.
//
// Catatan jujur / best-effort:
// - Bentuk pasti tiap baris JSON jsluice bervariasi antar versi (field
//   `url`/`method` di mode urls; `kind`/`data`/`severity` di mode secrets).
//   Parser di bawah toleran: menerima varian field yang masuk akal dan
//   melewati baris yang tidak dikenali — jangan asumsikan satu bentuk.
// - Severity secret: `high` HANYA bila nilainya cocok pola token format
//   yang dikenal (lib/secrets.js scanText); sisanya `medium` + catatan
//   "perlu verifikasi". Nilai secret TIDAK PERNAH ditulis ke kandidat /
//   evidence / store — yang disimpan hanya jenis + catatan verifikasi.
//   Nilai mentah hanya ada di hasil `secrets` (in-memory) untuk dipakai
//   verifikator, dan wajib di-redact sebelum masuk log/laporan.
// - sourcemapper mengikuti URL apa pun yang dirujuk sebagai sourcemap di
//   dalam JS (peringatan upstream). Karena itu input JS HARUS in-scope
//   (scope gate di bawah) dan jangan jalankan terhadap JS pihak ketiga.
// - Aturan keras (sama seperti runners.js): scope gate dulu, binary tidak
//   ada -> { skipped: true } bukan error, timeout per run, dedup via
//   lib/dedup.js sebelum masuk store.
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { checkScope } from "./scope.js";
import { dedupCandidates } from "./dedup.js";
import { scanText, redact } from "./secrets.js";

export const DEFAULT_TIMEOUT_MS = 120000;

export function findBinary(name, pathEnv = process.env.PATH) {
  const pathDirs = (pathEnv || "").split(delimiter);
  for (const dir of pathDirs) {
    const p = join(dir, name);
    try { accessSync(p, constants.X_OK); return p; } catch {}
  }
  return null;
}

function isHttpUrl(s) {
  return /^https?:\/\//i.test(String(s ?? "").trim());
}

function urlParts(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return { endpoint: u.pathname || "/", param: u.searchParams.keys().next().value ?? "" };
  } catch {
    return { endpoint: String(rawUrl || "/"), param: "" };
  }
}

function cleanFinding(f) {
  const { endpoint, param } = urlParts(f.endpoint ?? "/");
  return {
    endpoint,
    method: String(f.method ?? "GET").toUpperCase(),
    param: String(f.param ?? param ?? ""),
    vulnClass: String(f.vulnClass ?? "Unclassified Finding"),
    cwe: String(f.cwe ?? "").toUpperCase(),
    severity: String(f.severity ?? "medium").toLowerCase(),
    status: "candidate",
    ...(f.evidence ? { evidence: String(f.evidence).slice(0, 500) } : {}),
  };
}

// --- Parsers (pure, bisa di-test tanpa binary) ---

// Baris JSONL mode `urls`: {"url": "/api/v1/users?role=EXPR", "method": "GET", ...}
// atau {"url": "https://api.example.com/v1/users", "type": "fetch"}.
// Baris bukan JSON / tanpa url dilewati.
export function parseJsluiceUrls(text = "", baseUrl = "") {
  const out = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(t); } catch { continue; }
    const raw = item.url ?? item.URL ?? item.path ?? "";
    if (!raw || typeof raw !== "string") continue;
    let resolved = raw;
    if (baseUrl && !/^([a-z][a-z0-9+.-]*:)?\/\//i.test(raw) && !raw.startsWith("data:") && !raw.startsWith("mailto:")) {
      try { resolved = new URL(raw, baseUrl).toString(); } catch { resolved = raw; }
    }
    if (/^(data|mailto|javascript|blob):/i.test(resolved)) continue;
    const { endpoint, param } = urlParts(resolved);
    out.push({ url: resolved, endpoint, param, method: String(item.method ?? item.type ?? "GET").toUpperCase() });
  }
  return out;
}

// Baris JSONL mode `secrets`: {"kind": "AWSAccessKey", "data": {"key": "...",
// "secret": "..."}, "severity": "high"} atau varian {"kind": "...",
// "secret": "...", "value": "...", "severity": "..."}.
// Nilai secret dikembalikan apa adanya di sini (in-memory); pemanggil
// wajib redact sebelum log/laporan/store (lihat toCandidates).
export function parseJsluiceSecrets(text = "") {
  const out = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(t); } catch { continue; }
    const kind = item.kind ?? item.type ?? item.name ?? "";
    if (!kind || typeof kind !== "string") continue;
    const data = item.data && typeof item.data === "object" ? item.data : {};
    const value = String(
      item.secret ?? item.value ?? item.token ?? data.secret ?? data.key ?? data.token ?? data.value ?? ""
    );
    if (!value) continue;
    out.push({ kind: String(kind), value, severity: item.severity ? String(item.severity).toLowerCase() : "" });
  }
  return out;
}

// Klasifikasi secret: high hanya bila cocok pola format yang dikenal
// (scanText lib/secrets.js — mis. AKIA..., sk_live_..., ghp_...).
// Sisanya medium + catatan "perlu verifikasi" (bukan klaim pasti).
export function classifySecret(secret = {}) {
  const value = String(secret.value ?? "");
  if (!value) return { severity: "medium", knownFormat: "", note: "nilai kosong — perlu verifikasi" };
  const scan = scanText(value);
  if (scan.found) {
    return { severity: "high", knownFormat: scan.matches[0]?.type ?? "", note: `format dikenal (${scan.matches[0]?.type ?? "?"}) — verifikasi kepemilikan sebelum melapor` };
  }
  return { severity: "medium", knownFormat: "", note: "format tidak dikenal — perlu verifikasi manual" };
}

// Ubah hasil parse menjadi kandidat store. Nilai secret TIDAK masuk
// evidence (hanya jenis + catatan) — secret mentah tidak boleh masuk store.
export function toCandidates({ endpoints = [], secrets = [] } = {}, jsUrl = "") {
  const { endpoint: jsEndpoint } = urlParts(jsUrl);
  const out = [];
  for (const e of endpoints) {
    const { endpoint, param } = urlParts(e.endpoint ?? e.url ?? "/");
    if (!endpoint || endpoint === "/") continue;
    out.push(cleanFinding({
      endpoint,
      method: e.method ?? "GET",
      param,
      vulnClass: "Hidden Endpoint / API Discovery",
      cwe: "",
      severity: "low",
      evidence: `ditemukan di JS ${jsEndpoint || jsUrl || "?"}`,
    }));
  }
  for (const s of secrets) {
    const cls = classifySecret(s);
    const sev = s.severity === "high" && cls.severity === "high" ? "high" : cls.severity;
    out.push(cleanFinding({
      endpoint: jsEndpoint || "/",
      method: "GET",
      param: "",
      vulnClass: "Exposed Secret in JS",
      cwe: "CWE-798",
      severity: sev,
      evidence: `jenis: ${s.kind} (${cls.knownFormat || "format tidak dikenal"}) — ${cls.note}; nilai di-redact, tidak disimpan`,
    }));
  }
  return out;
}

// --- Runner jsluice ---

export function runJsluice(jsUrlOrFile, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {}, resolvePaths = true, unique = true } = {}) {
  const started = Date.now();
  const input = String(jsUrlOrFile ?? "").trim();
  if (!input) {
    return { tool: "jsluice", skipped: false, error: "input JS tidak diberikan (URL atau file lokal)", findings: [], duplicates: [], endpoints: [], secrets: [], time_ms: 0 };
  }
  // 1. Scope gate — hanya untuk URL (file lokal adalah input pengguna).
  if (program && isHttpUrl(input)) {
    const scope = checkScope(program, input);
    if (!scope.ok) {
      return { tool: "jsluice", skipped: false, blocked: true, reason: scope.reason, findings: [], duplicates: [], endpoints: [], secrets: [], time_ms: Date.now() - started };
    }
  }
  if (!isHttpUrl(input) && !existsSync(input)) {
    return { tool: "jsluice", skipped: false, error: `file JS tidak ditemukan: ${input}`, findings: [], duplicates: [], endpoints: [], secrets: [], time_ms: Date.now() - started };
  }
  // 2. Binary check — tidak ada = dilewati, bukan error.
  const binary = findBinary("jsluice", env.PATH ?? process.env.PATH);
  if (!binary) {
    return { tool: "jsluice", skipped: true, reason: "binary jsluice tidak ditemukan di PATH — instal dulu (go install github.com/BishopFox/jsluice/cmd/jsluice@latest) atau lewati", findings: [], duplicates: [], endpoints: [], secrets: [], time_ms: Date.now() - started };
  }
  // 3. Dua mode: urls + secrets (masing-masing satu run).
  const runMode = (mode) => {
    const args = [mode, "-o", "json"];
    if (mode === "urls" && unique) args.push("-u");
    if (mode === "urls" && resolvePaths && isHttpUrl(input)) args.push("-R", input);
    args.push(input);
    const res = spawnSync(binary, args, { encoding: "utf8", timeout: timeoutMs, env: { ...process.env, ...env } });
    if (res.error) return { error: res.error.message, text: "" };
    return { error: null, text: String(res.stdout ?? "") };
  };
  const urlsRun = runMode("urls");
  const secretsRun = runMode("secrets");
  if (urlsRun.error && secretsRun.error) {
    return { tool: "jsluice", skipped: false, error: `gagal menjalankan jsluice: ${urlsRun.error}`, findings: [], duplicates: [], endpoints: [], secrets: [], time_ms: Date.now() - started };
  }
  const endpoints = parseJsluiceUrls(urlsRun.text ?? "", isHttpUrl(input) ? input : "");
  const secrets = parseJsluiceSecrets(secretsRun.text ?? "");
  const parsed = toCandidates({ endpoints, secrets }, isHttpUrl(input) ? input : "");
  const { unique: uniqueFindings, duplicates } = dedupCandidates(parsed);
  return {
    tool: "jsluice", skipped: false, blocked: false,
    findings: uniqueFindings, duplicates,
    endpoints, secrets,
    rawCount: parsed.length,
    time_ms: Date.now() - started,
  };
}

// --- Runner sourcemapper ---

function walkFiles(dir, out = []) {
  let entries = [];
  try { entries = readdirSync(dir); } catch { return out; }
  for (const e of entries) {
    const p = join(dir, e);
    let st = null;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) walkFiles(p, out);
    else if (st.isFile()) out.push(p);
  }
  return out;
}

export function runSourcemapper(jsUrl, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {}, mapUrl = "", outputDir = "" } = {}) {
  const started = Date.now();
  const input = String(jsUrl ?? "").trim();
  const map = String(mapUrl ?? "").trim();
  if (!input && !map) {
    return { tool: "sourcemapper", skipped: false, error: "URL JS (-jsurl) atau URL .map (-url) tidak diberikan", files: [], outDir: "", time_ms: 0 };
  }
  // 1. Scope gate — URL JS dan URL .map harus in-scope.
  if (program) {
    for (const u of [input, map].filter(Boolean)) {
      if (!isHttpUrl(u)) continue;
      const scope = checkScope(program, u);
      if (!scope.ok) {
        return { tool: "sourcemapper", skipped: false, blocked: true, reason: scope.reason, files: [], outDir: "", time_ms: Date.now() - started };
      }
    }
  }
  // 2. Binary check — tidak ada = dilewati, bukan error.
  const binary = findBinary("sourcemapper", env.PATH ?? process.env.PATH);
  if (!binary) {
    return { tool: "sourcemapper", skipped: true, reason: "binary sourcemapper tidak ditemukan di PATH — instal dulu (go install github.com/denandz/sourcemapper@latest) atau lewati", files: [], outDir: "", time_ms: Date.now() - started };
  }
  // 3. Output dir: pakai yang diberikan, atau temp dir (dipertahankan
  //    bila ada file hasil, supaya pemanggil bisa memeriksa sumbernya).
  let outDir = String(outputDir ?? "").trim();
  let tmpCreated = false;
  if (!outDir) {
    outDir = mkdtempSync(join(tmpdir(), "bounty-sourcemap-"));
    tmpCreated = true;
  }
  const args = map ? ["-url", map, "-output", outDir] : ["-jsurl", input, "-output", outDir];
  const res = spawnSync(binary, args, { encoding: "utf8", timeout: timeoutMs, env: { ...process.env, ...env } });
  const files = walkFiles(outDir);
  if (res.error) {
    if (tmpCreated && files.length === 0) { try { rmSync(outDir, { recursive: true, force: true }); } catch {} }
    return { tool: "sourcemapper", skipped: false, error: `gagal menjalankan sourcemapper: ${res.error.message}`, files: [], outDir: tmpCreated ? "" : outDir, time_ms: Date.now() - started };
  }
  if (files.length === 0 && tmpCreated) { try { rmSync(outDir, { recursive: true, force: true }); } catch {} }
  return {
    tool: "sourcemapper", skipped: false, blocked: false,
    files, outDir: files.length === 0 && tmpCreated ? "" : outDir,
    findings: [],
    note: files.length === 0
      ? "tidak ada source map ditemukan (atau JS tidak merujuk .map) — bukan error"
      : `${files.length} file sumber asli diekstrak — jalankan jsluice ke file-file ini untuk mining lanjutan`,
    time_ms: Date.now() - started,
  };
}

export default { runJsluice, runSourcemapper, parseJsluiceUrls, parseJsluiceSecrets, classifySecret, toCandidates, findBinary };
export { redact };
