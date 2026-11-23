// bounty/lib/recon.js — pipeline recon P0-3 (subfinder -> dnsx -> httpx ->
// katana -> nuclei KEV) + sumber pasif crt.sh. Thin wrapper di atas binary
// ProjectDiscovery + crt.sh; TIDAK menggantikan runner di lib/runners.js
// (file ini baru, runners.js tidak disentuh).
// Kontrak sama seperti runTool (lib/runners.js):
//   - scope gate dulu: domain/target di luar scope program -> blocked.
//   - binary tidak ada di PATH -> { skipped: true }, BUKAN error.
//   - timeout per run; output di-parse -> hasil recon (bukan klaim vuln).
//   - hasil di-dedup via lib/dedup.js SEBELUM masuk store.
//   - recon pasif (crt.sh, subfinder) tidak menyentuh target; aktif
//     (httpx, katana, nuclei) HANYA ke target dalam scope.
// Catatan jujur per flag (best-effort, belum semua terverifikasi live
// di mesin ini karena binary PD tidak terinstal di VM):
//   - subfinder: `-d <domain> -silent -json` (JSON lines ke stdout);
//     parser juga menerima baris biasa bila -json tidak didukung.
//   - dnsx: `-json -resp -silent`, daftar host via stdin.
//   - httpx: `-json -tech-detect -silent`, daftar host/URL via stdin.
//   - katana: `-u <target> -jsonl -silent` (depth default 3).
//   - nuclei KEV: `-u <target> -tags kev -jsonl -silent` (template
//     bertag kev di nuclei-templates); `-update-templates` untuk
//     memperbarui template. Versi template di-parse best-effort dari
//     stdout (regex vX.Y.Z).
//   - crt.sh: GET https://crt.sh/?q=%.domain&output=json (API publik,
//     tanpa kunci). Rate limit tidak didokumentasikan — panggil sekali
//     per domain, jangan loop rapat.
import { spawnSync } from "node:child_process";
import { checkScope } from "./scope.js";
import { dedupCandidates } from "./dedup.js";
import { findBinary, parseNucleiOutput, DEFAULT_TIMEOUT_MS } from "./runners.js";

export const RECON_TOOLS = ["subfinder", "dnsx", "httpx", "katana", "nuclei-kev", "crtsh"];
export { DEFAULT_TIMEOUT_MS };

function domainTarget(domain) {
  return `https://${String(domain).replace(/^https?:\/\//, "").split("/")[0]}/`;
}

// Scope level host saja (untuk enum domain: subfinder/dnsx/crt.sh).
// Path-level gate (Allowed/Denied) tidak berlaku di level domain —
// path baru dicek saat ada URL lengkap (httpx/katana/nuclei-kev).
function hostInScope(program, domain) {
  if (!program) return { ok: true, reason: "tanpa program — scope tidak dicek" };
  if (!Array.isArray(program.allowedHosts) || program.allowedHosts.length === 0) {
    return { ok: false, reason: "program tanpa scope (allowedHosts kosong) — tolak" };
  }
  const h = String(domain).toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  const ok = program.allowedHosts.some((a) => {
    const x = String(a).toLowerCase();
    return h === x || h.endsWith(`.${x}`);
  });
  return ok
    ? { ok: true, reason: "Scope OK (host)" }
    : { ok: false, reason: `host ${h} di luar scope (${program.allowedHosts.join(", ")})` };
}

function scopeCheck(program, target) {
  if (!program) return { ok: true, reason: "tanpa program — scope tidak dicek" };
  return checkScope(program, target);
}

function runBinary(tool, binary, args, { timeoutMs, env = {}, input } = {}) {
  const started = Date.now();
  const res = spawnSync(binary, args, {
    encoding: "utf8",
    timeout: timeoutMs ?? DEFAULT_TIMEOUT_MS,
    env: { ...process.env, ...env },
    ...(input !== undefined ? { input } : {}),
  });
  if (res.error) {
    return { tool, skipped: false, error: `gagal menjalankan ${tool}: ${res.error.message}`, results: [], findings: [], duplicates: [], time_ms: Date.now() - started };
  }
  return { rawText: String(res.stdout ?? ""), exit: res.status ?? 0, time_ms: Date.now() - started };
}

function missing(tool) {
  return { tool, skipped: true, reason: `binary ${tool} tidak ditemukan di PATH — instal dulu atau lewati`, results: [], findings: [], duplicates: [], time_ms: 0 };
}

function blocked(tool, reason) {
  return { tool, skipped: false, blocked: true, reason, results: [], findings: [], duplicates: [], time_ms: 0 };
}

// --- Parsers (pure, bisa di-test tanpa binary) ---

export function parseSubfinderOutput(text = "") {
  const out = [];
  const seen = new Set();
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let host = "";
    if (t.startsWith("{")) {
      try { host = JSON.parse(t).host ?? ""; } catch { continue; }
    } else {
      host = t.split(/\s+/)[0];
    }
    host = String(host).toLowerCase().replace(/^\*\./, "").trim();
    if (!host || seen.has(host)) continue;
    seen.add(host);
    out.push({ subdomain: host, source: "subfinder" });
  }
  return out;
}

export function parseDnsxOutput(text = "") {
  const out = [];
  const seen = new Set();
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(t); } catch { continue; }
    const host = String(item.host ?? "").toLowerCase();
    if (!host || seen.has(host)) continue;
    seen.add(host);
    const ips = [...(item.a ?? []), ...(item.aaaa ?? [])].map(String);
    out.push({ host, ips, status: item.status_code ?? null, source: "dnsx" });
  }
  return out;
}

export function parseHttpxOutput(text = "") {
  const out = [];
  const seen = new Set();
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(t); } catch { continue; }
    const url = String(item.url ?? item.input ?? "");
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({
      url,
      status: item.status_code ?? null,
      title: String(item.title ?? ""),
      tech: [...(item.tech ?? [])].map(String),
      contentLength: item.content_length ?? null,
      source: "httpx",
    });
  }
  return out;
}

export function parseKatanaOutput(text = "") {
  const out = [];
  const seen = new Set();
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(t); } catch { continue; }
    const req = item.request ?? item;
    const url = String(req.url ?? item.url ?? "");
    if (!url || seen.has(url)) continue;
    seen.add(url);
    let endpoint = "/";
    let param = "";
    try {
      const u = new URL(url);
      endpoint = u.pathname || "/";
      param = u.searchParams.keys().next().value ?? "";
    } catch { endpoint = url; }
    out.push({
      url,
      endpoint,
      method: String(req.method ?? "GET").toUpperCase(),
      param,
      tag: String(req.tag ?? item.tag ?? ""),
      source: "katana",
    });
  }
  return out;
}

export function parseCrtshOutput(text = "") {
  let data;
  try { data = JSON.parse(String(text)); } catch { return []; }
  if (!Array.isArray(data)) return [];
  const seen = new Set();
  const out = [];
  for (const cert of data) {
    const names = String(cert.name_value ?? "").split("\n");
    for (const raw of names) {
      const name = raw.trim().toLowerCase().replace(/^\*\./, "");
      if (!name || seen.has(name)) continue;
      seen.add(name);
      out.push({ subdomain: name, source: "crt.sh" });
    }
  }
  return out;
}

// --- Runners ---

export function runSubfinder(domain, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "subfinder";
  if (!domain) return { tool, skipped: false, error: "domain tidak diberikan", results: [], findings: [], duplicates: [], time_ms: 0 };
  const scope = hostInScope(program, domain);
  if (!scope.ok) return blocked(tool, scope.reason);
  const binary = findBinary(tool, env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const run = runBinary(tool, binary, ["-d", domain, "-silent", "-json"], { timeoutMs, env });
  if (run.error) return run;
  const results = parseSubfinderOutput(run.rawText);
  return { tool, skipped: false, blocked: false, results, findings: [], duplicates: [], rawCount: results.length, time_ms: run.time_ms, exit: run.exit };
}

export function runDnsx(input, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "dnsx";
  const hosts = (Array.isArray(input) ? input : [input]).filter(Boolean).map(String);
  if (!hosts.length) return { tool, skipped: false, error: "daftar host kosong", results: [], findings: [], duplicates: [], time_ms: 0 };
  if (program) {
    for (const h of hosts) {
      const scope = hostInScope(program, h);
      if (!scope.ok) return blocked(tool, scope.reason);
    }
  }
  const binary = findBinary(tool, env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const run = runBinary(tool, binary, ["-json", "-resp", "-silent"], { timeoutMs, env, input: hosts.join("\n") + "\n" });
  if (run.error) return run;
  const results = parseDnsxOutput(run.rawText);
  return { tool, skipped: false, blocked: false, results, findings: [], duplicates: [], rawCount: results.length, time_ms: run.time_ms, exit: run.exit };
}

export function runHttpx(input, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "httpx";
  const targets = (Array.isArray(input) ? input : [input]).filter(Boolean).map(String);
  if (!targets.length) return { tool, skipped: false, error: "daftar target kosong", results: [], findings: [], duplicates: [], time_ms: 0 };
  if (program) {
    for (const t of targets) {
      const scope = checkScope(program, t.startsWith("http") ? t : domainTarget(t));
      if (!scope.ok) return blocked(tool, scope.reason);
    }
  }
  const binary = findBinary(tool, env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const run = runBinary(tool, binary, ["-json", "-tech-detect", "-silent"], { timeoutMs, env, input: targets.join("\n") + "\n" });
  if (run.error) return run;
  const results = parseHttpxOutput(run.rawText);
  return { tool, skipped: false, blocked: false, results, findings: [], duplicates: [], rawCount: results.length, time_ms: run.time_ms, exit: run.exit };
}

export function runKatana(target, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "katana";
  if (!target) return { tool, skipped: false, error: "target tidak diberikan", results: [], findings: [], duplicates: [], time_ms: 0 };
  const scope = scopeCheck(program, target);
  if (!scope.ok) return blocked(tool, scope.reason);
  const binary = findBinary(tool, env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const run = runBinary(tool, binary, ["-u", target, "-jsonl", "-silent"], { timeoutMs, env });
  if (run.error) return run;
  const results = parseKatanaOutput(run.rawText);
  // Endpoint katana masuk bentuk endpoint table (bukan klaim vuln).
  const { unique, duplicates } = dedupCandidates(results.map((r) => ({
    endpoint: r.endpoint, method: r.method, param: r.param,
    vulnClass: "Crawled Endpoint", cwe: "", severity: "info",
  })));
  return { tool, skipped: false, blocked: false, results, findings: unique, duplicates, rawCount: results.length, time_ms: run.time_ms, exit: run.exit };
}

export function runNucleiKev(target, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "nuclei-kev";
  if (!target) return { tool, skipped: false, error: "target tidak diberikan", results: [], findings: [], duplicates: [], time_ms: 0 };
  const scope = scopeCheck(program, target);
  if (!scope.ok) return blocked(tool, scope.reason);
  const binary = findBinary("nuclei", env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const run = runBinary(tool, binary, ["-u", target, "-tags", "kev", "-jsonl", "-silent"], { timeoutMs, env });
  if (run.error) return run;
  const parsed = parseNucleiOutput(run.rawText);
  const { unique, duplicates } = dedupCandidates(parsed);
  return { tool, skipped: false, blocked: false, results: unique, findings: unique, duplicates, rawCount: parsed.length, time_ms: run.time_ms, exit: run.exit };
}

export function updateNucleiTemplates({ timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "nuclei-update-templates";
  const binary = findBinary("nuclei", env.PATH ?? process.env.PATH);
  if (!binary) return { tool, skipped: true, reason: "binary nuclei tidak ditemukan di PATH — instal dulu atau lewati", updated: false, version: null, time_ms: 0 };
  const run = runBinary(tool, binary, ["-update-templates"], { timeoutMs, env });
  if (run.error) return { ...run, updated: false, version: null };
  const m = String(run.rawText).match(/v?\d+\.\d+\.\d+/);
  return { tool, skipped: false, updated: true, version: m ? m[0] : null, output: run.rawText.slice(0, 2000), time_ms: run.time_ms, exit: run.exit };
}

// --- Pasif: crt.sh (tanpa binary, tanpa menyentuh target) ---

export async function crtsh(domain, { program, fetchFn = globalThis.fetch } = {}) {
  const tool = "crtsh";
  if (!domain) return { tool, skipped: false, error: "domain tidak diberikan", results: [], time_ms: 0 };
  const scope = hostInScope(program, domain);
  if (!scope.ok) return blocked(tool, scope.reason);
  const started = Date.now();
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  try {
    const res = await fetchFn(url);
    if (!res.ok) return { tool, skipped: false, error: `crt.sh HTTP ${res.status}`, results: [], time_ms: Date.now() - started };
    const text = await res.text();
    const results = parseCrtshOutput(text);
    return { tool, skipped: false, blocked: false, results, rawCount: results.length, time_ms: Date.now() - started };
  } catch (e) {
    return { tool, skipped: false, error: `crt.sh gagal: ${e.message}`, results: [], time_ms: Date.now() - started };
  }
}

export default {
  runSubfinder, runDnsx, runHttpx, runKatana, runNucleiKev,
  updateNucleiTemplates, crtsh,
  parseSubfinderOutput, parseDnsxOutput, parseHttpxOutput,
  parseKatanaOutput, parseCrtshOutput, RECON_TOOLS,
};
