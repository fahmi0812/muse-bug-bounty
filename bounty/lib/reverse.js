// bounty/lib/reverse.js — runner reverse engineering (headless, GATED).
// P1-3: GhidraMCP 2.0 + REA 6.8.0 + jadx. Semua runner di sini HANYA
// menganalisis file lokal yang diberikan operator, dan MENOLAK jalan
// tanpa confirmed: true (operator harus memastikan binary/APK itu
// in-scope dan boleh dianalisis). Tidak ada unduhan jarak jauh, tidak
// ada eksekusi binary target, tidak ada bypass/aktivator/jailbreak.
//
// Bentuk hasil sama seperti runners.js: {tool, skipped, blocked, error,
// findings, duplicates, rawCount, time_ms}. findings = kandidat
// (status "candidate", UNVERIFIED) dengan NILAI SECRET TIDAK PERNAH
// DISIMPAN — evidence hanya jenis + posisi (baris/offset) + nama file.
//
// Yang terverifikasi dari sumber (23 Nov 2026):
// - GhidraMCP 2.0 (LaurieWired, Apache-2.0): `ghidra-mcp --headless
//   --binary /path/to/target`, Ghidra 12.1.4 + JDK 21, server MCP stdio
//   dengan 28 tools (list_strings, list_imports, decompile_function,
//   get_xrefs_to, ...). Docs: docs.corpusiq.io (GhidraMCP).
// - REA 6.8.0 (morluto/rea, MIT; npm rea-agents): `rea analyze
//   /path/to/program --provider ghidra --json` (default format TOON,
//   pakai --json untuk JSON). Provider ghidra butuh Ghidra 12.1.x +
//   JDK 21. Docs: morluto/rea docs/cli.md.
// - jadx 1.5.7: `jadx -d <outdir> <apk>` (decompile APK ke direktori).
//
// Best-effort (belum jalan live — binary tidak ada di VM):
// - Bentuk persis hasil tools/call list_strings/list_imports GhidraMCP
//   (parser dibuat toleran: JSON array, JSONL, atau baris biasa).
// - Skema envelope JSON `rea analyze` (parser berjalan rekursif atas
//   semua nilai string; bila skema berubah, hasil tetap dibaca sebagai
//   teks). Jalankan `rea --help` + `ghidra-mcp --help` di laptop
//   sebelum percaya satu flag pun.
import { spawn, spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, join } from "node:path";
import { createInterface } from "node:readline";
import { scanText } from "./secrets.js";
import { dedupCandidates } from "./dedup.js";

export const DEFAULT_TIMEOUT_MS = 300000; // RE lambat — 5 menit.
export const GHIDRA_PIN = "12.1.4"; // GhidraMCP 2.0 + REA 6.8.0 memakai Ghidra ini.
export const REA_PIN = "6.8.0";

// Marker kripto lemah + API berbahaya di dalam string/decompile.
// `\b` di akhir TIDAK dipakai: "DES_encrypt" tidak punya word boundary
// setelah DES ("_" adalah word char). Pakai (?![A-Za-z]) supaya
// "DES_encrypt" cocok tapi "MD5CryptoHelper" tidak salah cocok.
const WEAK_CRYPTO_RE = /\b(DES|DESede|3DES|RC4|RC2|MD5|MD4|SHA1|Blowfish|AES\/ECB|ECB)(?![A-Za-z])/i;
const DANGEROUS_API_RE = /\b(strcpy|strcat|sprintf|vsprintf|gets|memcpy|system|popen|exec[lv]?|eval|rand|random)\s*\(/;
const CLEARTEXT_URL_RE = /https?:\/\/[^\s"'<>]+/i;

export function findBinary(name, pathEnv = process.env.PATH) {
  const pathDirs = (pathEnv || "").split(delimiter);
  for (const dir of pathDirs) {
    const p = join(dir, name);
    try { accessSync(p, constants.X_OK); return p; } catch {}
  }
  return null;
}

function gateError(tool) {
  return {
    tool, skipped: false, blocked: false,
    error: "RE gated: berikan confirmed: true — operator harus memastikan binary/APK ini in-scope dan boleh dianalisis.",
    findings: [], duplicates: [], rawCount: 0, time_ms: 0,
  };
}

function missingFile(tool, path) {
  return { tool, skipped: false, blocked: false, error: `file tidak ditemukan: ${path}`, findings: [], duplicates: [], rawCount: 0, time_ms: 0 };
}

function missingBinary(tool, hint) {
  return { tool, skipped: true, reason: `binary ${tool} tidak ditemukan di PATH — ${hint}`, findings: [], duplicates: [], rawCount: 0, time_ms: 0 };
}

function checkLocalInput(tool, input) {
  if (!input || typeof input !== "string") return { ok: false, error: "input file tidak diberikan" };
  if (/^https?:\/\//i.test(input.trim())) return { ok: false, error: "hanya file lokal — URL jarak jauh ditolak" };
  if (!existsSync(input)) return { ok: false, error: `file tidak ditemukan: ${input}` };
  return { ok: true };
}

// --- Parser: string Ghidra (list_strings) ---
// Terima JSON array [{address, value}] / [{string}] / ["..."], JSONL,
// atau baris biasa. Kembalikan array string (panjang >= 4).
export function parseGhidraStrings(text = "") {
  const raw = String(text ?? "").trim();
  if (!raw) return [];
  const out = [];
  const push = (s) => {
    const v = String(s ?? "").trim();
    if (v.length >= 4) out.push(v);
  };
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      for (const e of parsed) {
        if (typeof e === "string") push(e);
        else if (e && typeof e === "object") push(e.value ?? e.string ?? e.text ?? e.name ?? "");
      }
      return out;
    }
    if (parsed && typeof parsed === "object") {
      for (const v of Object.values(parsed)) if (typeof v === "string") push(v);
      return out;
    }
  } catch {}
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      const j = JSON.parse(t);
      if (typeof j === "string") { push(j); continue; }
      if (j && typeof j === "object") { push(j.value ?? j.string ?? j.text ?? ""); continue; }
    } catch {}
    push(t);
  }
  return out;
}

// --- Parser: output REA (JSON envelope atau TOON/teks) ---
// Kumpulkan semua nilai string dari JSON (rekursif, dibatasi) atau
// pakai teks mentah bila bukan JSON.
export function parseReaOutput(text = "") {
  const raw = String(text ?? "").trim();
  if (!raw) return [];
  const out = [];
  const push = (s) => {
    const v = String(s ?? "").trim();
    if (v.length >= 4) out.push(v);
  };
  try {
    const parsed = JSON.parse(raw);
    const walk = (node, depth = 0) => {
      if (out.length > 20000 || depth > 12) return;
      if (typeof node === "string") { push(node); return; }
      if (Array.isArray(node)) { for (const e of node) walk(e, depth + 1); return; }
      if (node && typeof node === "object") { for (const v of Object.values(node)) walk(v, depth + 1); }
    };
    walk(parsed);
    return out;
  } catch {}
  for (const line of raw.split("\n")) push(line);
  return out;
}

// --- Analisis string -> kandidat ---
// strings: array string (urutan = posisi). source: nama file sumber
// (basename saja — jangan pernah path lengkap berisi nama user).
// Nilai secret TIDAK PERNAH masuk evidence: hanya jenis + nomor string.
export function stringsToFindings(strings = [], source = "binary") {
  const src = basename(String(source || "binary"));
  const joined = strings.map((s) => String(s)).join("\n");
  const scanned = scanText(joined);
  const raw = [];
  const lineToIndex = (line) => Math.max(0, (line ?? 1) - 1);
  for (const m of scanned.matches) {
    const idx = lineToIndex(m.line);
    raw.push({
      endpoint: src, method: "", param: m.type,
      vulnClass: "Hardcoded Secret in Binary", cwe: "CWE-798",
      severity: "high", status: "candidate",
      evidence: `Secret jenis ${m.type} terdeteksi di string #${idx} dari ${src} (nilai TIDAK disimpan — verifikasi manual di binary).`,
    });
  }
  strings.forEach((s, i) => {
    const text = String(s);
    const crypto = text.match(WEAK_CRYPTO_RE);
    if (crypto) {
      raw.push({
        endpoint: src, method: "", param: crypto[0].toUpperCase(),
        vulnClass: "Weak Crypto in Binary", cwe: "CWE-327",
        severity: "medium", status: "candidate",
        evidence: `Marker kripto lemah "${crypto[0]}" di string #${i} dari ${src} (perlu verifikasi di decompile — marker saja bukan bukti eksploitasi).`,
      });
    }
    const api = text.match(DANGEROUS_API_RE);
    if (api) {
      raw.push({
        endpoint: src, method: "", param: api[1],
        vulnClass: "Insecure API Usage", cwe: "CWE-676",
        severity: "medium", status: "candidate",
        evidence: `Pemanggilan API berbahaya "${api[1]}" di string #${i} dari ${src} (perlu verifikasi di decompile).`,
      });
    }
    const url = text.match(CLEARTEXT_URL_RE);
    if (url && url[0].startsWith("http://")) {
      raw.push({
        endpoint: src, method: "", param: "http",
        vulnClass: "Cleartext HTTP in Binary", cwe: "CWE-319",
        severity: "low", status: "candidate",
        evidence: `URL http:// (bukan https) di string #${i} dari ${src} (host disamarkan di evidence — cek langsung di binary).`,
      });
    }
  });
  const { unique, duplicates } = dedupCandidates(raw);
  return { findings: unique, duplicates, rawCount: raw.length };
}

// --- Klien MCP stdio minimal (untuk ghidra-mcp) ---
// Kirim initialize -> notifications/initialized -> tools/call satu per
// satu, tunggu jawaban per id. Batas waktu keseluruhan timeoutMs.
async function mcpCallTools(binary, args, calls, { timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const proc = spawn(binary, args, { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
  const rl = createInterface({ input: proc.stdout });
  const pending = new Map();
  let nextId = 1;
  let stderr = "";
  proc.stderr.on("data", (d) => { stderr += String(d).slice(0, 2000); });
  const send = (msg) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("timeout menunggu jawaban MCP")); }, timeoutMs);
    pending.set(id, { resolve: (v) => { clearTimeout(timer); resolve(v); }, reject });
    proc.stdin.write(JSON.stringify({ ...msg, id }) + "\n");
  });
  rl.on("line", (line) => {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (msg && typeof msg.id === "number" && pending.has(msg.id)) {
      const { resolve } = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  });
  const deadline = Date.now() + timeoutMs;
  try {
    const init = await send({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bounty", version: "1.5.0" } } });
    if (init.error) throw new Error(`MCP initialize gagal: ${JSON.stringify(init.error).slice(0, 300)}`);
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const results = [];
    for (const { name, arguments: args2 } of calls) {
      if (Date.now() > deadline) throw new Error("timeout MCP (batas keseluruhan)");
      const res = await send({ jsonrpc: "2.0", method: "tools/call", params: { name, arguments: args2 ?? {} } });
      if (res.error) throw new Error(`tools/call ${name} gagal: ${JSON.stringify(res.error).slice(0, 300)}`);
      const content = res.result?.content ?? [];
      results.push({ name, text: content.map((c) => c.text ?? "").join("\n") });
    }
    return { results, stderr };
  } finally {
    try { proc.kill("SIGTERM"); } catch {}
    setTimeout(() => { try { proc.kill("SIGKILL"); } catch {} }, 2000).unref?.();
    rl.close();
  }
}

// --- Runner: GhidraMCP 2.0 headless ---
export async function runGhidraMcp(binaryPath, { confirmed = false, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "ghidra-mcp";
  const started = Date.now();
  if (!confirmed) return gateError(tool);
  const chk = checkLocalInput(tool, binaryPath);
  if (!chk.ok) return { ...missingFile(tool, binaryPath), error: chk.error };
  const binary = findBinary("ghidra-mcp", env.PATH ?? process.env.PATH);
  if (!binary) return missingBinary(tool, `instal dulu: pip install "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP" (butuh Ghidra ${GHIDRA_PIN} + JDK 21)`);
  try {
    const { results } = await mcpCallTools(binary, ["--headless", "--binary", binaryPath], [
      { name: "list_strings", arguments: {} },
      { name: "list_imports", arguments: {} },
    ], { timeoutMs, env });
    const stringsText = results.find((r) => r.name === "list_strings")?.text ?? "";
    const importsText = results.find((r) => r.name === "list_imports")?.text ?? "";
    const strings = [...parseGhidraStrings(stringsText), ...parseGhidraStrings(importsText)];
    const { findings, duplicates, rawCount } = stringsToFindings(strings, binaryPath);
    return { tool, skipped: false, blocked: false, findings, duplicates, rawCount, strings: strings.length, time_ms: Date.now() - started };
  } catch (e) {
    return { tool, skipped: false, blocked: false, error: `ghidra-mcp gagal: ${e.message}`, findings: [], duplicates: [], rawCount: 0, time_ms: Date.now() - started };
  }
}

// --- Runner: REA 6.8.0 ---
export function runRea(binaryPath, { confirmed = false, provider = "ghidra", timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "rea";
  const started = Date.now();
  if (!confirmed) return gateError(tool);
  const chk = checkLocalInput(tool, binaryPath);
  if (!chk.ok) return { ...missingFile(tool, binaryPath), error: chk.error };
  const binary = findBinary("rea", env.PATH ?? process.env.PATH);
  if (!binary) return missingBinary(tool, `instal dulu: npm install --global rea-agents@${REA_PIN} (butuh provider: Ghidra ${GHIDRA_PIN} + JDK 21, atau Hopper)`);
  const res = spawnSync(binary, ["analyze", binaryPath, "--provider", provider, "--json"], { encoding: "utf8", timeout: timeoutMs, env: { ...process.env, ...env } });
  if (res.error) return { tool, skipped: false, blocked: false, error: `gagal menjalankan rea: ${res.error.message}`, findings: [], duplicates: [], rawCount: 0, time_ms: Date.now() - started };
  const text = String(res.stdout ?? "") + "\n" + String(res.stderr ?? "");
  const strings = parseReaOutput(text);
  const { findings, duplicates, rawCount } = stringsToFindings(strings, binaryPath);
  return { tool, skipped: false, blocked: false, findings, duplicates, rawCount, strings: strings.length, time_ms: Date.now() - started };
}

// --- Runner: jadx (APK) ---
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

// Analisis sumber hasil decompile: per file, scanText + marker.
// Exported component dibaca dari AndroidManifest.xml.
export function parseJadxSources(files = []) {
  const raw = [];
  for (const { path, content } of files) {
    const text = String(content ?? "");
    const scanned = scanText(text);
    for (const m of scanned.matches) {
      raw.push({
        endpoint: basename(path), method: "", param: m.type,
        vulnClass: "Hardcoded Secret in Binary", cwe: "CWE-798",
        severity: "high", status: "candidate",
        evidence: `Secret jenis ${m.type} di ${basename(path)} baris ${m.line} (nilai TIDAK disimpan — verifikasi manual di sumber).`,
      });
    }
    const crypto = text.match(WEAK_CRYPTO_RE);
    if (crypto) {
      raw.push({
        endpoint: basename(path), method: "", param: crypto[0].toUpperCase(),
        vulnClass: "Weak Crypto in Binary", cwe: "CWE-327",
        severity: "medium", status: "candidate",
        evidence: `Marker kripto lemah "${crypto[0]}" di ${basename(path)} (perlu verifikasi di sumber).`,
      });
    }
    if (/AndroidManifest\.xml$/.test(path) && /android:exported\s*=\s*"true"/.test(text) && /<intent-filter/i.test(text)) {
      raw.push({
        endpoint: basename(path), method: "", param: "exported",
        vulnClass: "Exported Component", cwe: "CWE-926",
        severity: "medium", status: "candidate",
        evidence: `Komponen android:exported="true" dengan intent-filter di AndroidManifest.xml (perlu verifikasi apakah komponen itu sensitif).`,
      });
    }
  }
  const { unique, duplicates } = dedupCandidates(raw);
  return { findings: unique, duplicates, rawCount: raw.length };
}

export function runJadxApk(apkPath, { confirmed = false, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "jadx";
  const started = Date.now();
  if (!confirmed) return gateError(tool);
  const chk = checkLocalInput(tool, apkPath);
  if (!chk.ok) return { ...missingFile(tool, apkPath), error: chk.error };
  const binary = findBinary("jadx", env.PATH ?? process.env.PATH);
  if (!binary) return missingBinary(tool, "instal dulu: jadx 1.5.7 (https://github.com/skylot/jadx)");
  const outDir = mkdtempSync(join(tmpdir(), "bounty-jadx-"));
  try {
    const res = spawnSync(binary, ["-d", outDir, apkPath], { encoding: "utf8", timeout: timeoutMs, env: { ...process.env, ...env } });
    if (res.error) return { tool, skipped: false, blocked: false, error: `gagal menjalankan jadx: ${res.error.message}`, findings: [], duplicates: [], rawCount: 0, time_ms: Date.now() - started };
    const files = walkFiles(outDir)
      .filter((p) => /\.(java|kt|xml|gradle)$/i.test(p))
      .slice(0, 2000)
      .map((p) => {
        try {
          const st = statSync(p);
          if (st.size > 1024 * 1024) return null;
          return { path: p, content: readFileSync(p, "utf8") };
        } catch { return null; }
      })
      .filter(Boolean);
    const { findings, duplicates, rawCount } = parseJadxSources(files);
    return { tool, skipped: false, blocked: false, findings, duplicates, rawCount, files: files.length, outDir, time_ms: Date.now() - started };
  } finally {
    try { rmSync(outDir, { recursive: true, force: true }); } catch {}
  }
}

export default { runGhidraMcp, runRea, runJadxApk, parseGhidraStrings, parseReaOutput, parseJadxSources, stringsToFindings, findBinary };
