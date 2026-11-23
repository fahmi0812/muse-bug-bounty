// bounty/lib/runners.js — runner on-demand untuk scanner klasik
// (nuclei, dalfox, ffuf). Pola pemanggilan mengikuti playbook:
//   playbooks/nuclei-trufflehog-trivy.md (nuclei -jsonl, severity filter)
//   playbooks/dalfox-amass.md (dalfox --skip-bav --format json)
// Aturan keras (sama seperti bounty run):
//   - scope gate dulu: target di luar scope program -> blocked, exit 2.
//   - binary tidak ada di PATH -> { skipped: true }, BUKAN error.
//   - timeout per run; output di-parse JSON -> kandidat (status candidate).
//   - semua hasil di-dedup via lib/dedup.js SEBELUM masuk store.
//   - tidak ada auto-submit, tidak ada pembayaran, tidak ada brute force.
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { checkScope } from "./scope.js";
import { dedupCandidates } from "./dedup.js";

export const DEFAULT_TIMEOUT_MS = 120000;
export const SUPPORTED_TOOLS = ["nuclei", "dalfox", "ffuf"];

export function findBinary(name, pathEnv = process.env.PATH) {
  const pathDirs = (pathEnv || "").split(delimiter);
  for (const dir of pathDirs) {
    const p = join(dir, name);
    try { accessSync(p, constants.X_OK); return p; } catch {}
  }
  return null;
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
    vulnClass: String(f.vulnClass ?? f.vuln_class ?? "Unclassified Finding"),
    cwe: String(f.cwe ?? "").toUpperCase(),
    severity: String(f.severity ?? "medium").toLowerCase(),
    status: "candidate",
  };
}

// --- Parsers (pure, bisa di-test tanpa binary) ---

export function parseNucleiOutput(text = "") {
  const out = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(t); } catch { continue; }
    const info = item.info ?? {};
    const cwe = (info.classification?.["cwe-id"] ?? info.classification?.cwe ?? [])[0] ?? "";
    const { endpoint, param } = urlParts(item["matched-at"] ?? item.host ?? "");
    out.push(cleanFinding({
      endpoint,
      method: "GET",
      param,
      vulnClass: info.name ?? item["template-id"] ?? "Nuclei Finding",
      cwe: String(cwe).toUpperCase(),
      severity: info.severity ?? "medium",
    }));
  }
  return out;
}

export function parseDalfoxOutput(text = "") {
  let data = null;
  try { data = JSON.parse(String(text)); } catch { return []; }
  const items = Array.isArray(data) ? data : data.result ?? data.results ?? data.findings ?? [];
  const out = [];
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const rawUrl = item.url ?? item.data ?? item.target ?? "";
    const { endpoint, param } = urlParts(rawUrl);
    if (!endpoint || endpoint === "/") continue;
    out.push(cleanFinding({
      endpoint,
      method: "GET",
      param: item.param ?? param,
      vulnClass: item.type ?? item.name ?? item.vuln ?? item.kind ?? "Cross-Site Scripting (XSS)",
      cwe: item.cwe ?? "CWE-79",
      severity: item.severity ?? "medium",
    }));
  }
  return out;
}

export function parseFfufOutput(text = "") {
  let data = null;
  try { data = JSON.parse(String(text)); } catch { return []; }
  const results = data.results ?? [];
  const out = [];
  for (const item of results) {
    const rawUrl = item.url ?? "";
    const { endpoint } = urlParts(rawUrl);
    if (!endpoint || endpoint === "/") continue;
    // ffuf menemukan endpoint tersembunyi — itu kandidat enumerasi,
    // BUKAN klaim vuln. Severity low, kelas eksplisit.
    out.push(cleanFinding({
      endpoint,
      method: "GET",
      param: "",
      vulnClass: "Hidden Endpoint / Directory Enumeration",
      cwe: "",
      severity: "low",
    }));
  }
  return out;
}

const PARSERS = { nuclei: parseNucleiOutput, dalfox: parseDalfoxOutput, ffuf: parseFfufOutput };

// --- Argumen per tool (flag output JSON sesuai playbook) ---

function buildArgs(tool, target, opts = {}) {
  switch (tool) {
    case "nuclei":
      return ["-u", target, "-t", "http/technologies/", "-t", "http/vulnerabilities/",
        "-severity", "critical,high", "-rate-limit", "10", "-silent", "-jsonl"];
    case "dalfox":
      return ["url", target, "--skip-bav", "--format", "json"];
    case "ffuf": {
      // ffuf wajib -w wordlist dan -o file output JSON.
      const wordlist = opts.wordlist || process.env.FFUF_WORDLIST || "";
      if (!wordlist) return null;
      return ["-u", `${target.replace(/\/+$/, "")}/FUZZ`, "-w", wordlist,
        "-o", opts.outFile, "-of", "json", "-rate", "10", "-silent"];
    }
    default:
      return null;
  }
}

// --- Runner utama ---

export function runTool(tool, { target, program, timeoutMs = DEFAULT_TIMEOUT_MS, wordlist, env = {} } = {}) {
  const started = Date.now();
  if (!SUPPORTED_TOOLS.includes(tool)) {
    return { tool, skipped: false, error: `tool tidak dikenal: ${tool} (pilih: ${SUPPORTED_TOOLS.join(", ")})`, findings: [], duplicates: [], time_ms: 0 };
  }
  if (!target) {
    return { tool, skipped: false, error: "target tidak diberikan (--target URL)", findings: [], duplicates: [], time_ms: 0 };
  }
  // 1. Scope gate (wajib, sebelum binary dicek maupun dijalankan).
  if (program) {
    const scope = checkScope(program, target);
    if (!scope.ok) {
      return { tool, skipped: false, blocked: true, reason: scope.reason, findings: [], duplicates: [], time_ms: Date.now() - started };
    }
  }
  // 2. Binary check — tidak ada = dilewati, bukan error.
  //    PATH yang dipakai adalah env yang diteruskan (agar test dengan
  //    tool palsu bisa menyuntikkan PATH sendiri).
  const binary = findBinary(tool, env.PATH ?? process.env.PATH);
  if (!binary) {
    return { tool, skipped: true, reason: `binary ${tool} tidak ditemukan di PATH — instal dulu atau lewati`, findings: [], duplicates: [], time_ms: Date.now() - started };
  }
  // 3. ffuf butuh wordlist eksplisit.
  let tmpDir = null;
  let outFile = null;
  if (tool === "ffuf") {
    const wl = wordlist || process.env.FFUF_WORDLIST || "";
    if (!wl || !existsSync(wl)) {
      return { tool, skipped: true, reason: "ffuf butuh wordlist (--wordlist <file> atau FFUF_WORDLIST)", findings: [], duplicates: [], time_ms: Date.now() - started };
    }
    tmpDir = mkdtempSync(join(tmpdir(), "bounty-ffuf-"));
    outFile = join(tmpDir, "ffuf-out.json");
  }
  const args = buildArgs(tool, target, { wordlist, outFile });
  if (!args) {
    return { tool, skipped: true, reason: `tidak bisa membangun argumen untuk ${tool}`, findings: [], duplicates: [], time_ms: Date.now() - started };
  }
  const res = spawnSync(binary, args, { encoding: "utf8", timeout: timeoutMs, env: { ...process.env, ...env } });
  let rawText = String(res.stdout ?? "");
  if (tool === "ffuf" && outFile) {
    try { rawText = readFileSync(outFile, "utf8"); } catch { rawText = ""; }
  }
  if (tmpDir) { try { rmSync(tmpDir, { recursive: true, force: true }); } catch {} }
  if (res.error) {
    return { tool, skipped: false, error: `gagal menjalankan ${tool}: ${res.error.message}`, findings: [], duplicates: [], time_ms: Date.now() - started };
  }
  // stderr bukan error fatal untuk scanner (peringatan template dsb) —
  // yang di-parse hanya stdout (atau file output ffuf).
  const parsed = PARSERS[tool](rawText);
  const { unique, duplicates } = dedupCandidates(parsed);
  return {
    tool, skipped: false, blocked: false,
    findings: unique, duplicates,
    rawCount: parsed.length,
    time_ms: Date.now() - started,
    exit: res.status ?? 0,
  };
}

export default { runTool, parseNucleiOutput, parseDalfoxOutput, parseFfufOutput, findBinary, SUPPORTED_TOOLS };
