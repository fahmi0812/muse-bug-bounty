// bounty/lib/firmware.js — firmware light path (P2-1).
// binwalk-ng 4.0 + unblob 26.6.x + cve-bin-tool 3.4 (SBOM + CVE scan).
// Semua runner di sini HANYA menganalisis file firmware lokal yang
// diberikan operator. Tidak ada unduhan jarak jauh, tidak ada eksekusi
// binary target, tidak ada bypass/aktivator/jailbreak.
//
// Bentuk hasil sama seperti runners.js/reverse.js:
//   {tool, skipped, blocked, error, findings, duplicates, rawCount, time_ms}
// findings = kandidat (status "candidate", UNVERIFIED). Temuan binwalk /
// unblob adalah INFO permukaan (komponen/file yang ditemukan), BUKAN klaim
// vuln. Temuan cve-bin-tool adalah "CVE dikenal di komponen" — CVE di
// komponen BUKAN bukti komponen itu reachable/exploitable di firmware
// ini; verifikasi manual wajib sebelum melapor (lihat docs/firmware.md).
//
// EMBA SENGAJA TIDAK DI-WIRE: EMBA butuh ~20 GB image Docker dan
// 14–25 jam per image (MDPI 2026) — itu menghancurkan model $5/target
// dan "ringan seperti Lumitome". EMBA hanya opt-in semalam (overnight)
// via Docker, prosedurnya ada di docs/firmware.md, bukan runner default.
//
// Yang terverifikasi dari sumber (23 Nov 2026):
// - binwalk-ng 4.0.0 (fork MIT dari binwalk v3, rilis crates.io 29 Sep
//   2026): perintah tetap `binwalk`, opsi sama seperti 3.1.1 minus `-s`
//   (stdin), plus `--no-mmap`; 114 signature, 75 bisa diekstrak.
//   `-B` scan signature, `-e` extract, `-M` matryoshka (rekursif),
//   `-C <dir>` direktori output, `-d <n>` batas kedalaman, `-n` batas
//   jumlah file, `-j` batas ukuran tiap file, `--log <file>` JSON.
//   `-J` adalah flag JSON binwalk v2 — JANGAN dipakai di v3/ng.
//   Sumber: binwalk.sh/binwalk-alternatives, crates.io binwalk-ng.
// - unblob 26.6.4 (ONEKEY, MIT, Python 3.10+): `unblob -e <dir> <file>`
//   (rekursif default, kedalaman 10, `-d` ubah kedalaman),
//   `--report <file.json>` laporan JSON (chunk, offset, entropi, hash,
//   tipe file). Output default `<file>_extract/`. Sandbox Landlock di
//   Linux (`--no-sandbox` mematikannya — JANGAN dipakai).
//   Sumber: pypi.org/project/unblob, unblob.org.
// - cve-bin-tool 3.4 (MIT): `cve-bin-tool <dir/file>`; `-f json
//   -o <report.json>` laporan JSON; `--offline` tanpa jaringan;
//   `--sbom-type cyclonedx --sbom-format json --sbom-output <sbom.json>`
//   hasilkan SBOM; `--sbom-file <sbom>` pindai SBOM yang sudah ada.
//   Data default dari mirror NVD https://cveb.in/ (sejak 3.3).
//   Sumber: cve-bin-tool.readthedocs.io (v3.4), PyPI cve-bin-tool.
//
// Best-effort (belum jalan live — binary tidak ada di VM):
// - Bentuk persis JSON `--log` binwalk-ng dan `--report` unblob
//   (parser dibuat toleran: JSON array/objek, atau teks tabel binwalk
//   klasik sebagai fallback; field tak dikenal dilewati).
// - Bentuk persis JSON cve-bin-tool (parser menerima bentuk objek
//   ber-kunci produk DAN bentuk array; field `cwe` tidak selalu ada).
// - Exit code cve-bin-tool saat CVE ditemukan (parser tidak bergantung
//   pada exit code: laporan ada + bisa di-parse = sukses).
// Jalankan `binwalk --help`, `unblob --help`, `cve-bin-tool --help` di
// laptop sebelum percaya satu flag pun.
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, join } from "node:path";
import { dedupCandidates } from "./dedup.js";

export const DEFAULT_TIMEOUT_MS = 600000; // Ekstraksi firmware lambat — 10 menit.
export const BINWALK_PIN = "4.0"; // binwalk-ng.
export const UNBLOB_PIN = "26.6.4";
export const CVE_BIN_TOOL_PIN = "3.4";

export function findBinary(name, pathEnv = process.env.PATH) {
  const pathDirs = (pathEnv || "").split(delimiter);
  for (const dir of pathDirs) {
    const p = join(dir, name);
    try { accessSync(p, constants.X_OK); return p; } catch {}
  }
  return null;
}

function missingBinary(tool, hint) {
  return { tool, skipped: true, reason: `binary ${tool} tidak ditemukan di PATH — ${hint}`, findings: [], duplicates: [], rawCount: 0, time_ms: 0 };
}

function inputError(tool, message) {
  return { tool, skipped: false, blocked: false, error: message, findings: [], duplicates: [], rawCount: 0, time_ms: 0 };
}

function checkLocalInput(tool, input) {
  if (!input || typeof input !== "string") return { ok: false, error: "input file tidak diberikan" };
  if (/^https?:\/\//i.test(input.trim())) return { ok: false, error: "hanya file lokal — URL jarak jauh ditolak" };
  if (!existsSync(input)) return { ok: false, error: `file tidak ditemukan: ${input}` };
  return { ok: true };
}

function runBinary(binary, args, { timeoutMs, env = {} } = {}) {
  const started = Date.now();
  const res = spawnSync(binary, args, {
    encoding: "utf8",
    timeout: timeoutMs ?? DEFAULT_TIMEOUT_MS,
    env: { ...process.env, ...env },
  });
  return { res, timeMs: Date.now() - started };
}

function finish(tool, findings, { timeMs, rawCount, outDir = null, reportFile = null } = {}) {
  const { unique, duplicates } = dedupCandidates(findings);
  return { tool, skipped: false, blocked: false, findings: unique, duplicates, rawCount: rawCount ?? findings.length, time_ms: timeMs, ...(outDir ? { outDir } : {}), ...(reportFile ? { reportFile } : {}) };
}

// --- Parser: binwalk ---
// Teks tabel klasik binwalk:
//   DECIMAL       HEXADECIMAL     DESCRIPTION
//   0             0x0             U-Boot version string...
//   131136        0x20040         SquashFS filesystem, little endian...
export function parseBinwalkText(text = "") {
  const out = [];
  for (const line of String(text ?? "").split("\n")) {
    const m = line.match(/^\s*(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+?)\s*$/);
    if (!m) continue;
    out.push({ offset: Number(m[1]), offsetHex: `0x${m[2]}`.toLowerCase(), description: m[3].trim() });
  }
  return out;
}

// JSON --log binwalk v3/ng: array objek (atau objek ber-kunci "results").
// Field offset/description bervariasi antar versi — parser toleran.
export function parseBinwalkJson(data) {
  let list = data;
  if (data && typeof data === "object" && !Array.isArray(data)) {
    list = data.results ?? data.signatures ?? data.matches ?? [];
  }
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const item of list) {
    if (typeof item === "string") {
      const parsed = parseBinwalkText(item);
      out.push(...parsed);
      continue;
    }
    if (!item || typeof item !== "object") continue;
    const offset = Number(item.offset ?? item.decimal ?? item.start_offset ?? NaN);
    const desc = String(item.description ?? item.type ?? item.name ?? "").trim();
    if (!desc && Number.isNaN(offset)) continue;
    out.push({
      offset: Number.isNaN(offset) ? 0 : offset,
      offsetHex: `0x${(Number.isNaN(offset) ? 0 : offset).toString(16)}`,
      description: desc,
    });
  }
  return out;
}

function binwalkFindings(imagePath, signatures) {
  const base = basename(imagePath);
  return signatures.map((s) => ({
    endpoint: base,
    method: "firmware",
    param: s.offsetHex,
    vulnClass: "Firmware Component",
    cwe: "",
    severity: "low",
    evidence: `${s.description} (offset ${s.offsetHex})`,
  }));
}

export function runBinwalkNg(imagePath, { outputDir = null, recursive = true, depth = 3, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "binwalk";
  const checked = checkLocalInput(tool, imagePath);
  if (!checked.ok) return inputError(tool, checked.error);
  const binary = findBinary("binwalk", env.PATH ?? process.env.PATH);
  if (!binary) return missingBinary(tool, "instal binwalk-ng 4.0 (cargo install binwalk-ng) atau image ghcr.io/binwalk-ng/binwalk-ng:main");
  const outDir = outputDir || mkdtempSync(join(tmpdir(), "bounty-binwalk-"));
  const logFile = join(mkdtempSync(join(tmpdir(), "bounty-binwalk-log-")), "results.json");
  const args = ["-B", "-e", ...(recursive ? ["-M", "-d", String(depth)] : []), "-n", "5000", "-j", "268435456", "-C", outDir, "--log", logFile, imagePath];
  const { res, timeMs } = runBinary(binary, args, { timeoutMs, env });
  if (res.error) return inputError(tool, `gagal menjalankan binwalk: ${res.error.message}`);
  let signatures = [];
  try {
    if (existsSync(logFile)) signatures = parseBinwalkJson(JSON.parse(readFileSync(logFile, "utf8")));
  } catch {}
  if (signatures.length === 0) signatures = parseBinwalkText(String(res.stdout ?? ""));
  return finish(tool, binwalkFindings(imagePath, signatures), { timeMs, rawCount: signatures.length, outDir, reportFile: existsSync(logFile) ? logFile : null });
}

// --- Parser: unblob --report ---
// Laporan JSON unblob: objek (dengan "chunks"/"files") atau array.
// Tiap chunk/file idealnya punya path + ukuran + tipe; parser berjalan
// rekursif dan mengumpulkan semua objek yang punya path string.
export function parseUnblobReport(data) {
  const out = [];
  const seen = new Set();
  const walk = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { for (const item of node) walk(item); return; }
    const p = node.path ?? node.file_path ?? node.filename ?? node.name;
    if (typeof p === "string" && p && !seen.has(p)) {
      seen.add(p);
      out.push({
        path: p,
        size: Number(node.size ?? node.file_size ?? 0) || 0,
        type: String(node.chunk_type ?? node.file_type ?? node.magic ?? node.type ?? "").trim(),
        startOffset: node.start_offset ?? node.offset ?? null,
      });
      return;
    }
    for (const v of Object.values(node)) walk(v);
  };
  walk(data);
  return out;
}

function listExtractedFiles(dir, cap = 2000) {
  const out = [];
  const walk = (d) => {
    if (out.length >= cap) return;
    let entries = [];
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= cap) break;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) out.push(p);
    }
  };
  walk(dir);
  return out;
}

export function runUnblob(imagePath, { outputDir = null, depth = 10, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "unblob";
  const checked = checkLocalInput(tool, imagePath);
  if (!checked.ok) return inputError(tool, checked.error);
  const binary = findBinary("unblob", env.PATH ?? process.env.PATH);
  if (!binary) return missingBinary(tool, "instal unblob 26.6.4 (pipx install unblob)");
  const outDir = outputDir || mkdtempSync(join(tmpdir(), "bounty-unblob-"));
  const reportFile = join(mkdtempSync(join(tmpdir(), "bounty-unblob-log-")), "report.json");
  const args = ["-e", outDir, "-d", String(depth), "--report", reportFile, imagePath];
  const { res, timeMs } = runBinary(binary, args, { timeoutMs, env });
  if (res.error) return inputError(tool, `gagal menjalankan unblob: ${res.error.message}`);
  let extracted = [];
  try {
    if (existsSync(reportFile)) extracted = parseUnblobReport(JSON.parse(readFileSync(reportFile, "utf8")));
  } catch {}
  if (extracted.length === 0) {
    // Fallback: daftar file hasil ekstraksi di direktori output.
    extracted = listExtractedFiles(outDir).map((p) => ({ path: p, size: 0, type: "", startOffset: null }));
  }
  const base = basename(imagePath);
  const findings = extracted.map((f) => ({
    endpoint: base,
    method: "firmware",
    param: f.path,
    vulnClass: "Extracted Firmware File",
    cwe: "",
    severity: "low",
    evidence: `${f.path}${f.size ? ` (${f.size} byte)` : ""}${f.type ? ` — ${f.type}` : ""}`,
  }));
  return finish(tool, findings, { timeMs, rawCount: extracted.length, outDir, reportFile: existsSync(reportFile) ? reportFile : null });
}

// --- Parser: cve-bin-tool JSON ---
// Bentuk objek: { produk: { versi: { cves: [{cve_number, severity,
// score, cvss_version, description}] } } } — atau bentuk array:
// [{product, version, cve_number, severity, score, ...}].
// Field `cwe` tidak selalu ada ("" bila tidak ada).
const SEVERITY_MAP = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", UNKNOWN: "low", NONE: "low" };

export function parseCveBinToolJson(data) {
  const cves = [];
  const pushCve = (product, version, c) => {
    if (!c || typeof c !== "object") return;
    const id = String(c.cve_number ?? c.cve ?? c.id ?? "").trim();
    if (!/^CVE-\d{4}-\d+$/i.test(id)) return;
    const sev = SEVERITY_MAP[String(c.severity ?? "").toUpperCase()] ?? "low";
    const score = Number(c.score ?? c.cvss_score ?? NaN);
    cves.push({
      cve: id.toUpperCase(),
      product: String(product ?? c.product ?? ""),
      version: String(version ?? c.version ?? ""),
      severity: sev,
      score: Number.isNaN(score) ? null : score,
      cwe: String(c.cwe ?? "").trim(),
      description: String(c.description ?? "").trim().slice(0, 500),
    });
  };
  const walkVersion = (product, version, node) => {
    if (Array.isArray(node)) { for (const c of node) pushCve(product, version, c); return; }
    if (!node || typeof node !== "object") return;
    if (node.cves) { walkVersion(product, version, node.cves); return; }
    if (node.cve_number || node.cve) { pushCve(product, version, node); return; }
    for (const [v, sub] of Object.entries(node)) walkVersion(product, v, sub);
  };
  if (Array.isArray(data)) {
    for (const item of data) {
      if (!item || typeof item !== "object") continue;
      if (item.cve_number || item.cve) pushCve(item.product, item.version, item);
      else for (const [prod, sub] of Object.entries(item)) walkVersion(prod, "", sub);
    }
  } else if (data && typeof data === "object") {
    for (const [product, sub] of Object.entries(data)) walkVersion(product, "", sub);
  }
  return cves;
}

export function runCveBinTool(target, { offline = true, sbomFile = null, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "cve-bin-tool";
  const checked = checkLocalInput(tool, target);
  if (!checked.ok) return inputError(tool, checked.error);
  const binary = findBinary("cve-bin-tool", env.PATH ?? process.env.PATH);
  if (!binary) return missingBinary(tool, "instal cve-bin-tool 3.4 (pipx install cve-bin-tool)");
  const reportFile = join(mkdtempSync(join(tmpdir(), "bounty-cvebintool-")), "cve-report.json");
  const args = [];
  if (sbomFile) args.push("--sbom", "cyclonedx", "--sbom-file", sbomFile);
  if (offline) args.push("--offline");
  args.push("-f", "json", "-o", reportFile, target);
  const { res, timeMs } = runBinary(binary, args, { timeoutMs, env });
  if (res.error) return inputError(tool, `gagal menjalankan cve-bin-tool: ${res.error.message}`);
  if (!existsSync(reportFile)) {
    const stderr = String(res.stderr ?? "").trim().slice(0, 500);
    return inputError(tool, `cve-bin-tool tidak menghasilkan laporan JSON${stderr ? `: ${stderr}` : ""}`);
  }
  let cves = [];
  try { cves = parseCveBinToolJson(JSON.parse(readFileSync(reportFile, "utf8"))); } catch (e) {
    return inputError(tool, `laporan cve-bin-tool bukan JSON valid: ${e.message}`);
  }
  const base = basename(target);
  const findings = cves.map((c) => ({
    endpoint: base,
    method: "firmware",
    param: `${c.product}@${c.version}`,
    vulnClass: "Known CVE in Firmware Component",
    cwe: c.cwe,
    severity: c.severity,
    evidence: `${c.cve} di ${c.product} ${c.version}${c.score !== null ? ` (CVSS ${c.score})` : ""}${c.description ? ` — ${c.description}` : ""} — kandidat, verifikasi reachability manual.`,
  }));
  return finish(tool, findings, { timeMs, rawCount: cves.length, reportFile });
}

export default { runBinwalkNg, runUnblob, runCveBinTool, parseBinwalkText, parseBinwalkJson, parseUnblobReport, parseCveBinToolJson, findBinary, BINWALK_PIN, UNBLOB_PIN, CVE_BIN_TOOL_PIN };
