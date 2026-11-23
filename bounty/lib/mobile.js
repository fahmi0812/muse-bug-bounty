// bounty/lib/mobile.js — runner statis mobile: MobSF (REST) + jadx (CLI).
// Status: P1-4. Analisis statis APK/IPA saja; dinamis (Frida/Objection)
// TIDAK di-wire di sini — opt-in saja dengan emulator rooted yang
// disediakan operator, dan hanya bila scope mengizinkan instrumentasi
// (lihat docs/p2-mobile.md checklist 6-8).
//
// MobSF REST API (terverifikasi dari dokumentasi MobSF + DeepWiki,
// 23 Nov 2026):
//   POST /api/v1/upload   (multipart file) -> { hash, scan_type, file_name }
//   POST /api/v1/scan     { scan_type, file_name, hash } -> laporan JSON penuh
//   POST /api/v1/report_json { hash } -> laporan JSON (dipakai untuk polling)
//   Auth: header `Authorization: <API_KEY>` — kunci mentah, BUKAN "Bearer".
//   (docs/p2-mobile.md lama menulis "Bearer" — itu keliru, jangan diikuti.)
// Docker (hanya perintah yang dibangun, TIDAK dijalankan di sini):
//   image kanonik di Docker Hub adalah
//   `opensecurity/mobile-security-framework-mobsf` — BUKAN `opensecurity/mobsf`
//   (nama itu tidak ada di Docker Hub; sudah diperbaiki dari draf awal).
//   Pin: `opensecurity/mobile-security-framework-mobsf:4.5.3`.
//   PERINGATAN CVE-2026-104585: verifikasi versi pin terhadap halaman
//   rilis MobSF sebelum dipakai — 4.5.3 mendahului publikasi CVE itu,
//   jangan asumsikan pin ini sudah menambalnya.
//
// Aturan keras (sama seperti runner lain):
//   - input HANYA file lokal (APK/IPA/AAB/XAPK) yang diberikan operator;
//     APK harus milik program yang scope-nya mengizinkan (gate nama program).
//   - API key MobSF hanya dari env MOBSF_API_KEY / opts.apiKey — tidak
//     pernah di-log, tidak pernah masuk temuan/laporan.
//   - Nilai secret TIDAK PERNAH masuk temuan/store — hanya jenis + lokasi.
//   - MobSF tidak terjangkau -> { error }, bukan sukses diam-diam.
//   - binary tidak ada di PATH -> { skipped: true }, bukan error.
//   - semua hasil di-dedup via lib/dedup.js SEBELUM masuk store.
//   - temuan = kandidat (status candidate), wajib diverifikasi manual.
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, extname, join } from "node:path";
import { findBinary } from "./runners.js";
import { dedupCandidates } from "./dedup.js";
import { scanText } from "./secrets.js";

export const DEFAULT_TIMEOUT_MS = 300000;
export const MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:4.5.3";
export const MOBSF_DEFAULT_URL = "http://127.0.0.1:8000";
export const MOBSF_CONTAINER_NAME = "mobsf";
export const SUPPORTED_EXTENSIONS = [".apk", ".ipa", ".aab", ".xapk"];

const SEVERITY_MAP = { critical: "high", high: "high", warning: "medium", medium: "medium", info: "low", low: "low" };

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// --- Scope gate: APK harus milik program bernama (name match) ---------
// Program di sini = objek hasil parseProgram (punya .name) atau string
// nama. Bila program punya daftar `apps`, basename APK harus terdaftar
// di situ; bila tidak ada daftar apps, operator yang menegaskan APK ini
// milik program tersebut (dicatat di hasil sebagai programName).
export function resolveProgram(program) {
  const name = typeof program === "string" ? program.trim() : String(program?.name ?? "").trim();
  if (!name) return { ok: false, reason: "program tidak diberikan — APK harus dikaitkan ke program bernama (scope)" };
  return { ok: true, name };
}

function programGate(program, apkPath) {
  const resolved = resolveProgram(program);
  if (!resolved.ok) return resolved;
  if (Array.isArray(program?.apps) && program.apps.length > 0) {
    const base = basename(String(apkPath));
    if (!program.apps.includes(base)) {
      return { ok: false, reason: `APK ${base} tidak terdaftar di apps program ${resolved.name}` };
    }
  }
  return resolved;
}

function blocked(tool, reason) {
  return { tool, skipped: false, blocked: true, reason, findings: [], duplicates: [], time_ms: 0 };
}

function validateApk(apkPath) {
  const input = String(apkPath ?? "").trim();
  if (!input) return { ok: false, reason: "path APK/IPA tidak diberikan" };
  if (!existsSync(input)) return { ok: false, reason: `file tidak ditemukan: ${input}` };
  if (!SUPPORTED_EXTENSIONS.includes(extname(input).toLowerCase())) {
    return { ok: false, reason: `ekstensi tidak didukung: ${extname(input)} (pakai .apk/.ipa/.aab/.xapk)` };
  }
  return { ok: true, fileName: basename(input) };
}

// --- MobSF: perintah Docker (dibangun saja, tidak dijalankan) ---------
export function buildDockerCommand({ image = MOBSF_IMAGE, port = 8000, name = MOBSF_CONTAINER_NAME } = {}) {
  return ["docker", "run", "--rm", "-d", "-p", `${port}:8000`, "--name", name, image];
}

// --- MobSF: parsing laporan JSON --------------------------------------
// Parser toleran: MobSF berubah bentuk antar versi (objek vs array).
// Severity MobSF: high / warning / info / good (good = dilewati).
function mapSeverity(raw) {
  return SEVERITY_MAP[String(raw ?? "").toLowerCase()] ?? "medium";
}

function normalizeCwe(raw) {
  const s = String(raw ?? "").trim();
  if (!s) return "";
  if (/^CWE-\d+$/i.test(s)) return s.toUpperCase();
  if (/^\d+$/.test(s)) return `CWE-${s}`;
  return s;
}

function asArray(v) {
  if (Array.isArray(v)) return v;
  if (v && typeof v === "object") return Object.entries(v).map(([k, item]) => ({ _key: k, ...(item ?? {}) }));
  return [];
}

export function parseMobSFReport(report = {}, { fileName = "", packageName = "" } = {}) {
  const findings = [];
  const endpoint = (section, key) => `${fileName || "app"}:${section}:${String(key ?? "").slice(0, 80) || "unknown"}`;
  const push = (f) => {
    findings.push({
      endpoint: f.endpoint,
      method: "STATIC",
      param: String(f.param ?? ""),
      vulnClass: f.vulnClass,
      cwe: String(f.cwe ?? ""),
      severity: mapSeverity(f.severity),
      status: "candidate",
    });
  };
  const pkg = String(packageName || report.package_name || "");

  // 1. Manifest analysis — array {title, severity, description, ...}.
  for (const item of asArray(report.manifest_analysis)) {
    const sev = String(item.severity ?? "").toLowerCase();
    if (sev === "good" || sev === "secure") continue;
    const title = String(item.title ?? item.name ?? "Manifest issue");
    const isExported = /exported/i.test(title);
    push({
      endpoint: endpoint("manifest", item.name ?? title),
      param: pkg,
      vulnClass: isExported ? "Exported Component" : "Manifest Security Issue",
      cwe: isExported ? "CWE-926" : "",
      severity: item.severity ?? "info",
    });
  }

  // 2. Code analysis — objek per rule {level/severity, cvss, cwe, files}.
  for (const item of asArray(report.code_analysis)) {
    const sev = String(item.level ?? item.severity ?? "").toLowerCase();
    if (sev === "good" || sev === "secure") continue;
    const rule = String(item._key ?? item.title ?? item.issue ?? "code-issue");
    const files = item.files && typeof item.files === "object" ? Object.keys(item.files) : [];
    push({
      endpoint: endpoint("code", rule),
      param: files[0] ?? "",
      vulnClass: /secret|hardcoded|api key|password|credential/i.test(rule + " " + (item.title ?? ""))
        ? "Hardcoded Secret in App"
        : /crypto|cipher|random|ssl|tls|certificate/i.test(rule + " " + (item.title ?? ""))
          ? "Weak Crypto"
          : "Insecure Code Pattern",
      cwe: normalizeCwe(item.cwe ?? item.CWE ?? ""),
      severity: item.level ?? item.severity ?? "warning",
    });
  }

  // 3. Binary analysis — array {title, severity, ...}.
  for (const item of asArray(report.binary_analysis)) {
    const sev = String(item.severity ?? "").toLowerCase();
    if (sev === "good" || sev === "secure") continue;
    push({
      endpoint: endpoint("binary", item.title ?? item.name ?? "binary-issue"),
      param: pkg,
      vulnClass: "Insecure Binary Configuration",
      cwe: "",
      severity: item.severity ?? "info",
    });
  }

  // 4. Secrets — daftar nilai; NILAI TIDAK PERNAH DISALIN, hanya jenis.
  for (const item of asArray(report.secrets)) {
    const label = typeof item === "string" ? "secret" : String(item.type ?? item.kind ?? item.title ?? "secret");
    push({
      endpoint: endpoint("secrets", label),
      param: pkg,
      vulnClass: "Hardcoded Secret in App",
      cwe: "CWE-798",
      severity: "high",
    });
  }

  // 5. Dangerous permissions — objek permission -> {status, ...}.
  for (const item of asArray(report.permissions)) {
    const status = String(item.status ?? item._key ?? "").toLowerCase();
    if (status !== "dangerous") continue;
    push({
      endpoint: endpoint("permission", item._key ?? item.permission ?? "permission"),
      param: pkg,
      vulnClass: "Dangerous Permission",
      cwe: "CWE-250",
      severity: "low",
    });
  }

  // 6. Insecure transport — domain tanpa TLS di daftar domains/urls.
  for (const item of asArray(report.domains)) {
    const domain = typeof item === "string" ? item : String(item.domain ?? item.name ?? "");
    if (!domain) continue;
    push({
      endpoint: endpoint("domain", domain),
      param: domain,
      vulnClass: "Insecure Transport",
      cwe: "CWE-319",
      severity: "low",
    });
  }

  const { unique, duplicates } = dedupCandidates(findings);
  return { findings: unique, duplicates };
}

// --- MobSF: upload + scan + poll via REST ------------------------------
function multipartBody(fileBuffer, fileName) {
  const boundary = `----bounty-mobsf-${Date.now().toString(36)}`;
  const head = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
  return { body: Buffer.concat([head, fileBuffer, tail]), contentType: `multipart/form-data; boundary=${boundary}` };
}

async function postJson(fetchFn, url, { headers = {}, body = null, timeoutMs }) {
  const res = await fetchFn(url, {
    method: "POST",
    headers,
    body,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`MobSF HTTP ${res.status} di ${url}`);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`MobSF mengembalikan non-JSON di ${url}`);
  }
}

export async function runMobsf(apkPath, {
  program,
  mobsfUrl = MOBSF_DEFAULT_URL,
  apiKey = "",
  env = {},
  fetchFn = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  useDocker = false,
  pollAttempts = 5,
  pollDelayMs = 2000,
  sleepFn = sleep,
} = {}) {
  const tool = "mobsf";
  const started = Date.now();
  const base = { tool, skipped: false, findings: [], duplicates: [], rawCount: 0, time_ms: 0 };
  const valid = validateApk(apkPath);
  if (!valid.ok) return { ...base, error: valid.reason };
  const gate = programGate(program, apkPath);
  if (!gate.ok) return { ...base, ...blocked(tool, gate.reason), time_ms: Date.now() - started };
  const key = String(apiKey || env.MOBSF_API_KEY || process.env.MOBSF_API_KEY || "").trim();
  if (!key) return { ...base, error: "MOBSF_API_KEY belum diset (env atau opts.apiKey) — ambil dari UI MobSF (API Docs)" };
  if (useDocker) {
    const docker = findBinary("docker", env.PATH ?? process.env.PATH);
    if (!docker) {
      return { ...base, skipped: true, reason: "binary docker tidak ditemukan di PATH — instal Docker dulu atau jalankan MobSF manual", time_ms: Date.now() - started };
    }
  }
  const url = String(mobsfUrl || MOBSF_DEFAULT_URL).replace(/\/+$/, "");
  const headers = { Authorization: key }; // kunci mentah, BUKAN "Bearer"
  const dockerCmd = buildDockerCommand().join(" ");
  let report;
  try {
    const fileBuffer = readFileSync(apkPath);
    const { body, contentType } = multipartBody(fileBuffer, valid.fileName);
    const uploaded = await postJson(fetchFn, `${url}/api/v1/upload`, {
      headers: { ...headers, "Content-Type": contentType }, body, timeoutMs,
    });
    const hash = String(uploaded?.hash ?? "").trim();
    if (!hash) throw new Error("MobSF upload tidak mengembalikan hash");
    const scanBody = new URLSearchParams({
      scan_type: String(uploaded.scan_type ?? "apk"),
      file_name: String(uploaded.file_name ?? valid.fileName),
      hash,
    }).toString();
    const scanned = await postJson(fetchFn, `${url}/api/v1/scan`, {
      headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
      body: scanBody, timeoutMs,
    });
    report = scanned;
    // Poll report_json bila /scan belum mengembalikan laporan penuh.
    const looksLikeReport = (r) => r && typeof r === "object" && ("manifest_analysis" in r || "code_analysis" in r || "permissions" in r);
    let attempts = 0;
    while (!looksLikeReport(report) && attempts < pollAttempts) {
      attempts += 1;
      await sleepFn(pollDelayMs);
      const polled = await postJson(fetchFn, `${url}/api/v1/report_json`, {
        headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ hash }).toString(), timeoutMs,
      });
      report = polled;
    }
    if (!looksLikeReport(report)) {
      throw new Error("MobSF tidak mengembalikan laporan JSON setelah polling — cek status scan di UI MobSF");
    }
  } catch (e) {
    return {
      ...base,
      error: `MobSF tidak terjangkau / gagal: ${e.message}. Pastikan MobSF jalan di ${url} (mis. ${dockerCmd}).`,
      time_ms: Date.now() - started,
    };
  }
  const parsed = parseMobSFReport(report, { fileName: valid.fileName, packageName: report.package_name });
  return {
    ...base,
    programName: gate.name,
    packageName: String(report.package_name ?? ""),
    findings: parsed.findings,
    duplicates: parsed.duplicates,
    rawCount: parsed.findings.length + parsed.duplicates.length,
    time_ms: Date.now() - started,
  };
}

// --- jadx: decompile + grep manifest & secret --------------------------
function walkFiles(dir, out = [], budget = { left: 300 }) {
  let entries = [];
  try { entries = readdirSync(dir); } catch { return out; }
  for (const e of entries) {
    if (budget.left <= 0) return out;
    const p = join(dir, e);
    let st = null;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) walkFiles(p, out, budget);
    else if (st.isFile()) { out.push(p); budget.left -= 1; }
  }
  return out;
}

export function parseAndroidManifest(xml = "", { packageName = "" } = {}) {
  const findings = [];
  // Komponen dengan android:exported="true" (activity/service/receiver/provider).
  const re = /<(activity|service|receiver|provider)\b([^>]*)>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const [, kind, attrs] = m;
    if (!/android:exported\s*=\s*"true"/.test(attrs)) continue;
    const name = /android:name\s*=\s*"([^"]+)"/.exec(attrs)?.[1] ?? kind;
    findings.push({
      endpoint: `manifest:${kind}:${name}`,
      method: "STATIC",
      param: packageName,
      vulnClass: "Exported Component",
      cwe: "CWE-926",
      severity: "medium",
      status: "candidate",
    });
  }
  // android:usesCleartextTraffic="true" di <application>.
  if (/android:usesCleartextTraffic\s*=\s*"true"/.test(xml)) {
    findings.push({
      endpoint: "manifest:application:usesCleartextTraffic",
      method: "STATIC",
      param: packageName,
      vulnClass: "Insecure Transport",
      cwe: "CWE-319",
      severity: "medium",
      status: "candidate",
    });
  }
  return findings;
}

export function runJadx(apkPath, {
  program,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  env = {},
  outDir = "",
} = {}) {
  const tool = "jadx";
  const started = Date.now();
  const base = { tool, skipped: false, findings: [], duplicates: [], rawCount: 0, time_ms: 0 };
  const valid = validateApk(apkPath);
  if (!valid.ok) return { ...base, error: valid.reason };
  const gate = programGate(program, apkPath);
  if (!gate.ok) return { ...base, ...blocked(tool, gate.reason), time_ms: Date.now() - started };
  const binary = findBinary("jadx", env.PATH ?? process.env.PATH);
  if (!binary) {
    return { ...base, skipped: true, reason: "binary jadx tidak ditemukan di PATH — instal dulu (https://github.com/skylot/jadx) atau lewati", time_ms: Date.now() - started };
  }
  let dir = String(outDir || "").trim();
  let tmpCreated = false;
  if (!dir) { dir = mkdtempSync(join(tmpdir(), "bounty-jadx-")); tmpCreated = true; }
  const res = spawnSync(binary, ["-d", dir, apkPath], { encoding: "utf8", timeout: timeoutMs, env: { ...process.env, ...env } });
  if (res.error) {
    if (tmpCreated) { try { rmSync(dir, { recursive: true, force: true }); } catch {} }
    return { ...base, error: `gagal menjalankan jadx: ${res.error.message}`, time_ms: Date.now() - started };
  }
  const findings = [];
  // 1. Manifest (resources/AndroidManifest.xml atau AndroidManifest.xml).
  let manifest = "";
  for (const candidate of [join(dir, "resources", "AndroidManifest.xml"), join(dir, "AndroidManifest.xml")]) {
    try { manifest = readFileSync(candidate, "utf8"); break; } catch {}
  }
  if (manifest) findings.push(...parseAndroidManifest(manifest, { packageName: "" }));
  // 2. Grep secret di sumber ter-decompile (.java/.kt, maks 300 file, 512 KB/file).
  //    scanText hanya mengembalikan jenis + nomor baris — nilai TIDAK disalin.
  const sources = walkFiles(join(dir, "sources")).filter((f) => /\.(java|kt)$/.test(f));
  for (const file of sources) {
    let text = "";
    try {
      const st = statSync(file);
      if (st.size > 512 * 1024) continue;
      text = readFileSync(file, "utf8");
    } catch { continue; }
    const { matches } = scanText(text);
    for (const match of matches) {
      findings.push({
        endpoint: `${valid.fileName}:source:${basename(file)}`,
        method: "STATIC",
        param: `line ${match.line}`,
        vulnClass: "Hardcoded Secret in App",
        cwe: "CWE-798",
        severity: "medium",
        status: "candidate",
      });
    }
  }
  const { unique, duplicates } = dedupCandidates(findings);
  return {
    ...base,
    programName: gate.name,
    outDir: dir,
    findings: unique,
    duplicates,
    rawCount: findings.length,
    time_ms: Date.now() - started,
  };
}

export default {
  runMobsf, runJadx, parseMobSFReport, parseAndroidManifest,
  buildDockerCommand, resolveProgram,
  MOBSF_IMAGE, MOBSF_DEFAULT_URL, SUPPORTED_EXTENSIONS,
};
