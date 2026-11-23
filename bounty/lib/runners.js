// bounty/lib/runners.js — runner on-demand untuk scanner klasik
// (nuclei, dalfox, ffuf) + batch 2/3.4/3.7 (arjun, graphql-cop,
// gitleaks, trufflehog, osv-scanner, garak, deepteam). Pola pemanggilan
// mengikuti playbook:
//   playbooks/nuclei-trufflehog-trivy.md (nuclei -jsonl, severity filter)
//   playbooks/dalfox-amass.md (dalfox --skip-bav --format json)
//   playbooks/runners-v13.md (flag batch 2/3.4/3.7 + catatan ketidakpastian)
// Aturan keras (sama seperti bounty run):
//   - scope gate dulu: target di luar scope program -> blocked, exit 2.
//   - binary tidak ada di PATH -> { skipped: true }, BUKAN error.
//   - timeout per run; output di-parse JSON -> kandidat (status candidate).
//   - semua hasil di-dedup via lib/dedup.js SEBELUM masuk store.
//   - tidak ada auto-submit, tidak ada pembayaran, tidak ada brute force.
// Catatan jujur per tool:
//   - gitleaks/trufflehog: target HARUS URL repo git (mis. github.com/...),
//     bukan URL aplikasi — keduanya memindai repo, bukan endpoint HTTP.
//   - osv-scanner: butuh checkout lokal repo target (opts.localPath atau
//     env OSV_PATH); tanpa itu di-skip. Reachability HANYA ditandai
//     'reachable' bila ada bukti pemakaian (opts.reachablePackages);
//     tanpa bukti = 'unproven', tidak pernah diklaim 'unreachable'.
//   - garak/deepteam: butuh model LLM (opts.model atau env GARAK_MODEL /
//     DEEPTEAM_MODEL, default gpt-4o-mini). Hasilnya kandidat yang wajib
//     diverifikasi manual — bukan klaim pasti. Flag CLI mengikuti
//     dokumentasi masing-masing tool (best-effort); parser toleran
//     terhadap JSON / JSONL / ringkasan teks.
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { checkScope } from "./scope.js";
import { dedupCandidates } from "./dedup.js";

export const DEFAULT_TIMEOUT_MS = 120000;
export const SUPPORTED_TOOLS = ["nuclei", "dalfox", "ffuf", "arjun", "graphql-cop", "gitleaks", "trufflehog", "osv-scanner", "garak", "deepteam"];

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
  const out = {
    endpoint,
    method: String(f.method ?? "GET").toUpperCase(),
    param: String(f.param ?? param ?? ""),
    vulnClass: String(f.vulnClass ?? f.vuln_class ?? "Unclassified Finding"),
    cwe: String(f.cwe ?? "").toUpperCase(),
    severity: String(f.severity ?? "medium").toLowerCase(),
    status: "candidate",
  };
  // Field tambahan diteruskan bila ada (reachability OSV, evidence
  // file/komit secret, catatan verifikasi LLM) — tidak mengubah dedup.
  if (f.reachability) out.reachability = String(f.reachability);
  if (f.evidence) out.evidence = String(f.evidence).slice(0, 500);
  return out;
}

function severityFrom(raw = "") {
  const s = String(raw).toLowerCase();
  if (s.includes("crit")) return "critical";
  if (s.includes("high")) return "high";
  if (s.includes("med")) return "medium";
  if (s.includes("low")) return "low";
  return "medium";
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

export function parseArjunOutput(text = "", target = "") {
  // arjun -o menulis JSON: {"parameters": [...]} atau {url: [...]}
  // atau array string. Tiap parameter tersembunyi = kandidat enumerasi
  // (low, BUKAN klaim vuln — sama alasannya seperti ffuf).
  let data = null;
  try { data = JSON.parse(String(text)); } catch { return []; }
  let params = [];
  if (Array.isArray(data)) params = data.filter((p) => typeof p === "string");
  else if (Array.isArray(data.parameters)) params = data.parameters;
  else if (data && typeof data === "object") {
    for (const v of Object.values(data)) if (Array.isArray(v)) params = params.concat(v.filter((p) => typeof p === "string"));
  }
  const { endpoint } = urlParts(target);
  return params.filter(Boolean).map((p) => cleanFinding({
    endpoint: endpoint || "/",
    method: "GET",
    param: String(p),
    vulnClass: "Hidden Parameter Discovery",
    cwe: "",
    severity: "low",
  }));
}

export function parseGraphqlCopOutput(text = "", target = "") {
  // graphql-cop --format json: array (atau JSONL) {title, severity, cwe, url}.
  const items = [];
  const t = String(text).trim();
  if (!t) return [];
  try {
    const data = JSON.parse(t);
    if (Array.isArray(data)) items.push(...data);
    else if (data && typeof data === "object") items.push(data);
  } catch {
    for (const line of t.split("\n")) {
      const s = line.trim();
      if (!s.startsWith("{")) continue;
      try { items.push(JSON.parse(s)); } catch {}
    }
  }
  const out = [];
  for (const item of items) {
    if (!item || typeof item !== "object" || !item.title) continue;
    const { endpoint } = urlParts(item.url ?? item.target ?? target);
    out.push(cleanFinding({
      endpoint: endpoint || "/",
      method: "POST",
      param: "",
      vulnClass: String(item.title).startsWith("GraphQL") ? String(item.title) : `GraphQL: ${item.title}`,
      cwe: item.cwe ?? item.CWE ?? "",
      severity: item.severity ?? "medium",
      evidence: item.description ?? "",
    }));
  }
  return out;
}

function secretFinding({ endpoint, rule, cwe = "CWE-798", severity = "high", evidence = "" }) {
  return cleanFinding({
    endpoint,
    method: "GET",
    param: "",
    vulnClass: `Exposed Secret (${rule})`,
    cwe,
    severity,
    evidence,
  });
}

export function parseGitleaksOutput(text = "", target = "") {
  // gitleaks --report-format json: array [{RuleID, Secret, File, Commit, ...}].
  let data = null;
  try { data = JSON.parse(String(text)); } catch { return []; }
  const items = Array.isArray(data) ? data : [];
  const { endpoint } = urlParts(target);
  return items.filter((i) => i && typeof i === "object" && i.RuleID).map((i) => secretFinding({
    endpoint: endpoint || "/",
    rule: String(i.RuleID),
    evidence: `file: ${i.File ?? "?"} commit: ${i.Commit ?? "?"}`,
  }));
}

export function parseTrufflehogOutput(text = "", target = "") {
  // trufflehog git --json: JSONL, satu objek per temuan
  // {DetectorName, Verified, SourceMetadata: {Data: {Git: {file, commit, line}}}}.
  const { endpoint } = urlParts(target);
  const out = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(t); } catch { continue; }
    if (!item.DetectorName) continue;
    const git = item.SourceMetadata?.Data?.Git ?? {};
    out.push(secretFinding({
      endpoint: endpoint || "/",
      rule: String(item.DetectorName),
      severity: item.Verified === true ? "high" : "medium",
      evidence: `file: ${git.file ?? "?"} commit: ${git.commit ?? "?"} line: ${git.line ?? "?"}`,
    }));
  }
  return out;
}

export function parseOsvOutput(text = "", reachablePackages = []) {
  // osv-scanner --format json: {results: [{packageSource, packages:
  // [{package: {name, version, ecosystem}, vulnerabilities: [{id, summary,
  // database_specific: {severity}}]}]}]}.
  // Reachability: HANYA 'reachable' bila nama paket ada di
  // reachablePackages (bukti pemakaian di repo); tanpa bukti = 'unproven'.
  // Tidak pernah diklaim 'unreachable' tanpa bukti.
  let data = null;
  try { data = JSON.parse(String(text)); } catch { return []; }
  const reachable = new Set((reachablePackages ?? []).map((p) => String(p).toLowerCase()));
  const out = [];
  for (const result of data.results ?? []) {
    for (const pkg of result.packages ?? []) {
      const name = pkg.package?.name ?? "";
      const version = pkg.package?.version ?? "";
      const isReachable = name && reachable.has(name.toLowerCase());
      for (const vuln of pkg.vulnerabilities ?? []) {
        const id = vuln.id ?? vuln.aliases?.[0] ?? "UNKNOWN";
        out.push(cleanFinding({
          endpoint: "/",
          method: "GET",
          param: name,
          vulnClass: `Vulnerable Dependency (${isReachable ? "reachable" : "unproven"}): ${name} ${version} — ${id}`,
          cwe: "",
          severity: severityFrom(vuln.database_specific?.severity ?? vuln.severity ?? "medium"),
          reachability: isReachable ? "reachable" : "unproven",
          evidence: vuln.summary ?? "",
        }));
      }
    }
  }
  return out;
}

function llmProbeName(raw = "") {
  // "dan.Dan_6_0" / "encoding.Encode" -> "Dan_6_0" / "Encode".
  const s = String(raw).split(".").pop() ?? "";
  return s.replace(/_/g, " ").trim() || "unknown";
}

export function parseGarakOutput(text = "") {
  // garak *.report.jsonl: JSONL per attempt; sukses jailbreak ditandai
  // detector_results berisi 1, passed=false, atau result FAIL. Fallback:
  // ringkasan teks ("FAIL <probe>"). Semua hasil = kandidat yang wajib
  // diverifikasi manual, bukan klaim pasti.
  const t = String(text);
  const out = [];
  const seen = new Set();
  const push = (probe, goal) => {
    const name = llmProbeName(probe);
    const key = name.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(cleanFinding({
      endpoint: "/",
      method: "POST",
      param: "",
      vulnClass: `LLM Jailbreak (${name})`,
      cwe: "CWE-74",
      severity: "medium",
      evidence: `kandidat — hasil garak, perlu verifikasi manual (bukan klaim pasti)${goal ? `: ${goal}` : ""}`,
    }));
  };
  for (const line of t.split("\n")) {
    const s = line.trim();
    if (!s.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(s); } catch { continue; }
    const probe = item.probe_classname ?? item.probe ?? item.probeClassname ?? "";
    if (!probe) continue;
    const det = item.detector_results ?? item.detectors ?? {};
    const detHit = Object.values(det).some((v) => v === 1 || v === true || (Array.isArray(v) && v.includes(1)));
    const failed = item.passed === false || /^(fail|failed|vulnerable)$/i.test(String(item.result ?? item.outcome ?? item.status ?? ""));
    if (detHit || failed) push(probe, item.goal ?? "");
  }
  if (out.length === 0) {
    for (const line of t.split("\n")) {
      // "FAIL <probe>" di mana saja dalam baris (bukan cuma di awal);
      // "1 FAIL, 1 pass" tidak cocok karena setelah FAIL bukan token probe.
      const m = line.match(/FAIL[:\s]+([A-Za-z][\w.]*)/i) ?? line.match(/VULNERABLE[:\s]+([A-Za-z][\w.]*)/i);
      if (m) push(m[1], "");
    }
  }
  return out;
}

export function parseDeepteamOutput(text = "") {
  // deepteam: JSON (array / JSONL) {attack, vulnerability_type, risk,
  // score, description} atau ringkasan teks. Sama seperti garak: kandidat.
  const t = String(text).trim();
  const items = [];
  if (t) {
    try {
      const data = JSON.parse(t);
      if (Array.isArray(data)) items.push(...data);
      else if (data && typeof data === "object") items.push(data);
    } catch {
      for (const line of t.split("\n")) {
        const s = line.trim();
        if (!s.startsWith("{")) continue;
        try { items.push(JSON.parse(s)); } catch {}
      }
    }
  }
  const out = [];
  const seen = new Set();
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const attack = item.attack ?? item.vulnerability_type ?? item.vulnerability ?? item.type ?? "";
    if (!attack) continue;
    const key = String(attack).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const score = Number(item.score ?? item.risk_score ?? NaN);
    const severity = item.risk ?? item.severity ?? (Number.isFinite(score) ? (score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low") : "medium");
    out.push(cleanFinding({
      endpoint: "/",
      method: "POST",
      param: "",
      vulnClass: `LLM Red-Team (${llmProbeName(attack)})`,
      cwe: "CWE-74",
      severity: severityFrom(severity),
      evidence: `kandidat — hasil deepteam, perlu verifikasi manual (bukan klaim pasti)${item.description ? `: ${String(item.description).slice(0, 200)}` : ""}`,
    }));
  }
  if (out.length === 0) {
    for (const line of t.split("\n")) {
      const m = line.match(/FAIL[:\s]+([A-Za-z][\w.]*)/i) ?? line.match(/VULNERABLE[:\s]+([A-Za-z][\w.]*)/i);
      if (m && !seen.has(m[1].toLowerCase())) {
        seen.add(m[1].toLowerCase());
        out.push(cleanFinding({ endpoint: "/", method: "POST", param: "", vulnClass: `LLM Red-Team (${llmProbeName(m[1])})`, cwe: "CWE-74", severity: "medium", evidence: "kandidat — hasil deepteam, perlu verifikasi manual (bukan klaim pasti)" }));
      }
    }
  }
  return out;
}

const PARSERS = { nuclei: parseNucleiOutput, dalfox: parseDalfoxOutput, ffuf: parseFfufOutput, arjun: parseArjunOutput, "graphql-cop": parseGraphqlCopOutput, gitleaks: parseGitleaksOutput, trufflehog: parseTrufflehogOutput, "osv-scanner": parseOsvOutput, garak: parseGarakOutput, deepteam: parseDeepteamOutput };

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
    case "arjun":
      // arjun: parameter discovery, output JSON ke file -o.
      return ["-u", target, "-o", opts.outFile, "--stable"];
    case "graphql-cop":
      return ["-t", target, "--format", "json"];
    case "gitleaks":
      // gitleaks v8: `gitleaks git <repo-url>` + laporan JSON ke file.
      return ["git", target, "--report-format", "json", "--report-path", opts.outFile, "--log-level", "warn"];
    case "trufflehog":
      return ["git", target, "--json"];
    case "osv-scanner":
      // Butuh checkout lokal (opts.localPath / env OSV_PATH) — dicek
      // sebelum buildArgs; di sini localPath dijamin ada.
      return ["--format", "json", opts.localPath];
    case "garak": {
      // garak menulis <prefix>.report.jsonl + ringkasan teks ke stdout.
      const model = opts.model || process.env.GARAK_MODEL || "gpt-4o-mini";
      const probes = opts.probes || process.env.GARAK_PROBES || "encoding,dan";
      return ["--model_type", "openai", "--model_name", model,
        "--probes", probes, "--generators", "1", "--report_prefix", opts.outFile];
    }
    case "deepteam": {
      const model = opts.model || process.env.DEEPTEAM_MODEL || "gpt-4o-mini";
      const attacks = opts.attacks || process.env.DEEPTEAM_ATTACKS || "PromptInjection";
      return ["red-team", "--model", model, "--target", target, "--attacks", attacks];
    }
    default:
      return null;
  }
}

// Tool yang menulis output ke file (bukan stdout): ffuf, arjun,
// gitleaks (report-path), garak (report_prefix -> <prefix>.report.jsonl).
const FILE_OUT_TOOLS = new Set(["ffuf", "arjun", "gitleaks", "garak"]);

// --- Runner utama ---

export function runTool(tool, { target, program, timeoutMs = DEFAULT_TIMEOUT_MS, wordlist, env = {}, localPath, model, probes, attacks, reachablePackages } = {}) {
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
  // 3. Prasyarat per tool.
  let tmpDir = null;
  let outFile = null;
  if (tool === "ffuf") {
    const wl = wordlist || process.env.FFUF_WORDLIST || "";
    if (!wl || !existsSync(wl)) {
      return { tool, skipped: true, reason: "ffuf butuh wordlist (--wordlist <file> atau FFUF_WORDLIST)", findings: [], duplicates: [], time_ms: Date.now() - started };
    }
  }
  if (tool === "osv-scanner") {
    const lp = localPath || process.env.OSV_PATH || "";
    if (!lp || !existsSync(lp)) {
      return { tool, skipped: true, reason: "osv-scanner butuh checkout lokal repo target (localPath atau env OSV_PATH) — tanpa itu dependensi tidak bisa dinilai", findings: [], duplicates: [], time_ms: Date.now() - started };
    }
    localPath = lp;
  }
  if (FILE_OUT_TOOLS.has(tool)) {
    tmpDir = mkdtempSync(join(tmpdir(), `bounty-${tool}-`));
    outFile = join(tmpDir, `${tool}-out`);
  }
  const args = buildArgs(tool, target, { wordlist, outFile, localPath, model, probes, attacks });
  if (!args) {
    if (tmpDir) { try { rmSync(tmpDir, { recursive: true, force: true }); } catch {} }
    return { tool, skipped: true, reason: `tidak bisa membangun argumen untuk ${tool}`, findings: [], duplicates: [], time_ms: Date.now() - started };
  }
  const res = spawnSync(binary, args, { encoding: "utf8", timeout: timeoutMs, env: { ...process.env, ...env } });
  let rawText = String(res.stdout ?? "");
  if (FILE_OUT_TOOLS.has(tool) && outFile) {
    // garak: file laporan = <prefix>.report.jsonl; sisanya baca outFile.
    const candidates = tool === "garak" ? [`${outFile}.report.jsonl`, outFile] : [outFile];
    for (const p of candidates) {
      try { rawText = readFileSync(p, "utf8"); break; } catch {}
    }
    if (tool === "garak" && !rawText) rawText = String(res.stdout ?? "");
  }
  if (tmpDir) { try { rmSync(tmpDir, { recursive: true, force: true }); } catch {} }
  if (res.error) {
    return { tool, skipped: false, error: `gagal menjalankan ${tool}: ${res.error.message}`, findings: [], duplicates: [], time_ms: Date.now() - started };
  }
  // stderr bukan error fatal untuk scanner (peringatan template dsb) —
  // yang di-parse hanya stdout (atau file output).
  // Parser yang butuh target (arjun/graphql-cop/gitleaks/trufflehog)
  // menerima target sebagai argumen kedua; osv butuh daftar paket
  // terbukti terpakai untuk reachability.
  let parsed;
  if (tool === "osv-scanner") parsed = parseOsvOutput(rawText, reachablePackages ?? []);
  else if (["arjun", "graphql-cop", "gitleaks", "trufflehog"].includes(tool)) parsed = PARSERS[tool](rawText, target);
  else parsed = PARSERS[tool](rawText);
  const { unique, duplicates } = dedupCandidates(parsed);
  return {
    tool, skipped: false, blocked: false,
    findings: unique, duplicates,
    rawCount: parsed.length,
    time_ms: Date.now() - started,
    exit: res.status ?? 0,
  };
}

export default { runTool, parseNucleiOutput, parseDalfoxOutput, parseFfufOutput, parseArjunOutput, parseGraphqlCopOutput, parseGitleaksOutput, parseTrufflehogOutput, parseOsvOutput, parseGarakOutput, parseDeepteamOutput, findBinary, SUPPORTED_TOOLS };
