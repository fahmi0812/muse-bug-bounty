// bounty/lib/cloud.js — enumerasi cloud + deteksi subdomain takeover (P1-2).
// HANYA cek tanpa kredensial (unauthenticated). Tidak pernah memakai
// kredensial cloud asli, tidak pernah mengklaim/mengambil alih apa pun.
// Fingerprint matching saja: CNAME -> layanan -> cek body HTTP apakah
// layanan itu menampilkan halaman "tidak diklaim".
//
// Prowler TIDAK ada di sini (sengaja): Prowler butuh kredensial cloud
// yang diotorisasi dan merupakan opt-in terpisah — bukan bagian dari
// enumerasi tanpa kredensial ini.
//
// Kontrak sama seperti runTool (lib/runners.js):
//   - scope gate dulu: target di luar scope program -> blocked.
//   - binary tidak ada di PATH -> { skipped: true }, BUKAN error.
//   - timeout per run; hasil di-dedup via lib/dedup.js SEBELUM masuk store.
//   - temuan takeover / bucket publik = kandidat (UNVERIFIED), bukan vonis.
//
// Catatan jujur per flag (best-effort — binary cloud tidak ada di VM ini):
//   - nuclei takeovers: `-t http/takeovers/ -jsonl -silent` — path template
//     TERVERIFIK dari docs (nuclei-templates/http/takeovers, tag `takeover`;
//     sumber: webasha.com, appsecmaster.net, nuclei-templates README).
//   - cloud_enum: `cloud_enum -k <keyword>` — output teks "FOUND ...";
//     parser toleran (baris bukan JSON dilewati). Flag belum diuji live.
//   - s3scanner: `s3scanner scan --bucket <bucket>` — bentuk JSON/text
//     output belum diuji live; parser menerima "public: true"/"isPublic"
//     dan baris "bucket is public". Flag belum diuji live.
//   - aws s3 ls: `aws s3 ls s3://<bucket> --no-sign-request` — exit 0 +
//     listing = publik; "AccessDenied"/403 = tidak publik (bukan error);
//     "NoSuchBucket"/404 = bucket tidak ada.
//   - Fingerprint takeover: dari can-i-take-over-xyz (komunitas, publik).
//     Layanan bisa diperbaiki sewaktu-waktu (mis. Shopify, Zendesk,
//     CloudFront dilaporkan tidak lagi bisa diklaim) — field `claimable`
//     menandai itu; SELALU verifikasi manual sebelum melapor.
import { spawnSync } from "node:child_process";
import { checkScope } from "./scope.js";
import { dedupCandidates } from "./dedup.js";
import { findBinary, parseNucleiOutput, DEFAULT_TIMEOUT_MS } from "./runners.js";

export const CLOUD_TOOLS = ["cloud-enum", "s3scanner", "aws-s3-ls", "nuclei-takeovers"];
export { DEFAULT_TIMEOUT_MS };

// --- Tabel fingerprint takeover (can-i-take-over-xyz, publik) ---
// cname: regex terhadap CNAME target (huruf kecil).
// fingerprints: potongan body HTTP yang menandakan resource tidak diklaim.
// claimable: "yes" | "no" (dilaporkan sudah diperbaiki) | "unknown".
export const TAKEOVER_SIGNATURES = [
  { service: "AWS S3", cname: /\.s3[.-]website[-.][a-z0-9-]+\.amazonaws\.com$|\.s3\.amazonaws\.com$/, fingerprints: ["NoSuchBucket", "The specified bucket does not exist"], claimable: "yes", cwe: "CWE-284" },
  { service: "GitHub Pages", cname: /\.github\.io$/, fingerprints: ["There isn't a GitHub Pages site here."], claimable: "yes", cwe: "CWE-284" },
  { service: "Heroku", cname: /\.herokuapp\.com$/, fingerprints: ["No such app"], claimable: "yes", cwe: "CWE-284" },
  { service: "Azure Web Apps", cname: /\.azurewebsites\.net$/, fingerprints: ["404 Web Site not found"], claimable: "yes", cwe: "CWE-284" },
  { service: "Azure Traffic Manager", cname: /\.trafficmanager\.net$/, fingerprints: ["404 Web Site not found"], claimable: "unknown", cwe: "CWE-284" },
  { service: "Azure Cloud Service", cname: /\.cloudapp\.azure\.com$/, fingerprints: ["404 Web Site not found"], claimable: "unknown", cwe: "CWE-284" },
  { service: "Shopify", cname: /\.myshopify\.com$/, fingerprints: ["Sorry, this shop is currently unavailable."], claimable: "no", cwe: "CWE-284" },
  { service: "Fastly", cname: /\.(global\.ssl\.)?fastly\.net$/, fingerprints: ["Fastly error: unknown domain"], claimable: "unknown", cwe: "CWE-284" },
  { service: "Tumblr", cname: /\.tumblr\.com$/, fingerprints: ["There's nothing here."], claimable: "unknown", cwe: "CWE-284" },
  { service: "WordPress.com", cname: /\.wordpress\.com$/, fingerprints: ["Do you want to register"], claimable: "unknown", cwe: "CWE-284" },
  { service: "Bitbucket", cname: /\.bitbucket\.io$/, fingerprints: ["Repository not found"], claimable: "yes", cwe: "CWE-284" },
  { service: "Zendesk", cname: /\.zendesk\.com$/, fingerprints: ["Help Center Closed", "Oops, this help center no longer exists"], claimable: "no", cwe: "CWE-284" },
  { service: "Ghost", cname: /\.ghost\.io$/, fingerprints: ["The thing you were looking for is no longer here"], claimable: "unknown", cwe: "CWE-284" },
  { service: "Pantheon", cname: /\.pantheonsite\.io$/, fingerprints: ["The gods are not here"], claimable: "unknown", cwe: "CWE-284" },
  { service: "Vercel", cname: /^cname\.vercel-dns\.com$/, fingerprints: ["The deployment could not be found"], claimable: "yes", cwe: "CWE-284" },
  { service: "Netlify", cname: /\.netlify\.app$/, fingerprints: ["Not Found - Request ID"], claimable: "unknown", cwe: "CWE-284" },
  { service: "Surge", cname: /\.surge\.sh$/, fingerprints: ["project not found"], claimable: "unknown", cwe: "CWE-284" },
];

export function matchTakeoverService(cname = "") {
  const c = String(cname).toLowerCase().replace(/\.$/, "");
  return TAKEOVER_SIGNATURES.find((s) => s.cname.test(c)) ?? null;
}

function fingerprintHit(body = "", signature) {
  const text = String(body);
  return signature.fingerprints.find((f) => text.includes(f)) ?? null;
}

// --- Scope level host saja (enum domain / bucket / CNAME) ---
// Bucket bukan host: scope bucket = namanya mengandung label domain
// program (mis. bucket "example-assets" untuk allowedHosts example.com).
// Ini heuristik yang didokumentasikan — bucket yang tidak mengandung
// label program ditolak, dan pencatatan publik tetap butuh review.
function bucketInScope(program, bucket) {
  if (!program) return { ok: true, reason: "tanpa program — scope tidak dicek" };
  if (!Array.isArray(program.allowedHosts) || program.allowedHosts.length === 0) {
    return { ok: false, reason: "program tanpa scope (allowedHosts kosong) — tolak" };
  }
  const b = String(bucket).toLowerCase();
  const ok = program.allowedHosts.some((a) => {
    const label = String(a).toLowerCase().split(".")[0];
    return label && b.includes(label);
  });
  return ok
    ? { ok: true, reason: "Scope OK (bucket mengandung label program)" }
    : { ok: false, reason: `bucket ${b} tidak mengandung label scope (${program.allowedHosts.join(", ")})` };
}

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
  return { rawText: String(res.stdout ?? "") + String(res.stderr ?? ""), exit: res.status ?? 0, time_ms: Date.now() - started };
}

function missing(tool) {
  return { tool, skipped: true, reason: `binary ${tool} tidak ditemukan di PATH — instal dulu atau lewati`, results: [], findings: [], duplicates: [], time_ms: 0 };
}

function blocked(tool, reason) {
  return { tool, skipped: false, blocked: true, reason, results: [], findings: [], duplicates: [], time_ms: 0 };
}

// --- checkTakeover: fingerprint matching saja, tanpa klaim ---
// input: string CNAME target, atau objek { host, cname, body }.
// Bila body diberikan -> cocokkan fingerprint langsung.
// Bila fetchFn diberikan + host ada -> ambil http://host/ lalu cocokkan.
// Tanpa body/fetch -> hanya kenali layanan (vulnerable: false).
export async function checkTakeover(input, { fetchFn = null, program = null } = {}) {
  const rec = typeof input === "string" ? { cname: input } : (input ?? {});
  const host = rec.host ?? "";
  const cname = String(rec.cname ?? "").trim();
  if (program && host) {
    const scope = hostInScope(program, host);
    if (!scope.ok) return { service: null, host, cname, vulnerable: false, blocked: true, reason: scope.reason, evidence: "" };
  }
  const signature = cname ? matchTakeoverService(cname) : null;
  if (!signature) {
    return { service: null, host, cname, vulnerable: false, evidence: cname ? `CNAME ${cname} tidak cocok dengan layanan takeover yang dikenal` : "CNAME kosong" };
  }
  let body = rec.body ?? null;
  if (body === null && fetchFn && host) {
    try {
      const res = await fetchFn(`http://${host}/`);
      body = res.ok === false ? "" : await res.text();
    } catch (e) {
      return { service: signature.service, host, cname, vulnerable: false, claimable: signature.claimable, evidence: `tidak bisa ambil body http://${host}/: ${e.message}` };
    }
  }
  if (body === null) {
    return { service: signature.service, host, cname, vulnerable: false, claimable: signature.claimable, evidence: `CNAME mengarah ke ${signature.service} — perlu cek body HTTP untuk fingerprint "tidak diklaim"` };
  }
  const hit = fingerprintHit(body, signature);
  if (!hit) {
    return { service: signature.service, host, cname, vulnerable: false, claimable: signature.claimable, evidence: `body http://${host}/ tidak mengandung fingerprint ${signature.service}` };
  }
  return {
    service: signature.service, host, cname, vulnerable: true,
    claimable: signature.claimable, cwe: signature.cwe,
    evidence: `fingerprint "${hit}" (${signature.service}) di http://${host}/` +
      (signature.claimable === "no" ? " — layanan ini dilaporkan sudah diperbaiki, verifikasi manual sebelum melapor" : ""),
  };
}

// --- Parsers (pure, bisa di-test tanpa binary) ---

export function parseCloudEnumOutput(text = "") {
  const out = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t) continue;
    // cloud_enum mencetak baris "FOUND ..." berisi URL bucket.
    const m = t.match(/(https?:\/\/[a-z0-9.-]*(?:s3\.amazonaws\.com|s3-[a-z0-9-]+\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^\s]*)/i)
      ?? t.match(/([a-z0-9.-]+\.(?:s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com))/i);
    if (!m) continue;
    const url = m[1].startsWith("http") ? m[1] : `https://${m[1]}`;
    out.push({ bucket: url, source: "cloud_enum" });
  }
  return out;
}

export function parseS3ScannerOutput(text = "") {
  const out = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let item = null;
    if (t.startsWith("{")) {
      try { item = JSON.parse(t); } catch { continue; }
    }
    if (item) {
      const name = item.bucket ?? item.name ?? item.Bucket ?? "";
      if (!name) continue;
      const isPublic = item.public === true || item.isPublic === true || String(item.access ?? "").toLowerCase() === "public";
      out.push({ bucket: String(name), isPublic, exists: item.exists !== false, source: "s3scanner" });
      continue;
    }
    const m = t.match(/bucket\s+["']?([a-z0-9.-]+)["']?\s+is\s+public/i)
      ?? t.match(/([a-z0-9.-]+)\s*:\s*public/i);
    if (m) out.push({ bucket: m[1], isPublic: true, exists: true, source: "s3scanner" });
  }
  return out;
}

// aws s3 ls --no-sign-request: stdout listing = publik; stderr AccessDenied
// = tidak publik (bukan error); NoSuchBucket = tidak ada.
export function parseAwsS3LsOutput(stdout = "", stderr = "", exitCode = 0) {
  const err = `${stderr}\n${stdout}`;
  if (/NoSuchBucket|does not exist/i.test(err)) {
    return { bucket: null, exists: false, isPublic: false, evidence: "NoSuchBucket — bucket tidak ada" };
  }
  if (/AccessDenied|403/i.test(err)) {
    return { bucket: null, exists: true, isPublic: false, evidence: "AccessDenied — bucket ada tapi listing ditolak (tidak publik)" };
  }
  if (exitCode !== 0) {
    return { bucket: null, exists: false, isPublic: false, evidence: `aws s3 ls gagal (exit ${exitCode})` };
  }
  const files = String(stdout).split("\n").map((l) => l.trim()).filter(Boolean);
  return { bucket: null, exists: true, isPublic: true, evidence: `listing publik: ${files.length} entri`, files: files.slice(0, 20) };
}

// --- Runners (binary, scope-gated, missing -> skipped) ---

export function runCloudEnum(domain, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "cloud-enum";
  const keyword = String(domain ?? "").trim().replace(/^https?:\/\//, "").split("/")[0].split(".")[0];
  if (!keyword) return { tool, skipped: false, error: "domain tidak diberikan", results: [], findings: [], duplicates: [], time_ms: 0 };
  const scope = hostInScope(program, domain);
  if (!scope.ok) return blocked(tool, scope.reason);
  const binary = findBinary("cloud_enum", env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const run = runBinary(tool, binary, ["-k", keyword], { timeoutMs, env });
  if (run.error) return run;
  const results = parseCloudEnumOutput(run.rawText);
  // cloud_enum hanya menemukan bucket — BUKAN klaim publik. Kandidat info.
  const { unique, duplicates } = dedupCandidates(results.map((r) => ({
    endpoint: r.bucket, method: "GET", param: "", vulnClass: "Cloud Bucket Found", cwe: "", severity: "info",
  })));
  return { tool, skipped: false, blocked: false, results, findings: unique, duplicates, rawCount: results.length, time_ms: run.time_ms, exit: run.exit };
}

export function runS3Scanner(bucket, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "s3scanner";
  const name = String(bucket ?? "").trim().replace(/^s3:\/\//, "").split("/")[0];
  if (!name) return { tool, skipped: false, error: "nama bucket tidak diberikan", results: [], findings: [], duplicates: [], time_ms: 0 };
  const scope = bucketInScope(program, name);
  if (!scope.ok) return blocked(tool, scope.reason);
  const binary = findBinary("s3scanner", env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const run = runBinary(tool, binary, ["scan", "--bucket", name], { timeoutMs, env });
  if (run.error) return run;
  const results = parseS3ScannerOutput(run.rawText);
  const { unique, duplicates } = dedupCandidates(results.filter((r) => r.isPublic).map((r) => ({
    endpoint: `https://${r.bucket}.s3.amazonaws.com/`, method: "GET", param: "",
    vulnClass: "Public Cloud Storage", cwe: "CWE-200", severity: "high",
  })));
  return { tool, skipped: false, blocked: false, results, findings: unique, duplicates, rawCount: results.length, time_ms: run.time_ms, exit: run.exit };
}

export function runAwsS3Ls(bucket, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "aws-s3-ls";
  const name = String(bucket ?? "").trim().replace(/^s3:\/\//, "").split("/")[0];
  if (!name) return { tool, skipped: false, error: "nama bucket tidak diberikan", results: [], findings: [], duplicates: [], time_ms: 0 };
  const scope = bucketInScope(program, name);
  if (!scope.ok) return blocked(tool, scope.reason);
  const binary = findBinary("aws", env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const started = Date.now();
  const res = spawnSync(binary, ["s3", "ls", `s3://${name}`, "--no-sign-request"], {
    encoding: "utf8", timeout: timeoutMs ?? DEFAULT_TIMEOUT_MS, env: { ...process.env, ...env },
  });
  if (res.error) {
    return { tool, skipped: false, error: `gagal menjalankan aws: ${res.error.message}`, results: [], findings: [], duplicates: [], time_ms: Date.now() - started };
  }
  const parsed = parseAwsS3LsOutput(res.stdout ?? "", res.stderr ?? "", res.status ?? 0);
  const results = [{ bucket: name, ...parsed, source: "aws-s3-ls" }];
  const findings = parsed.isPublic
    ? dedupCandidates([{ endpoint: `https://${name}.s3.amazonaws.com/`, method: "GET", param: "", vulnClass: "Public Cloud Storage", cwe: "CWE-200", severity: "high" }]).unique
    : [];
  return { tool, skipped: false, blocked: false, results, findings, duplicates: [], rawCount: results.length, time_ms: Date.now() - started, exit: res.status ?? 0 };
}

export function runNucleiTakeovers(target, { program, timeoutMs = DEFAULT_TIMEOUT_MS, env = {} } = {}) {
  const tool = "nuclei-takeovers";
  if (!target) return { tool, skipped: false, error: "target tidak diberikan", results: [], findings: [], duplicates: [], time_ms: 0 };
  if (program) {
    const scope = checkScope(program, target);
    if (!scope.ok) return blocked(tool, scope.reason);
  }
  const binary = findBinary("nuclei", env.PATH ?? process.env.PATH);
  if (!binary) return missing(tool);
  const run = runBinary(tool, binary, ["-u", target, "-t", "http/takeovers/", "-jsonl", "-silent"], { timeoutMs, env });
  if (run.error) return run;
  const parsed = parseNucleiOutput(run.rawText).map((f) => ({
    ...f,
    vulnClass: "Subdomain Takeover",
    cwe: f.cwe || "CWE-284",
    severity: f.severity === "low" ? "medium" : (f.severity ?? "high"),
  }));
  const { unique, duplicates } = dedupCandidates(parsed);
  return { tool, skipped: false, blocked: false, results: unique, findings: unique, duplicates, rawCount: parsed.length, time_ms: run.time_ms, exit: run.exit };
}

export default {
  checkTakeover, matchTakeoverService, runCloudEnum, runS3Scanner, runAwsS3Ls, runNucleiTakeovers,
  parseCloudEnumOutput, parseS3ScannerOutput, parseAwsS3LsOutput,
  TAKEOVER_SIGNATURES, CLOUD_TOOLS,
};
