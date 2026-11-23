// bounty/lib/oast.js — Out-of-Band Application Security Testing (OAST) via
// interactsh-client (P0-5). Blind SSRF / XXE / SQLi / RCE tidak menghasilkan
// respons in-band — tanpa OAST, kerentanan itu tidak terlihat BY DESIGN,
// padahal termasuk kelas berbayar tertinggi. OAST memberi tiap run sebuah
// subdomain callback unik; bila server target memanggil balik subdomain
// itu (DNS/HTTP/SMTP), callback-nya adalah bukti eksploitasi.
//
// Tool: interactsh-client (ProjectDiscovery,
// go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest).
// Flag terverifikasi dari README upstream:
//   -s/-server <server[,server...]>  server interactsh (default publik:
//     oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me — bisa
//     berubah/mati sewaktu-waktu; self-hosted dianjurkan)
//   -n/-number <int>                 jumlah payload yang dibuat (default 1)
//   -t/-token <token>                token untuk server self-hosted yang dilindungi
//   -pi/-poll-interval <detik>       interval poll interaksi (default 5)
//   -o <file>                        file output interaksi
//   -json                            output JSONL
//   -sf/-session-file <file>         simpan/baca sesi (lanjutkan poll setelah restart)
//   -ps/-payload-store, -psf <file>  tulis payload yang dibuat ke file
//   -v                               verbose
//
// Aturan keras:
// - OAST HANYA untuk target in-scope: subdomain callback hanya boleh
//   disuntikkan ke target yang lolos scope gate (pemanggil yang menegakkan;
//   lib ini tidak menerima target — ia hanya mengelola sesi callback).
// - Token server (opts.token / env INTERACTSH_TOKEN) TIDAK PERNAH
//   dikembalikan di objek sesi, log, atau evidence.
// - Callback saja bukan bukti final: correlateCallback hanya mengaitkan
//   callback ke payload pengirim; reviewer tetap memverifikasi bahwa
//   callback itu memang berasal dari target (bukan noise/lalu lintas lain).
// - Binary tidak ada -> { skipped: true } bukan error.
// - Self-hosted: opts.server atau env INTERACTSH_SERVER; bila tidak diisi,
//   dipakai server publik default interactsh-client.
//
// Catatan jujur / best-effort:
// - Bentuk pasti baris JSONL `-json` bervariasi antar versi (field
//   `protocol`, `unique-id`/`full-id`, `host`, `timestamp`,
//   `remote-address`, `raw-request`). Parser toleran terhadap varian nama
//   field dan melewati baris non-JSON — jangan asumsikan satu bentuk.
// - Poll di sini membaca file output (-o) yang ditulis client; client
//   harus tetap jalan (proc) selama polling. stopInteractsh mematikan proc.
import { spawn } from "node:child_process";
import { accessSync, constants, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

export const DEFAULT_TIMEOUT_MS = 120000;
export const DEFAULT_STARTUP_TIMEOUT_MS = 10000;
export const DEFAULT_POLL_INTERVAL_S = 5;

export function findBinary(name, pathEnv = process.env.PATH) {
  const pathDirs = (pathEnv || "").split(delimiter);
  for (const dir of pathDirs) {
    const p = join(dir, name);
    try { accessSync(p, constants.X_OK); return p; } catch {}
  }
  return null;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Ambil domain callback dari teks (file payload-store / stdout client).
// Bentuk yang diterima: URL lengkap (https://abc123.oast.pro) atau
// domain telanjang (abc123.oast.pro). Mengembalikan host pertama yang
// terlihat seperti subdomain callback, atau "" bila tidak ada.
export function extractInteractshDomain(text = "") {
  const t = String(text ?? "");
  const urlMatch = t.match(/https?:\/\/([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/);
  if (urlMatch) return urlMatch[1].toLowerCase();
  const bareMatch = t.match(/\b([A-Za-z0-9-]{3,}\.)+(oast\.(?:pro|live|site|online|fun|me)|[A-Za-z0-9-]+\.[a-z]{2,})\b/);
  return bareMatch ? bareMatch[0].toLowerCase() : "";
}

// Payload yang disuntikkan ke target: URL callback (SSRF/XXE memanggilnya).
export function buildInteractshPayload(domain) {
  const d = String(domain ?? "").trim().toLowerCase();
  if (!d) return "";
  return `https://${d}`;
}

// --- Parser output JSONL interactsh-client (`-json`) ---
// Baris contoh (nama field bervariasi antar versi):
// {"protocol":"dns","unique-id":"abc123...","full-id":"abc123....oast.pro",
//  "host":"abc123....oast.pro","timestamp":"2026-11-23T11:00:00Z",
//  "remote-address":"203.0.113.10","raw-request":"..."}
export function parseInteractshOutput(text = "") {
  const out = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let item;
    try { item = JSON.parse(t); } catch { continue; }
    const host = item.host ?? item["full-id"] ?? item.full_id ?? "";
    if (!host) continue;
    out.push({
      protocol: String(item.protocol ?? item.type ?? "unknown").toLowerCase(),
      host: String(host).toLowerCase(),
      correlationId: String(item["unique-id"] ?? item.unique_id ?? item["correlation-id"] ?? item.correlation_id ?? ""),
      fullId: String(item["full-id"] ?? item.full_id ?? ""),
      timestamp: String(item.timestamp ?? item.time ?? item.received_at ?? ""),
      remoteAddress: String(item["remote-address"] ?? item.remote_address ?? item["remote-ip"] ?? ""),
      rawRequest: String(item["raw-request"] ?? item.raw_request ?? item.request ?? "").slice(0, 500),
    });
  }
  return out;
}

// --- Sesi interactsh ---

export async function startInteractsh({ server = "", token = "", number = 1, pollInterval = DEFAULT_POLL_INTERVAL_S, env = {}, timeoutMs = DEFAULT_TIMEOUT_MS, startupTimeoutMs = DEFAULT_STARTUP_TIMEOUT_MS } = {}) {
  const startedAt = Date.now();
  const resolvedServer = String(server || env.INTERACTSH_SERVER || process.env.INTERACTSH_SERVER || "").trim();
  const resolvedToken = String(token || env.INTERACTSH_TOKEN || process.env.INTERACTSH_TOKEN || "");
  // 1. Binary check — tidak ada = dilewati, bukan error.
  const binary = findBinary("interactsh-client", env.PATH ?? process.env.PATH);
  if (!binary) {
    return { skipped: true, reason: "binary interactsh-client tidak ditemukan di PATH — instal dulu (go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest) atau lewati", time_ms: Date.now() - startedAt };
  }
  const tmpDir = mkdtempSync(join(tmpdir(), "bounty-oast-"));
  const sessionFile = join(tmpDir, "session.txt");
  const payloadFile = join(tmpDir, "payload.txt");
  const outFile = join(tmpDir, "interactions.jsonl");
  const args = [
    "-n", String(Math.max(1, Number(number) || 1)),
    "-pi", String(Math.max(1, Number(pollInterval) || DEFAULT_POLL_INTERVAL_S)),
    "-json",
    "-sf", sessionFile,
    "-ps", "-psf", payloadFile,
    "-o", outFile,
  ];
  if (resolvedServer) args.push("-s", resolvedServer);
  if (resolvedToken) args.push("-t", resolvedToken);
  // 2. Client jalan sebagai proses latar (polling) — spawn async, bukan
  //    spawnSync, supaya pemanggil bisa menyuntikkan payload lalu poll.
  //    Token TIDAK PERNAH masuk objek sesi / log (hanya argv proses).
  let proc;
  try {
    proc = spawn(binary, args, { env: { ...process.env, ...env }, timeout: timeoutMs });
  } catch (err) {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    return { skipped: false, error: `gagal menjalankan interactsh-client: ${err.message}`, time_ms: Date.now() - startedAt };
  }
  // 3. Tunggu file payload-store muncul (client menulis domain callback
  //    ke sana begitu sesi terdaftar) — batas startupTimeoutMs.
  const deadline = Date.now() + Math.max(1000, Number(startupTimeoutMs) || DEFAULT_STARTUP_TIMEOUT_MS);
  let domain = "";
  let exited = false;
  proc.on("exit", () => { exited = true; });
  while (Date.now() < deadline) {
    try {
      const content = readFileSync(payloadFile, "utf8");
      domain = extractInteractshDomain(content);
      if (domain) break;
    } catch {}
    if (exited) break;
    await sleep(100);
  }
  if (!domain) {
    try { proc.kill("SIGTERM"); } catch {}
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    return { skipped: false, error: exited ? "interactsh-client berhenti sebelum menulis payload (cek server/token)" : "interactsh-client tidak menulis payload dalam batas waktu startup", time_ms: Date.now() - startedAt };
  }
  // Domain ketemu — tapi client palsu/asli menulis file output (interaksi)
  // sesaat SETELAH file payload. Tunggu sebentar sampai file output ada
  // atau proses berhenti, supaya sesi langsung bisa di-poll saat kembali
  // (tanpa ini ada race: start kembali sebelum file output ditulis).
  const outDeadline = Date.now() + 2000;
  while (Date.now() < outDeadline) {
    if (exited) break;
    try { accessSync(outFile, constants.F_OK); break; } catch {}
    await sleep(50);
  }
  return {
    skipped: false,
    domain,
    payload: buildInteractshPayload(domain),
    pid: proc.pid ?? null,
    proc,
    sessionFile, payloadFile, outFile, tmpDir,
    server: resolvedServer || "default (oast.pro, oast.live, ...)",
    startedAt: new Date(startedAt).toISOString(),
    _seen: 0,
    time_ms: Date.now() - startedAt,
  };
}

export function pollInteractsh(session, { sinceIndex } = {}) {
  if (!session || !session.outFile) {
    return { callbacks: [], total: 0, error: "sesi interactsh tidak valid (tanpa outFile)" };
  }
  let text = "";
  try { text = readFileSync(session.outFile, "utf8"); } catch {
    return { callbacks: [], total: 0, reason: "belum ada interaksi tercatat (file output belum ada)" };
  }
  const all = parseInteractshOutput(text);
  const from = Number.isFinite(Number(sinceIndex)) ? Number(sinceIndex) : (Number(session._seen) || 0);
  const fresh = all.slice(Math.max(0, from));
  session._seen = all.length;
  return { callbacks: fresh, total: all.length, newCount: fresh.length };
}

export function stopInteractsh(session) {
  if (!session || (!session.proc && !session.domain)) return { stopped: false, reason: "tidak ada sesi" };
  let killed = false;
  try {
    const proc = session.proc;
    if (!proc) {
      killed = true; // tidak ada proses (mis. sesi dari file) — anggap berhenti
    } else if (proc.exitCode !== null || proc.killed) {
      killed = true; // proses sudah berhenti sendiri sebelum di-stop
    } else {
      killed = proc.kill("SIGTERM");
      if (!killed) {
        // kill gagal karena proses berhenti tepat di antara cek dan kill.
        killed = proc.exitCode !== null || proc.kill("SIGKILL");
      }
    }
  } catch {
    killed = false;
  }
  return { stopped: killed, domain: session.domain ?? "" };
}

// --- Korelasi callback -> payload ---
// Cocok bila: host callback muncul di payload, correlation-id/full-id
// callback muncul di payload, atau token subdomain payload sama dengan
// host callback. Mengembalikan evidence per callback (matched true/false).
export function correlateCallback(callbacks = [], payloads = []) {
  const list = Array.isArray(payloads) ? payloads.map((p) => String(p)) : [];
  const out = [];
  for (const cb of callbacks ?? []) {
    const host = String(cb?.host ?? "").toLowerCase();
    const corr = String(cb?.correlationId ?? "").toLowerCase();
    const full = String(cb?.fullId ?? "").toLowerCase();
    let matchedPayload = null;
    let token = "";
    for (const p of list) {
      const pl = p.toLowerCase();
      if ((host && pl.includes(host)) || (corr && pl.includes(corr)) || (full && pl.includes(full))) {
        matchedPayload = p;
        token = host || corr || full;
        break;
      }
      // Token subdomain dari payload (bagian sebelum server): cocokkan
      // dengan host callback yang mengandung token yang sama.
      const m = pl.match(/https?:\/\/([a-z0-9-]+)\./);
      if (m && host && host.startsWith(m[1])) {
        matchedPayload = p;
        token = m[1];
        break;
      }
    }
    out.push({
      callback: cb,
      payload: matchedPayload,
      token,
      matched: matchedPayload !== null,
    });
  }
  return out;
}

export default { startInteractsh, pollInteractsh, stopInteractsh, correlateCallback, parseInteractshOutput, extractInteractshDomain, buildInteractshPayload, findBinary };
