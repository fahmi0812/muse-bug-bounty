// bounty/lib/caido.js — jalur live Caido MCP (P1-7): baca/replay request
// lewat proxy Caido selagi hunting, bukan hanya baca SARIF post-hoc
// (lib/sarif.js). Read/replay SAJA: tidak ada modifikasi request selain
// replay yang diminta operator, tidak ada auto-submit, tidak ada kirim
// laporan.
// Server MCP: @caido/mcp-server via stdio JSON-RPC (initialize +
// tools/list + tools/call). Caido sendiri harus jalan lokal
// (default http://127.0.0.1:8080, API lokal diaktifkan di Settings).
//
// Catatan jujur soal nama tool & paket (diverifikasi 23 Nov 2026):
// - VERIFIKASI dari docs @caido/mcp-server (76 tool): `caido_list_requests`
//   (filter HTTPQL), `caido_get_request`, `caido_send_request`,
//   `caido_diff_responses`. Fork Vibe Hacking memakai nama tanpa prefix:
//   `list_requests`, `get_requests_by_ids`, `send_requests` (kirim request
//   tersimpan via ID). Kode ini menyelesaikan nama tool secara adaptif
//   dari hasil tools/list (lihat resolveToolNames) — jadi jalan di
//   keduanya.
// - BEST-EFFORT (tidak terverifikasi live — tidak ada Caido di VM):
//   bentuk argumen tools/call (filter/limit/request_id), dan nama paket
//   npm `@caido/mcp-server`: registry npm mengembalikan 404 untuk nama
//   itu pada 23 Nov 2026, jadi paket itu kemungkinan TIDAK ADA. Jalur
//   yang terverifikasi dari README caido/mcp-caido: clone repo lalu
//   `node dist/index.js` dengan env CAIDO_API_URL — pakai opts.mcpPath
//   untuk jalur itu. Bila npx gagal, pesan error mengarahkan ke mcpPath.
// - Replay = kirim ulang request tersimpan via ID (fork) / via send tool
//   resmi; TIDAK ada fuzzing/mutasi di lib ini — itu kerja skill/operator.
import { spawn } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { findBinary } from "./runners.js";

export const DEFAULT_CAIDO_URL = "http://127.0.0.1:8080";
export const DEFAULT_TIMEOUT_MS = 15000;
export const BODY_PREVIEW_LIMIT = 2000;

// Nama tool resmi (prefix caido_) + fallback fork (tanpa prefix).
const TOOL_ALIASES = {
  list: ["caido_list_requests", "list_requests"],
  get: ["caido_get_request", "get_requests_by_ids"],
  send: ["caido_send_request", "send_requests"],
  diff: ["caido_diff_responses", "diff_responses"],
};

export function resolveToolNames(toolNames = []) {
  const names = new Set((Array.isArray(toolNames) ? toolNames : []).map(String));
  const resolved = {};
  for (const [kind, aliases] of Object.entries(TOOL_ALIASES)) {
    resolved[kind] = aliases.find((a) => names.has(a)) ?? null;
  }
  return resolved;
}

// --- Klien JSON-RPC stdio (newline-delimited JSON) ---

class McpStdioClient {
  constructor(proc) {
    this.proc = proc;
    this.nextId = 1;
    this.pending = new Map();
    this.buf = "";
    this.exited = false;
    this.stderr = "";
    proc.stdout.on("data", (d) => {
      this.buf += String(d);
      let idx;
      while ((idx = this.buf.indexOf("\n")) !== -1) {
        const line = this.buf.slice(0, idx);
        this.buf = this.buf.slice(idx + 1);
        this.handleLine(line);
      }
    });
    proc.stderr.on("data", (d) => {
      this.stderr = String(this.stderr + d).slice(-2000);
    });
    proc.on("exit", () => {
      this.exited = true;
      for (const [, p] of this.pending) p.reject(new Error("proses MCP berhenti"));
      this.pending.clear();
    });
  }

  handleLine(line) {
    const text = String(line).trim();
    if (!text) return;
    let msg;
    try { msg = JSON.parse(text); } catch { return; } // baris non-JSON dilewati
    if (msg.id !== undefined && this.pending.has(msg.id)) {
      const p = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      if (msg.error) p.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
      else p.resolve(msg.result);
    }
  }

  request(method, params = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
    return new Promise((resolvePromise, rejectPromise) => {
      if (this.exited) return rejectPromise(new Error("proses MCP sudah berhenti"));
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        rejectPromise(new Error(`timeout ${timeoutMs}ms untuk ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolvePromise(v); },
        reject: (e) => { clearTimeout(timer); rejectPromise(e); },
      });
      try {
        this.proc.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      } catch (e) {
        this.pending.delete(id);
        clearTimeout(timer);
        rejectPromise(e);
      }
    });
  }

  notify(method, params = {}) {
    try { this.proc.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`); } catch {}
  }

  close() {
    try { this.proc.kill("SIGTERM"); } catch {}
  }
}

// --- Health check Caido (opsional, hanya bila opts.checkHealth) ---

export async function checkCaidoHealth(caidoUrl = DEFAULT_CAIDO_URL, { fetchFn = globalThis.fetch, timeoutMs = 5000 } = {}) {
  const url = String(caidoUrl || DEFAULT_CAIDO_URL).replace(/\/$/, "");
  try {
    const res = await fetchFn(`${url}/api/health`, { signal: AbortSignal.timeout(timeoutMs) });
    return { ok: res.ok, status: res.status, url };
  } catch (e) {
    return { ok: false, status: 0, url, error: e.message };
  }
}

// --- Start server MCP ---

export async function startCaidoMcp({
  mcpPath = "",
  caidoUrl = DEFAULT_CAIDO_URL,
  apiKey = "",
  timeoutMs = DEFAULT_TIMEOUT_MS,
  startupTimeoutMs = 10000,
  env = {},
  checkHealth = false,
} = {}) {
  const started = Date.now();
  const url = String(caidoUrl || DEFAULT_CAIDO_URL).trim();
  // Token HANYA dari env, tidak pernah di-log atau dikembalikan.
  const key = String(apiKey || env.CAIDO_API_KEY || process.env.CAIDO_API_KEY || "");
  if (checkHealth) {
    const health = await checkCaidoHealth(url);
    if (!health.ok) {
      return { skipped: false, error: `Caido tidak terjangkau di ${url} (HTTP ${health.status || "gagal"}) — jalankan Caido dulu dan aktifkan API lokal di Settings`, time_ms: Date.now() - started };
    }
  }
  // 1. Perintah server: mcpPath eksplisit dulu (jalur terverifikasi),
  //    lalu npx @caido/mcp-server (nama paket belum terverifikasi — lihat header).
  let command;
  let args;
  if (mcpPath) {
    if (String(mcpPath).endsWith(".js") || String(mcpPath).endsWith(".mjs")) { command = process.execPath; args = [String(mcpPath)]; }
    else { command = String(mcpPath); args = []; }
  } else {
    command = "npx";
    args = ["@caido/mcp-server"];
  }
  const bin = command.includes("/")
    ? (() => { try { accessSync(command, constants.X_OK); return command; } catch { return null; } })()
    : findBinary(command, env.PATH ?? process.env.PATH);
  if (!bin) {
    return { skipped: true, reason: `binary ${command} tidak ditemukan di PATH — instal Caido MCP dulu (clone caido/mcp-caido lalu node dist/index.js via opts.mcpPath, atau npm i -g @caido/mcp-server bila paket itu tersedia)`, time_ms: Date.now() - started };
  }
  let proc;
  try {
    proc = spawn(bin, args, {
      env: {
        ...process.env,
        ...env,
        CAIDO_API_URL: url,
        ...(key ? { CAIDO_API_KEY: key } : {}),
      },
    });
  } catch (e) {
    return { skipped: false, error: `gagal menjalankan MCP server: ${e.message}`, time_ms: Date.now() - started };
  }
  // 2. Handshake JSON-RPC: initialize -> initialized -> tools/list.
  const client = new McpStdioClient(proc);
  try {
    await client.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "muse-bug-bounty", version: "1.5.0" },
    }, startupTimeoutMs);
    client.notify("notifications/initialized", {});
    const list = await client.request("tools/list", {}, startupTimeoutMs);
    const tools = Array.isArray(list?.tools) ? list.tools.map((t) => String(t.name)) : [];
    const resolved = resolveToolNames(tools);
    return {
      skipped: false,
      proc,
      client,
      tools,
      resolved,
      caidoUrl: url,
      _requests: new Map(),
      time_ms: Date.now() - started,
    };
  } catch (e) {
    try { proc.kill("SIGTERM"); } catch {}
    return { skipped: false, error: `MCP handshake gagal: ${e.message}${client.stderr ? ` (stderr: ${client.stderr.slice(0, 300)})` : ""}`, time_ms: Date.now() - started };
  }
}

export function stopCaidoMcp(session) {
  if (!session || !session.client) return { stopped: false, reason: "tidak ada sesi" };
  try { session.client.close(); } catch {}
  return { stopped: true };
}

// --- Parser hasil tools/call (pure, bisa di-test tanpa server) ---

// Isi tools/call: { content: [{ type: "text", text: "<JSON string>" }] }
// atau sudah berbentuk objek. Bentuk JSON bervariasi antar versi —
// terima {requests:[...]} / {items:[...]} / array telanjang.
export function parseListResponse(result) {
  let data = result;
  if (data && Array.isArray(data.content)) {
    const text = data.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");
    try { data = JSON.parse(text); } catch { return []; }
  }
  if (typeof data === "string") {
    try { data = JSON.parse(data); } catch { return []; }
  }
  const list = Array.isArray(data) ? data : (Array.isArray(data?.requests) ? data.requests : (Array.isArray(data?.items) ? data.items : []));
  const out = [];
  for (const r of list) {
    if (!r || typeof r !== "object") continue;
    const id = r.id ?? r.request_id ?? r.requestId ?? r.request?.id ?? "";
    if (!id) continue;
    const url = r.url ?? r.request?.url ?? ((r.host && r.path) ? `https://${r.host}${r.path}` : (r.host ?? ""));
    out.push({
      id: String(id),
      method: String(r.method ?? r.request?.method ?? "").toUpperCase(),
      url: String(url),
      status: Number(r.status ?? r.response?.status ?? r.status_code ?? 0) || 0,
    });
  }
  return out;
}

// Isi replay: {status, body} / {response:{status,body}} / teks biasa.
// body dipotong 2000 karakter (BODY_PREVIEW_LIMIT).
export function parseReplayResponse(result) {
  let data = result;
  if (data && Array.isArray(data.content)) {
    const text = data.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");
    try { data = JSON.parse(text); } catch { data = { body: text }; }
  }
  if (typeof data === "string") data = { body: data };
  const status = Number(data?.status ?? data?.response?.status ?? data?.status_code ?? 0) || 0;
  const body = String(data?.body ?? data?.response?.body ?? data?.text ?? "");
  return { status, bodyPreview: body.slice(0, BODY_PREVIEW_LIMIT) };
}

// --- Operasi sesi (read/replay saja) ---

export async function listRequests(session, { filter = "", limit = 20, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const started = Date.now();
  if (!session || !session.client) return { error: "sesi Caido tidak valid — jalankan startCaidoMcp dulu", requests: [], time_ms: 0 };
  const tool = session.resolved?.list;
  if (!tool) return { error: "server MCP tidak menyediakan tool list requests (caido_list_requests / list_requests)", requests: [], time_ms: Date.now() - started };
  try {
    // filter = HTTPQL mentah (mis. `req.method == "POST" and req.path contains "/graphql"`).
    const result = await session.client.request("tools/call", { name: tool, arguments: { filter, limit } }, timeoutMs);
    const requests = parseListResponse(result);
    for (const r of requests) session._requests?.set(r.id, r);
    return { requests, count: requests.length, time_ms: Date.now() - started };
  } catch (e) {
    return { error: `list requests gagal: ${e.message}`, requests: [], time_ms: Date.now() - started };
  }
}

export async function replayRequest(session, requestId, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const started = Date.now();
  if (!session || !session.client) return { error: "sesi Caido tidak valid — jalankan startCaidoMcp dulu", time_ms: 0 };
  if (!requestId) return { error: "requestId wajib (ID request Caido dari listRequests)", time_ms: Date.now() - started };
  const tool = session.resolved?.send;
  if (!tool) return { error: "server MCP tidak menyediakan tool replay (caido_send_request / send_requests)", time_ms: Date.now() - started };
  try {
    // Replay request tersimpan via ID. Bentuk argumen best-effort:
    // fork send_requests menerima ID tersimpan; server resmi menerima
    // request_id (verifikasi terhadap inputSchema tools/list bila ragu).
    const result = await session.client.request("tools/call", { name: tool, arguments: { request_id: String(requestId) } }, timeoutMs);
    const parsed = parseReplayResponse(result);
    return { requestId: String(requestId), ...parsed, time_ms: Date.now() - started };
  } catch (e) {
    return { error: `replay gagal: ${e.message}`, time_ms: Date.now() - started };
  }
}

// Helper murni: tempel evidence ID HTTP Caido ke finding (seperti
// Strix 1.7 — findings membawa HTTP request ID sebagai evidence).
// Mengembalikan finding BARU; finding asli tidak diubah.
export function attachEvidenceToFinding(session, requestId, finding = {}) {
  const id = String(requestId ?? "");
  const req = session?._requests?.get(id);
  const url = req?.url ?? "";
  const evidence = url ? `Caido request #${id} — ${url}` : `Caido request #${id}`;
  return { ...finding, evidence, caidoRequestId: id };
}

export default {
  startCaidoMcp, stopCaidoMcp, listRequests, replayRequest,
  attachEvidenceToFinding, parseListResponse, parseReplayResponse,
  resolveToolNames, checkCaidoHealth,
  DEFAULT_CAIDO_URL, DEFAULT_TIMEOUT_MS, BODY_PREVIEW_LIMIT,
};
