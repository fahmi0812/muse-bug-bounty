// tests/caido.test.js — bounty/lib/caido.js (P1-7: jalur live Caido MCP).
// Server MCP palsu (script Node di tmp dir) menjawab initialize/tools/list
// + tools/call, jadi tidak butuh Caido atau server MCP asli dan tidak ada
// panggilan jaringan. Fixture memakai domain .example dan token
// TOKEN_CONTOH (bukan kredensial asli).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  resolveToolNames, parseListResponse, parseReplayResponse,
  attachEvidenceToFinding, checkCaidoHealth,
  startCaidoMcp, stopCaidoMcp, listRequests, replayRequest,
  BODY_PREVIEW_LIMIT,
} from "../bounty/lib/caido.js";

const FAKE_SERVER = `
let buf = "";
const mode = process.argv[2] || "official";
const tools = mode === "fork"
  ? [{ name: "list_requests" }, { name: "get_requests_by_ids" }, { name: "send_requests" }]
  : [{ name: "caido_list_requests" }, { name: "caido_get_request" }, { name: "caido_send_request" }, { name: "caido_diff_responses" }];
function send(o) { process.stdout.write(JSON.stringify(o) + "\\n"); }
process.stdin.on("data", (d) => {
  buf += d.toString("utf8");
  let idx;
  while ((idx = buf.indexOf("\\n")) !== -1) {
    const line = buf.slice(0, idx); buf = buf.slice(idx + 1);
    if (!line.trim()) continue;
    let msg; try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === "initialize") {
      send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "caido-mcp-test", version: "0.0.0" } } });
    } else if (msg.method === "tools/list") {
      send({ jsonrpc: "2.0", id: msg.id, result: { tools } });
    } else if (msg.method === "tools/call") {
      const name = msg.params && msg.params.name;
      if (name === "caido_list_requests" || name === "list_requests") {
        const body = JSON.stringify({ requests: [
          { id: "req-1", method: "GET", url: "https://example.com/api/users", status: 200 },
          { id: "req-2", method: "POST", url: "https://example.com/api/login", status: 401 },
        ] });
        send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: body }] } });
      } else if (name === "caido_send_request" || name === "send_requests") {
        const body = JSON.stringify({ status: 200, body: "OK ".repeat(1500) });
        send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: body }] } });
      } else {
        send({ jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: "tool tidak dikenal" } });
      }
    }
  }
});
`;

const CRASH_SERVER = `process.exit(1);\n`;

function writeFakeServer(dir, name, content) {
  const file = join(dir, name);
  writeFileSync(file, content);
  return file;
}

// --- Parser + resolver murni ---

test("caido: resolveToolNames -> resmi (prefix caido_) diutamakan, fallback fork", () => {
  const official = resolveToolNames(["caido_list_requests", "caido_get_request", "caido_send_request", "caido_diff_responses"]);
  assert.equal(official.list, "caido_list_requests");
  assert.equal(official.get, "caido_get_request");
  assert.equal(official.send, "caido_send_request");
  assert.equal(official.diff, "caido_diff_responses");
  const fork = resolveToolNames(["list_requests", "get_requests_by_ids", "send_requests"]);
  assert.equal(fork.list, "list_requests");
  assert.equal(fork.get, "get_requests_by_ids");
  assert.equal(fork.send, "send_requests");
  assert.equal(fork.diff, null);
  assert.deepEqual(resolveToolNames([]), { list: null, get: null, send: null, diff: null });
  assert.deepEqual(resolveToolNames(null), { list: null, get: null, send: null, diff: null });
});

test("caido: parseListResponse -> {requests}, array telanjang, {items}, teks JSON, sampah", () => {
  const a = parseListResponse({ content: [{ type: "text", text: JSON.stringify({ requests: [{ id: "r1", method: "get", url: "https://example.com/api/", status: 200 }] }) }] });
  assert.equal(a.length, 1);
  assert.equal(a[0].id, "r1");
  assert.equal(a[0].method, "GET");
  assert.equal(a[0].status, 200);
  const b = parseListResponse([{ id: "r2", method: "POST", host: "example.com", path: "/api/login", response: { status: 401 } }]);
  assert.equal(b[0].url, "https://example.com/api/login");
  assert.equal(b[0].status, 401);
  const c = parseListResponse({ content: [{ type: "text", text: JSON.stringify({ items: [{ request_id: "r3", method: "PUT", url: "https://example.com/api/x" }] }) }] });
  assert.equal(c[0].id, "r3");
  assert.equal(c[0].status, 0);
  assert.deepEqual(parseListResponse({ content: [{ type: "text", text: "bukan json" }] }), []);
  assert.deepEqual(parseListResponse("bukan json"), []);
  assert.deepEqual(parseListResponse(null), []);
});

test("caido: parseReplayResponse -> status + body dipotong 2000 karakter", () => {
  const long = "x".repeat(5000);
  const r = parseReplayResponse({ content: [{ type: "text", text: JSON.stringify({ status: 200, body: long }) }] });
  assert.equal(r.status, 200);
  assert.equal(r.bodyPreview.length, BODY_PREVIEW_LIMIT);
  assert.equal(BODY_PREVIEW_LIMIT, 2000);
  assert.deepEqual(parseReplayResponse({ response: { status: 404, body: "tidak ada" } }), { status: 404, bodyPreview: "tidak ada" });
  assert.deepEqual(parseReplayResponse("teks biasa"), { status: 0, bodyPreview: "teks biasa" });
});

test("caido: attachEvidenceToFinding -> evidence ID + URL, asli tidak diubah", () => {
  const session = { _requests: new Map([["req-1", { id: "req-1", url: "https://example.com/api/users" }]]) };
  const finding = { vulnClass: "IDOR", endpoint: "/api/users/2" };
  const out = attachEvidenceToFinding(session, "req-1", finding);
  assert.equal(out.evidence, "Caido request #req-1 — https://example.com/api/users");
  assert.equal(out.caidoRequestId, "req-1");
  assert.equal(finding.evidence, undefined); // asli tidak diubah
  const out2 = attachEvidenceToFinding({}, "req-9", finding);
  assert.equal(out2.evidence, "Caido request #req-9");
});

test("caido: checkCaidoHealth -> stub fetch (ok 200, gagal throw)", async () => {
  const ok = await checkCaidoHealth("http://127.0.0.1:8080", { fetchFn: async () => ({ ok: true, status: 200 }) });
  assert.equal(ok.ok, true);
  assert.equal(ok.status, 200);
  const bad = await checkCaidoHealth("http://127.0.0.1:8080", { fetchFn: async () => { throw new Error("ECONNREFUSED"); } });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /ECONNREFUSED/);
});

// --- Sesi MCP palsu (stdio) ---

test("caido: start + list + replay + evidence + stop (server resmi palsu)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-caido-"));
  try {
    const server = writeFakeServer(dir, "fake-mcp.mjs", FAKE_SERVER);
    const session = await startCaidoMcp({ mcpPath: server });
    try {
      assert.equal(session.skipped, false);
      assert.equal(session.error, undefined);
      assert.deepEqual(session.tools, ["caido_list_requests", "caido_get_request", "caido_send_request", "caido_diff_responses"]);
      assert.equal(session.resolved.list, "caido_list_requests");
      const listed = await listRequests(session, {});
      assert.equal(listed.error, undefined);
      assert.equal(listed.requests.length, 2);
      assert.equal(listed.requests[0].id, "req-1");
      assert.equal(listed.requests[1].status, 401);
      const replayed = await replayRequest(session, "req-1", {});
      assert.equal(replayed.error, undefined);
      assert.equal(replayed.status, 200);
      assert.equal(replayed.bodyPreview.length, 2000);
      const withEvidence = attachEvidenceToFinding(session, "req-2", { vulnClass: "Broken Auth", endpoint: "/api/login" });
      assert.equal(withEvidence.evidence, "Caido request #req-2 — https://example.com/api/login");
    } finally {
      // Selalu di-stop, termasuk bila assert di atas gagal — kalau tidak,
      // server palsu yatim akan menahan event loop dan node --test gantung.
      assert.equal(stopCaidoMcp(session).stopped, true);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("caido: server fork palsu -> nama tool tanpa prefix ter-resolve", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-caido-fork-"));
  try {
    // Fake server membaca mode dari argumen tambahan: tiru dengan menulis
    // varian fork (argv[2] tidak dipakai startCaidoMcp — jadi tulis file fork).
    const forkServer = FAKE_SERVER.replace('process.argv[2] || "official"', '"fork"');
    const server = writeFakeServer(dir, "fake-mcp-fork.mjs", forkServer);
    const session = await startCaidoMcp({ mcpPath: server });
    try {
      assert.equal(session.error, undefined);
      assert.equal(session.resolved.list, "list_requests");
      assert.equal(session.resolved.send, "send_requests");
      const listed = await listRequests(session, {});
      assert.equal(listed.requests.length, 2);
    } finally {
      stopCaidoMcp(session);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("caido: binary hilang -> skipped; server crash -> error (bukan throw)", async () => {
  const missing = await startCaidoMcp({ mcpPath: "/tmp/tidak-ada-caido-mcp-xyz" });
  assert.equal(missing.skipped, true);
  assert.match(missing.reason, /tidak ditemukan/);
  const dir = mkdtempSync(join(tmpdir(), "bounty-caido-crash-"));
  try {
    const server = writeFakeServer(dir, "crash-mcp.mjs", CRASH_SERVER);
    const crashed = await startCaidoMcp({ mcpPath: server, startupTimeoutMs: 5000 });
    assert.equal(crashed.skipped, false);
    assert.match(crashed.error, /handshake gagal|berhenti/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("caido: list/replay tanpa sesi valid -> error object", async () => {
  assert.match((await listRequests(null, {})).error, /tidak valid/);
  assert.match((await replayRequest(null, "req-1", {})).error, /tidak valid/);
  assert.match((await replayRequest({ client: {}, resolved: {} }, "", {})).error, /requestId wajib/);
});
