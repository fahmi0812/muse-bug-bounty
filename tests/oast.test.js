// tests/oast.test.js — bounty/lib/oast.js (P0-5: interactsh-client OAST).
// Client palsu (shell script di PATH) menulis file payload-store + output
// JSONL palsu, jadi tidak butuh interactsh-client asli dan tidak ada
// panggilan ke server OAST mana pun. Domain fixture memakai .example
// (bukan server OAST sungguhan) supaya test tidak pernah menyentuh jaringan.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseInteractshOutput, extractInteractshDomain, buildInteractshPayload, startInteractsh, pollInteractsh, stopInteractsh, correlateCallback } from "../bounty/lib/oast.js";

// --- Parser unit ---

test("oast: parseInteractshOutput -> JSONL + varian nama field, non-JSON dilewati", () => {
  const text = [
    JSON.stringify({ protocol: "dns", "unique-id": "abc123def456", "full-id": "abc123def456.oast.example", host: "abc123def456.oast.example", timestamp: "2026-11-23T11:00:00Z", "remote-address": "203.0.113.10", "raw-request": "GET / HTTP/1.1" }),
    JSON.stringify({ protocol: "http", unique_id: "zzz999", full_id: "zzz999.oast.example", host: "zzz999.oast.example", time: "2026-11-23T11:01:00Z" }),
    "bukan json, dilewati",
    JSON.stringify({ protocol: "dns" }),
  ].join("\n");
  const f = parseInteractshOutput(text);
  assert.equal(f.length, 2);
  assert.equal(f[0].protocol, "dns");
  assert.equal(f[0].host, "abc123def456.oast.example");
  assert.equal(f[0].correlationId, "abc123def456");
  assert.equal(f[0].remoteAddress, "203.0.113.10");
  assert.equal(f[0].timestamp, "2026-11-23T11:00:00Z");
  assert.equal(f[1].correlationId, "zzz999");
  assert.deepEqual(parseInteractshOutput("bukan json"), []);
});

test("oast: extractInteractshDomain -> URL lengkap, domain telanjang, tanpa cocok", () => {
  assert.equal(extractInteractshDomain("https://abc123def456.oast.example\n"), "abc123def456.oast.example");
  assert.equal(extractInteractshDomain("abc123def456.oast.example"), "abc123def456.oast.example");
  assert.equal(extractInteractshDomain("tidak ada domain di sini"), "");
  assert.equal(extractInteractshDomain(""), "");
});

test("oast: buildInteractshPayload -> URL callback, kosong bila domain kosong", () => {
  assert.equal(buildInteractshPayload("abc123def456.oast.example"), "https://abc123def456.oast.example");
  assert.equal(buildInteractshPayload(""), "");
  assert.equal(buildInteractshPayload("  ABC123.OAST.EXAMPLE  "), "https://abc123.oast.example");
});

// --- Korelasi callback -> payload ---

const CB_DNS = { protocol: "dns", host: "abc123def456.oast.example", correlationId: "abc123def456", fullId: "abc123def456.oast.example", timestamp: "2026-11-23T11:00:00Z" };
const CB_HTTP = { protocol: "http", host: "zzz999.oast.example", correlationId: "zzz999", fullId: "zzz999.oast.example", timestamp: "2026-11-23T11:01:00Z" };

test("oast: correlateCallback -> cocok via host + via correlation-id", () => {
  const payloads = [
    "https://example.com/api/fetch?url=https://abc123def456.oast.example/x",
    "https://example.com/api/xxe?xml=zzz999",
  ];
  const r = correlateCallback([CB_DNS, CB_HTTP], payloads);
  assert.equal(r.length, 2);
  assert.equal(r[0].matched, true);
  assert.equal(r[0].payload, payloads[0]);
  assert.equal(r[0].token, "abc123def456.oast.example");
  assert.equal(r[1].matched, true, "cocok via correlation-id di dalam payload");
  assert.equal(r[1].payload, payloads[1]);
});

test("oast: correlateCallback -> tidak cocok bila payload lain + daftar kosong", () => {
  const r = correlateCallback([CB_DNS], ["https://example.com/api/fetch?url=https://lain.oast.example/x"]);
  assert.equal(r.length, 1);
  assert.equal(r[0].matched, false);
  assert.equal(r[0].payload, null);
  assert.deepEqual(correlateCallback([], ["https://example.com/x"]), []);
  assert.deepEqual(correlateCallback([CB_DNS], []), [{ callback: CB_DNS, payload: null, token: "", matched: false }]);
});

// --- Sesi: binary hilang / client palsu ---

function fakeToolDir() {
  const dir = mkdtempSync(join(tmpdir(), "bounty-fake-oast-"));
  writeFileSync(join(dir, "interactsh-client"), `#!/bin/sh
psf=""
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-psf" ]; then psf="$a"; fi
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
echo 'https://abc123def456.oast.example' > "$psf"
echo '{"protocol":"dns","unique-id":"abc123def456","full-id":"abc123def456.oast.example","host":"abc123def456.oast.example","timestamp":"2026-11-23T11:00:00Z","remote-address":"203.0.113.10"}' > "$out"
echo '{"protocol":"http","unique-id":"zzz999","full-id":"zzz999.oast.example","host":"zzz999.oast.example","timestamp":"2026-11-23T11:01:00Z","remote-address":"203.0.113.11"}' >> "$out"
`, { mode: 0o755 });
  return dir;
}

test("oast: interactsh-client tanpa binary -> skipped:true tanpa error", async () => {
  const emptyDir = mkdtempSync(join(tmpdir(), "bounty-empty-path-"));
  const r = await startInteractsh({ env: { PATH: emptyDir } });
  assert.equal(r.skipped, true);
  assert.match(r.reason, /interactsh-client/);
  assert.equal(r.domain, undefined);
});

test("oast: client palsu -> sesi + domain, poll 2 callback, korelasi cocok, stop", async () => {
  const dir = fakeToolDir();
  const env = { PATH: `${dir}:${process.env.PATH}` };
  const s = await startInteractsh({ env, startupTimeoutMs: 5000 });
  assert.equal(s.skipped, false);
  assert.equal(s.domain, "abc123def456.oast.example");
  assert.equal(s.payload, "https://abc123def456.oast.example");
  assert.ok(s.sessionFile && s.payloadFile && s.outFile);
  assert.ok(!("token" in s), "token tidak boleh ada di objek sesi");
  // Poll pertama: 2 callback baru; poll kedua: 0 baru.
  const p1 = pollInteractsh(s);
  assert.equal(p1.total, 2);
  assert.equal(p1.newCount, 2);
  assert.equal(p1.callbacks[0].protocol, "dns");
  const p2 = pollInteractsh(s);
  assert.equal(p2.newCount, 0);
  assert.deepEqual(p2.callbacks, []);
  // Korelasi: callback pertama cocok dengan payload SSRF yang memakainya.
  const corr = correlateCallback(p1.callbacks, ["https://example.com/api/fetch?url=https://abc123def456.oast.example/x"]);
  assert.equal(corr[0].matched, true);
  assert.equal(corr[1].matched, false);
  const stopped = stopInteractsh(s);
  assert.equal(stopped.stopped, true);
  assert.equal(stopped.domain, "abc123def456.oast.example");
});

test("oast: pollInteractsh tanpa sesi/outFile -> error; stop tanpa sesi -> stopped:false", () => {
  const p = pollInteractsh(null);
  assert.equal(p.callbacks.length, 0);
  assert.match(p.error, /tidak valid/);
  assert.equal(stopInteractsh(null).stopped, false);
  assert.equal(stopInteractsh({}).stopped, false);
});
