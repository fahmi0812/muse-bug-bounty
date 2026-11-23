// tests/recon.test.js — bounty/lib/recon.js (P0-3).
// Tool palsu (shell script di PATH) mencetak output JSON palsu, jadi
// tidak butuh subfinder/dnsx/httpx/katana/nuclei asli. Semua hasil recon
// = data permukaan, BUKAN klaim vuln (kecuali nuclei-kev = candidate).
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import {
  parseSubfinderOutput, parseDnsxOutput, parseHttpxOutput,
  parseKatanaOutput, parseCrtshOutput,
  runSubfinder, runDnsx, runHttpx, runKatana, runNucleiKev,
  updateNucleiTemplates, crtsh,
} from "../bounty/lib/recon.js";
import { parseProgram } from "../bounty/lib/scope.js";

const ROOT = resolve(import.meta.dirname, "..");

const PROGRAM_MD = `Nama: Example Program
Scope: example.com
Allowed: /api/, /login
Denied: /admin, /logout
Budget: $5
Rate: 10 req/detik
Roles: low, high
`;
const PROGRAM = parseProgram(PROGRAM_MD);
const EMPTY_PATH = { PATH: "/nonexistent-dir-xyz" };

function fakeBinDir() {
  const dir = mkdtempSync(join(tmpdir(), "bounty-recon-"));
  const mk = (name, body) => {
    const p = join(dir, name);
    writeFileSync(p, `#!/bin/sh\n${body}\n`);
    chmodSync(p, 0o755);
  };
  mk("subfinder", `printf '%s\\n' '{"host":"a.example.com"}' '{"host":"b.example.com"}' 'c.example.com' '{"host":"a.example.com"}'`);
  mk("dnsx", `printf '%s\\n' '{"host":"a.example.com","a":["93.184.216.34"],"status_code":200}' '{"host":"b.example.com","a":["93.184.216.35"],"status_code":200}'`);
  mk("httpx", `printf '%s\\n' '{"url":"https://example.com/api/","status_code":200,"title":"API","tech":["nginx"],"content_length":123}' '{"url":"https://example.com/login","status_code":200,"title":"Login","tech":[],"content_length":45}'`);
  mk("katana", `printf '%s\\n' '{"timestamp":"2026-01-01T00:00:00Z","request":{"method":"GET","url":"https://example.com/api/users?id=1","tag":"xhr"}}' '{"timestamp":"2026-01-01T00:00:00Z","request":{"method":"POST","url":"https://example.com/api/login","tag":"form"}}'`);
  mk("nuclei", [
    `if [ "$1" = "-update-templates" ]; then`,
    `  echo "Successfully updated nuclei templates to v10.2.0"`,
    `  exit 0`,
    `fi`,
    `printf '%s\\n' '{"template-id":"http/cve-2024-1234","matched-at":"https://example.com/api/","info":{"name":"CVE-2024-1234","severity":"critical","classification":{"cwe-id":["CWE-89"]}}}'`,
  ].join("\n"));
  return dir;
}

function envWith(dir) {
  return { PATH: `${dir}${delimiter}${process.env.PATH}` };
}

// --- Parser unit ---

test("recon: parseSubfinderOutput JSONL + baris biasa, dedup", () => {
  const r = parseSubfinderOutput('{"host":"a.example.com"}\nb.example.com\n{"host":"*.c.example.com"}\na.example.com\n');
  assert.deepEqual(r.map((x) => x.subdomain), ["a.example.com", "b.example.com", "c.example.com"]);
  assert.equal(r[0].source, "subfinder");
  assert.deepEqual(parseSubfinderOutput("{ rusak"), []);
});

test("recon: parseDnsxOutput JSONL -> host + IP", () => {
  const r = parseDnsxOutput('{"host":"a.example.com","a":["1.2.3.4"],"aaaa":["::1"],"status_code":200}\n{"host":"a.example.com","a":["1.2.3.4"]}\n');
  assert.equal(r.length, 1);
  assert.deepEqual(r[0].ips, ["1.2.3.4", "::1"]);
  assert.equal(r[0].status, 200);
});

test("recon: parseHttpxOutput JSONL -> URL + tech", () => {
  const r = parseHttpxOutput('{"url":"https://example.com/api/","status_code":200,"title":"API","tech":["nginx","php"],"content_length":99}\n');
  assert.equal(r.length, 1);
  assert.equal(r[0].status, 200);
  assert.deepEqual(r[0].tech, ["nginx", "php"]);
  assert.equal(r[0].contentLength, 99);
});

test("recon: parseKatanaOutput JSONL -> endpoint + method + param", () => {
  const r = parseKatanaOutput('{"request":{"method":"GET","url":"https://example.com/api/users?id=1","tag":"xhr"}}\n{"url":"https://example.com/login"}\n');
  assert.equal(r.length, 2);
  assert.equal(r[0].endpoint, "/api/users");
  assert.equal(r[0].param, "id");
  assert.equal(r[0].tag, "xhr");
  assert.equal(r[1].method, "GET");
});

test("recon: parseCrtshOutput -> dedup, wildcard dibuang, multi-nama", () => {
  const text = JSON.stringify([
    { name_value: "a.example.com\n*.b.example.com" },
    { name_value: "a.example.com" },
    { name_value: "c.example.com" },
  ]);
  const r = parseCrtshOutput(text);
  assert.deepEqual(r.map((x) => x.subdomain), ["a.example.com", "b.example.com", "c.example.com"]);
  assert.deepEqual(parseCrtshOutput("bukan json"), []);
  assert.deepEqual(parseCrtshOutput("{}"), []);
});

// --- crt.sh dengan stub fetch ---

test("recon: crtsh stub fetch 2 sertifikat -> subdomain terdedup", async () => {
  const stub = async (url) => {
    assert.match(url, /^https:\/\/crt\.sh\/\?q=%25\.example\.com&output=json$/);
    return {
      ok: true,
      text: async () => JSON.stringify([
        { name_value: "a.example.com\nb.example.com" },
        { name_value: "b.example.com\nc.example.com" },
      ]),
    };
  };
  const r = await crtsh("example.com", { fetchFn: stub });
  assert.equal(r.tool, "crtsh");
  assert.deepEqual(r.results.map((x) => x.subdomain), ["a.example.com", "b.example.com", "c.example.com"]);
});

test("recon: crtsh fetch gagal -> error, bukan throw; domain di luar scope -> blocked", async () => {
  const failing = async () => { throw new Error("jaringan putus"); };
  const r = await crtsh("example.com", { fetchFn: failing });
  assert.match(r.error, /jaringan putus/);
  const blocked = await crtsh("evil.com", { program: PROGRAM, fetchFn: failing });
  assert.equal(blocked.blocked, true);
});

// --- Missing binary -> skipped ---

test("recon: semua runner tanpa binary -> skipped (bukan error)", () => {
  assert.equal(runSubfinder("example.com", { program: PROGRAM, env: EMPTY_PATH }).skipped, true);
  assert.equal(runDnsx(["a.example.com"], { program: PROGRAM, env: EMPTY_PATH }).skipped, true);
  assert.equal(runHttpx(["https://example.com/api/"], { program: PROGRAM, env: EMPTY_PATH }).skipped, true);
  assert.equal(runKatana("https://example.com/api/", { program: PROGRAM, env: EMPTY_PATH }).skipped, true);
  assert.equal(runNucleiKev("https://example.com/api/", { program: PROGRAM, env: EMPTY_PATH }).skipped, true);
  assert.equal(updateNucleiTemplates({ env: EMPTY_PATH }).skipped, true);
});

// --- Out of scope -> blocked ---

test("recon: target di luar scope -> blocked", () => {
  assert.equal(runSubfinder("evil.com", { program: PROGRAM }).blocked, true);
  assert.equal(runDnsx(["evil.com"], { program: PROGRAM }).blocked, true);
  assert.equal(runHttpx(["https://evil.com/"], { program: PROGRAM }).blocked, true);
  assert.equal(runKatana("https://evil.com/api/", { program: PROGRAM }).blocked, true);
  assert.equal(runNucleiKev("https://evil.com/api/", { program: PROGRAM }).blocked, true);
});

// --- Fake binary e2e ---

test("recon: fake binary subfinder/dnsx/httpx/katana -> hasil ter-parse", () => {
  const dir = fakeBinDir();
  try {
    const env = envWith(dir);
    const s = runSubfinder("example.com", { program: PROGRAM, env });
    assert.equal(s.skipped, false);
    assert.deepEqual(s.results.map((x) => x.subdomain), ["a.example.com", "b.example.com", "c.example.com"]);

    const d = runDnsx(["a.example.com", "b.example.com"], { program: PROGRAM, env });
    assert.equal(d.results.length, 2);
    assert.deepEqual(d.results[0].ips, ["93.184.216.34"]);

    const h = runHttpx(["https://example.com/api/", "https://example.com/login"], { program: PROGRAM, env });
    assert.equal(h.results.length, 2);
    assert.deepEqual(h.results[0].tech, ["nginx"]);

    const k = runKatana("https://example.com/api/", { program: PROGRAM, env });
    assert.equal(k.results.length, 2);
    assert.equal(k.results[0].endpoint, "/api/users");
    assert.equal(k.findings.length, 2, "endpoint katana jadi kandidat info (dedup)");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recon: fake nuclei KEV -> candidate + update-templates versi", () => {
  const dir = fakeBinDir();
  try {
    const env = envWith(dir);
    const n = runNucleiKev("https://example.com/api/", { program: PROGRAM, env });
    assert.equal(n.skipped, false);
    assert.equal(n.findings.length, 1);
    assert.equal(n.findings[0].vulnClass, "CVE-2024-1234");
    assert.equal(n.findings[0].severity, "critical");
    assert.equal(n.findings[0].status, "candidate");

    const u = updateNucleiTemplates({ env });
    assert.equal(u.updated, true);
    assert.equal(u.version, "v10.2.0");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recon: input kosong -> error, bukan crash", () => {
  assert.match(runSubfinder("", {}).error, /domain tidak diberikan/);
  assert.match(runDnsx([], {}).error, /daftar host kosong/);
  assert.match(runHttpx([], {}).error, /daftar target kosong/);
  assert.match(runKatana("", {}).error, /target tidak diberikan/);
});
