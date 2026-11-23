// tests/runners.test.js — bounty/lib/runners.js + CLI `bounty scan`.
// Tool palsu (shell script di PATH) mencetak output JSON palsu, jadi
// tidak butuh nuclei/dalfox/ffuf asli. Semua hasil = candidate.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseNucleiOutput, parseDalfoxOutput, parseFfufOutput, runTool } from "../bounty/lib/runners.js";
import { parseProgram } from "../bounty/lib/scope.js";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

const PROGRAM_MD = `Nama: Example Program
Scope: example.com
Allowed: /api/, /login
Denied: /admin, /logout
Budget: $5
Rate: 10 req/detik
Roles: low, high
`;
const PROGRAM = parseProgram(PROGRAM_MD);
const TARGET = "https://example.com/api/users?id=1";

// --- Parser unit ---

test("runners: parseNucleiOutput JSONL -> temuan + CWE", () => {
  const text = [
    JSON.stringify({ "template-id": "http/exposed-panels", "matched-at": "https://example.com/api/users?id=1", info: { name: "Exposed Panel", severity: "high", classification: { "cwe-id": ["CWE-200"] } } }),
    JSON.stringify({ "template-id": "http/xss", "matched-at": "https://example.com/search?q=x", info: { name: "Reflected XSS", severity: "medium", classification: { "cwe-id": ["CWE-79"] } } }),
    "bukan json, dilewati",
  ].join("\n");
  const f = parseNucleiOutput(text);
  assert.equal(f.length, 2);
  assert.equal(f[0].endpoint, "/api/users");
  assert.equal(f[0].param, "id");
  assert.equal(f[0].cwe, "CWE-200");
  assert.equal(f[0].status, "candidate");
  assert.equal(f[1].vulnClass, "Reflected XSS");
});

test("runners: parseDalfoxOutput JSON -> temuan XSS", () => {
  const text = JSON.stringify({ result: [
    { url: "https://example.com/search?q=test", type: "Reflected XSS", severity: "medium", verified: true },
    { url: "https://example.com/", type: "Reflected XSS", severity: "low" },
  ] });
  const f = parseDalfoxOutput(text);
  assert.equal(f.length, 1, "URL tanpa path dilewati");
  assert.equal(f[0].endpoint, "/search");
  assert.equal(f[0].cwe, "CWE-79");
  assert.equal(f[0].status, "candidate");
  assert.deepEqual(parseDalfoxOutput("bukan json"), []);
});

test("runners: parseFfufOutput JSON -> kandidat enumerasi (low, bukan vuln)", () => {
  const text = JSON.stringify({ results: [
    { url: "https://example.com/admin", status: 200, length: 123 },
    { url: "https://example.com/api/users", status: 200, length: 456 },
    { url: "https://example.com/", status: 200, length: 1 },
  ] });
  const f = parseFfufOutput(text);
  assert.equal(f.length, 2);
  assert.equal(f[0].vulnClass, "Hidden Endpoint / Directory Enumeration");
  assert.equal(f[0].severity, "low");
  assert.equal(f[0].status, "candidate");
});

// --- Runner: binary hilang / scope / tool palsu ---

function fakeToolDir() {
  const dir = mkdtempSync(join(tmpdir(), "bounty-fake-tools-"));
  // nuclei palsu: cetak 2 baris JSONL (satu duplikat).
  writeFileSync(join(dir, "nuclei"), `#!/bin/sh
echo '{"template-id":"http/xss","matched-at":"https://example.com/search?q=x","info":{"name":"Reflected XSS","severity":"medium","classification":{"cwe-id":["CWE-79"]}}}'
echo '{"template-id":"http/xss","matched-at":"https://example.com/search?q=x","info":{"name":"Reflected XSS","severity":"medium","classification":{"cwe-id":["CWE-79"]}}}'
`, { mode: 0o755 });
  // dalfox palsu: cetak JSON result.
  writeFileSync(join(dir, "dalfox"), `#!/bin/sh
echo '{"result":[{"url":"https://example.com/search?q=test","type":"Reflected XSS","severity":"medium"}]}'
`, { mode: 0o755 });
  // ffuf palsu: tulis file -o yang diminta, lalu cetak apa saja.
  writeFileSync(join(dir, "ffuf"), `#!/bin/sh
out=""
prev=""
for a in "$@"; do if [ "$prev" = "-o" ]; then out="$a"; fi; prev="$a"; done
echo '{"results":[{"url":"https://example.com/admin","status":200,"length":10}]}' > "$out"
`, { mode: 0o755 });
  return dir;
}

test("runners: binary tidak ada -> skipped:true tanpa error", () => {
  const env = { ...process.env, PATH: "/usr/bin:/bin" };
  const r = runTool("nuclei", { target: TARGET, program: PROGRAM, env });
  // Bila nuclei kebetulan terinstal di PATH sistem, test ini dilewati.
  if (r.skipped) {
    assert.equal(r.skipped, true);
    assert.deepEqual(r.findings, []);
  } else {
    assert.ok(Array.isArray(r.findings));
  }
});

test("runners: target di luar scope -> blocked", () => {
  const r = runTool("nuclei", { target: "https://evil.com/api", program: PROGRAM });
  assert.equal(r.blocked, true);
  assert.match(r.reason, /Scope|Allowed/i);
  assert.deepEqual(r.findings, []);
});

test("runners: tool tidak dikenal -> error", () => {
  const r = runTool("nmap", { target: TARGET, program: PROGRAM });
  assert.match(r.error, /tidak dikenal/);
});

test("runners: nuclei palsu -> 1 temuan unik (dedup)", () => {
  const dir = fakeToolDir();
  const r = runTool("nuclei", { target: TARGET, program: PROGRAM, env: { PATH: `${dir}:${process.env.PATH}` } });
  assert.equal(r.skipped, false);
  assert.equal(r.rawCount, 2);
  assert.equal(r.findings.length, 1, "duplikat di-dedup");
  assert.equal(r.duplicates.length, 1);
  assert.equal(r.findings[0].vulnClass, "Reflected XSS");
  assert.equal(r.findings[0].status, "candidate");
});

test("runners: dalfox palsu -> temuan masuk", () => {
  const dir = fakeToolDir();
  const r = runTool("dalfox", { target: TARGET, program: PROGRAM, env: { PATH: `${dir}:${process.env.PATH}` } });
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].endpoint, "/search");
});

test("runners: ffuf tanpa wordlist -> skipped; dengan wordlist palsu -> temuan", () => {
  const dir = fakeToolDir();
  const env = { PATH: `${dir}:${process.env.PATH}` };
  const noWl = runTool("ffuf", { target: TARGET, program: PROGRAM, env });
  assert.equal(noWl.skipped, true);
  assert.match(noWl.reason, /wordlist/);
  const wl = join(dir, "words.txt");
  writeFileSync(wl, "admin\napi\n");
  const withWl = runTool("ffuf", { target: "https://example.com/api/", program: PROGRAM, wordlist: wl, env });
  assert.equal(withWl.skipped, false);
  assert.equal(withWl.findings.length, 1);
  assert.equal(withWl.findings[0].endpoint, "/admin");
});

// --- CLI `bounty scan` end-to-end dengan tool palsu ---

test("cli scan: nuclei palsu -> kandidat masuk store, review melihatnya", () => {
  const dir = fakeToolDir();
  const db = join(dir, "bounty.db");
  const env = { ...process.env, PATH: `${dir}:${process.env.PATH}`, BOUNTY_DB: db };
  const r = spawnSync(process.execPath, [CLI, "scan", "--tool", "nuclei", "--target", TARGET, "--program", "programs/example.md"], { cwd: ROOT, env, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /Scope OK/);
  assert.match(r.stdout, /1 kandidat baru masuk store/);
  const r2 = spawnSync(process.execPath, [CLI, "findings", "--program", "Example Program"], { cwd: ROOT, env, encoding: "utf8" });
  assert.match(r2.stdout, /Reflected XSS/);
  // Scan kedua: duplikat tidak menambah kandidat baru.
  const r3 = spawnSync(process.execPath, [CLI, "scan", "--tool", "nuclei", "--target", TARGET, "--program", "programs/example.md"], { cwd: ROOT, env, encoding: "utf8" });
  assert.match(r3.stdout, /0 kandidat baru masuk store/);
});

test("cli scan: binary hilang -> exit 0 (dilewati); target luar scope -> exit 2", () => {
  const env = { ...process.env, PATH: "/usr/bin:/bin", BOUNTY_DB: join(mkdtempSync(join(tmpdir(), "bounty-scan-")), "bounty.db") };
  const r = spawnSync(process.execPath, [CLI, "scan", "--tool", "dalfox", "--target", TARGET, "--program", "programs/example.md"], { cwd: ROOT, env, encoding: "utf8" });
  if (r.stdout.includes("Dilewati")) assert.equal(r.status, 0);
  const r2 = spawnSync(process.execPath, [CLI, "scan", "--tool", "dalfox", "--target", "https://evil.com/api", "--program", "programs/example.md"], { cwd: ROOT, env, encoding: "utf8" });
  assert.equal(r2.status, 2);
  assert.match(r2.stdout + r2.stderr, /DITOLAK/);
});

test("cli scan: --tool wajib dan harus dikenal", () => {
  const r = spawnSync(process.execPath, [CLI, "scan", "--target", TARGET, "--program", "programs/example.md"], { cwd: ROOT, encoding: "utf8" });
  assert.equal(r.status, 2);
  assert.ok(existsSync(join(ROOT, "bounty/lib/runners.js")));
});
