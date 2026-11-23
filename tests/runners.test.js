// tests/runners.test.js — bounty/lib/runners.js + CLI `bounty scan`.
// Tool palsu (shell script di PATH) mencetak output JSON palsu, jadi
// tidak butuh nuclei/dalfox/ffuf asli. Semua hasil = candidate.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseNucleiOutput, parseDalfoxOutput, parseFfufOutput, parseArjunOutput, parseGraphqlCopOutput, parseGitleaksOutput, parseTrufflehogOutput, parseOsvOutput, parseGarakOutput, parseDeepteamOutput, runTool, SUPPORTED_TOOLS } from "../bounty/lib/runners.js";
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
  // arjun palsu: tulis JSON parameter ke file -o.
  writeFileSync(join(dir, "arjun"), `#!/bin/sh
out=""
prev=""
for a in "$@"; do if [ "$prev" = "-o" ]; then out="$a"; fi; prev="$a"; done
echo '{"parameters":["debug","id"]}' > "$out"
`, { mode: 0o755 });
  // graphql-cop palsu: cetak JSON array ke stdout.
  writeFileSync(join(dir, "graphql-cop"), `#!/bin/sh
echo '[{"title":"Introspection Enabled","severity":"high","cwe":"CWE-200","url":"https://example.com/graphql"}]'
`, { mode: 0o755 });
  // gitleaks palsu: tulis JSON array ke file --report-path.
  writeFileSync(join(dir, "gitleaks"), `#!/bin/sh
out=""
prev=""
for a in "$@"; do if [ "$prev" = "--report-path" ]; then out="$a"; fi; prev="$a"; done
echo '[{"RuleID":"github-pat","File":"config.js","Commit":"abc123"}]' > "$out"
`, { mode: 0o755 });
  // trufflehog palsu: cetak JSONL ke stdout.
  writeFileSync(join(dir, "trufflehog"), `#!/bin/sh
echo '{"DetectorName":"Slack Webhook","Verified":true,"SourceMetadata":{"Data":{"Git":{"file":"app.js","commit":"def456","line":12}}}}'
echo '{"DetectorName":"Generic Credential","Verified":false,"SourceMetadata":{"Data":{"Git":{"file":"x.js","commit":"def456","line":3}}}}'
echo 'bukan json'
`, { mode: 0o755 });
  // osv-scanner palsu: cetak JSON results ke stdout.
  writeFileSync(join(dir, "osv-scanner"), `#!/bin/sh
echo '{"results":[{"packageSource":{"path":"package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"lodash","version":"4.17.20","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-xxxx-yyyy-zzzz","summary":"Prototype Pollution","database_specific":{"severity":"HIGH"}}]},{"package":{"name":"express","version":"4.17.1","ecosystem":"npm"},"vulnerabilities":[{"id":"CVE-2022-12345","summary":"Open Redirect","database_specific":{"severity":"MEDIUM"}}]}]}]}'
`, { mode: 0o755 });
  // garak palsu: tulis <prefix>.report.jsonl + ringkasan teks.
  writeFileSync(join(dir, "garak"), `#!/bin/sh
prefix=""
prev=""
for a in "$@"; do if [ "$prev" = "--report_prefix" ]; then prefix="$a"; fi; prev="$a"; done
echo '{"probe_classname":"dan.Dan_6_0","goal":"jailbreak","detector_results":{"detector":1}}' > "$prefix.report.jsonl"
echo '{"probe_classname":"encoding.Encode","goal":"encode","detector_results":{"detector":0}}' >> "$prefix.report.jsonl"
echo 'garak summary: 1 FAIL, 1 pass'
`, { mode: 0o755 });
  // deepteam palsu: cetak JSON array ke stdout.
  writeFileSync(join(dir, "deepteam"), `#!/bin/sh
echo '[{"attack":"PromptInjection","risk":"High","score":0.9,"description":"model mengikuti instruksi di input"},{"attack":"PromptInjection","risk":"High","score":0.9}]'
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

// --- Batch 2 / 3.4 / 3.7: parser unit ---

test("runners v1.3: parseArjunOutput -> parameter tersembunyi (low, bukan vuln)", () => {
  const f = parseArjunOutput('{"parameters":["debug","id"]}', TARGET);
  assert.equal(f.length, 2);
  assert.equal(f[0].param, "debug");
  assert.equal(f[0].endpoint, "/api/users");
  assert.equal(f[0].vulnClass, "Hidden Parameter Discovery");
  assert.equal(f[0].severity, "low");
  assert.equal(f[0].status, "candidate");
  assert.deepEqual(parseArjunOutput("bukan json", TARGET), []);
});

test("runners v1.3: parseGraphqlCopOutput -> temuan GraphQL + CWE", () => {
  const f = parseGraphqlCopOutput(JSON.stringify([{ title: "Introspection Enabled", severity: "high", cwe: "CWE-200", url: "https://example.com/graphql" }]), TARGET);
  assert.equal(f.length, 1);
  assert.equal(f[0].vulnClass, "GraphQL: Introspection Enabled");
  assert.equal(f[0].cwe, "CWE-200");
  assert.equal(f[0].severity, "high");
  assert.equal(f[0].method, "POST");
});

test("runners v1.3: parseGitleaksOutput -> secret CWE-798", () => {
  const f = parseGitleaksOutput(JSON.stringify([{ RuleID: "github-pat", File: "config.js", Commit: "abc123" }]), "https://github.com/org/repo");
  assert.equal(f.length, 1);
  assert.equal(f[0].vulnClass, "Exposed Secret (github-pat)");
  assert.equal(f[0].cwe, "CWE-798");
  assert.equal(f[0].severity, "high");
  assert.match(f[0].evidence, /config\.js/);
  assert.deepEqual(parseGitleaksOutput("bukan json"), []);
});

test("runners v1.3: parseTrufflehogOutput JSONL -> verified=high, unverified=medium", () => {
  const text = [
    JSON.stringify({ DetectorName: "Slack Webhook", Verified: true, SourceMetadata: { Data: { Git: { file: "app.js", commit: "c1", line: 12 } } } }),
    JSON.stringify({ DetectorName: "Generic Credential", Verified: false, SourceMetadata: { Data: { Git: { file: "x.js", commit: "c1", line: 3 } } } }),
    "bukan json",
  ].join("\n");
  const f = parseTrufflehogOutput(text, "https://github.com/org/repo");
  assert.equal(f.length, 2);
  assert.equal(f[0].vulnClass, "Exposed Secret (Slack Webhook)");
  assert.equal(f[0].severity, "high");
  assert.equal(f[1].severity, "medium");
});

test("runners v1.3: parseOsvOutput -> reachable hanya bila ada bukti, sisanya unproven", () => {
  const text = JSON.stringify({ results: [{ packages: [
    { package: { name: "lodash", version: "4.17.20" }, vulnerabilities: [{ id: "GHSA-xxxx-yyyy-zzzz", summary: "Prototype Pollution", database_specific: { severity: "HIGH" } }] },
    { package: { name: "express", version: "4.17.1" }, vulnerabilities: [{ id: "CVE-2022-12345", summary: "Open Redirect", database_specific: { severity: "MEDIUM" } }] },
  ] }] });
  const f = parseOsvOutput(text, ["lodash"]);
  assert.equal(f.length, 2);
  assert.equal(f[0].reachability, "reachable");
  assert.match(f[0].vulnClass, /reachable/);
  assert.equal(f[0].severity, "high");
  assert.equal(f[1].reachability, "unproven");
  assert.match(f[1].vulnClass, /unproven/);
  assert.ok(!f.some((x) => (x.reachability ?? "").includes("unreachable")), "tidak boleh ada klaim unreachable tanpa bukti");
  assert.deepEqual(parseOsvOutput("bukan json"), []);
});

test("runners v1.3: parseGarakOutput JSONL -> hanya detector hit jadi temuan (kandidat)", () => {
  const text = [
    JSON.stringify({ probe_classname: "dan.Dan_6_0", goal: "jailbreak", detector_results: { detector: 1 } }),
    JSON.stringify({ probe_classname: "encoding.Encode", goal: "encode", detector_results: { detector: 0 } }),
  ].join("\n");
  const f = parseGarakOutput(text);
  assert.equal(f.length, 1);
  assert.match(f[0].vulnClass, /Dan 6 0/);
  assert.equal(f[0].cwe, "CWE-74");
  assert.match(f[0].evidence, /kandidat/);
  // Fallback ringkasan teks.
  assert.equal(parseGarakOutput("garak summary: FAIL dan.Dan_6_0\n").length, 1);
  assert.equal(parseGarakOutput("semua pass").length, 0);
});

test("runners v1.3: parseDeepteamOutput -> dedup serangan sama, severity dari risk", () => {
  const text = JSON.stringify([
    { attack: "PromptInjection", risk: "High", score: 0.9, description: "model mengikuti instruksi" },
    { attack: "PromptInjection", risk: "High", score: 0.9 },
    { attack: "Bias", risk: "Low", score: 0.2 },
  ]);
  const f = parseDeepteamOutput(text);
  assert.equal(f.length, 2);
  assert.equal(f[0].severity, "high");
  assert.equal(f[0].cwe, "CWE-74");
  assert.match(f[0].evidence, /kandidat/);
  assert.equal(f[1].severity, "low");
});

// --- Batch 2 / 3.4 / 3.7: runTool dengan tool palsu ---

const REPO_PROGRAM = parseProgram(`Nama: Repo Program
Scope: github.com
Budget: $5
Rate: 10 req/detik
Roles: low, high
`);
const REPO_TARGET = "https://github.com/org/repo";

test("runners v1.3: SUPPORTED_TOOLS berisi 10 tool", () => {
  assert.deepEqual(SUPPORTED_TOOLS, ["nuclei", "dalfox", "ffuf", "arjun", "graphql-cop", "gitleaks", "trufflehog", "osv-scanner", "garak", "deepteam"]);
});

test("runners v1.3: 7 tool baru tanpa binary -> skipped:true (PATH kosong)", () => {
  const emptyDir = mkdtempSync(join(tmpdir(), "bounty-empty-path-"));
  const env = { PATH: emptyDir };
  for (const tool of ["arjun", "graphql-cop", "gitleaks", "trufflehog", "osv-scanner", "garak", "deepteam"]) {
    const r = runTool(tool, { target: tool === "gitleaks" || tool === "trufflehog" ? REPO_TARGET : TARGET, program: tool === "gitleaks" || tool === "trufflehog" ? REPO_PROGRAM : PROGRAM, env });
    assert.equal(r.skipped, true, `${tool} harus skipped tanpa binary`);
    assert.deepEqual(r.findings, []);
  }
});

test("runners v1.3: arjun palsu -> 2 parameter tersembunyi", () => {
  const dir = fakeToolDir();
  const r = runTool("arjun", { target: TARGET, program: PROGRAM, env: { PATH: `${dir}:${process.env.PATH}` } });
  assert.equal(r.skipped, false);
  assert.equal(r.findings.length, 2);
  assert.deepEqual(r.findings.map((f) => f.param).sort(), ["debug", "id"]);
});

test("runners v1.3: graphql-cop palsu -> temuan introspection", () => {
  const dir = fakeToolDir();
  const r = runTool("graphql-cop", { target: "https://example.com/api/graphql", program: PROGRAM, env: { PATH: `${dir}:${process.env.PATH}` } });
  assert.equal(r.findings.length, 1);
  assert.match(r.findings[0].vulnClass, /Introspection/);
});

test("runners v1.3: gitleaks + trufflehog palsu -> secret dari repo", () => {
  const dir = fakeToolDir();
  const env = { PATH: `${dir}:${process.env.PATH}` };
  const g = runTool("gitleaks", { target: REPO_TARGET, program: REPO_PROGRAM, env });
  assert.equal(g.findings.length, 1);
  assert.equal(g.findings[0].vulnClass, "Exposed Secret (github-pat)");
  const t = runTool("trufflehog", { target: REPO_TARGET, program: REPO_PROGRAM, env });
  assert.equal(t.findings.length, 2);
  assert.equal(t.findings[0].severity, "high");
});

test("runners v1.3: gitleaks/trufflehog target bukan repo in-scope -> blocked", () => {
  const r = runTool("gitleaks", { target: "https://evil.com/org/repo", program: REPO_PROGRAM });
  assert.equal(r.blocked, true);
});

test("runners v1.3: osv-scanner tanpa localPath -> skipped; dengan localPath -> reachable/unproven", () => {
  const dir = fakeToolDir();
  const env = { PATH: `${dir}:${process.env.PATH}` };
  const noPath = runTool("osv-scanner", { target: TARGET, program: PROGRAM, env });
  assert.equal(noPath.skipped, true);
  assert.match(noPath.reason, /checkout lokal|OSV_PATH/);
  const repoDir = mkdtempSync(join(tmpdir(), "bounty-osv-repo-"));
  const withPath = runTool("osv-scanner", { target: TARGET, program: PROGRAM, env, localPath: repoDir, reachablePackages: ["lodash"] });
  assert.equal(withPath.skipped, false);
  assert.equal(withPath.findings.length, 2);
  assert.equal(withPath.findings[0].reachability, "reachable");
  assert.equal(withPath.findings[1].reachability, "unproven");
});

test("runners v1.3: garak + deepteam palsu -> kandidat LLM (bukan klaim pasti)", () => {
  const dir = fakeToolDir();
  const env = { PATH: `${dir}:${process.env.PATH}` };
  const g = runTool("garak", { target: "https://example.com/api/chat", program: PROGRAM, env });
  assert.equal(g.findings.length, 1);
  assert.match(g.findings[0].vulnClass, /LLM Jailbreak/);
  assert.match(g.findings[0].evidence, /kandidat/);
  const d = runTool("deepteam", { target: "https://example.com/api/chat", program: PROGRAM, env });
  assert.equal(d.findings.length, 1);
  assert.match(d.findings[0].vulnClass, /LLM Red-Team/);
  assert.equal(d.findings[0].severity, "high");
});

test("cli scan v1.3: arjun palsu -> kandidat masuk store (SUPPORTED_TOOLS otomatis)", () => {
  const dir = fakeToolDir();
  const db = join(dir, "bounty.db");
  const env = { ...process.env, PATH: `${dir}:${process.env.PATH}`, BOUNTY_DB: db };
  const r = spawnSync(process.execPath, [CLI, "scan", "--tool", "arjun", "--target", TARGET, "--program", "programs/example.md"], { cwd: ROOT, env, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /2 kandidat baru masuk store/);
  const r2 = spawnSync(process.execPath, [CLI, "findings", "--program", "Example Program"], { cwd: ROOT, env, encoding: "utf8" });
  assert.match(r2.stdout, /Hidden Parameter Discovery/);
});
