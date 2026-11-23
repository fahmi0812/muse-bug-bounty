import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, execSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseStrixOutput, parseCost, classifyVuln, readStrixArtifacts } from "../bounty/lib/strix-output.js";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

test("parseCost menemukan $0.68", () => {
  assert.equal(parseCost("Done. Total cost: $0.68"), 0.68);
  assert.equal(parseCost("tidak ada biaya"), 0);
});

test("classifyVuln memetakan kata kunci ke kelas + CWE", () => {
  assert.deepEqual(classifyVuln("found SQL injection in /api"), { vulnClass: "SQL Injection", cwe: "CWE-89" });
  assert.equal(classifyVuln("hello world"), null);
});

test("parseStrixOutput: JSON array + dedup + biaya", () => {
  const text = JSON.stringify([
    { endpoint: "/api/users?id=1", method: "GET", param: "id", vuln_class: "SQL Injection", cwe: "CWE-89" },
    { endpoint: "/api/users?id=1", method: "GET", param: "id", vuln_class: "SQL Injection", cwe: "CWE-89" },
    { endpoint: "/search?q=x", method: "GET", vuln_class: "Cross-Site Scripting (XSS)", cwe: "CWE-79" },
  ]) + "\nTotal cost: $0.68";
  const { findings, usd } = parseStrixOutput(text, "example");
  assert.equal(findings.length, 2);
  assert.equal(usd, 0.68);
  assert.equal(findings[0].program, "example");
});

test("parseStrixOutput: JSONL + markdown heading", () => {
  const text = '{"endpoint":"/api/login","method":"POST","vulnerability":"auth bypass"}\n## [XSS] /search?q=test\n';
  const { findings } = parseStrixOutput(text, "example");
  assert.ok(findings.length >= 2);
  assert.ok(findings.some((f) => f.vulnClass.includes("Authentication")));
  assert.ok(findings.some((f) => f.endpoint.includes("/search")));
});

test("parseStrixOutput: teks kosong -> 0 temuan", () => {
  assert.deepEqual(parseStrixOutput("", "example").findings, []);
});

test("run nyata dengan strix palsu: skill diteruskan + hasil masuk store", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-fake-strix-"));
  // Strix palsu: cetak --skills-dir yang diterima + temuan JSON + biaya.
  writeFileSync(join(dir, "strix"), `#!/bin/sh
echo "skills-dir=$STRIX_SKILLS_DIR"
echo "$@" | grep -q -- "--skills-dir" && echo "HAS_SKILLS_DIR"
echo "$@" | grep -q -- "--max-turns" && echo "HAS_MAX_TURNS"
cat <<'EOF'
[{"endpoint":"/api/users?id=1","method":"GET","param":"id","vuln_class":"SQL Injection","cwe":"CWE-89"}]
EOF
echo 'Total cost: $0.42'
`, { mode: 0o755 });
  const db = join(dir, "bounty.db");
  const env = { ...process.env, PATH: `${dir}:${process.env.PATH}`, BOUNTY_DB: db };
  const r = spawnSync(process.execPath, [CLI, "run", "--target", "https://example.com/api/users", "--program", "programs/example.md"], { cwd: ROOT, env, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /HAS_SKILLS_DIR/);
  assert.match(r.stdout, /HAS_MAX_TURNS/);
  assert.match(r.stdout, /1 kandidat baru masuk store/);
  assert.match(r.stdout, /\$0\.42/);
  // Review: kandidat ada di antrean
  const r2 = spawnSync(process.execPath, [CLI, "findings", "--program", "Example Program"], { cwd: ROOT, env, encoding: "utf8" });
  assert.match(r2.stdout, /SQL Injection/);
});

test("readStrixArtifacts: run.json + vulnerabilities.json jadi sumber utama", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-artifacts-"));
  const runDir = join(dir, "strix_runs", "run-1");
  mkdirSync(runDir, { recursive: true });
  writeFileSync(join(runDir, "run.json"), JSON.stringify({ status: "completed", usage: { total_cost_usd: 1.23 } }));
  writeFileSync(join(runDir, "vulnerabilities.json"), JSON.stringify([
    { url: "https://example.com/api/search?q=x", method: "GET", param: "q", vuln_class: "SQL Injection", cwe: "CWE-89", severity: "High" },
  ]));
  const out = readStrixArtifacts(dir, Date.now() - 60000);
  assert.equal(out.usd, 1.23);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].vulnClass, "SQL Injection");
  assert.deepEqual(readStrixArtifacts(dir, Date.now() + 60000), { usd: 0, findings: [] });
});

test("run nyata: Strix exit 2 = temuan ditemukan, bukan error (exit 0)", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-exit2-"));
  // Guard hanya mengizinkan perintah dari dalam workspace: fake strix
  // ditulis ke repo (sementara) dan strix_runs dibersihkan setelah test.
  const fakeStrix = join(ROOT, "strix");
  const runsDir = join(ROOT, "strix_runs");
  try {
    writeFileSync(fakeStrix, `#!/bin/sh
mkdir -p strix_runs/run-x
cat > strix_runs/run-x/run.json <<'JSON'
{"status":"completed","usage":{"total_cost_usd":0.55}}
JSON
cat > strix_runs/run-x/vulnerabilities.json <<'JSON'
[{"url":"https://example.com/api/users?id=1","method":"GET","param":"id","vuln_class":"SQL Injection","cwe":"CWE-89","severity":"High"}]
JSON
echo "vulns found"
exit 2
`, { mode: 0o755 });
    const db = join(dir, "bounty.db");
    const env = { ...process.env, PATH: `${ROOT}:${process.env.PATH}`, BOUNTY_DB: db };
    const r = spawnSync(process.execPath, [CLI, "run", "--target", "https://example.com/api/", "--program", "programs/example.md"], { cwd: ROOT, env, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /exit 2 = temuan ditemukan/);
    assert.match(r.stdout, /1 kandidat baru masuk store/);
    assert.match(r.stdout, /\$0\.55/);
  } finally {
    rmSync(fakeStrix, { force: true });
    rmSync(runsDir, { recursive: true, force: true });
  }
});
