// tests/integration-v13.test.js — v1.3: multi-target, cost warning, view, scan --path.
// node:test, CLI nyata dengan strix palsu.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

function runCli(args, env) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, env, encoding: "utf8" });
}

test("v1.3 e2e: --targets jalan berurutan, ringkasan antrean + total biaya", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v13-queue-"));
  const fakeStrix = join(ROOT, "strix");
  const runsDir = join(ROOT, "strix_runs");
  try {
    writeFileSync(fakeStrix, `#!/bin/sh
cat <<'EOF'
[{"endpoint":"/api/users?id=1","method":"GET","param":"id","vuln_class":"SQL Injection","cwe":"CWE-89"}]
EOF
echo 'Total cost: $0.10'
`, { mode: 0o755 });
    const db = join(dir, "bounty.db");
    const env = { ...process.env, PATH: `${ROOT}:${process.env.PATH}`, BOUNTY_DB: db };
    const r = runCli(["run", "--targets", "https://example.com/api/,https://example.com/login", "--program", "programs/example.md"], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Antrean multi-target: 2 target/);
    assert.match(r.stdout, /Antrean selesai: 2\/2 target/);
    assert.match(r.stdout, /total biaya \$0\.2/);
  } finally {
    rmSync(fakeStrix, { force: true });
    rmSync(runsDir, { recursive: true, force: true });
  }
});

test("v1.3: cost warning muncul saat biaya mendekati budget", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v13-cost-"));
  const fakeStrix = join(ROOT, "strix");
  const runsDir = join(ROOT, "strix_runs");
  try {
    writeFileSync(fakeStrix, `#!/bin/sh
cat <<'EOF'
[{"endpoint":"/api/users?id=1","method":"GET","param":"id","vuln_class":"SQL Injection","cwe":"CWE-89"}]
EOF
echo 'Total cost: $4.50'
`, { mode: 0o755 });
    const db = join(dir, "bounty.db");
    const env = { ...process.env, PATH: `${ROOT}:${process.env.PATH}`, BOUNTY_DB: db };
    const r = runCli(["run", "--target", "https://example.com/api/", "--program", "programs/example.md", "--budget", "5"], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /90% dari budget/);
  } finally {
    rmSync(fakeStrix, { force: true });
    rmSync(runsDir, { recursive: true, force: true });
  }
});

test("v1.3: bounty view tanpa strix -> pesan instal, bukan crash; scan osv tanpa --path -> dilewati", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v13-view-"));
  const env = { ...process.env, PATH: `/usr/bin:/bin`, BOUNTY_DB: join(dir, "bounty.db") };
  const r = runCli(["view"], env);
  assert.equal(r.status, 2, r.stderr + r.stdout);
  assert.match(r.stdout, /Strix tidak ditemukan/);
  const r2 = runCli(["scan", "--tool", "osv-scanner", "--target", "https://example.com/api/", "--program", "programs/example.md"], env);
  assert.equal(r2.status, 0, r2.stderr + r2.stdout);
  assert.match(r2.stdout, /Dilewati/);
});
