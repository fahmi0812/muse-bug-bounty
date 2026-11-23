// tests/integration-v12.test.js — v1.2: memori + graf + trace end-to-end via CLI.
// node:test. Seed store lewat Store langsung, lalu jalankan CLI nyata.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Store } from "../bounty/lib/store.js";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

function runCli(args, env) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, env, encoding: "utf8" });
}

test("v1.2 e2e: review approve/reject -> lesson + episode; similar/graph/trace jalan", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v12-"));
  const db = join(dir, "bounty.db");
  const env = { ...process.env, BOUNTY_DB: db };
  const store = new Store(db);
  try {
    store.addCandidate({ program: "Example Program", endpoint: "/api/users?id=1", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" });
    store.addCandidate({ program: "Example Program", endpoint: "/api/users?id=2", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" });
    store.addCandidate({ program: "Example Program", endpoint: "/search?q=x", method: "GET", param: "q", vulnClass: "Cross-Site Scripting (XSS)", cwe: "CWE-79" });
  } finally { store.close(); }

  // Approve #1 (confirmed) + reject #3 (false positive) lewat CLI.
  const r1 = runCli(["review", "--approve", "1"], env);
  assert.equal(r1.status, 0, r1.stderr + r1.stdout);
  assert.match(r1.stdout, /disetujui/);
  const r2 = runCli(["review", "--reject", "3"], env);
  assert.equal(r2.status, 0, r2.stderr + r2.stdout);
  assert.match(r2.stdout, /ditolak/);

  // Lesson tercatat dari verdict manusia.
  const r3 = runCli(["memory", "--lessons"], env);
  assert.equal(r3.status, 0, r3.stderr + r3.stdout);
  assert.match(r3.stdout, /confirmed/);
  assert.match(r3.stdout, /false_positive/);

  // Episode review tercatat.
  const r4 = runCli(["memory"], env);
  assert.equal(r4.status, 0, r4.stderr + r4.stdout);
  assert.match(r4.stdout, /review/);

  // Similar: #2 mirip #1 (SQLi, endpoint sama).
  const r5 = runCli(["findings", "--similar", "2"], env);
  assert.equal(r5.status, 0, r5.stderr + r5.stdout);
  assert.match(r5.stdout, /#1/);

  // Graph + trace jalan.
  const r6 = runCli(["graph", "--program", "Example Program"], env);
  assert.equal(r6.status, 0, r6.stderr + r6.stdout);
  assert.match(r6.stdout, /Graf/);
  const r7 = runCli(["trace", "1"], env);
  assert.equal(r7.status, 0, r7.stderr + r7.stdout);
  assert.match(r7.stdout, /Trace #1/);
});

test("v1.2 e2e: run dengan strix palsu -> episode run + coverage tercatat", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v12-run-"));
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
    const r = runCli(["run", "--target", "https://example.com/api/", "--program", "programs/example.md"], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /1 kandidat baru masuk store/);
    const m = runCli(["memory"], env);
    assert.match(m.stdout, /run/);
    assert.match(m.stdout, /kandidat baru/);
    const g = runCli(["graph", "--program", "Example Program"], env);
    assert.equal(g.status, 0, g.stderr + g.stdout);
    assert.match(g.stdout, /Graf/);
  } finally {
    rmSync(fakeStrix, { force: true });
    rmSync(runsDir, { recursive: true, force: true });
  }
});
