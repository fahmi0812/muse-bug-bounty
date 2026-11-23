// tests/integration-v111.test.js — v1.11.0: ingatan (track record + similarity vektor).
// Seed store lewat Store langsung, lalu jalankan CLI nyata.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Store } from "../bounty/lib/store.js";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

function runCli(args, env) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, env, encoding: "utf8" });
}

function seedDb() {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v111-"));
  const db = join(dir, "bounty.db");
  const env = { ...process.env, BOUNTY_DB: db };
  const store = new Store(db);
  try {
    // 4 kandidat SQLi (3 terkonfirmasi lewat approve, 1 FP lewat reject)
    // + 1 XSS — cukup untuk track record hunt-sqli (total 4 >= 3).
    const ids = [];
    ids.push(store.addCandidate({ program: "example", endpoint: "/api/users?id=1", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" }));
    ids.push(store.addCandidate({ program: "example", endpoint: "/api/users?id=2", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" }));
    ids.push(store.addCandidate({ program: "example", endpoint: "/api/orders?id=3", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" }));
    ids.push(store.addCandidate({ program: "example", endpoint: "/api/users?id=9", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" }));
    ids.push(store.addCandidate({ program: "example", endpoint: "/search?q=x", method: "GET", param: "q", vulnClass: "Cross-Site Scripting", cwe: "CWE-79" }));
    return { dir, env, ids };
  } finally { store.close(); }
}

test("v1.11 e2e: memory --track-record tampilkan presisi skill setelah verdict", () => {
  const { dir, env, ids } = seedDb();
  try {
    // Kosong dulu: belum ada verdict.
    const empty = runCli(["memory", "--track-record"], env);
    assert.equal(empty.status, 0, empty.stderr + empty.stdout);
    assert.match(empty.stdout, /Belum ada track record/);
    // 3 approve + 1 reject untuk hunt-sqli (expectedSkillFor("SQL Injection") = hunt-sqli).
    for (const id of [ids[0], ids[1], ids[2]]) {
      const r = runCli(["review", "--approve", String(id)], env);
      assert.equal(r.status, 0, r.stderr + r.stdout);
    }
    const rj = runCli(["review", "--reject", String(ids[3])], env);
    assert.equal(rj.status, 0, rj.stderr + rj.stdout);
    const r = runCli(["memory", "--track-record"], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /hunt-sqli/);
    assert.match(r.stdout, /75%/); // 3 confirmed dari 4 = presisi 75%
    assert.match(r.stdout, /Bobot dipakai router/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("v1.11 e2e: findings --similar pakai vektor hash, temukan duplikat dekat", () => {
  const { dir, env, ids } = seedDb();
  try {
    const r = runCli(["findings", "--similar", String(ids[0])], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, new RegExp(`Serupa dengan #${ids[0]}`));
    // Kandidat SQLi lain di endpoint mirip harus muncul sebagai serupa.
    assert.match(r.stdout, /\/api\/users\?id=2/);
    const bad = runCli(["findings", "--similar", "99999"], env);
    assert.equal(bad.status, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
