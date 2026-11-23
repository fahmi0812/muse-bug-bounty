// tests/integration-v110.test.js — v1.10.0: planner coverage + `bounty plan` e2e.
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
  const dir = mkdtempSync(join(tmpdir(), "bounty-v110-"));
  const db = join(dir, "bounty.db");
  const env = { ...process.env, BOUNTY_DB: db };
  const store = new Store(db);
  try {
    // Surface panas: /api/users (3 kandidat) vs /api/search (1 kandidat).
    store.addCandidate({ program: "example", endpoint: "/api/users", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" });
    store.addCandidate({ program: "example", endpoint: "/api/users", method: "GET", param: "id", vulnClass: "Insecure Direct Object Reference", cwe: "CWE-639" });
    store.addCandidate({ program: "example", endpoint: "/api/users", method: "POST", param: "role", vulnClass: "Broken Access Control", cwe: "CWE-862" });
    store.addCandidate({ program: "example", endpoint: "/api/search", method: "GET", param: "q", vulnClass: "Cross-Site Scripting", cwe: "CWE-79" });
  } finally { store.close(); }
  return { dir, env };
}

test("v1.10 e2e: bounty plan urutkan surface panas dulu, max 3 kelas per surface", () => {
  const { dir, env } = seedDb();
  try {
    const r = runCli(["plan", "--program", "example"], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Coverage example/);
    assert.match(r.stdout, /Surface: 2/);
    // /api/users (3 kandidat) muncul sebelum /api/search (1 kandidat).
    assert.ok(r.stdout.indexOf("/api/users") < r.stdout.indexOf("/api/search"), r.stdout);
    // Noise governor: max 3 baris /api/users di tabel rencana.
    const usersRows = (r.stdout.match(/\/api\/users/g) ?? []).length;
    assert.ok(usersRows <= 3, `baris /api/users: ${usersRows}`);
    assert.match(r.stdout, /Lanjut hunt: bounty scan/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("v1.10 e2e: bounty plan --record daftarkan surface baru; tanpa --program exit 2", () => {
  const { dir, env } = seedDb();
  try {
    const r = runCli(["plan", "--program", "example", "--record", "/api/admin"], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Surface didaftarkan: \/api\/admin/);
    assert.match(r.stdout, /Surface: 3/);
    const r2 = runCli(["plan", "--program", "example", "--limit", "2"], env);
    assert.equal(r2.status, 0, r2.stderr + r2.stdout);
    assert.match(r2.stdout, /Total: 2 pasangan/);
    const bad = runCli(["plan"], env);
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /Pakai: bounty plan/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("v1.10 e2e: bounty plan program kosong -> exit 0 + petunjuk", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v110-empty-"));
  const env = { ...process.env, BOUNTY_DB: join(dir, "bounty.db") };
  try {
    const r = runCli(["plan", "--program", "tidak-ada"], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Belum ada surface untuk program tidak-ada/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
