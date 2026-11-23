// tests/integration-v19.test.js — v1.10.0: otak BugHunter (22 skill baru,
// pola bersitasi 124, pendalaman Tier-1) + perintah `bounty skills`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = process.cwd();
const BIN = join(ROOT, "bounty/bin/bounty.mjs");

function runCli(args, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v19-skills-"));
  try {
    const r = spawnSync(process.execPath, [BIN, ...args], {
      cwd: ROOT,
      encoding: "utf8",
      env: { ...process.env, BOUNTY_DB: join(dir, "bounty.db"), ...env },
    });
    return r;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("v1.10 CLI: bounty skills list 89 skill + sebutkan yang baru", () => {
  const r = runCli(["skills"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Total: 89 skill\./);
  for (const name of ["hunt-aspnet", "hunt-grpc", "hunt-laravel", "hunt-nextjs", "hunt-subdomain", "hunt-brute-force", "hunt-captcha-bypass"]) {
    assert.match(r.stdout, new RegExp(name));
  }
});

test("v1.10 CLI: bounty skills --skill tampilkan isi + skill tak dikenal exit 2", () => {
  const r = runCli(["skills", "--skill", "hunt-grpc"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Scope & larangan/);
  assert.match(r.stdout, /Gate-0/);
  const bad = runCli(["skills", "--skill", "hunt-tidak-ada"]);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /Skill tidak ditemukan/);
});

test("v1.10 CLI: bounty patterns total 124, bersitasi 112", () => {
  const r = runCli(["patterns"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /124 total, 112 bersitasi/);
  const r2 = runCli(["patterns", "--skill", "hunt-http-smuggling"]);
  assert.equal(r2.status, 0, r2.stderr);
  assert.match(r2.stdout, /8 bersitasi/);
});
