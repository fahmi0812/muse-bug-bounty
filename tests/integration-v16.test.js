// tests/integration-v16.test.js — P1 v1.6.0: perintah baru tanpa binary eksternal.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

function runCli(args, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v16-cli-"));
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, env: { ...process.env, BOUNTY_DB: join(dir, "bounty.db"), ...env }, encoding: "utf8" });
  rmSync(dir, { recursive: true, force: true });
  return r;
}

test("v1.10 CLI: --version mencetak 1.11.0; index skill 89 entri", async () => {
  const r = runCli(["--version"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /bounty v1.11.0/);
  const { readFileSync } = await import("node:fs");
  const idx = JSON.parse(readFileSync(join(ROOT, "skills/bounty/skills-index.json"), "utf8"));
  assert.equal(idx.length, 89);
  for (const n of ["hunt-entra-m365", "hunt-okta", "hunt-vcenter", "hunt-ssl-vpn", "hunt-sharepoint", "hunt-cloud-iam"]) {
    assert.ok(idx.some((x) => x.name === n), n);
  }
});

test("v1.6 CLI: cloud --tool tidak valid -> exit 2; takeover tanpa body -> layanan dikenal", () => {
  const r1 = runCli(["cloud", "--tool", "bogus", "--target", "example.com"]);
  assert.equal(r1.status, 2, r1.stderr + r1.stdout);
  const r2 = runCli(["cloud", "--tool", "takeover", "--target", "x.s3-website-us-east-1.amazonaws.com"]);
  assert.equal(r2.status, 0, r2.stderr + r2.stdout);
  assert.match(r2.stdout, /s3|amazonaws/i);
});

test("v1.6 CLI: reverse tanpa --confirm -> exit 2; caido tanpa server -> skipped/error", () => {
  const r1 = runCli(["reverse", "--tool", "rea", "--file", "app.apk"]);
  assert.equal(r1.status, 2, r1.stderr + r1.stdout);
  assert.match(r1.stdout + r1.stderr, /--confirm/);
  const r2 = runCli(["caido", "--list"]);
  assert.ok(r2.status === 0 || r2.status === 2, r2.stderr + r2.stdout);
  assert.match(r2.stdout + r2.stderr, /Dilewati|tidak ditemukan|error/i);
});

test("v1.6 CLI: graphql tanpa target -> exit 2; scan --tool tidak valid tetap ditolak", () => {
  const r1 = runCli(["graphql"]);
  assert.equal(r1.status, 2, r1.stderr + r1.stdout);
  const r2 = runCli(["scan", "--tool", "bogus-tool", "--target", "https://example.com/"]);
  assert.equal(r2.status, 2, r2.stderr + r2.stdout);
});
