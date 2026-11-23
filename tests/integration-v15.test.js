// tests/integration-v15.test.js — v1.5: recon, jsluice, agent-breaker, pyrit, oast, platform, patterns.
// CLI nyata tanpa binary eksternal (semua runner dilewati dengan exit 0).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

function runCli(args, extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v15-"));
  const env = { ...process.env, BOUNTY_DB: join(dir, "bounty.db"), ...extraEnv };
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, env, encoding: "utf8" });
  rmSync(dir, { recursive: true, force: true });
  return r;
}

test("v1.5 e2e: recon tanpa binary -> dilewati exit 0", () => {
  for (const tool of ["subfinder", "dnsx", "httpx", "katana", "nuclei-kev", "crtsh"]) {
    const target = tool === "crtsh" || tool === "subfinder" || tool === "dnsx" ? "example.com" : "https://example.com/api/";
    const r = runCli(["recon", "--tool", tool, "--target", target, "--program", "programs/example.md"]);
    // crtsh memakai fetch jaringan — di VM tanpa akses bisa error, bukan dilewati.
    if (tool === "crtsh") { assert.ok([0, 2].includes(r.status), r.stderr + r.stdout); continue; }
    assert.equal(r.status, 0, `${tool}: ${r.stderr}${r.stdout}`);
    assert.match(r.stdout, /Dilewati/);
  }
});

test("v1.5 e2e: recon --update-templates tanpa nuclei -> dilewati exit 0", () => {
  const r = runCli(["recon", "--update-templates"]);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /Dilewati/);
});

test("v1.5 e2e: scan jsluice + garak-agent-breaker tanpa binary -> dilewati exit 0", () => {
  const r1 = runCli(["scan", "--tool", "jsluice", "--target", "https://example.com/api/app.js", "--program", "programs/example.md"]);
  assert.equal(r1.status, 0, r1.stderr + r1.stdout);
  assert.match(r1.stdout, /Dilewati/);
  const r2 = runCli(["scan", "--tool", "garak-agent-breaker", "--target", "https://example.com/api/", "--program", "programs/example.md"]);
  assert.equal(r2.status, 0, r2.stderr + r2.stdout);
  assert.match(r2.stdout, /Dilewati/);
});

test("v1.5 e2e: scan pyrit tanpa --objective -> exit 2 (validasi dulu)", () => {
  const r = runCli(["scan", "--tool", "pyrit", "--target", "https://example.com/api/", "--program", "programs/example.md"]);
  assert.equal(r.status, 2, r.stderr + r.stdout);
  assert.match(r.stdout + r.stderr, /--objective wajib/);
});

test("v1.5 e2e: oast poll tanpa sesi -> exit 2; platform draft id tidak ada -> exit 2", () => {
  const r1 = runCli(["oast", "poll"]);
  assert.equal(r1.status, 2, r1.stderr + r1.stdout);
  assert.match(r1.stdout + r1.stderr, /Tidak ada sesi OAST/);
  const r2 = runCli(["platform", "draft", "--finding", "999999"]);
  assert.equal(r2.status, 2, r2.stderr + r2.stdout);
  assert.match(r2.stdout + r2.stderr, /tidak ditemukan/);
});

test("v1.5 e2e: patterns tampilkan 184 total 172 bersitasi (naik di v1.9)", () => {
  const r = runCli(["patterns"]);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /184 total, 172 bersitasi/);
  const r2 = runCli(["patterns", "--skill", "hunt-ato"]);
  assert.equal(r2.status, 0, r2.stderr + r2.stdout);
  assert.match(r2.stdout, /7 bersitasi/);
});
