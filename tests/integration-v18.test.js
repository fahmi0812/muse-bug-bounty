// tests/integration-v18.test.js — v1.8 UI: tampilan CLI (tabel, ringkasan, warna), dibawa ke v1.12.0.
// Output CLI di sini di-pipe (bukan TTY) -> warna otomatis mati, teks polos.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

function runCli(args, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v18-cli-"));
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, env: { ...process.env, BOUNTY_DB: join(dir, "bounty.db"), ...env }, encoding: "utf8" });
  rmSync(dir, { recursive: true, force: true });
  return r;
}

test("v1.10 CLI: --version mencetak 1.12.0", () => {
  const r = runCli(["--version"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /bounty v1.13.0/);
});

test("v1.10 CLI: programs tampil sebagai tabel ber-header", () => {
  const r = runCli(["programs"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Program\s+Scope\s+Budget\s+Rate\s+Roles/);
  assert.match(r.stdout, /dvga/);
  assert.match(r.stdout, /llm-app/);
});

test("v1.10 CLI: dry-run tetap teks lama + tanpa kode ANSI saat di-pipe", () => {
  const r = runCli(["run", "--target", "https://example.com/api/users", "--program", "programs/example.md", "--dry-run"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Scope OK/);
  assert.match(r.stdout, /Budget: \$5/);
  assert.doesNotMatch(r.stdout, /\x1b\[/, "output pipe tidak boleh berisi ANSI");
});

test("v1.10 CLI: findings + review kosong tetap exit 0 dengan tabel/total", () => {
  const r1 = runCli(["findings"]);
  assert.equal(r1.status, 0, r1.stderr);
  assert.match(r1.stdout, /Tidak ada temuan tersimpan/);
  const r2 = runCli(["review"]);
  assert.equal(r2.status, 0, r2.stderr);
  assert.match(r2.stdout, /Tidak ada kandidat/);
});

test("v1.10 CLI: NO_COLOR=1 tidak mengubah output pipe (tetap polos)", () => {
  const r = runCli(["programs"], { NO_COLOR: "1" });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /\x1b\[/);
  assert.match(r.stdout, /dvga/);
});
