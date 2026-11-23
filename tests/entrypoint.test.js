// tests/entrypoint.test.js — Regresi isMain di bounty/bin/bounty.mjs.
// Bug live 23 Nov 2026: main() tidak pernah jalan saat CLI dijalankan lewat
// symlink (instal global npm) atau dari path berisi spasi — isMain lama
// membandingkan resolve(argv[1]) dengan resolve(new URL(...).pathname):
// symlink tidak di-resolve, dan pathname URL masih ter-encode (%20).
// Hasilnya: CLI exit 0 tanpa output apa pun. Perbaikan: realpathSync +
// fileURLToPath. Tes ini menjalankan CLI sungguhan lewat kedua jalur itu.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

test("entrypoint: lewat symlink (instal global npm) --version mencetak versi", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-entry-"));
  try {
    const link = join(dir, "bounty");
    symlinkSync(CLI, link);
    // Jalankan lewat node dengan argv[1] = path symlink (sama seperti yang
    // diterima node saat file dieksekusi lewat shebang). File repo sendiri
    // tidak +x; npm yang memberi +x saat instal global.
    const r = spawnSync(process.execPath, [link, "--version"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /bounty v\d+\.\d+\.\d+/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("entrypoint: dari path berisi spasi --version mencetak versi", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty entry "));
  try {
    const link = join(dir, "bounty.mjs");
    symlinkSync(CLI, link);
    const r = spawnSync(process.execPath, [link, "--version"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /bounty v\d+\.\d+\.\d+/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("entrypoint: lewat symlink programs mencetak tabel program", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-entry-"));
  try {
    const link = join(dir, "bounty");
    symlinkSync(CLI, link);
    const r = spawnSync(process.execPath, [link, "programs"], { cwd: ROOT, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Example Program/);
    assert.match(r.stdout, /juice-shop/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
