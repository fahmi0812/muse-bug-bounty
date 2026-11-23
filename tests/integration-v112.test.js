// tests/integration-v112.test.js — v1.12.0: perbaikan kecil.
// (1) Router promosi penuh (scoreAll diekspor) — lihat tests/learning.test.js.
// (2) Recon otomatis daftarkan surface ke planner.
// (3) Router accuracy 100% semua lab — lihat tests/bench.test.js + npm run bench.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

function runCli(args, env) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, env, encoding: "utf8" });
}

test("v1.12 e2e: bounty recon subfinder palsu -> surface masuk planner", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-v112-"));
  const binDir = join(dir, "bin");
  mkdirSync(binDir, { recursive: true });
  const fake = join(binDir, "subfinder");
  writeFileSync(fake, "#!/bin/sh\nprintf '%s\\n' 'api.example.com' 'app.example.com' 'api.example.com'\n");
  chmodSync(fake, 0o755);
  const env = {
    ...process.env,
    BOUNTY_DB: join(dir, "bounty.db"),
    PATH: `${binDir}${delimiter}${process.env.PATH}`,
  };
  try {
    const r = runCli(["recon", "--tool", "subfinder", "--target", "example.com", "--program", "programs/example.md"], env);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /2 surface baru didaftarkan ke planner/);
    const p = runCli(["plan", "--program", "Example Program"], env);
    assert.equal(p.status, 0, p.stderr + p.stdout);
    assert.match(p.stdout, /Surface: 2/);
    assert.match(p.stdout, /api\.example\.com/);
    assert.match(p.stdout, /app\.example\.com/);
    // Idempotent: recon kedua tidak menambah surface lagi.
    const r2 = runCli(["recon", "--tool", "subfinder", "--target", "example.com", "--program", "programs/example.md"], env);
    assert.equal(r2.status, 0, r2.stderr + r2.stdout);
    assert.doesNotMatch(r2.stdout, /surface baru didaftarkan/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
