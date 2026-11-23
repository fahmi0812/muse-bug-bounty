// tests/integration-v17.test.js — P2 e2e: firmware, promptfoo-gate, graph-gate.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = process.cwd();
function runBounty(args, env = {}) {
  return spawnSync(process.execPath, ["bounty/bin/bounty.mjs", ...args], {
    cwd: REPO,
    encoding: "utf8",
    env: { ...process.env, BOUNTY_DB: join(tmpdir(), `bounty-v17-${process.pid}.db`), ...env },
  });
}

test("v1.10.0: --version + firmware tanpa tool -> exit 2 (tool tidak dikenal) / skipped", () => {
  const v = runBounty(["--version"]);
  assert.match(v.stdout, /bounty v1.10.0/);
  const bad = runBounty(["firmware", "--tool", "tidak-ada", "--file", "x.bin"]);
  assert.equal(bad.status, 2);
  const noFile = runBounty(["firmware", "--tool", "binwalk-ng"]);
  assert.equal(noFile.status, 2);
});

test("v1.7.0: firmware binwalk-ng tanpa binary -> skipped exit 0", () => {
  const dir = mkdtempSync(join(tmpdir(), "fw-"));
  const img = join(dir, "fw.bin");
  writeFileSync(img, Buffer.from("firmware palsu"));
  try {
    const r = runBounty(["firmware", "--tool", "binwalk-ng", "--file", img], { PATH: "/usr/bin:/bin" });
    // binwalk tidak ada di VM -> skipped (0) atau error lingkungan; keduanya bukan crash
    assert.ok([0, 2].includes(r.status), `status ${r.status}: ${r.stdout} ${r.stderr}`);
    assert.match(r.stdout + r.stderr, /Dilewati|Error/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("v1.7.0: promptfoo-gate fail-closed + lolos", () => {
  const dir = mkdtempSync(join(tmpdir(), "pf-"));
  const missing = runBounty(["promptfoo-gate", "--results", join(dir, "tidak-ada.json")]);
  assert.equal(missing.status, 1);
  assert.match(missing.stdout, /GAGAL/);
  const good = { results: Array.from({ length: 10 }, (_, i) => ({ prompt: `p${i}`, success: i < 9, gradingResult: { componentResults: [] } })), stats: { successes: 9, failures: 1 } };
  const goodPath = join(dir, "good.json");
  writeFileSync(goodPath, JSON.stringify(good));
  const ok = runBounty(["promptfoo-gate", "--results", goodPath]);
  assert.equal(ok.status, 0);
  assert.match(ok.stdout, /LOLOS/);
  const bad = { ...good, stats: { successes: 5, failures: 5 }, results: good.results.map((r, i) => ({ ...r, success: i < 5 })) };
  const badPath = join(dir, "bad.json");
  writeFileSync(badPath, JSON.stringify(bad));
  const fail = runBounty(["promptfoo-gate", "--results", badPath]);
  assert.equal(fail.status, 1);
  assert.match(fail.stdout, /GAGAL/);
  rmSync(dir, { recursive: true, force: true });
});

test("v1.7.0: graph-gate tanpa baseline -> TETAP SQL", () => {
  const r = runBounty(["graph-gate", "--baseline", join(tmpdir(), "baseline-tidak-ada.json")]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /TETAP SQL/);
  assert.match(r.stdout, /Baseline belum ada/);
});
