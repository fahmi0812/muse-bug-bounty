// tests/failon-codesearch.test.js — P1-5: --fail-on + pencarian kode.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { severityFor, meetsThreshold, checkFailOn } from "../bounty/lib/failon.js";
import { searchCode } from "../bounty/lib/codesearch.js";

test("failon: severity heuristik dari kelas + ambang", () => {
  assert.equal(severityFor({ vulnClass: "Remote Code Execution" }), "critical");
  assert.equal(severityFor({ vulnClass: "SQL Injection", cwe: "CWE-89" }), "high");
  assert.equal(severityFor({ vulnClass: "CORS Misconfiguration" }), "low");
  assert.equal(severityFor({ vulnClass: "Kelas Tidak Dikenal" }), "medium");
  assert.equal(meetsThreshold("critical", "high"), true);
  assert.equal(meetsThreshold("medium", "high"), false);
  assert.equal(meetsThreshold("high", "bogus"), false);
});

test("failon: checkFailOn memicu hanya bila ada temuan >= ambang", () => {
  const findings = [
    { vulnClass: "SQL Injection" },
    { vulnClass: "CORS Misconfiguration" },
  ];
  const hit = checkFailOn(findings, "high");
  assert.equal(hit.triggered, true);
  assert.equal(hit.count, 1);
  assert.equal(hit.worst, "high");
  assert.equal(checkFailOn(findings, "critical").triggered, false);
  assert.equal(checkFailOn([], "high").triggered, false);
  assert.equal(checkFailOn(findings, "").triggered, false);
});

test("codesearch: temukan pola di file, regex tidak valid -> error", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-codesearch-"));
  try {
    writeFileSync(join(dir, "app.js"), "const x = 1;\n// TODO: pakai eval di sini\neval(userInput);\n");
    writeFileSync(join(dir, "readme.md"), "tidak ada yang dicari\n");
    const r = searchCode(dir, "eval\\(", { useRipgrep: false });
    assert.equal(r.results.length, 1);
    assert.equal(r.results[0].line, 3);
    assert.match(r.results[0].file, /app\.js$/);
    const bad = searchCode(dir, "([", { useRipgrep: false });
    assert.ok(bad.error);
    const missing = searchCode(join(dir, "tidak-ada"), "x", { useRipgrep: false });
    assert.ok(missing.error);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// CLI nyata (tanpa strix): validasi --fail-on, dedup, codesearch.
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");
function runCli(args, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bounty-p15-cli-"));
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, env: { ...process.env, BOUNTY_DB: join(dir, "bounty.db"), ...env }, encoding: "utf8" });
  rmSync(dir, { recursive: true, force: true });
  return r;
}

test("P1-5 CLI: run --fail-on tidak valid -> exit 2; dedup kosong -> exit 0", () => {
  const r1 = runCli(["run", "--fail-on", "bogus", "--dry-run"]);
  assert.equal(r1.status, 2, r1.stderr + r1.stdout);
  assert.match(r1.stdout + r1.stderr, /--fail-on wajib/);
  const r2 = runCli(["dedup"]);
  assert.equal(r2.status, 0, r2.stderr + r2.stdout);
  assert.match(r2.stdout, /Validasi lolos/);
});

test("P1-5 CLI: codesearch ketemu + regex rusak -> exit 2", () => {
  const r1 = runCli(["codesearch", "--dir", "bounty/lib", "--pattern", "severityFor", "--max", "3"]);
  assert.equal(r1.status, 0, r1.stderr + r1.stdout);
  assert.match(r1.stdout, /kecocokan/);
  const r2 = runCli(["codesearch", "--dir", "bounty/lib", "--pattern", "(["]);
  assert.equal(r2.status, 2, r2.stderr + r2.stdout);
});
