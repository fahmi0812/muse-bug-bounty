// tests/promptfoo-gate.test.js — P2-3: baca hasil promptfoo + gerbang.
// Hanya memakai objek JSON contoh (bentuk dari docs promptfoo) dan file
// temp — tidak pernah menjalankan promptfoo atau provider nyata.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readPromptfooResults, parsePromptfooResults, gateResults, DEFAULT_MIN_PASS_RATE } from "../bounty/lib/promptfoo-gate.js";

function sampleResults({ successes = 8, failures = 2 } = {}) {
  const rows = [];
  for (let i = 0; i < successes; i++) {
    rows.push({ testIdx: i, success: true, score: 1, prompt: { raw: `case ok ${i}` }, gradingResult: { componentResults: [{ pass: true, score: 1, reason: "", assertion: { type: "llm-rubric" } }] } });
  }
  for (let i = 0; i < failures; i++) {
    rows.push({ testIdx: successes + i, success: false, score: 0, prompt: { raw: `case fail ${i}` }, gradingResult: { componentResults: [{ pass: false, score: 0, reason: "revealed scope detail", assertion: { type: "llm-rubric" } }] } });
  }
  return { version: 3, timestamp: "2026-11-23T00:00:00Z", results: { stats: { successes, failures }, results: rows } };
}

test("promptfoo-gate: parse hasil lengkap (stats + baris) -> total/passRate/daftar gagal", () => {
  const r = parsePromptfooResults(sampleResults({ successes: 8, failures: 2 }));
  assert.equal(r.total, 10);
  assert.equal(r.passed, 8);
  assert.equal(r.failed, 2);
  assert.equal(r.passRate, 0.8);
  assert.equal(r.failures.length, 2);
  assert.equal(r.failures[0].assertion, "llm-rubric");
  assert.match(r.failures[0].reason, /revealed scope/);
  assert.match(r.failures[0].prompt, /case fail 0/);
});

test("promptfoo-gate: tanpa stats -> hitung dari baris; tanpa gradingResult -> pakai success", () => {
  const r = parsePromptfooResults({ results: { results: [
    { success: true, prompt: "a" },
    { success: false, prompt: "b", error: "provider timeout" },
    { success: false, prompt: "c" },
  ] } });
  assert.equal(r.total, 3);
  assert.equal(r.passed, 1);
  assert.equal(r.failed, 2);
  assert.equal(r.failures[1].reason, "");
  assert.equal(r.failures[0].assertion, "unknown");
});

test("promptfoo-gate: baca dari path file; file hilang / JSON rusak -> error", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-promptfoo-"));
  try {
    const p = join(dir, "results.json");
    writeFileSync(p, JSON.stringify(sampleResults({ successes: 5, failures: 0 })));
    const r = readPromptfooResults(p);
    assert.equal(r.total, 5);
    assert.equal(r.passRate, 1);
    assert.equal(readPromptfooResults(join(dir, "tidak-ada.json")).error !== undefined, true);
    const bad = join(dir, "rusak.json");
    writeFileSync(bad, "{bukan json");
    assert.match(readPromptfooResults(bad).error, /bukan JSON valid/);
    assert.match(readPromptfooResults("").error, /butuh path/);
    assert.match(readPromptfooResults(null).error, /butuh path/);
    assert.match(readPromptfooResults([1, 2]).error, /butuh path/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("promptfoo-gate: ambang default 0.8 — 8/10 lolos, 7/10 gagal", () => {
  assert.equal(DEFAULT_MIN_PASS_RATE, 0.8);
  const ok = gateResults(parsePromptfooResults(sampleResults({ successes: 8, failures: 2 })));
  assert.equal(ok.pass, true);
  assert.match(ok.reason, /80\.0% >= 80%/);
  const no = gateResults(parsePromptfooResults(sampleResults({ successes: 7, failures: 3 })));
  assert.equal(no.pass, false);
  assert.match(no.reason, /70\.0% < 80%/);
});

test("promptfoo-gate: ambang kustom dihormati", () => {
  const r = parsePromptfooResults(sampleResults({ successes: 9, failures: 1 }));
  assert.equal(gateResults(r, { minPassRate: 1 }).pass, false);
  assert.equal(gateResults(r, { minPassRate: 0.9 }).pass, true);
  assert.equal(gateResults(r, { minPassRate: 0.5 }).pass, true);
});

test("promptfoo-gate: fail-closed — error, kosong, dan tanpa hasil tidak pernah lolos", () => {
  assert.equal(gateResults({ error: "file hilang" }).pass, false);
  assert.equal(gateResults(parsePromptfooResults({ results: { stats: { successes: 0, failures: 0 }, results: [] } })).pass, false);
  assert.equal(gateResults(parsePromptfooResults({})).pass, false);
  assert.equal(gateResults(null).pass, false);
  assert.equal(gateResults(parsePromptfooResults("bukan objek")).pass, false);
});
