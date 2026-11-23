// bounty/lib/promptfoo-gate.js — Gerbang CI red-team Promptfoo (P2-3).
// Promptfoo adalah alat EVAL, bukan runner bounty: ia menguji pertahanan
// harness eval kita (eval/promptfoo/promptfooconfig.yaml) lewat
// `promptfoo eval` (kasus tetap) dan `promptfoo redteam run` (serangan
// yang dibangkitkan plugin). Modul ini HANYA membaca hasil JSON-nya dan
// memutuskan lolos/gagal — tidak menjalankan promptfoo, tidak memanggil
// provider, tidak menulis apa pun.
//
// Bentuk JSON yang dibaca (terverifikasi dari docs promptfoo, 23 Nov 2026):
//   { version: 3, timestamp, results: { stats: { successes, failures },
//     results: [ { success, score, prompt, gradingResult:
//       { componentResults: [ { pass, score, reason, assertion: { type } } ] } } ] } }
// Parser toleran: bila `results.stats` hilang, hitung dari baris
// (`success === false` = gagal); bila `gradingResult` hilang, pakai
// `success` baris saja. Best-effort: output `redteam run` diasumsikan
// memakai bentuk eval yang sama (belum pernah dijalankan live di VM ini).
import { readFileSync, existsSync } from "node:fs";

export const DEFAULT_MIN_PASS_RATE = 0.8;

function toNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function rowPrompt(row = {}) {
  const p = row.prompt;
  if (typeof p === "string") return p;
  if (p && typeof p === "object") return String(p.raw ?? p.label ?? JSON.stringify(p));
  return String(row.testIdx !== undefined ? `test #${row.testIdx}` : "");
}

function rowFailures(row = {}) {
  const comps = row.gradingResult?.componentResults;
  if (Array.isArray(comps)) {
    return comps
      .filter((c) => c && c.pass === false)
      .map((c) => ({
        assertion: String(c.assertion?.type ?? c.assertion ?? "unknown"),
        reason: String(c.reason ?? ""),
        score: toNumber(c.score, 0),
      }));
  }
  return [];
}

export function parsePromptfooResults(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return { error: "hasil promptfoo bukan objek JSON" };
  }
  const results = data.results && typeof data.results === "object" ? data.results : data;
  const stats = results.stats && typeof results.stats === "object" ? results.stats : null;
  const rows = Array.isArray(results.results)
    ? results.results
    : Array.isArray(results)
      ? results
      : [];
  let passed = 0;
  let failed = 0;
  if (stats && (stats.successes !== undefined || stats.failures !== undefined)) {
    passed = toNumber(stats.successes, 0);
    failed = toNumber(stats.failures, 0);
  } else {
    for (const row of rows) {
      if (row && row.success === false) failed += 1;
      else passed += 1;
    }
  }
  const total = passed + failed;
  const failures = [];
  for (const row of rows) {
    if (!row || row.success !== false) continue;
    const comps = rowFailures(row);
    failures.push({
      prompt: rowPrompt(row),
      assertion: comps[0]?.assertion ?? "unknown",
      reason: comps[0]?.reason ?? String(row.error ?? ""),
      score: toNumber(row.score, 0),
    });
  }
  return {
    total,
    passed,
    failed,
    passRate: total > 0 ? passed / total : 0,
    failures,
  };
}

export function readPromptfooResults(pathOrObj) {
  if (pathOrObj && typeof pathOrObj === "object" && !Array.isArray(pathOrObj)) {
    return parsePromptfooResults(pathOrObj);
  }
  if (typeof pathOrObj !== "string" || !pathOrObj) {
    return { error: "butuh path file JSON atau objek hasil promptfoo" };
  }
  if (!existsSync(pathOrObj)) {
    return { error: `file hasil promptfoo tidak ditemukan: ${pathOrObj}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(pathOrObj, "utf8"));
  } catch (e) {
    return { error: `file hasil promptfoo bukan JSON valid: ${e.message}` };
  }
  return parsePromptfooResults(parsed);
}

// Gerbang fail-closed: error, hasil kosong, atau passRate di bawah ambang
// semuanya GAGAL (tidak pernah lolos diam-diam).
export function gateResults(results, { minPassRate = DEFAULT_MIN_PASS_RATE } = {}) {
  if (!results || typeof results !== "object") {
    return { pass: false, reason: "hasil promptfoo tidak ada" };
  }
  if (results.error) {
    return { pass: false, reason: `tidak bisa membaca hasil: ${results.error}` };
  }
  const total = toNumber(results.total, 0);
  if (total <= 0) {
    return { pass: false, reason: "tidak ada hasil tes promptfoo (total 0) — gerbang gagal tertutup" };
  }
  const rate = toNumber(results.passRate, 0);
  const min = toNumber(minPassRate, DEFAULT_MIN_PASS_RATE);
  if (rate >= min) {
    return { pass: true, reason: `pass rate ${(rate * 100).toFixed(1)}% >= ${(min * 100).toFixed(0)}% (${results.passed}/${total} lolos)` };
  }
  return { pass: false, reason: `pass rate ${(rate * 100).toFixed(1)}% < ${(min * 100).toFixed(0)}% (${results.passed}/${total} lolos, ${results.failed} gagal)` };
}

export default { readPromptfooResults, parsePromptfooResults, gateResults, DEFAULT_MIN_PASS_RATE };
