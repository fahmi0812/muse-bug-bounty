// tests/graph-gate.test.js — P2-4: upgrade graf hanya bila baseline membuktikan.
import { test } from "node:test";
import assert from "node:assert/strict";
import { decideGraphUpgrade } from "../bounty/lib/graph-gate.js";

test("graph-gate: tanpa baseline -> tetap SQL, tidak bisa diputuskan", () => {
  const r = decideGraphUpgrade({ baseline: null });
  assert.equal(r.recommend, "keep-sql");
  assert.match(r.reason, /Baseline belum ada/);
});

test("graph-gate: baseline bagus + statistik bersih -> tetap SQL", () => {
  const baseline = {
    labs: {
      "juice-shop": { baseline: { tp: 8 }, bounty: { tp: 9 } },
      dvwa: { baseline: { tp: 7 }, bounty: { tp: 7 } },
    },
  };
  const r = decideGraphUpgrade({ baseline, stats: { repeatedFpClasses: 0, openCoverage: 1, untracedFindings: 1, totalFindings: 10 } });
  assert.equal(r.recommend, "keep-sql");
  assert.equal(r.signals.length, 0);
});

test("graph-gate: TP turun di 2 lab + FP berulang -> upgrade", () => {
  const baseline = {
    labs: {
      "juice-shop": { baseline: { tp: 8 }, bounty: { tp: 5 } },
      dvwa: { baseline: { tp: 7 }, bounty: { tp: 4 } },
      vampi: { baseline: { tp: 6 }, bounty: { tp: 6 } },
    },
  };
  const r = decideGraphUpgrade({ baseline, stats: { repeatedFpClasses: 3, openCoverage: 0, untracedFindings: 0, totalFindings: 10 } });
  assert.equal(r.recommend, "upgrade");
  assert.ok(r.signals.some((s) => s.name === "tp-down"));
  assert.ok(r.signals.some((s) => s.name === "repeated-fp"));
});

test("graph-gate: satu sinyal saja belum cukup -> tetap SQL", () => {
  const baseline = {
    labs: { "juice-shop": { baseline: { tp: 8 }, bounty: { tp: 5 } } },
  };
  const r = decideGraphUpgrade({ baseline, stats: {} });
  assert.equal(r.recommend, "keep-sql");
});

test("graph-gate: temuan tanpa chain > 50% -> upgrade", () => {
  const baseline = { labs: { dvwa: { baseline: { tp: 7 }, bounty: { tp: 7 } } } };
  const r = decideGraphUpgrade({ baseline, stats: { untracedFindings: 6, totalFindings: 10 } });
  assert.equal(r.recommend, "upgrade");
  assert.ok(r.signals.some((s) => s.name === "untraced-chains"));
});
