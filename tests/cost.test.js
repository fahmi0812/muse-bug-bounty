// tests/cost.test.js — v1.3 (3.5): cost tracking nyata dari run.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { costFromRunJson, budgetStatus, shouldStop } from "../bounty/lib/cost.js";

test("costFromRunJson: baca usage.total_cost_usd, lalu total_cost_usd, lalu cost", () => {
  assert.equal(costFromRunJson({ usage: { total_cost_usd: 1.23 } }), 1.23);
  assert.equal(costFromRunJson({ total_cost_usd: 0.55 }), 0.55);
  assert.equal(costFromRunJson({ cost: 2 }), 2);
  assert.equal(costFromRunJson({ usage: { cost: 0.42 } }), 0.42);
});

test("costFromRunJson: kosong / rusak / negatif -> 0", () => {
  assert.equal(costFromRunJson(null), 0);
  assert.equal(costFromRunJson({}), 0);
  assert.equal(costFromRunJson({ usage: { total_cost_usd: -1 } }), 0);
  assert.equal(costFromRunJson({ usage: { total_cost_usd: "bukan-angka" } }), 0);
  assert.equal(costFromRunJson("teks"), 0);
});

test("budgetStatus: warn di 80%, exceeded bila biaya >= budget", () => {
  assert.deepEqual(budgetStatus({ spent: 1, budget: 5 }), { spent: 1, budget: 5, pct: 0.2, warn: false, exceeded: false });
  const w = budgetStatus({ spent: 4, budget: 5 });
  assert.equal(w.pct, 0.8);
  assert.equal(w.warn, true);
  assert.equal(w.exceeded, false);
  const e = budgetStatus({ spent: 5, budget: 5 });
  assert.equal(e.exceeded, true);
  assert.equal(e.warn, false);
  assert.equal(budgetStatus({ spent: 10, budget: 0 }).exceeded, false); // tanpa budget = tanpa batas
});

test("shouldStop: true hanya bila budget > 0 dan spent >= budget", () => {
  assert.equal(shouldStop({ spent: 4.99, budget: 5 }), false);
  assert.equal(shouldStop({ spent: 5, budget: 5 }), true);
  assert.equal(shouldStop({ spent: 6, budget: 5 }), true);
  assert.equal(shouldStop({ spent: 100, budget: 0 }), false);
});
