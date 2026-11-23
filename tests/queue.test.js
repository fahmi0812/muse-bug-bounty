// tests/queue.test.js — v1.3 (3.6): antrean multi-target, berhenti saat budget habis.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runQueue } from "../bounty/lib/queue.js";

test("runQueue: target jalan satu per satu, ringkasan per target", async () => {
  const seen = [];
  const out = await runQueue(["a", "b", "c"], async (t) => {
    seen.push(t);
    return { usd: 1, findings: [{}, {}] };
  }, { budget: 10 });
  assert.deepEqual(seen, ["a", "b", "c"]);
  assert.equal(out.done, 3);
  assert.equal(out.totalUsd, 3);
  assert.equal(out.stopped, false);
  assert.deepEqual(out.results.map((r) => r.status), ["done", "done", "done"]);
  assert.deepEqual(out.results.map((r) => r.findings), [2, 2, 2]);
});

test("runQueue: berhenti saat total biaya >= budget, target sisa tidak jalan", async () => {
  const seen = [];
  const out = await runQueue(["a", "b", "c", "d"], async (t) => {
    seen.push(t);
    return { usd: 2, findings: [{}] };
  }, { budget: 5 });
  // a=2, b=4, c=6 >= 5 -> berhenti setelah c; d tidak jalan.
  assert.deepEqual(seen, ["a", "b", "c"]);
  assert.equal(out.done, 3);
  assert.equal(out.totalUsd, 6);
  assert.equal(out.stopped, true);
  assert.equal(out.results[2].status, "stopped-budget");
});

test("runQueue: onProgress dipanggil per target; runOne tanpa findings tetap jalan", async () => {
  const progress = [];
  const out = await runQueue(["a", "b"], async () => ({ usd: 0.5 }), {
    budget: 5,
    onProgress: (p) => progress.push(p),
  });
  assert.equal(progress.length, 2);
  assert.equal(progress[1].totalUsd, 1);
  assert.equal(out.results[0].findings, 0);
});

test("runQueue: menolak runOne bukan fungsi; daftar kosong -> 0 target", async () => {
  await assert.rejects(() => runQueue(["a"], null), /runOne harus fungsi/);
  const out = await runQueue([], async () => ({ usd: 1 }), { budget: 5 });
  assert.deepEqual(out, { results: [], totalUsd: 0, stopped: false, done: 0, total: 0 });
});
