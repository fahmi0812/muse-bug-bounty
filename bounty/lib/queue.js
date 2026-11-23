// bounty/lib/queue.js — Antrean multi-target (v1.3, 3.6).
// Target dijalankan SATU PER SATU (bukan paralel, bukan spawnSync
// blocking per target di CLI — runOne boleh async), tiap target dengan
// budget-nya sendiri. Berhenti bila total biaya >= budget (shouldStop
// dari cost.js). runOne(target) -> { usd, findings } (findings = array
// temuan, boleh kosong). Tidak ada auto-submit, tidak ada pembayaran.
import { shouldStop } from "./cost.js";

export async function runQueue(targets = [], runOne, { budget = 0, onProgress = null } = {}) {
  const list = Array.isArray(targets) ? targets : [];
  if (typeof runOne !== "function") throw new TypeError("runOne harus fungsi (target) => { usd, findings }");
  const results = [];
  let totalUsd = 0;
  let stopped = false;
  for (const target of list) {
    if (shouldStop({ spent: totalUsd, budget })) { stopped = true; break; }
    const out = await runOne(target);
    const usd = Number(out?.usd) || 0;
    const findings = Array.isArray(out?.findings) ? out.findings : [];
    totalUsd += usd;
    const status = shouldStop({ spent: totalUsd, budget }) ? "stopped-budget" : "done";
    results.push({ target, status, usd, findings: findings.length });
    if (typeof onProgress === "function") {
      try { onProgress({ target, status, usd, totalUsd, done: results.length, total: list.length }); } catch {}
    }
    if (status === "stopped-budget") { stopped = true; break; }
  }
  return { results, totalUsd, stopped, done: results.length, total: list.length };
}

export default { runQueue };
