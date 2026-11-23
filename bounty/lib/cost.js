// bounty/lib/cost.js — Cost tracking nyata (v1.3, 3.5).
// Sumber andal biaya adalah run.json Strix (usage/cost); stdout regex
// (parseCost) hanya fallback. Semua fungsi murni, tanpa I/O.
export function costFromRunJson(runJson = null) {
  if (!runJson || typeof runJson !== "object") return 0;
  const usage = runJson.usage && typeof runJson.usage === "object" ? runJson.usage : {};
  const raw = usage.total_cost_usd ?? usage.cost ?? runJson.total_cost_usd ?? runJson.cost ?? 0;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

// Status budget: warn di 80%, exceeded bila biaya >= budget.
export function budgetStatus({ spent = 0, budget = 0 } = {}) {
  const s = Number(spent) || 0;
  const b = Number(budget) || 0;
  const pct = b > 0 ? s / b : 0;
  return { spent: s, budget: b, pct, warn: pct >= 0.8 && s < b, exceeded: b > 0 && s >= b };
}

export function shouldStop({ spent = 0, budget = 0 } = {}) {
  return budgetStatus({ spent, budget }).exceeded;
}

export default { costFromRunJson, budgetStatus, shouldStop };
