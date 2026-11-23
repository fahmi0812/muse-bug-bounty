// bounty/lib/bench.js — scoring + benchmark runner.
export function median(values) {
  const sorted = [...(values ?? [])].map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  if (sorted.length === 0) return 0;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function findingKey(f) {
  const endpoint = String(f.endpoint ?? f.path ?? "").toLowerCase().replace(/\/+$/, "");
  const method = String(f.method ?? "").toUpperCase();
  const cls = String(f.vuln_class ?? f.vulnClass ?? "").toLowerCase().replace(/[\s_]+/g, "-");
  const cwe = String(f.cwe ?? "").toUpperCase();
  return [endpoint, method, cls, cwe].join("|");
}

export function scoreFindings(findings = [], oracle = []) {
  const oracleKeys = new Set(oracle.map(findingKey));
  const seen = new Set();
  let tp = 0;
  let fp = 0;
  for (const f of findings) {
    const k = findingKey(f);
    if (oracleKeys.has(k) && !seen.has(k)) {
      tp += 1;
      seen.add(k);
    } else {
      fp += 1;
    }
  }
  const fn = Math.max(0, oracleKeys.size - seen.size);
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const fpRate = findings.length === 0 ? 0 : fp / findings.length;
  return { tp, fp, fn, precision, recall, fpRate };
}

export async function runBench({ labs = [], runs = 3, runFn }) {
  if (typeof runFn !== "function") throw new Error("runFn wajib fungsi async");
  const results = [];
  for (const lab of labs) {
    const perRun = [];
    for (let i = 0; i < runs; i++) {
      const started = Date.now();
      const out = await runFn(lab, i);
      const elapsed = Date.now() - started;
      const findings = out?.findings ?? [];
      const oracle = lab.oracle ?? lab.expected ?? [];
      const scored = scoreFindings(findings, oracle);
      perRun.push({
        ...scored,
        time_ms: out?.time_ms ?? elapsed,
        usd: out?.usd ?? 0,
      });
    }
    const pick = (k) => perRun.map((r) => r[k]);
    const variance = (arr) => {
      if (arr.length < 2) return 0;
      const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
      return arr.reduce((a, b) => a + (b - mean) ** 2, 0) / arr.length;
    };
    results.push({
      lab: lab.name ?? lab.id ?? "lab",
      runs: perRun.length,
      median: {
        tp: median(pick("tp")),
        fp: median(pick("fp")),
        fn: median(pick("fn")),
        time_ms: median(pick("time_ms")),
        usd: median(pick("usd")),
        precision: median(pick("precision")),
        recall: median(pick("recall")),
      },
      variance: {
        tp: variance(pick("tp")),
        fp: variance(pick("fp")),
        time_ms: variance(pick("time_ms")),
        usd: variance(pick("usd")),
      },
      perRun,
    });
  }
  return results;
}

export default { scoreFindings, median, runBench };
