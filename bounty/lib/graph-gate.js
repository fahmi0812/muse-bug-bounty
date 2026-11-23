// bounty/lib/graph-gate.js — P2-4: gerbang keputusan upgrade graf/memori.
// Aturan dari gap report: graf ala Cairn / memori ala PentAGI (pgvector +
// Neo4j) HANYA dibangun bila baseline P0-1 membuktikan planning/state
// adalah bottleneck. Tanpa baseline, jawabannya selalu "tetap SQL".
// Fungsi murni (tanpa I/O) agar bisa dites; CLI `bounty graph-gate`
// membaca baseline.json + statistik store lalu memanggil decideGraphUpgrade.
export const DEFAULT_THRESHOLDS = {
  minLabsTpDown: 2,        // TP bounty di bawah baseline di >= N lab
  minRepeatedFp: 3,        // kelas vuln sama ditolak reviewer >= N kali
  minOpenCoverage: 5,      // permukaan x kelas masih "open" >= N
  maxUntracedShare: 0.5,   // > 50% temuan tanpa chain = sinyal perencanaan lemah
};

export function decideGraphUpgrade({ baseline = null, stats = {} } = {}, thresholds = {}) {
  const t = { ...DEFAULT_THRESHOLDS, ...thresholds };
  const signals = [];
  if (!baseline) {
    return {
      recommend: "keep-sql",
      reason: "Baseline belum ada (eval/results/baseline.json tidak ditemukan) — upgrade graf tidak bisa diputuskan. Jalankan baseline dulu (scripts/baseline-laptop.sh).",
      signals,
    };
  }
  const labs = baseline.labs ?? baseline ?? {};
  const labNames = Object.keys(labs);
  let tpDown = 0;
  for (const name of labNames) {
    const lab = labs[name] ?? {};
    const base = lab.baseline ?? lab.base ?? {};
    const bounty = lab.bounty ?? lab.ours ?? {};
    const baseTp = Number(base.tp ?? base.true_positives ?? 0);
    const bountyTp = Number(bounty.tp ?? bounty.true_positives ?? 0);
    if (baseTp > 0 && bountyTp < baseTp) tpDown++;
  }
  if (tpDown >= t.minLabsTpDown) {
    signals.push({ name: "tp-down", detail: `TP bounty di bawah baseline Strix di ${tpDown}/${labNames.length} lab — perencanaan melewatkan temuan.` });
  }
  const repeatedFp = Number(stats.repeatedFpClasses ?? 0);
  if (repeatedFp >= t.minRepeatedFp) {
    signals.push({ name: "repeated-fp", detail: `${repeatedFp} kelas vuln ditolak berulang oleh reviewer — memori lintas-run tidak cukup menahan FP.` });
  }
  const openCoverage = Number(stats.openCoverage ?? 0);
  if (openCoverage >= t.minOpenCoverage) {
    signals.push({ name: "open-coverage", detail: `${openCoverage} pasangan permukaan x kelas masih "open" — planner tidak menutup peta.` });
  }
  const untraced = Number(stats.untracedFindings ?? 0);
  const total = Number(stats.totalFindings ?? 0);
  if (total > 0 && untraced / total > t.maxUntracedShare) {
    signals.push({ name: "untraced-chains", detail: `${untraced}/${total} temuan tanpa chain — graf SQL-view tidak cukup melacak asal temuan.` });
  }
  if (signals.length === 0) {
    return {
      recommend: "keep-sql",
      reason: "Tidak ada sinyal bottleneck planning/state di baseline — graf SQL-view + memori SQLite cukup. Cek ulang setelah baseline berikutnya.",
      signals,
    };
  }
  return {
    recommend: "upgrade",
    reason: `${signals.length} sinyal bottleneck: ${signals.map((s) => s.name).join(", ")}. Upgrade ke graf fact-intent (Cairn) / pgvector+Neo4j (PentAGI) kini beralasan — baca eval/benchmarks/graph-gate.md sebelum membangun.`,
    signals,
  };
}

export default { decideGraphUpgrade, DEFAULT_THRESHOLDS };
