// eval/measure-baseline.mjs — ukur baseline Strix vs bounty (dengan skill)
// secara LIVE di lab Docker. BUKAN mock: script ini exit 2 bila Docker
// atau biner strix tidak ada. Dipakai di laptop (bukan VM/CI).
// Cara pakai:
//   node eval/measure-baseline.mjs [--labs juice-shop,dvwa] [--runs 1] [--mode both|baseline|bounty]
// Hasil: eval/results/baseline.json (baseline Strix) + eval/results/latest.json
// (bounty dengan skill). Gate: TP bounty tidak turun & FP tidak naik vs baseline.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrixOutput } from "../bounty/lib/strix-output.js";
import { scoreFindings } from "../bounty/lib/bench.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const LABELS_DIR = join(ROOT, "eval", "oracle", "labels");
const RESULTS_DIR = join(ROOT, "eval", "results");
const BOUNTY = join(ROOT, "bounty", "bin", "bounty.mjs");

// Port lab (harus sama dengan eval/docker-compose.yml + programs/*.md)
const LAB_TARGET = {
  "juice-shop": "http://localhost:3000",
  dvwa: "http://localhost:8080",
  vampi: "http://localhost:5000",
  dvga: "http://localhost:5013",
  "llm-app": "http://localhost:8000",
};

function has(cmd) {
  return spawnSync("which", [cmd], { encoding: "utf8" }).status === 0;
}
function loadOracle(lab) {
  const j = JSON.parse(readFileSync(join(LABELS_DIR, `${lab}.json`), "utf8"));
  return j.vulns ?? j;
}
function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, { encoding: "utf8", cwd: ROOT, timeout: 600000, ...opts });
}

export function checkPrereqs() {
  const missing = [];
  if (!has("docker")) missing.push("docker");
  if (!has("strix")) missing.push("strix (curl -sSL https://strix.ai/install | bash)");
  if (!has("node")) missing.push("node >= 24");
  return missing;
}

export function measureLab(lab, mode, runs = 1) {
  const oracle = loadOracle(lab);
  const target = LAB_TARGET[lab];
  if (!target) throw new Error(`Target lab ${lab} belum dipetakan di LAB_TARGET`);
  const out = { lab, target, runs: [] };
  for (let i = 0; i < runs; i++) {
    const started = Date.now();
    let res;
    if (mode === "baseline") {
      res = run("strix", ["--target", target, "--max-budget", "5", "--max-turns", "500"]);
    } else {
      res = run(process.execPath, [BOUNTY, "run", "--target", target, "--program", join(ROOT, "programs", `${lab}.md`), "--budget", "5"], { env: { ...process.env, BOUNTY_DB: join(ROOT, ".bounty", `bench-${lab}.db`) } });
    }
    const text = `${res.stdout ?? ""}\n${res.stderr ?? ""}`;
    const { findings, usd } = parseStrixOutput(text, lab);
    const scored = scoreFindings(findings, oracle);
    out.runs.push({ ...scored, usd, time_ms: Date.now() - started, exit: res.status ?? 0 });
  }
  const med = (k) => {
    const v = out.runs.map((r) => r[k]).sort((a, b) => a - b);
    return v[Math.floor(v.length / 2)];
  };
  out.median = { tp: med("tp"), fp: med("fp"), fn: med("fn"), usd: med("usd"), time_ms: med("time_ms") };
  return out;
}

export function main(argv = process.argv.slice(2)) {
  const labsArg = argv.find((a) => a.startsWith("--labs="))?.split("=")[1];
  const runs = Number(argv.find((a) => a.startsWith("--runs="))?.split("=")[1] || 1);
  const mode = argv.find((a) => a.startsWith("--mode="))?.split("=")[1] || "both";
  const labs = labsArg ? labsArg.split(",") : ["juice-shop", "dvwa", "vampi"];
  const missing = checkPrereqs();
  if (missing.length) {
    console.error(`Baseline LIVE tidak bisa jalan di mesin ini — tidak ada: ${missing.join(", ")}.`);
    console.error("Jalankan di laptop dengan Docker + Strix terinstal. Bench mock tetap jalan via: npm run bench");
    return 2;
  }
  console.log("Menyalakan lab Docker...");
  const up = run("docker", ["compose", "-f", join(ROOT, "eval", "docker-compose.yml"), "up", "-d", ...labs]);
  if (up.status !== 0) { console.error("docker compose up gagal:", up.stderr); return 2; }
  mkdirSync(RESULTS_DIR, { recursive: true });
  const results = { measured_at: new Date().toISOString(), mode, runs, labs: {} };
  try {
    for (const lab of labs) {
      if (mode === "both" || mode === "baseline") {
        console.log(`[${lab}] baseline Strix (tanpa skill)...`);
        results.labs[`${lab}:baseline`] = measureLab(lab, "baseline", runs);
      }
      if (mode === "both" || mode === "bounty") {
        console.log(`[${lab}] bounty (dengan skill)...`);
        results.labs[`${lab}:bounty`] = measureLab(lab, "bounty", runs);
      }
    }
    const baselineOnly = Object.fromEntries(Object.entries(results.labs).filter(([k]) => k.endsWith(":baseline")));
    const bountyOnly = Object.fromEntries(Object.entries(results.labs).filter(([k]) => k.endsWith(":bounty")));
    if (Object.keys(baselineOnly).length) writeFileSync(join(RESULTS_DIR, "baseline.json"), JSON.stringify({ ...results, labs: baselineOnly }, null, 2));
    if (Object.keys(bountyOnly).length) writeFileSync(join(RESULTS_DIR, "latest.json"), JSON.stringify({ ...results, labs: bountyOnly }, null, 2));
    console.log("Hasil disimpan ke eval/results/baseline.json + latest.json");
    // Gate: TP bounty tidak turun & FP tidak naik vs baseline (per lab)
    let gateFail = false;
    for (const lab of labs) {
      const b = results.labs[`${lab}:baseline`]?.median;
      const n = results.labs[`${lab}:bounty`]?.median;
      if (!b || !n) continue;
      const ok = n.tp >= b.tp && n.fp <= b.fp;
      console.log(`Gate ${lab}: baseline TP=${b.tp} FP=${b.fp} -> bounty TP=${n.tp} FP=${n.fp} : ${ok ? "LOLOS" : "GAGAL"}`);
      if (!ok) gateFail = true;
    }
    return gateFail ? 1 : 0;
  } finally {
    console.log("Mematikan lab Docker...");
    run("docker", ["compose", "-f", join(ROOT, "eval", "docker-compose.yml"), "down"]);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main());
export default { main, measureLab, checkPrereqs };
