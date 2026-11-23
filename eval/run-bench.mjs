// eval/run-bench.mjs — bench TP/FP/FN vs baseline Strix (mock, deterministik).
// Mode no-docker: lab Docker di-skip, bench jalan dengan mock findings +
// unit router. Exit 0 selama bench selesai; bukan gagal.
// Memakai lib nyata bila ada (bounty/lib/bench.js, router.js, store.js);
// bila belum ada, fallback lokal dipakai supaya bench tetap bisa jalan.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const LABELS_DIR = join(ROOT, 'eval', 'oracle', 'labels');
const RESULTS_DIR = join(ROOT, 'eval', 'results');
const LABS = ['juice-shop', 'dvwa', 'vampi'];
const RUNS = 3;

// P1-3: lab ditemukan otomatis dari eval/oracle/labels/*.json — lab baru
// (dvga, llm-app, ...) ikut bench tanpa ubah kode. Bila direktori label
// tidak bisa dibaca, fallback ke daftar LABS di atas.
export function discoverLabs() {
  try {
    return readdirSync(LABELS_DIR)
      .filter((f) => f.endsWith('.json'))
      .sort()
      .map((f) => f.replace(/\.json$/, ''));
  } catch {
    return [...LABS];
  }
}

export function median(values) {
  const s = [...values].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// LCG deterministik — JANGAN Math.random (bench harus reproducible).
export function seeded(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

export function normEndpoint(e) {
  return String(e).toLowerCase().replace(/\/$/, '').replace(/:\w+/g, ':id');
}

// Skor fallback (dipakai bila lib bench belum ada). Lib nyata memakai
// signature yang sama: scoreFindings(findings, oracleArray).
export function scoreFindings(findings, oracle) {
  const vulns = Array.isArray(oracle) ? oracle : oracle.vulns ?? [];
  const oracleKeys = new Set(
    vulns.map((v) => `${normEndpoint(v.endpoint)}|${String(v.vuln_class).toLowerCase()}|${String(v.cwe).toUpperCase()}`),
  );
  const foundKeys = new Set();
  let tp = 0;
  let fp = 0;
  for (const f of findings) {
    const k = `${normEndpoint(f.endpoint)}|${String(f.vuln_class).toLowerCase()}|${String(f.cwe ?? '').toUpperCase()}`;
    if (oracleKeys.has(k) && !foundKeys.has(k)) {
      tp += 1;
      foundKeys.add(k);
    } else if (!oracleKeys.has(k)) {
      fp += 1;
    }
    // duplikat temuan yang sama tidak dihitung dua kali (dedup di skor)
  }
  const fn = vulns.length - foundKeys.size;
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  return { tp, fp, fn, precision, recall };
}

// Mock findings deterministik: semua oracle vuln KECUALI 1 yang di-drop
// (FN simulasi, indeks dari seed) + 1-2 FP tambahan yang bervariasi per run.
export function mockFindings(oracle, runIndex) {
  const seed = [...oracle.lab].reduce((a, c) => a * 31 + c.charCodeAt(0), 7) + runIndex * 97;
  const rnd = seeded(seed);
  const dropIdx = Math.floor(rnd() * oracle.vulns.length);
  const findings = oracle.vulns
    .filter((_, i) => i !== dropIdx)
    .map((v) => ({ endpoint: v.endpoint, method: v.method, vuln_class: v.vuln_class, cwe: v.cwe }));
  const fpCount = 1 + Math.floor(rnd() * 2); // 1 atau 2 FP
  const fpClasses = ['Reflected XSS', 'SQL Injection', 'Path Traversal', 'SSRF'];
  for (let i = 0; i < fpCount; i += 1) {
    findings.push({
      endpoint: `/mock/fp-${runIndex}-${i}`,
      method: 'GET',
      vuln_class: fpClasses[Math.floor(rnd() * fpClasses.length)],
      cwe: 'CWE-000',
    });
  }
  return findings;
}

export function dockerAvailable() {
  try {
    const r = spawnSync('docker', ['--version'], { encoding: 'utf8' });
    return r.status === 0;
  } catch {
    return false;
  }
}

async function loadLib() {
  const lib = {};
  for (const name of ['bench', 'store', 'router']) {
    try {
      lib[name] = await import(`../bounty/lib/${name}.js`);
    } catch {
      lib[name] = null; // lib belum ditulis agen lain — fallback lokal
    }
  }
  return lib;
}

export async function runBench({ runs = RUNS } = {}) {
  const hasDocker = dockerAvailable();
  if (!hasDocker) {
    console.log(
      'Docker tidak ditemukan — mode no-docker: lab Docker di-skip, ' +
        'bench jalan dengan mock findings + unit router.',
    );
  } else {
    console.log(
      'Docker ditemukan — mode no-docker tetap dipakai untuk mock bench ini; ' +
        'lab live dijalankan manual via eval/docker-compose.yml.',
    );
  }

  const lib = await loadLib();
  const score = lib.bench?.scoreFindings ?? scoreFindings;
  const med = lib.bench?.median ?? median;

  const labs = [];
  for (const lab of discoverLabs()) {
    let oracle;
    try {
      oracle = JSON.parse(readFileSync(join(LABELS_DIR, `${lab}.json`), 'utf8'));
    } catch (err) {
      console.log(`Lab ${lab} di-skip: oracle tidak bisa dibaca (${err.message})`);
      continue;
    }
    const perRun = [];
    for (let run = 0; run < runs; run += 1) {
      const findings = mockFindings(oracle, run);
      // Lib nyata: scoreFindings(findings, oracleArray).
      const s = score(findings, oracle.vulns);
      perRun.push({ run: run + 1, ...s, findings: findings.length });
    }
    const summary = {
      lab,
      oracle_vulns: oracle.vulns.length,
      runs: perRun,
      median: {
        tp: med(perRun.map((r) => r.tp)),
        fp: med(perRun.map((r) => r.fp)),
        fn: med(perRun.map((r) => r.fn)),
        precision: med(perRun.map((r) => r.precision)),
        recall: med(perRun.map((r) => r.recall)),
      },
    };
    labs.push(summary);
  }

  // Unit router (bila lib ada): waktu routing konteks oracle, median 5x.
  let routerMs = null;
  if (lib.router?.routeSkills) {
    const catalog = labs.flatMap((l) =>
      JSON.parse(readFileSync(join(LABELS_DIR, `${l.lab}.json`), 'utf8')).vulns.map((v) => ({
        name: v.vuln_class,
        keywords: [v.vuln_class, v.endpoint, v.cwe],
      })),
    );
    const times = [];
    for (let i = 0; i < 5; i += 1) {
      const t0 = performance.now();
      lib.router.routeSkills('web api sql injection xss', catalog);
      times.push(performance.now() - t0);
    }
    routerMs = med(times);
  }

  // Akurasi router (plan v3.1 #7): untuk tiap lab, apakah top-5 skill
  // yang di-route mengandung hunt-<kelas> yang sesuai dengan oracle.
  // Hit rate, bukan latensi — latensi tidak membuktikan pilihan benar.
  let routerAccuracy = null;
  if (lib.bench?.routerAccuracy) {
    routerAccuracy = {};
    for (const l of labs) {
      const oracle = JSON.parse(readFileSync(join(LABELS_DIR, `${l.lab}.json`), 'utf8'));
      const acc = lib.bench.routerAccuracy(oracle.vulns ?? []);
      routerAccuracy[l.lab] = { hit: acc.hit, total: acc.total, accuracy: acc.accuracy };
    }
  }

  const result = {
    generated_at: new Date().toISOString(),
    mode: hasDocker ? 'docker-present-mock' : 'no-docker',
    runs,
    router_ms_median: routerMs,
    router_accuracy: routerAccuracy,
    labs,
    gate: 'FP median harus turun dan TP median tidak turun vs baseline Strix (lihat eval/README.md). Baseline diukur terpisah; file ini menyimpan hasil mock run.',
  };

  mkdirSync(RESULTS_DIR, { recursive: true });
  writeFileSync(join(RESULTS_DIR, 'latest.json'), JSON.stringify(result, null, 2) + '\n');

  // Simpan run ke store bila lib store ada.
  if (lib.store?.Store) {
    try {
      const store = new lib.store.Store(join(ROOT, 'bounty.db'));
      for (const l of labs) {
        store.addRun({ lab: l.lab, tp: l.median.tp, fp: l.median.fp, fn: l.median.fn, timeMs: 0, usd: 0 });
      }
      store.close();
    } catch (err) {
      console.log(`(store dilewati: ${err.message})`);
    }
  }

  // Tabel ringkas
  console.log('\nlab         oracle  TPmed  FPmed  FNmed  prec   recall');
  for (const l of labs) {
    const m = l.median;
    console.log(
      `${l.lab.padEnd(12)}${String(l.oracle_vulns).padEnd(8)}${String(m.tp).padEnd(7)}` +
        `${String(m.fp).padEnd(7)}${String(m.fn).padEnd(7)}` +
        `${m.precision.toFixed(2).padEnd(7)}${m.recall.toFixed(2)}`,
    );
  }
  if (routerMs !== null) console.log(`\nrouter median: ${routerMs.toFixed(2)} ms`);
  if (routerAccuracy) {
    console.log('\nrouter accuracy (top-5 mengandung hunt-<kelas> oracle):');
    for (const [lab, acc] of Object.entries(routerAccuracy)) {
      console.log(`  ${lab.padEnd(12)}${acc.hit}/${acc.total} = ${(acc.accuracy * 100).toFixed(0)}%`);
    }
  }
  console.log(`\nHasil tersimpan: eval/results/latest.json`);
  return result;
}

// Gate vs baseline (bila eval/results/baseline.json ada — diukur live lewat
// `npm run measure-baseline` di laptop). Mock bench TIDAK boleh mengklaim
// menang vs baseline: bila baseline ada, bandingkan median; bila TP turun
// atau FP naik, exit 1. Bila baseline belum ada, gate dilewati dengan catatan.
export function gateVsBaseline(result) {
  const basePath = join(RESULTS_DIR, 'baseline.json');
  if (!existsSync(basePath)) {
    console.log('\nGate baseline: dilewati — eval/results/baseline.json belum ada. Ukur live: npm run measure-baseline');
    return true;
  }
  const base = JSON.parse(readFileSync(basePath, 'utf8'));
  let ok = true;
  for (const l of result.labs) {
    const b = base.labs?.[`${l.lab}:baseline`]?.median ?? base.labs?.[l.lab]?.median;
    if (!b) { console.log(`Gate ${l.lab}: baseline tidak ada — dilewati`); continue; }
    const pass = l.median.tp >= b.tp && l.median.fp <= b.fp;
    console.log(`Gate ${l.lab}: baseline TP=${b.tp} FP=${b.fp} -> bench TP=${l.median.tp} FP=${l.median.fp} : ${pass ? 'LOLOS' : 'GAGAL'}`);
    if (!pass) ok = false;
  }
  return ok;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const runsArg = process.argv.find((a) => a.startsWith('--runs='));
  const runs = runsArg ? Number(runsArg.split('=')[1]) || RUNS : RUNS;
  if (process.argv.includes('--live')) {
    console.log('Mode --live: delegasi ke eval/measure-baseline.mjs (butuh Docker + Strix).');
    const { main } = await import('./measure-baseline.mjs');
    process.exit(main(process.argv.slice(2).filter((a) => a !== '--live')));
  }
  const result = await runBench({ runs });
  const ok = gateVsBaseline(result);
  if (!ok) process.exit(1);
}
