#!/usr/bin/env node
// bounty — zero-dependency CLI wrapper (Node >= 20).
// Commands: provider | run | review | report | bench | install | programs | findings | scan | memory | graph | trace | --help | --version
import { readFileSync, writeFileSync, existsSync, accessSync, constants, readdirSync, statSync } from "node:fs";
import { resolve, join, delimiter, dirname } from "node:path";
import { spawnSync, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { Store } from "../lib/store.js";
import { parseProgram, loadProgramFile, checkScope } from "../lib/scope.js";
import { checkCommand } from "../lib/guard.js";
import { logAudit } from "../lib/audit.js";
import { scanText, redact } from "../lib/secrets.js";
import { buildReviewHtml } from "../lib/review-html.js";
import { TokenBucket } from "../lib/rate.js";
import { getRoleProfile, buildInstruction } from "../lib/auth.js";
import { detectModels, saveProvider, writeStrixConfig, NINE_ROUTER_BASE } from "../lib/provider.js";
import { runBench, scoreFindings } from "../lib/bench.js";
import { parseStrixOutput, readStrixArtifacts } from "../lib/strix-output.js";
import { dedupCandidates } from "../lib/dedup.js";
import { runTool, SUPPORTED_TOOLS } from "../lib/runners.js";
import { budgetStatus } from "../lib/cost.js";
import { runQueue } from "../lib/queue.js";
import { readSarif } from "../lib/sarif.js";
import { recordEpisode, listEpisodes, listLessons, addLesson, findSimilar, recordCoverage } from "../lib/memory.js";
import { listNodes, listEdges, traceFinding } from "../lib/graph.js";
import { routeWithLessons } from "../lib/router.js";
import { loadPatterns } from "../lib/patterns.js";
import { expectedSkillFor } from "../lib/bench.js";
import { fileURLToPath } from "node:url";

export const VERSION = "1.3.0";
const DEFAULT_BUDGET_USD = 5;
const DEFAULT_MAX_TURNS = 500;
// Root repo (untuk --skills-dir): bounty/bin/ -> ../../
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SKILLS_DIR = process.env.STRIX_SKILLS_DIR || resolve(REPO_ROOT, "skills", "bounty");

const HELP = `bounty — muse-bug-bounty wrapper v${VERSION} (zero-dependency, $0)

Penggunaan:
  bounty provider [--type openai|anthropic] [--base-url URL] [--model ID]
      Pilih provider/model LLM (interaktif via stdin). Deteksi model dari
      {baseUrl}/models. Simpan ke .bounty/providers/ (0600).
  bounty run [--program programs/example.md] [--target URL] [--role low|high]
             [--budget 5] [--dry-run] [--targets URL1,URL2]
      --targets: antrean multi-target (satu per satu, satu pool budget).
  bounty view
      Buka dashboard Strix (strix view) di background.
      Jalankan Strix dalam scope program. Scope-gate dulu, lalu pre-exec
      guard, rate limiter, budget default $${DEFAULT_BUDGET_USD}.
      Tanpa --dry-run dan tanpa binary strix di PATH -> exit 2.
  bounty review [--queue] [--approve <id> | --reject <id>] [--export-html [FILE]]
  bounty programs
      List program di programs/*.md (nama, scope, budget, rate).
  bounty findings [--program <nama>] [--similar <id>]
      List kandidat + finding tersimpan, opsional filter program.
      --similar <id>: temuan serupa dari memori (FTS5 + RRF).
  bounty memory [--list] [--lessons] [--program <nama>]
      Episode memori per run/review + lesson dari verdict manusia.
  bounty graph [--program <nama>]
      Graf aset (view SQL): node/edge, aset terpanas, cakupan open.
  bounty trace <finding-id>
      Jejak source -> sink dari chain + evidence yang tercatat.
      List kandidat (status candidate); approve/reject per id.
      --queue: tampilkan antrean kandidat. --export-html: tulis halaman
      review statis (default eval/review.html) untuk review manual.
  bounty report [--out FILE]
      Render laporan temuan ke stdout (atau file).
  bounty bench [--lab NAME] [--runs N]
      Jalankan benchmark (eval/run-bench.mjs bila ada, fallback mock).
  bounty scan --tool nuclei|dalfox|ffuf|arjun|graphql-cop|gitleaks|trufflehog|osv-scanner|garak|deepteam --target URL --program programs/<nama>.md [--wordlist FILE] [--timeout-ms N] [--path DIR] [--model MODEL]
      --path: checkout lokal untuk osv-scanner. --model: model LLM untuk garak/deepteam.
      Jalankan satu scanner klasik on-demand dalam scope program.
      Binary tidak ada -> dilewati (bukan error). Hasil = kandidat
      (UNVERIFIED) di store; review dulu di 'bounty review'.
  bounty install [--strix]
      Cek/instal Strix via curl resmi (hanya tampilkan perintah, tidak auto-run pipe-to-shell).
  bounty --help | bounty --version

Aturan keras: scope-gate, budget, tanpa submit/bayar/deposit, tanpa API berbayar
tanpa persetujuan. Kredensial asli JANGAN ditaruh di repo — pakai env/provider.
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const eq = key.indexOf("=");
      if (eq !== -1) {
        args[key.slice(0, eq)] = key.slice(eq + 1);
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        args[key] = argv[++i];
      } else {
        args[key] = true;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function findBinary(name) {
  const pathDirs = (process.env.PATH || "").split(delimiter);
  for (const dir of pathDirs) {
    const p = join(dir, name);
    try { accessSync(p, constants.X_OK); return p; } catch {}
  }
  return null;
}

function ask(rl, q) {
  return new Promise((resolve) => rl.question(q, (a) => resolve(a.trim())));
}

async function cmdProvider(args) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const type = args.type || (await ask(rl, "Tipe provider (openai/anthropic) [openai]: ")) || "openai";
    const defBase = type === "anthropic" ? "https://api.anthropic.com" : NINE_ROUTER_BASE;
    const baseUrl = args["base-url"] || (await ask(rl, `Base URL [${defBase}]: `)) || defBase;
    const apiKey = args["api-key"] || process.env.LLM_API_KEY || (await ask(rl, "API key (tidak ditampilkan/dilog): "));
    if (!apiKey) { console.error("API key kosong — batal."); return 2; }
    console.log("Mendeteksi model...");
    let detected;
    try {
      detected = await detectModels({ type, baseUrl, apiKey });
    } catch (e) {
      console.error(`Gagal deteksi model: ${e.message}`);
      return 2;
    }
    if (detected.warning) console.log(`Peringatan: ${detected.warning}`);
    console.log(`Model tersedia (${detected.models.length}):`);
    detected.models.slice(0, 20).forEach((m, i) => console.log(`  ${i + 1}. ${m}`));
    const model = args.model || (await ask(rl, "Pilih model (ketik id/nomor): "));
    const picked = /^\d+$/.test(model) ? detected.models[Number(model) - 1] : model;
    if (!picked) { console.error("Model tidak dipilih — batal."); return 2; }
    const name = `${type}-${picked}`;
    saveProvider({ name, type, baseUrl, apiKey, model: picked });
    const cfg = writeStrixConfig(picked, baseUrl, apiKey, type);
    console.log(`Provider tersimpan. Strix config: ${cfg}`);
    console.log(`STRIX_LLM=${type}/${picked} (key TIDAK ditampilkan di log ini)`);
    return 0;
  } finally {
    rl.close();
  }
}

async function runSingleTarget(args, targetOverride = null) {
  const programPath = args.program || resolve(process.cwd(), "programs/example.md");
  if (!existsSync(programPath)) {
    console.error(`Program tidak ditemukan: ${programPath}`);
    console.error("Buat programs/<nama>.md dulu (Scope/Allowed/Denied/Budget/Rate/Roles).");
    try { logAudit({ command: "run", program: String(args.program || "example"), result: "error" }); } catch {}
    return { code: 2, usd: 0, added: 0, findings: [] };
  }
  const program = loadProgramFile(programPath);
  const target = targetOverride || args.target || (program.allowedHosts[0] ? `https://${program.allowedHosts[0]}/` : "");
  if (!target) {
    console.error("Target tidak diberikan dan program tanpa Scope.");
    try { logAudit({ command: "run", program: program.name, result: "error" }); } catch {}
    return { code: 2, usd: 0, added: 0, findings: [] };
  }

  // 1. Scope gate
  const scope = checkScope(program, target);
  console.log(scope.ok ? "Scope OK" : `Scope DITOLAK: ${scope.reason}`);
  if (!scope.ok) {
    try { logAudit({ command: "run", target, program: program.name, result: "blocked" }); } catch {}
    return 2;
  }

  // 2. Budget + role (auth-minimal)
  const budget = Number(args.budget ?? program.maxBudgetUsd ?? DEFAULT_BUDGET_USD);
  // Audit trail (P1-1): catat sebelum jalan + sesudah selesai. Gagal tulis
  // audit tidak menggagalkan run.
  const auditEntry = { command: "run", target, program: program.name, budget };
  const auditLog = (result) => { try { logAudit({ ...auditEntry, result }); } catch {} };
  auditLog("started");
  const done = (code, result) => { auditLog(result); return code; };
  const role = String(args.role || "low").toLowerCase();
  if (!program.roles.includes(role)) {
    console.error(`Role "${role}" tidak diizinkan program ini (roles: ${program.roles.join(", ")}).`);
    return { code: done(2, "blocked"), usd: 0, added: 0, findings: [] };
  }
  const profile = getRoleProfile(program, role);
  console.log(`Budget: $${budget} | Role: ${profile.role} | Rate: ${program.rateLimit}/detik`);

  // 3. Strix binary check
  const strix = findBinary("strix");
  if (!strix) {
    console.log("Strix tidak ditemukan — jalankan mode --dry-run atau install Strix via curl resmi");
    console.log("  Jalankan: bounty install --strix   (menampilkan perintah resmi, tanpa auto-run)");
    if (args["dry-run"]) {
      console.log(`[dry-run] skills-dir: ${SKILLS_DIR} (akan diteruskan ke Strix via --skills-dir / STRIX_SKILLS_DIR)`);
      console.log("[dry-run] Instruksi yang akan dikirim ke Strix:");
      console.log(buildInstruction(program, role));
      return { code: done(0, "dry-run"), usd: 0, added: 0, findings: [] };
    }
    return { code: done(2, "error"), usd: 0, added: 0, findings: [] };
  }

  // 4. Pre-exec guard + rate limiter
  // Rate limiter: TokenBucket menegakkan rate request WRAPPER (pre/post
  // run). Request internal Strix TIDAK lewat bucket ini — Strix dibatasi
  // lewat --max-budget-usd / --max-turns + instruksi rate di bawah, dan
  // itu ditulis jujur di README (bukan klaim penegakan penuh).
  const rate = Number(program.rateLimit) || 10;
  const bucket = new TokenBucket(rate, rate);
  const maxTurns = Number(args["max-turns"] ?? DEFAULT_MAX_TURNS);
  const skillsDir = existsSync(SKILLS_DIR) ? SKILLS_DIR : null;
  const strixArgs = ["--target", target, "--budget", String(budget), "--max-budget-usd", String(budget), "--max-turns", String(maxTurns)];
  if (skillsDir) strixArgs.push("--skills-dir", skillsDir);
  const cmd = `strix ${strixArgs.join(" ")}`;
  const guard = checkCommand(cmd, process.cwd());
  if (!guard.allowed) {
    console.error(`Perintah diblokir guard: ${guard.reason}`);
    return { code: done(2, "blocked"), usd: 0, added: 0, findings: [] };
  }
  await bucket.acquire();

  if (args["dry-run"]) {
    console.log(`[dry-run] strix ditemukan di ${strix}; perintah yang akan jalan: ${cmd}`);
    console.log(`[dry-run] skills-dir: ${skillsDir ?? "(tidak ditemukan — skill tidak diteruskan)"}`);
    console.log(buildInstruction(program, role));
    return { code: done(0, "dry-run"), usd: 0, added: 0, findings: [] };
  }

  // 5. Jalankan Strix (tanpa API berbayar dari wrapper ini — Strix memakai
  //    konfigurasi provider yang sudah disetel lewat `bounty provider`).
  //    Output di-pipe (bukan inherit) agar bisa diparse ke store.
  console.log(`Menjalankan: ${cmd}`);
  const instruction = buildInstruction(program, role);
  const startedAt = Date.now();
  const res = spawnSync(strix, [...strixArgs, "--instruction", instruction], {
    encoding: "utf8",
    // Privasi tim: telemetri Strix dimatikan (default Strix = 1).
    env: { ...process.env, ...(skillsDir ? { STRIX_SKILLS_DIR: skillsDir } : {}), STRIX_TELEMETRY: "0" },
  });
  if (res.error) { console.error(`Gagal menjalankan strix: ${res.error.message}`); return { code: done(2, "error"), usd: 0, added: 0, findings: [] }; }
  const stdout = String(res.stdout ?? "");
  const stderr = String(res.stderr ?? "");
  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);

  let runUsd = 0, runAdded = 0, runFindings = [];
  // 6. Parse output Strix -> store (run -> store -> review).
  //    Semua temuan masuk sebagai "candidate" (UNVERIFIED) — reviewer
  //    yang memutuskan di `bounty review`. Dedup dulu vs store + internal.
  //    Exit code Strix: 2 = "vulns found" (bukan error) -> sukses dengan
  //    temuan; sumber utama temuan/biaya adalah artefak strix_runs/
  //    (run.json + vulnerabilities.json), stdout hanya fallback.
  const code = res.status ?? 0;
  const strixOk = code === 0 || code === 2;
  if (code === 2) console.log("\nStrix exit 2 = temuan ditemukan (bukan error).");
  try {
    const store = new Store();
    try {
      const parsed = parseStrixOutput(stdout + "\n" + stderr, program.name);
      const artifacts = readStrixArtifacts(process.cwd(), startedAt);
      // SARIF Strix (findings.sarif) sebagai sumber ketiga, bila ada.
      let sarifFindings = [];
      try {
        const runsBase = join(process.cwd(), "strix_runs");
        if (existsSync(runsBase)) {
          const dirs = readdirSync(runsBase, { withFileTypes: true })
            .filter((d) => d.isDirectory())
            .map((d) => join(runsBase, d.name))
            .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
          if (dirs.length > 0) sarifFindings = readSarif(join(dirs[0], "findings.sarif")).map((f) => ({ ...f, program: program.name }));
        }
      } catch {}
      if (sarifFindings.length > 0) console.log(`Artefak Strix: ${sarifFindings.length} temuan dari strix_runs/findings.sarif.`);
      const findings = [...parsed.findings, ...artifacts.findings.map((f) => ({ ...f, program: program.name })), ...sarifFindings];
      const usd = artifacts.usd > 0 ? artifacts.usd : parsed.usd;
      if (artifacts.findings.length > 0) console.log(`Artefak Strix: ${artifacts.findings.length} temuan dari strix_runs/vulnerabilities.json${artifacts.usd > 0 ? `, biaya $${artifacts.usd} dari run.json` : ""}.`);
      const existing = store.listCandidates(program.name, "candidate")
        .map((c) => ({ endpoint: c.endpoint, method: c.method, param: c.param, vuln_class: c.vuln_class, cwe: c.cwe }));
      const { unique } = dedupCandidates([...existing, ...findings]);
      const fresh = unique.slice(existing.length);
      let added = 0;
      for (const f of fresh) {
        store.addCandidate({ program: program.name, endpoint: f.endpoint, method: f.method, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe });
        added++;
      }
      store.addRun({ version: "bounty", target, lab: program.name, tp: 0, fp: 0, fn: 0, timeMs: Date.now() - startedAt, usd });
      runUsd = usd; runAdded = added; runFindings = fresh;
      // v1.3 cost tracking nyata: peringatan saat mendekati budget.
      const bs = budgetStatus({ spent: usd, budget });
      if (bs.exceeded) console.log(`Peringatan: biaya $${usd} sudah MELEBIHI budget $${budget} untuk target ini.`);
      else if (bs.warn) console.log(`Peringatan: biaya $${usd} sudah ${Math.round(bs.pct * 100)}% dari budget $${budget}.`);
      console.log(`\nHasil parse: ${findings.length} temuan dari output Strix, ${added} kandidat baru masuk store (dedup: ${findings.length - added} duplikat). Biaya terukur: $${usd}.`);
      console.log(`Lihat antrean: bounty review  |  bounty findings --program ${program.name}`);
      // v1.2 memori: episode per run + coverage kelas yang diperiksa +
      // peringatan bila pola serupa pernah ditolak (FP) oleh reviewer.
      try {
        for (const f of fresh) recordCoverage(store.db, program.name, f.endpoint, f.vulnClass, "examined");
        const rejectedIds = new Set(store.listCandidates(program.name, "rejected").map((c) => c.id));
        for (const f of fresh) {
          const similar = findSimilar(store.db, { endpoint: f.endpoint, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe }, 3)
            .filter((s) => rejectedIds.has(s.id));
          if (similar.length > 0) console.log(`Peringatan: pola serupa pernah DITOLAK (FP) — kandidat #${similar[0].id} ${similar[0].endpoint} (${similar[0].vulnClass}). Verifikasi ekstra sebelum approve.`);
        }
        recordEpisode(store.db, { program: program.name, target, kind: "run", summary: `${added} kandidat baru, ${findings.length} temuan parse, $${usd}` });
      } catch (e) { console.error(`Peringatan: gagal menulis memori: ${e.message}`); }
    } finally { store.close(); }
  } catch (e) { console.error(`Peringatan: gagal menyimpan hasil ke store: ${e.message}`); }
  return { code: done(strixOk ? 0 : code, strixOk ? (code === 2 ? "ok-findings" : "ok") : "failed"), usd: runUsd, added: runAdded, findings: runFindings };
}

// v1.3 multi-target: `bounty run --targets url1,url2` menjalankan target
// satu per satu (bukan paralel) dengan satu pool budget --budget; antrean
// berhenti bila biaya total mencapai budget. Satu target = perilaku lama.
async function cmdRun(args) {
  if (args.targets) {
    const targets = String(args.targets).split(",").map((t) => t.trim()).filter(Boolean);
    if (targets.length === 0) { console.error("--targets butuh daftar URL dipisah koma."); return 2; }
    let budget = DEFAULT_BUDGET_USD;
    try {
      const programPath = args.program || resolve(process.cwd(), "programs/example.md");
      const program = loadProgramFile(programPath);
      budget = Number(args.budget ?? program.maxBudgetUsd ?? DEFAULT_BUDGET_USD);
    } catch {}
    console.log(`Antrean multi-target: ${targets.length} target, budget total $${budget} (berhenti bila tercapai).`);
    const summary = await runQueue(targets, async (t) => {
      const r = await runSingleTarget({ ...args, target: t }, t);
      return { status: r.code === 0 ? "ok" : "failed", usd: r.usd, findings: r.findings };
    }, {
      budget,
      onProgress: (p) => console.log(`[${p.done}/${p.total}] ${p.target}: ${p.status}, $${p.usd} (total $${p.totalUsd})`),
    });
    console.log(`Antrean selesai: ${summary.done}/${summary.total} target, total biaya $${summary.totalUsd}${summary.stopped ? " (berhenti: budget habis)" : ""}.`);
    return summary.stopped || summary.results.every((r) => r.status === "ok" || r.status === "done") ? 0 : 2;
  }
  const r = await runSingleTarget(args);
  return r.code;
}

function cmdView() {
  // Tautkan ke dashboard Strix (jangan bangun dashboard sendiri).
  const strix = findBinary("strix");
  if (!strix) { console.log("Strix tidak ditemukan — instal dulu: bounty install --strix"); return 2; }
  console.log("Membuka dashboard Strix (strix view) di background — bukan dashboard bounty.");
  try {
    const child = spawn(strix, ["view"], { detached: true, stdio: "ignore" });
    child.unref();
    console.log("Dashboard Strix berjalan di background. Tutup dengan menghentikan proses strix.");
    return 0;
  } catch (e) { console.error(`Gagal membuka strix view: ${e.message}`); return 2; }
}

function cmdReview(args) {
  const store = new Store();
  const auditLog = (result, target = "") => { try { logAudit({ command: "review", target, result }); } catch {} };
  try {
    if (args.approve) {
      const row = store.approveCandidate(Number(args.approve));
      console.log(row ? `Kandidat #${row.id} disetujui (approved).` : `Kandidat #${args.approve} tidak ditemukan.`);
      auditLog(row ? "ok" : "error", `#${args.approve}`);
      if (row) { try { addLesson(store.db, { skill: expectedSkillFor(row.vuln_class), vulnClass: row.vuln_class, outcome: "confirmed", note: `review approve #${row.id}` }); recordEpisode(store.db, { program: row.program, target: row.endpoint, kind: "review", summary: `approve #${row.id} ${row.vuln_class}` }); } catch (e) { console.error(`Peringatan: gagal menulis memori: ${e.message}`); } }
      return row ? 0 : 2;
    }
    if (args.reject) {
      const row = store.rejectCandidate(Number(args.reject));
      console.log(row ? `Kandidat #${row.id} ditolak (rejected).` : `Kandidat #${args.reject} tidak ditemukan.`);
      auditLog(row ? "ok" : "error", `#${args.reject}`);
      if (row) { try { addLesson(store.db, { skill: expectedSkillFor(row.vuln_class), vulnClass: row.vuln_class, outcome: "false_positive", note: `review reject #${row.id}` }); recordEpisode(store.db, { program: row.program, target: row.endpoint, kind: "review", summary: `reject #${row.id} ${row.vuln_class} (FP)` }); } catch (e) { console.error(`Peringatan: gagal menulis memori: ${e.message}`); } }
      return row ? 0 : 2;
    }
    // --export-html [FILE]: halaman review statis (P1-2), default eval/review.html.
    if (args["export-html"] !== undefined) {
      const outPath = resolve(typeof args["export-html"] === "string" ? args["export-html"] : "eval/review.html");
      const list = store.listCandidates(null, "candidate");
      const html = redact(buildReviewHtml(list));
      writeFileSync(outPath, html, "utf8");
      console.log(`Halaman review ditulis ke ${outPath} (${list.length} kandidat).`);
      auditLog("ok", outPath);
      return 0;
    }
    // --queue (atau tanpa argumen): list antrean kandidat.
    const list = store.listCandidates(null, "candidate");
    if (list.length === 0) {
      console.log("Tidak ada kandidat (status candidate).");
      auditLog("ok");
      return 0;
    }
    console.log("Antrean review (status candidate):");
    for (const c of list) {
      console.log(`  #${c.id} [${c.program}] ${c.method} ${c.endpoint} param=${c.param || "-"} kelas=${c.vuln_class} cwe=${c.cwe || "-"}`);
    }
    console.log("Gunakan: bounty review --approve <id> | --reject <id>");
    console.log("Halaman HTML: bounty review --export-html [file]");
    auditLog("ok");
    return 0;
  } finally {
    store.close();
  }
}


function cmdPrograms() {
  const dir = resolve(process.cwd(), "programs");
  let files = [];
  try { files = readdirSync(dir).filter((f) => f.endsWith(".md")).sort(); } catch { console.error("Folder programs/ tidak ditemukan."); return 2; }
  if (files.length === 0) { console.log("Tidak ada program di programs/."); return 0; }
  console.log("Program:");
  for (const f of files) {
    try {
      const prog = loadProgramFile(join(dir, f));
      console.log(`  ${prog.name || f.replace(/\.md$/, "")} — scope: ${prog.allowedHosts.join(", ") || "-"} | budget: $${prog.maxBudgetUsd ?? 5} | rate: ${prog.rateLimit}/detik | roles: ${prog.roles.join(", ")}`);
    } catch (e) { console.log(`  ${f} — (gagal dibaca: ${e.message})`); }
  }
  return 0;
}

function cmdFindings(args) {
  const store = new Store();
  try {
    // --similar <id>: temuan serupa dari memori (FTS5 + RRF, v1.2 M1).
    if (args.similar) {
      const row = store.db.prepare("SELECT * FROM candidate WHERE id = ?").get(Number(args.similar));
      if (!row) { console.log(`Kandidat #${args.similar} tidak ditemukan.`); return 2; }
      console.log(`Serupa dengan #${row.id} ${row.method} ${row.endpoint} (${row.vuln_class}):`);
      const similar = findSimilar(store.db, { endpoint: row.endpoint, param: row.param, vulnClass: row.vuln_class, cwe: row.cwe }, 5)
        .filter((s) => s.id !== row.id);
      if (similar.length === 0) { console.log("  (tidak ada yang serupa di store)"); return 0; }
      for (const s of similar) console.log(`  #${s.id} skor=${s.score.toFixed(2)} ${s.endpoint} (${s.vulnClass})`);
      return 0;
    }
    const program = args.program || null;
    const candidates = store.listCandidates(program, "candidate");
    const approved = store.listCandidates(program, "approved");
    const rows = [...candidates.map((c) => ({ ...c, status: "candidate" })), ...approved.map((c) => ({ ...c, status: "approved" }))];
    if (rows.length === 0) { console.log(program ? `Tidak ada temuan untuk program ${program}.` : "Tidak ada temuan tersimpan."); return 0; }
    console.log("Temuan tersimpan:");
    for (const c of rows) console.log(`  #${c.id} [${c.status}] [${c.program}] ${c.method} ${c.endpoint} param=${c.param || "-"} kelas=${c.vuln_class} cwe=${c.cwe || "-"}`);
    return 0;
  } finally { store.close(); }
}

function cmdMemory(args) {
  const store = new Store();
  try {
    if (args.lessons) {
      const lessons = listLessons(store.db);
      if (lessons.length === 0) { console.log("Belum ada lesson dari verdict reviewer."); return 0; }
      console.log("Lesson (hanya dari verdict manusia):");
      for (const l of lessons) console.log(`  ${l.skill} [${l.vuln_class}] ${l.outcome}${l.note ? ` — ${l.note}` : ""}`);
      return 0;
    }
    const episodes = listEpisodes(store.db, args.program || null);
    if (episodes.length === 0) { console.log("Belum ada episode memori."); return 0; }
    console.log("Episode memori:");
    for (const e of episodes) console.log(`  #${e.id} [${e.kind}] [${e.program}] ${e.target} — ${e.summary} (${e.created_at})`);
    return 0;
  } finally { store.close(); }
}

function cmdGraph(args) {
  const store = new Store();
  try {
    const program = args.program || null;
    const nodes = listNodes(store.db, program);
    const edges = listEdges(store.db, program);
    const kinds = {};
    for (const n of nodes) kinds[n.kind] = (kinds[n.kind] || 0) + 1;
    console.log(`Graf${program ? ` [${program}]` : ""}: ${nodes.length} node (${Object.entries(kinds).map(([k, v]) => `${k}=${v}`).join(", ") || "-"}) | ${edges.length} edge`);
    const hot = store.db.prepare("SELECT * FROM v_hot_asset LIMIT 5").all();
    if (hot.length > 0) {
      console.log("Aset terpanas:");
      for (const h of hot) console.log(`  ${h.host} [${h.program}] — ${h.finding_count} temuan, ${h.candidate_count ?? 0} kandidat`);
    } else {
      // Tabel asset hampir tidak pernah terisi — fallback: program dengan
      // kandidat terbanyak, supaya graf tidak tampil kosong setelah run.
      const top = store.db.prepare("SELECT program, COUNT(*) AS n FROM candidate GROUP BY program ORDER BY n DESC LIMIT 5").all();
      if (top.length > 0) {
        console.log("Program dengan kandidat terbanyak:");
        for (const t of top) console.log(`  [${t.program}] — ${t.n} kandidat`);
      }
    }
    const open = store.db.prepare("SELECT * FROM v_coverage WHERE status = 'open' LIMIT 20").all();
    if (open.length > 0) {
      console.log("Cakupan masih open (arah run berikutnya):");
      for (const o of open) console.log(`  [${o.program}] ${o.vuln_class} — open (${o.n} tercatat)`);
    }
    return 0;
  } finally { store.close(); }
}

function cmdTrace(args) {
  const store = new Store();
  try {
    const id = Number(args._?.[1] ?? args.id);
    if (!id) { console.error("Pakai: bounty trace <finding-id>"); return 2; }
    const t = traceFinding(store.db, id);
    if (t && t.finding) {
      console.log(`Trace #${id} ${t.finding.endpoint} (${t.finding.vuln_class}) — ${t.traced ? "jalur tercatat" : "jalur minimal (bukan taint analysis dinamis)"}:`);
      for (const step of t.path ?? []) console.log(`  -> ${step.endpoint || step.label || step.id} [${step.role ?? ""}] ${step.vuln_class || ""}`.trim());
      if (t.note) console.log(`Catatan: ${t.note}`);
      if (t.evidence?.length) { console.log("Evidence:"); for (const ev of t.evidence) console.log(`  [${ev.kind ?? "evidence"}] ${String(ev.content ?? ev).slice(0, 200)}`); }
      return 0;
    }
    // Fallback: id kandidat (finding table baru terisi setelah review
    // approve -> finding; kandidat belum punya chain, jadi path minimal).
    const cand = store.db.prepare("SELECT * FROM candidate WHERE id = ?").get(id);
    if (!cand) { console.log(`Finding/kandidat #${id} tidak ditemukan.`); return 2; }
    console.log(`Trace #${id} ${cand.endpoint} (${cand.vuln_class}) — jalur minimal (kandidat, belum ada chain/evidence):`);
    console.log(`  -> ${cand.endpoint} [source]`);
    console.log(`  -> #${cand.id} ${cand.vuln_class} [sink]`);
    console.log("Catatan: trace penuh butuh chain/evidence di store; approve kandidat dulu lalu catat langkah di chain.");
    return 0;
  } finally { store.close(); }
}

function cmdReport(args) {
  const store = new Store();
  try {
    const candidates = store.listCandidates(null, "candidate");
    const approved = store.listCandidates(null, "approved");
    const runs = store.listRuns(10);
    const lines = [
      "# Laporan Bug Bounty",
      "",
      `Dibuat: ${new Date().toISOString()}`,
      "",
      "## Kandidat (candidate)",
      ...(candidates.length ? candidates.map((c) => `- #${c.id} [${c.program}] ${c.method} ${c.endpoint} param=${c.param || "-"} kelas=${c.vuln_class} cwe=${c.cwe || "-"}`) : ["- (tidak ada)"]),
      "",
      "## Disetujui (approved)",
      ...(approved.length ? approved.map((c) => `- #${c.id} [${c.program}] ${c.method} ${c.endpoint} kelas=${c.vuln_class}`) : ["- (tidak ada)"]),
      "",
      "## Run terakhir",
      ...(runs.length ? runs.map((r) => `- #${r.id} ${r.lab || "-"} target=${r.target || "-"} tp=${r.tp} fp=${r.fp} fn=${r.fn} ${r.time_ms}ms $${r.usd}`) : ["- (tidak ada)"]),
      "",
    ];
    const out = lines.join("\n");
    // Secret-leak guard (P1-1): scan + redact SEBELUM laporan ditulis ke
    // file/stdout. Laporan yang mengandung secret diblokir isinya (bukan
    // perintahnya): secret diganti [REDACTED], peringatan dicetak ke stderr.
    const scanned = scanText(out);
    if (scanned.found) {
      const types = [...new Set(scanned.matches.map((m) => m.type))].join(", ");
      console.error(`Peringatan: laporan mengandung secret (${types}) — di-redact otomatis.`);
    }
    const safe = redact(out);
    if (args.out) {
      writeFileSync(resolve(args.out), safe, "utf8");
      console.log(`Laporan ditulis ke ${args.out}`);
    } else {
      process.stdout.write(safe);
    }
    try { logAudit({ command: "report", target: args.out ? resolve(args.out) : "stdout", result: "ok" }); } catch {}
    return 0;
  } finally {
    store.close();
  }
}

async function cmdScan(args) {
  const tool = String(args.tool ?? "").toLowerCase();
  const target = args.target;
  const programPath = args.program || resolve(process.cwd(), "programs/example.md");
  if (!SUPPORTED_TOOLS.includes(tool)) {
    console.error(`--tool wajib: ${SUPPORTED_TOOLS.join(" | ")} (dapat: "${tool || ""}")`);
    return 2;
  }
  if (!existsSync(programPath)) {
    console.error(`Program tidak ditemukan: ${programPath}`);
    console.error("Buat programs/<nama>.md dulu (Scope/Allowed/Denied/Budget/Rate/Roles).");
    return 2;
  }
  if (!target) {
    console.error("--target URL wajib.");
    return 2;
  }
  const program = loadProgramFile(programPath);
  const scope = checkScope(program, target);
  console.log(scope.ok ? "Scope OK" : `Scope DITOLAK: ${scope.reason}`);
  if (!scope.ok) {
    try { logAudit({ command: "scan", tool, target, program: program.name, result: "blocked" }); } catch {}
    return 2;
  }
  try { logAudit({ command: "scan", tool, target, program: program.name, result: "started" }); } catch {}
  const result = runTool(tool, {
    target,
    program,
    timeoutMs: Number(args["timeout-ms"] ?? 120000),
    wordlist: args.wordlist,
    localPath: args.path,
    model: args.model,
  });
  if (result.error) {
    console.error(result.error);
    try { logAudit({ command: "scan", tool, target, program: program.name, result: "error" }); } catch {}
    return 2;
  }
  if (result.skipped) {
    console.log(`Dilewati: ${result.reason}`);
    try { logAudit({ command: "scan", tool, target, program: program.name, result: "skipped" }); } catch {}
    return 0;
  }
  // Simpan kandidat ke store (dedup vs yang sudah ada di program ini).
  const store = new Store();
  try {
    const existing = store.listCandidates(program.name, "candidate")
      .map((c) => ({ endpoint: c.endpoint, method: c.method, param: c.param, vuln_class: c.vuln_class, cwe: c.cwe }));
    const { unique } = dedupCandidates([...existing, ...result.findings]);
    const fresh = unique.slice(existing.length);
    let added = 0;
    for (const f of fresh) {
      store.addCandidate({ program: program.name, endpoint: f.endpoint, method: f.method, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe });
      added++;
    }
    console.log(`[${tool}] ${result.rawCount} temuan mentah, ${added} kandidat baru masuk store (dedup: ${result.findings.length - added} duplikat) dalam ${result.time_ms} ms.`);
    console.log(`Lihat antrean: bounty review  |  bounty findings --program ${program.name}`);
  } finally { store.close(); }
  try { logAudit({ command: "scan", tool, target, program: program.name, result: "ok" }); } catch {}
  return 0;
}

async function cmdBench(args) {
  // Per spec: bench memanggil lib/bench.js (runBench + scoreFindings).
  // Oracle dibaca dari eval/oracle/labels/*.json bila ada; runFn mock
  // deterministik (menemukan vuln pertama tiap lab) sampai runner Strix nyata ada.
  const { readdirSync } = await import("node:fs");
  const labelsDir = resolve(process.cwd(), "eval/oracle/labels");
  let labs = [];
  try {
    const files = readdirSync(labelsDir).filter((f) => f.endsWith(".json"));
    const wanted = args.lab ? files.filter((f) => f.startsWith(args.lab)) : files;
    for (const f of wanted) {
      const lab = JSON.parse(readFileSync(join(labelsDir, f), "utf8"));
      labs.push({ name: lab.lab ?? f.replace(".json", ""), oracle: lab.vulns ?? [] });
    }
  } catch { /* tanpa oracle -> mock lab */ }
  if (labs.length === 0) {
    labs = [{ name: args.lab || "mock-lab", oracle: [
      { endpoint: "/api/user", method: "GET", vuln_class: "idor", cwe: "CWE-639" },
    ] }];
  }
  const results = await runBench({
    labs,
    runs: Number(args.runs ?? 3),
    runFn: async (lab) => ({
      // Mock deterministik: temuan = vuln pertama oracle (TP parsial, sisanya FN).
      findings: (lab.oracle ?? []).slice(0, 1).map((v) => ({
        endpoint: v.endpoint, method: v.method, vuln_class: v.vuln_class, cwe: v.cwe,
      })),
      time_ms: 100,
      usd: 0,
    }),
  });
  console.log(JSON.stringify(results, null, 2));
  return 0;
}

function cmdInstall(args) {
  console.log("Install Strix (resmi) — perintah di bawah ini TIDAK auto-run oleh wrapper:");
  console.log("  curl -fsSL https://strix.ai/install.sh | sh   # verifikasi URL resmi dulu sebelum menjalankan");
  console.log("  strix --version");
  console.log("");
  console.log("Catatan: wrapper memblokir pipe-to-shell otomatis (guard). Jalankan manual");
  console.log("setelah memverifikasi URL instalasi resmi Strix.");
  return 0;
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const cmd = args._[0];
  if (args.version || cmd === "--version" || cmd === "version") {
    console.log(`bounty v${VERSION}`);
    return 0;
  }
  if (args.help || cmd === "--help" || cmd === "help" || !cmd) {
    process.stdout.write(HELP);
    return 0;
  }
  switch (cmd) {
    case "provider": return await cmdProvider(args);
    case "run": return await cmdRun(args);
    case "view": return cmdView();
    case "review": return cmdReview(args);
    case "programs": return cmdPrograms();
    case "findings": return cmdFindings(args);
    case "memory": return cmdMemory(args);
    case "graph": return cmdGraph(args);
    case "trace": return cmdTrace(args);
    case "report": return cmdReport(args);
    case "bench": return await cmdBench(args);
    case "scan": return await cmdScan(args);
    case "install": return cmdInstall(args);
    default:
      console.error(`Perintah tidak dikenal: ${cmd}\n`);
      process.stdout.write(HELP);
      return 2;
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname);
if (isMain) {
  main().then((code) => { process.exitCode = code; }).catch((e) => {
    console.error(e?.message ?? e);
    process.exitCode = 2;
  });
}
