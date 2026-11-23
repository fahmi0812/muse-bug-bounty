#!/usr/bin/env node
// bounty — zero-dependency CLI wrapper (Node >= 20).
// Commands: provider | run | review | report | bench | install | programs | findings | scan | --help | --version
import { readFileSync, writeFileSync, existsSync, accessSync, constants, readdirSync } from "node:fs";
import { resolve, join, delimiter, dirname } from "node:path";
import { spawnSync } from "node:child_process";
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
import { fileURLToPath } from "node:url";

export const VERSION = "0.1.0";
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
             [--budget 5] [--dry-run]
      Jalankan Strix dalam scope program. Scope-gate dulu, lalu pre-exec
      guard, rate limiter, budget default $${DEFAULT_BUDGET_USD}.
      Tanpa --dry-run dan tanpa binary strix di PATH -> exit 2.
  bounty review [--queue] [--approve <id> | --reject <id>] [--export-html [FILE]]
  bounty programs
      List program di programs/*.md (nama, scope, budget, rate).
  bounty findings [--program <nama>]
      List kandidat + finding tersimpan, opsional filter program.
      List kandidat (status candidate); approve/reject per id.
      --queue: tampilkan antrean kandidat. --export-html: tulis halaman
      review statis (default eval/review.html) untuk review manual.
  bounty report [--out FILE]
      Render laporan temuan ke stdout (atau file).
  bounty bench [--lab NAME] [--runs N]
      Jalankan benchmark (eval/run-bench.mjs bila ada, fallback mock).
  bounty scan --tool nuclei|dalfox|ffuf --target URL --program programs/<nama>.md [--wordlist FILE] [--timeout-ms N]
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

async function cmdRun(args) {
  const programPath = args.program || resolve(process.cwd(), "programs/example.md");
  if (!existsSync(programPath)) {
    console.error(`Program tidak ditemukan: ${programPath}`);
    console.error("Buat programs/<nama>.md dulu (Scope/Allowed/Denied/Budget/Rate/Roles).");
    try { logAudit({ command: "run", program: String(args.program || "example"), result: "error" }); } catch {}
    return 2;
  }
  const program = loadProgramFile(programPath);
  const target = args.target || (program.allowedHosts[0] ? `https://${program.allowedHosts[0]}/` : "");
  if (!target) {
    console.error("Target tidak diberikan dan program tanpa Scope.");
    try { logAudit({ command: "run", program: program.name, result: "error" }); } catch {}
    return 2;
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
    return done(2, "blocked");
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
      return done(0, "dry-run");
    }
    return done(2, "error");
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
    return done(2, "blocked");
  }
  await bucket.acquire();

  if (args["dry-run"]) {
    console.log(`[dry-run] strix ditemukan di ${strix}; perintah yang akan jalan: ${cmd}`);
    console.log(`[dry-run] skills-dir: ${skillsDir ?? "(tidak ditemukan — skill tidak diteruskan)"}`);
    console.log(buildInstruction(program, role));
    return done(0, "dry-run");
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
  if (res.error) { console.error(`Gagal menjalankan strix: ${res.error.message}`); return done(2, "error"); }
  const stdout = String(res.stdout ?? "");
  const stderr = String(res.stderr ?? "");
  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);

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
      const findings = [...parsed.findings, ...artifacts.findings.map((f) => ({ ...f, program: program.name }))];
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
      console.log(`\nHasil parse: ${findings.length} temuan dari output Strix, ${added} kandidat baru masuk store (dedup: ${findings.length - added} duplikat). Biaya terukur: $${usd}.`);
      console.log(`Lihat antrean: bounty review  |  bounty findings --program ${program.name}`);
    } finally { store.close(); }
  } catch (e) { console.error(`Peringatan: gagal menyimpan hasil ke store: ${e.message}`); }
  return done(strixOk ? 0 : code, strixOk ? (code === 2 ? "ok-findings" : "ok") : "failed");
}

function cmdReview(args) {
  const store = new Store();
  const auditLog = (result, target = "") => { try { logAudit({ command: "review", target, result }); } catch {} };
  try {
    if (args.approve) {
      const row = store.approveCandidate(Number(args.approve));
      console.log(row ? `Kandidat #${row.id} disetujui (approved).` : `Kandidat #${args.approve} tidak ditemukan.`);
      auditLog(row ? "ok" : "error", `#${args.approve}`);
      return row ? 0 : 2;
    }
    if (args.reject) {
      const row = store.rejectCandidate(Number(args.reject));
      console.log(row ? `Kandidat #${row.id} ditolak (rejected).` : `Kandidat #${args.reject} tidak ditemukan.`);
      auditLog(row ? "ok" : "error", `#${args.reject}`);
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
    case "review": return cmdReview(args);
    case "programs": return cmdPrograms();
    case "findings": return cmdFindings(args);
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
