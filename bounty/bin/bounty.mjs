#!/usr/bin/env node
// bounty — zero-dependency CLI wrapper (Node >= 20).
// Commands: provider | run | review | report | bench | install | --help | --version
import { readFileSync, writeFileSync, existsSync, accessSync, constants } from "node:fs";
import { resolve, join, delimiter } from "node:path";
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

export const VERSION = "0.1.0";
const DEFAULT_BUDGET_USD = 5;

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
      List kandidat (status candidate); approve/reject per id.
      --queue: tampilkan antrean kandidat. --export-html: tulis halaman
      review statis (default eval/review.html) untuk review manual.
  bounty report [--out FILE]
      Render laporan temuan ke stdout (atau file).
  bounty bench [--lab NAME] [--runs N]
      Jalankan benchmark (eval/run-bench.mjs bila ada, fallback mock).
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
      console.log("[dry-run] Instruksi yang akan dikirim ke Strix:");
      console.log(buildInstruction(program, role));
      return done(0, "dry-run");
    }
    return done(2, "error");
  }

  // 4. Pre-exec guard + rate limiter
  const rate = Number(program.rateLimit) || 10;
  const bucket = new TokenBucket(rate, rate);
  const cmd = `strix --target ${target} --budget ${budget}`;
  const guard = checkCommand(cmd, process.cwd());
  if (!guard.allowed) {
    console.error(`Perintah diblokir guard: ${guard.reason}`);
    return done(2, "blocked");
  }
  await bucket.acquire();

  if (args["dry-run"]) {
    console.log(`[dry-run] strix ditemukan di ${strix}; perintah yang akan jalan: ${cmd}`);
    console.log(buildInstruction(program, role));
    return done(0, "dry-run");
  }

  // 5. Jalankan Strix (tanpa API berbayar dari wrapper ini — Strix memakai
  //    konfigurasi provider yang sudah disetel lewat `bounty provider`).
  console.log(`Menjalankan: ${cmd}`);
  const instruction = buildInstruction(program, role);
  const res = spawnSync(strix, ["--target", target, "--budget", String(budget), "--instruction", instruction], {
    stdio: "inherit",
    env: { ...process.env },
  });
  if (res.error) { console.error(`Gagal menjalankan strix: ${res.error.message}`); return done(2, "error"); }
  const code = res.status ?? 0;
  return done(code, code === 0 ? "ok" : "failed");
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
    case "report": return cmdReport(args);
    case "bench": return await cmdBench(args);
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
