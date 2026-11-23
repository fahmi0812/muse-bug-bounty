#!/usr/bin/env node
// bounty — zero-dependency CLI wrapper (Node >= 20).
// Commands: provider | run | review | report | bench | install | programs | findings | scan | memory | graph | trace | --help | --version
import { readFileSync, writeFileSync, existsSync, accessSync, constants, readdirSync, statSync, mkdirSync, appendFileSync, realpathSync } from "node:fs";
import { resolve, join, delimiter, dirname } from "node:path";
import { spawnSync, spawn } from "node:child_process";
import { homedir } from "node:os";
import { createInterface } from "node:readline";
import { checkStrixConfig, STRIX_CONFIG_KEY } from "../lib/strix-config.js";
import { Store } from "../lib/store.js";
import { parseProgram, loadProgramFile, checkScope } from "../lib/scope.js";
import { checkCommand } from "../lib/guard.js";
import { logAudit } from "../lib/audit.js";
import { scanText, redact } from "../lib/secrets.js";
import { buildReviewHtml } from "../lib/review-html.js";
import { TokenBucket } from "../lib/rate.js";
import { getRoleProfile, buildInstruction } from "../lib/auth.js";
import { detectModels, saveProvider, writeStrixConfig, loadProviders, loadProviderCreds, syncStrixConfig, buildStrixEnv, NINE_ROUTER_BASE } from "../lib/provider.js";
import { runBench, scoreFindings } from "../lib/bench.js";
import { parseStrixOutput, readStrixArtifacts } from "../lib/strix-output.js";
import { dedupCandidates, canonicalKey } from "../lib/dedup.js";
import { checkFailOn, severityFor } from "../lib/failon.js";
import { color, table, summaryBox, formatUsd, progressBar, severityBadge, phaseLine, heading, hint } from "../lib/ui.js";
import { slugify, normalizeHost, scopeTemplate, SCOPE_TEMPLATES, defaultProviderBase, filterModels, buildProgramMarkdown, exampleTargetFor } from "../lib/setup.js";
import { searchCode } from "../lib/codesearch.js";
import { runTool, SUPPORTED_TOOLS } from "../lib/runners.js";
import { budgetStatus } from "../lib/cost.js";
import { runQueue } from "../lib/queue.js";
import { readSarif } from "../lib/sarif.js";
import { recordEpisode, listEpisodes, listLessons, addLesson, findSimilar, recordCoverage, listCoverage } from "../lib/memory.js";
import { listNodes, listEdges, traceFinding } from "../lib/graph.js";
import { routeWithLessons } from "../lib/router.js";
import { loadPatterns, citedPatterns, patternEvidence } from "../lib/patterns.js";
import { buildCoverageMap, planNext, recordSurface, coverageSummary } from "../lib/planner.js";
import { findSimilarV2, skillTrackRecord, routeWithTrackRecord } from "../lib/learning.js";
import { runSubfinder, runDnsx, runHttpx, runKatana, runNucleiKev, updateNucleiTemplates, crtsh, RECON_TOOLS } from "../lib/recon.js";
import { runJsluice, runSourcemapper } from "../lib/jsmining.js";
import { startInteractsh, pollInteractsh, stopInteractsh } from "../lib/oast.js";
import { runGarakAgentBreaker, runPyrit } from "../lib/llm-runners.js";
import { fingerprintGraphql, introspectSchema, rebuildSchemaFromClairvoyance, testBola } from "../lib/graphql.js";
import { checkTakeover, runCloudEnum, runS3Scanner, runAwsS3Ls, runNucleiTakeovers, CLOUD_TOOLS } from "../lib/cloud.js";
import { runGhidraMcp, runRea, runJadxApk } from "../lib/reverse.js";
import { runMobsf, runJadx } from "../lib/mobile.js";
import { startCaidoMcp, listRequests, replayRequest, stopCaidoMcp } from "../lib/caido.js";
import { getProgramScope, searchHacktivity, draftReport, syncScopeToProgram } from "../lib/platforms.js";
import { runBinwalkNg, runUnblob, runCveBinTool } from "../lib/firmware.js";
import { readPromptfooResults, gateResults } from "../lib/promptfoo-gate.js";
import { decideGraphUpgrade } from "../lib/graph-gate.js";
import { findRepoDir, runUpdate } from "../lib/update.js";
import { expectedSkillFor } from "../lib/bench.js";
import { fileURLToPath } from "node:url";

// node:sqlite memancarkan ExperimentalWarning di setiap invokasi (import
// store -> node:sqlite). Warning itu bocor ke stderr bahkan pada perintah
// baca sederhana (--version, findings, review) dan mengotori log/CI.
// Saring HANYA warning spesifik itu; warning lain tetap dicetak apa adanya.
// Aman karena process.emitWarning menunda emisi ke nextTick, jadi listener
// pengganti ini sudah terpasang sebelum warning benar-benar dipancarkan.
process.removeAllListeners("warning");
process.on("warning", (w) => {
  if (w?.name === "ExperimentalWarning" && /sqlite/i.test(w?.message ?? "")) return;
  process.stderr.write(`${w?.stack || w?.message || w}\n`);
});

export const VERSION = "1.13.6";
const DEFAULT_BUDGET_USD = 5;
const DEFAULT_MAX_TURNS = 500;
// Root repo (skills/ + allowRoots guard): bounty/bin/ -> ../../
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SKILLS_DIR = process.env.STRIX_SKILLS_DIR || resolve(REPO_ROOT, "skills", "bounty");

const HELP = `bounty — muse-bug-bounty wrapper v${VERSION} (zero-dependency, $0)

Penggunaan: bounty <perintah> [opsi]   (jalankan 'bounty --help' untuk detail)

SETUP
  bounty setup
      Wizard terpandu satu alur (berwarna di terminal): prasyarat -> provider
      -> target/scope -> verifikasi. Folder programs/ & .bounty/ dibuat
      otomatis; program disimpan ke programs/<nama>.md. Key tersimpan 0600,
      tidak pernah dilog/ditampilkan. Non-interaktif: tambahkan --yes beserta
      flag (--api-key, --model, --host, --template all|api|custom, --budget,
      --rate, --roles, --skip-provider).
  bounty provider [--type openai|anthropic] [--base-url URL] [--model ID]
      Pilih provider/model LLM (interaktif via stdin). Deteksi model dari
      {baseUrl}/models. Simpan ke .bounty/providers/ (0600).
  bounty install [--strix]
      Cek/instal Strix via curl resmi (hanya tampilkan perintah, tidak auto-run pipe-to-shell).
  bounty update [--source DIR] [--dry-run]
      Perbarui wrapper ke versi terbaru: cari clone repo (folder saat ini,
      ~/muse-bug-bounty, atau --source), stash perubahan lokal bila ada,
      git pull --ff-only, lalu npm install -g. --dry-run hanya menampilkan
      rencana tanpa mengubah apa pun.

ALUR INTI
  bounty run [--program programs/example.md] [--target URL] [--role low|high]
             [--budget 5] [--dry-run] [--targets URL1,URL2]
      Jalankan Strix dalam scope program. Scope-gate dulu, lalu pre-exec
      guard, rate limiter, budget default $${DEFAULT_BUDGET_USD}.
      Tanpa argumen di terminal: tampilkan daftar program tersimpan untuk
      dipilih (pilih nomor, lalu konfirmasi target).
      Tanpa --dry-run dan tanpa binary strix di PATH -> exit 2.
      --targets: antrean multi-target (satu per satu, satu pool budget).
      --fail-on low|medium|high|critical: exit 3 bila ada temuan >= ambang
        (severity heuristik dari kelas vuln — bukan CVSS).
      --pause: bila budget habis di tengah antrean, simpan state jeda
        (.bounty/pause-<ts>.json) dan exit 4. --resume <file>: lanjutkan.
      BOUNTY_RECORD_TIMINGS=1: tulis timings per fase ke .bounty/timings.jsonl.
  bounty review [--queue] [--approve <id> | --reject <id>] [--export-html [FILE]]
      List kandidat (status candidate); approve/reject per id.
      --queue: tampilkan antrean kandidat. --export-html: tulis halaman
      review statis (default eval/review.html) untuk review manual.
  bounty findings [--program <nama>] [--similar <id>]
      List kandidat + finding tersimpan, opsional filter program.
      --similar <id>: temuan serupa dari memori (FTS5 + RRF + vektor hash).
  bounty report [--out FILE]
      Render laporan temuan ke stdout (atau file).
  bounty trace <finding-id>
      Jejak source -> sink dari chain + evidence yang tercatat.
  bounty dedup [--program <nama>]
      Validasi keputusan dedup: kelompokkan kandidat per kunci kanonik,
      laporkan bila ada kunci yang muncul >1 kali (seharusnya 0).

RECON & SCAN
  bounty recon --tool subfinder|dnsx|httpx|katana|nuclei-kev|crtsh --target DOMAIN-atau-URL --program programs/<nama>.md [--timeout-ms N]
      Pipeline recon ProjectDiscovery + crt.sh pasif. subfinder/dnsx/httpx/crtsh
      mengembalikan daftar aset (bukan klaim vuln); katana/nuclei-kev menyimpan
      kandidat ke store. Hasil recon otomatis didaftarkan sebagai surface
      untuk bounty plan (max 20/run). Binary tidak ada -> dilewati (bukan error).
  bounty recon --update-templates
      Perbarui template nuclei (nuclei -update-templates).
  bounty scan --tool nuclei|dalfox|ffuf|arjun|graphql-cop|gitleaks|trufflehog|osv-scanner|garak|deepteam|jsluice|sourcemapper|garak-agent-breaker|pyrit --target URL --program programs/<nama>.md [--wordlist FILE] [--timeout-ms N] [--path DIR] [--model MODEL] [--strategy crescendo|tap] [--objective "..."]
      --path: checkout lokal untuk osv-scanner. --model: model LLM untuk garak/deepteam/agent-breaker/pyrit.
      jsluice: target boleh URL JS atau file JS lokal. sourcemapper: --map-url URL .map, --output-dir DIR.
      pyrit: --strategy crescendo (default) atau tap; --objective wajib untuk pyrit.
      Jalankan satu scanner klasik on-demand dalam scope program.
      Binary tidak ada -> dilewati (bukan error). Hasil = kandidat
      (UNVERIFIED) di store; review dulu di 'bounty review'.
  bounty codesearch --dir <dir> --pattern <regex> [--max N]
      Cari pola di kode (ripgrep bila ada, fallback jalan kaki file).
      Hanya baca, tidak menulis.
  bounty oast start [--server URL] [--number N] | bounty oast poll | bounty oast stop
      Sesi interactsh OAST untuk blind SSRF/XXE/SQLi/RCE. start jalan di
      foreground (Ctrl-C berhenti), poll dibaca dari terminal lain.
      Payload hanya disuntikkan ke target in-scope.

GRAPHQL / CLOUD / RE / FIRMWARE
  bounty graphql --target URL [--program P] [--field user]
      Fingerprint + introspeksi (atau rebuild clairvoyance bila dimatikan)
      + tes BOLA/alias/batching. Temuan masuk store sebagai kandidat.
  bounty cloud --tool takeover|cloud-enum|s3scanner|aws-s3-ls|nuclei-takeovers --target X [--program P]
      Enum cloud + deteksi takeover tanpa kredensial. Fingerprint takeover
      wajib verifikasi manual — tidak pernah mengklaim apa pun.
  bounty reverse --tool ghidra-mcp|rea|jadx --file <binary/APK> --confirm true
      RE headless gated: file lokal dalam scope saja. Nilai secret tidak
      pernah masuk temuan.
  bounty firmware --tool binwalk-ng|unblob|cve-bin-tool --file <image> [--program P]
      Analisis firmware lokal (file saja, bukan URL). EMBA sengaja tidak
      di-wire (opt-in semalam via Docker, lihat docs/firmware.md).
  bounty caido [--list] [--filter Q] [--limit N] | --replay <id>
      Jalur proxy live Caido MCP (read/replay saja). Butuh Caido lokal +
      server MCP (clone caido/mcp-caido, --mcp-path dist/index.js).

PLATFORM (read-only, tanpa auto-submit)
  bounty platform scope --platform hackerone|bugcrowd --handle NAMA
      Lihat scope program (read-only, token dari env HACKERONE_TOKEN /
      HACKERONE_USERNAME / BUGCROWD_TOKEN).
  bounty platform hacktivity --platform hackerone --query "..."
      Cari laporan publik (cek duplikat sebelum menulis draf).
  bounty platform draft --finding <id>
      Buat draf laporan Markdown dari kandidat (DRAFT — kirim manual).
  bounty platform sync-scope --platform hackerone|bugcrowd --handle NAMA --program programs/<nama>.md
      Bandingkan scope platform vs program lokal (hanya bandingkan,
      tidak menulis file).

MEMORI, GRAF & POLA
  bounty programs
      List program di programs/*.md (nama, scope, budget, rate).
  bounty memory [--list] [--lessons] [--track-record] [--program <nama>]
      Episode memori per run/review + lesson dari verdict manusia.
  bounty graph [--program <nama>]
      Graf aset (view SQL): node/edge, aset terpanas, cakupan open.
  bounty patterns [--skill <nama>]
      Pustaka pola laporan: total, bersitasi, per skill (+ bonus router).
  bounty skills [--skill <nama>]
      Daftar skill hunt di skills-index.json; --skill tampilkan isi skill.
  bounty plan --program <nama> [--limit N] [--record <surface>]
      Rencana hunt berbasis coverage: surface terpanas dulu, max 3 kelas
      per surface. --record daftarkan surface baru dari recon.

GERBANG CI & BENCHMARK
  bounty promptfoo-gate --results <hasil.json> [--min-pass-rate 0.8]
      Gerbang CI red-team: baca hasil promptfoo eval, lolos hanya bila
      pass rate >= ambang. Tanpa hasil/kunci -> gagal (bukan lolos diam-diam).
  bounty graph-gate [--baseline eval/results/baseline.json]
      Keputusan upgrade graf/memori: hanya "upgrade" bila baseline
      membuktikan planning/state adalah bottleneck; tanpa baseline
      jawabannya selalu "tetap SQL".
  bounty bench [--lab NAME] [--runs N]
      Jalankan benchmark (eval/run-bench.mjs bila ada, fallback mock).

LAINNYA
  bounty view
      Buka dashboard Strix (strix view) di background.
  bounty --help | bounty --version

Aturan keras: scope-gate, budget, tanpa submit/bayar/deposit, tanpa API berbayar
tanpa persetujuan. Kredensial asli JANGAN ditaruh di repo — pakai env/provider.
Tampilan: warna otomatis mati bila output di-pipe atau NO_COLOR diset
(BOUNTY_NO_COLOR=1 juga bisa).
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

// Prompt tanpa echo (untuk API key): tulis prompt SEKALI, bisukan semua
// echo readline selama input, lalu akhiri dengan tepat satu newline. Nilai
// tidak pernah tampil di layar maupun dilog. Hanya dipakai di TTY; bila
// _writeToOutput tak tersedia, jatuh balik ke ask biasa.
function askHidden(rl, q) {
  return new Promise((resolve) => {
    const orig = typeof rl._writeToOutput === "function" ? rl._writeToOutput.bind(rl) : null;
    if (!orig) { rl.question(q, (a) => resolve(String(a).trim())); return; }
    rl.output.write(q);
    rl._writeToOutput = () => {}; // bisukan echo ketikan (prompt sudah ditulis)
    rl.question("", (a) => {
      rl._writeToOutput = orig;
      rl.output.write("\n");
      resolve(String(a).trim());
    });
  });
}

// Tampilan scope gate yang seragam: OK -> stdout (hijau, gaya fase),
// DITOLAK -> stderr (merah) karena itu kondisi gagal + exit 2.
function printScope(ok, reason) {
  if (ok) { console.log(color("Scope OK", "green")); return true; }
  console.error(color(`Scope DITOLAK: ${reason ?? ""}`.trim(), "red"));
  return false;
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
    const filter = String(await ask(rl, "Cari model (kosong = tampilkan semua): ") ?? "").trim().toLowerCase();
    let shown = filter ? detected.models.filter((m) => m.toLowerCase().includes(filter)) : detected.models;
    if (shown.length === 0) {
      console.log(`Tidak ada model yang cocok dengan "${filter}" — menampilkan semua.`);
      shown = detected.models;
    }
    shown.forEach((m, i) => console.log(`  ${i + 1}. ${m}`));
    let picked = null;
    while (!picked) {
      const raw = args.model || (await ask(rl, "Pilih model (ketik nomor / id / sebagian nama): "));
      args.model = null;
      const model = String(raw ?? "").trim();
      if (!model) { console.error("Model tidak dipilih — batal."); return 2; }
      if (/^\d+$/.test(model)) picked = shown[Number(model) - 1];
      else if (shown.includes(model)) picked = model;
      else {
        const hits = shown.filter((m) => m.toLowerCase().includes(model.toLowerCase()));
        if (hits.length === 1) picked = hits[0];
        else if (hits.length > 1) {
          console.log(`Cocok ${hits.length} model:`);
          hits.forEach((m) => console.log(`  ${m}`));
          console.log("Perjelas pilihanmu (ketik nomor / id yang lebih spesifik).");
        } else console.error(`Tidak ada model yang cocok dengan "${model}" — coba lagi.`);
      }
      if (!picked && /^\d+$/.test(model)) console.error(`Nomor ${model} di luar daftar (1-${shown.length}) — coba lagi.`);
    }
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

// --- bounty setup: wizard terpandu satu alur (prasyarat -> provider ->
//     program -> verifikasi). Warna nyala otomatis di TTY (colorsEnabled).
//     Non-TTY: tidak menggantung — minta flag atau keluar dengan pesan. ---
function listProgramFiles() {
  const dir = resolve(process.cwd(), "programs");
  try { return readdirSync(dir).filter((f) => f.endsWith(".md")).sort().map((f) => join(dir, f)); }
  catch { return []; }
}

async function stepPrerequisites() {
  console.log(heading("1/4 — Prasyarat"));
  const nodeOk = (() => { try { return Number(process.versions.node.split(".")[0]) >= 20; } catch { return false; } })();
  console.log(`  Node ${process.version}: ${nodeOk ? color("OK", "green") : color("perlu >= 20", "red")}`);
  const strix = findBinary("strix");
  if (strix) console.log(`  Strix: ${color("ditemukan", "green")} (${strix})`);
  else console.log(`  Strix: ${color("belum ada", "yellow")} — install nanti via 'bounty install --strix' (setup tetap lanjut)`);
  return { nodeOk, strixFound: Boolean(strix) };
}

async function stepProvider(rl, args) {
  console.log("");
  console.log(heading("2/4 — Provider LLM"));
  const existing = loadProviders();
  if (existing && rl && !args["reconfigure-provider"]) {
    const reuse = (await ask(rl, `  Provider tersimpan: ${existing.type}/${existing.model}. Pakai ini? [Y/n] `)).toLowerCase();
    if (reuse !== "n" && reuse !== "no") { console.log(`  ${color("Pakai provider tersimpan.", "green")}`); return { ok: true, reused: true }; }
  }
  const type = args["provider-type"] || (rl ? (await ask(rl, `  Tipe (openai/anthropic) ${hint("[openai]")}: `)) : "") || "openai";
  const defBase = defaultProviderBase(type);
  const baseUrl = args["base-url"] || (rl ? (await ask(rl, `  Base URL ${hint(`[${defBase}]`)}: `)) : "") || defBase;
  const apiKey = args["api-key"] || process.env.LLM_API_KEY || (rl ? await askHidden(rl, "  API key (tidak ditampilkan/dilog): ") : "");
  if (!apiKey) { console.error(color("  API key kosong — provider tidak bisa disetel.", "red")); return { ok: false }; }
  console.log("  Mendeteksi model...");
  let detected;
  try { detected = await detectModels({ type, baseUrl, apiKey }); }
  catch (e) { console.error(color(`  Gagal deteksi model: ${e.message}`, "red")); return { ok: false }; }
  if (detected.warning) console.log(color(`  Peringatan: ${detected.warning}`, "yellow"));
  const allModels = detected.models;
  let models = allModels;
  const PAGE = 40;
  if (rl && models.length > PAGE) {
    console.log(`  ${models.length} model tersedia — ketik kata kunci untuk mempersempit (mis. "opus", "sonnet", "gpt-6").`);
    for (;;) {
      const q = (await ask(rl, `  Filter (Enter = tampilkan ${PAGE} teratas): `)).trim();
      if (!q) break;
      const filtered = filterModels(allModels, q);
      if (filtered.length === 0) { console.log(color(`  Tidak ada yang cocok dengan "${q}" — coba kata lain.`, "yellow")); continue; }
      models = filtered;
      if (models.length <= PAGE) break;
      console.log(`  Masih ${models.length} model cocok — persempit lagi, atau Enter untuk ${PAGE} teratas.`);
    }
  }
  const shown = models.slice(0, PAGE);
  console.log(`  Model (${models.length}${shown.length < models.length ? `, tampil ${shown.length} teratas` : ""}):`);
  shown.forEach((m, i) => console.log(`    ${color(String(i + 1), "cyan")}. ${m}`));
  if (shown.length < models.length) console.log(hint(`    … dan ${models.length - shown.length} lagi — ketik sebagian nama untuk memilih yang tak tampil.`));
  let picked = null;
  while (!picked) {
    const raw = args.model || (rl ? await ask(rl, "  Pilih model (nomor / id / sebagian nama): ") : "");
    args.model = null;
    const sel = String(raw ?? "").trim();
    if (!sel) { console.error(color("  Model tidak dipilih.", "red")); return { ok: false }; }
    if (/^\d+$/.test(sel)) picked = models[Number(sel) - 1];
    else if (models.includes(sel)) picked = sel;
    else {
      const hits = models.filter((m) => m.toLowerCase().includes(sel.toLowerCase()));
      if (hits.length === 1) picked = hits[0];
      else if (hits.length > 1) {
        console.log(`  Cocok ${hits.length} model:`);
        hits.forEach((m) => console.log(`    ${m}`));
        console.log("  Perjelas pilihanmu (ketik nomor / id yang lebih spesifik).");
      } else console.error(color(`  Tidak ada model yang cocok dengan "${sel}" — coba lagi.`, "red"));
    }
    if (!picked && /^\d+$/.test(sel)) console.error(color(`  Nomor ${sel} di luar daftar (1-${models.length}) — coba lagi.`, "red"));
  }
  saveProvider({ name: `${type}-${picked}`, type, baseUrl, apiKey, model: picked });
  const cfg = writeStrixConfig(picked, baseUrl, apiKey, type);
  console.log(`  ${color("Provider tersimpan", "green")} (0600). Strix config: ${cfg}`);
  console.log(`  STRIX_LLM=${type}/${picked} ${hint("(key tidak ditampilkan)")}`);
  return { ok: true, model: picked };
}

async function stepProgram(rl, args) {
  console.log("");
  console.log(heading("3/4 — Target & scope"));
  const existingFiles = listProgramFiles();
  // Mode pilih program yang sudah ada (hanya interaktif, bila tidak maksa buat baru).
  if (rl && existingFiles.length > 0 && !args.host && !args.name) {
    console.log(`  Program tersimpan (${existingFiles.length}):`);
    existingFiles.forEach((f, i) => {
      let label = f;
      try { label = (loadProgramFile(f).name || f).replace(/^Program:\s*/i, ""); } catch {}
      console.log(`    ${color(String(i + 1), "cyan")}. ${label}  ${hint(f.replace(process.cwd() + "/", ""))}`);
    });
    const ans = await ask(rl, `  Pilih nomor untuk pakai yang ada, atau 'b' untuk buat baru ${hint("[b]")}: `);
    if (/^\d+$/.test(ans) && existingFiles[Number(ans) - 1]) {
      const path = existingFiles[Number(ans) - 1];
      const prog = loadProgramFile(path);
      return { ok: true, path, host: prog.allowedHosts[0] || "", allowed: prog.allowedPaths.length ? prog.allowedPaths : ["/"] };
    }
  }
  // Buat program baru.
  const host = normalizeHost(args.host || (rl ? await ask(rl, "  Host target (mis. staging.contoh.com): ") : ""));
  if (!host) { console.error(color("  Host kosong — tidak bisa bikin program.", "red")); return { ok: false }; }
  const name = (args.name || (rl ? await ask(rl, `  Nama program ${hint(`[${host}]`)}: `) : "") || host).trim();
  let tmpl = scopeTemplate(args.template || "");
  if (!tmpl && rl) {
    console.log("  Template scope:");
    console.log(`    ${color("1", "cyan")}. ${SCOPE_TEMPLATES.all.label}`);
    console.log(`    ${color("2", "cyan")}. ${SCOPE_TEMPLATES.api.label}`);
    console.log(`    ${color("3", "cyan")}. ${SCOPE_TEMPLATES.custom.label}`);
    tmpl = scopeTemplate(await ask(rl, `  Pilih ${hint("[1]")}: `)) || scopeTemplate("all");
  }
  tmpl = tmpl || scopeTemplate("all");
  let allowed = tmpl.allowed;
  if (tmpl.key === "custom") {
    const raw = rl ? await ask(rl, `  Path Allowed (pisah koma) ${hint("[/]")}: `) : "";
    allowed = raw ? raw.split(",").map((s) => s.trim()).filter(Boolean) : ["/"];
  }
  const deniedRaw = args.denied ?? (rl ? await ask(rl, `  Path Denied (pisah koma) ${hint("[kosong]")}: `) : "");
  const denied = String(deniedRaw || "").split(",").map((s) => s.trim()).filter(Boolean);
  const budget = Number(args.budget ?? (rl ? await ask(rl, `  Budget USD ${hint("[5]")}: `) : "") ) || 5;
  const rate = Number(args.rate ?? (rl ? await ask(rl, `  Rate req/detik ${hint("[10]")}: `) : "")) || 10;
  const rolesRaw = args.roles ?? (rl ? await ask(rl, `  Roles ${hint("[low, high]")}: `) : "");
  const roles = String(rolesRaw || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const md = buildProgramMarkdown({ name, host, allowed, denied, budget, rate, roles: roles.length ? roles : ["low", "high"] });
  const path = join(resolve(process.cwd(), "programs"), `${slugify(name)}.md`);
  mkdirSync(resolve(process.cwd(), "programs"), { recursive: true });
  if (existsSync(path) && rl) {
    const ow = (await ask(rl, `  ${color(`${path} sudah ada. Timpa?`, "yellow")} [y/N] `)).toLowerCase();
    if (ow !== "y" && ow !== "yes") { console.log("  Dibatalkan — pakai file yang ada."); return { ok: true, path, host, allowed: loadProgramFile(path).allowedPaths.length ? loadProgramFile(path).allowedPaths : ["/"] }; }
  }
  writeFileSync(path, md, "utf8");
  console.log(`  ${color("Program ditulis", "green")}: ${path.replace(process.cwd() + "/", "")}`);
  return { ok: true, path, host, allowed };
}

function stepVerify(programPath, host, allowed) {
  console.log("");
  console.log(heading("4/4 — Verifikasi scope"));
  const program = loadProgramFile(programPath);
  const target = exampleTargetFor(host || program.allowedHosts[0] || "", allowed);
  const scope = checkScope(program, target);
  console.log(`  Target contoh: ${target}`);
  if (scope.ok) console.log(`  ${color("Scope OK", "green")}`);
  else console.error(`  ${color(`Scope DITOLAK: ${scope.reason}`, "red")}`);
  return { ok: scope.ok, target };
}

async function cmdSetup(args) {
  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY) && !args["non-interactive"];
  if (!interactive && !args.yes) {
    console.error("bounty setup butuh terminal interaktif (TTY).");
    console.error("Untuk non-interaktif tambahkan --yes beserta flag, mis.:");
    console.error("  bounty setup --yes --api-key KEY --model ID --host staging.contoh.com \\");
    console.error("    [--provider-type openai] [--base-url URL] [--name NAMA] \\");
    console.error("    [--template all|api|custom] [--budget 5] [--rate 10] [--roles low,high]");
    console.error("Skip langkah: --skip-provider (pakai provider tersimpan).");
    return 2;
  }
  const rl = interactive ? createInterface({ input: process.stdin, output: process.stdout }) : null;
  try {
    console.log(heading(`bounty setup — alur terpandu v${VERSION}`));
    await stepPrerequisites();
    if (!args["skip-provider"]) {
      const prov = await stepProvider(rl, args);
      if (!prov.ok) return 2;
    } else {
      console.log("");
      console.log(heading("2/4 — Provider LLM"));
      console.log(`  ${color("Dilewati", "yellow")} (--skip-provider) — pakai provider tersimpan bila ada.`);
    }
    const prog = await stepProgram(rl, args);
    if (!prog.ok) return 2;
    const verify = stepVerify(prog.path, prog.host, prog.allowed);
    console.log("");
    const relPath = prog.path.replace(process.cwd() + "/", "");
    console.log(summaryBox([
      `Program: ${relPath}`,
      `Scope: ${verify.ok ? color("OK", "green") : color("DITOLAK", "red")}`,
      "Perintah siap jalan:",
      `  bounty run --program ${relPath} --target ${verify.target}`,
    ], { title: "Setup selesai" }));
    if (!verify.ok) { console.error(color("Scope belum lolos — perbaiki Allowed/Denied di program lalu ulangi.", "red")); return 2; }
    return 0;
  } finally {
    if (rl) rl.close();
  }
}

// Picker interaktif untuk `bounty run` tanpa argumen: pilih program lalu
// konfirmasi target (default = contoh in-scope). Non-TTY -> kembalikan null
// agar cmdRun memakai perilaku default lama (tidak menggantung).
async function pickRunInteractive() {
  const files = listProgramFiles();
  if (files.length === 0) {
    console.log("Belum ada program di programs/. Jalankan 'bounty setup' dulu untuk membuatnya.");
    return { code: 2 };
  }
  console.log(heading("Pilih program untuk di-run:"));
  files.forEach((f, i) => {
    let label = f;
    try { label = (loadProgramFile(f).name || f).replace(/^Program:\s*/i, ""); } catch {}
    console.log(`  ${color(String(i + 1), "cyan")}. ${label}  ${hint(f.replace(process.cwd() + "/", ""))}`);
  });
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const sel = await ask(rl, "Nomor program (Enter = batal): ");
    if (!/^\d+$/.test(sel) || !files[Number(sel) - 1]) { console.log("Dibatalkan."); return null; }
    const path = files[Number(sel) - 1];
    const prog = loadProgramFile(path);
    const def = exampleTargetFor(prog.allowedHosts[0] || "", prog.allowedPaths.length ? prog.allowedPaths : ["/"]);
    const t = await ask(rl, `Target ${hint(`[${def}]`)}: `);
    return { program: path, target: t || def };
  } finally { rl.close(); }
}

async function runSingleTarget(args, targetOverride = null) {
  // P1-5: per-run timings (analogue STRIX_RUN_RECORD_TIMINGS) — dicatat
  // bila BOUNTY_RECORD_TIMINGS=1, ke .bounty/timings.jsonl + stdout.
  const t0 = Date.now();
  const mark = {};
  const recordTimings = () => {
    if (process.env.BOUNTY_RECORD_TIMINGS !== "1") return;
    const timings = {
      at: new Date().toISOString(), target: targetOverride || args.target || "",
      scope_ms: (mark.scope ?? t0) - t0,
      guard_ms: (mark.guard ?? mark.scope ?? t0) - (mark.scope ?? t0),
      strix_ms: (mark.strix ?? mark.guard ?? t0) - (mark.guard ?? mark.scope ?? t0),
      parse_ms: Date.now() - (mark.strix ?? t0),
      total_ms: Date.now() - t0,
    };
    try {
      mkdirSync(join(process.cwd(), ".bounty"), { recursive: true, mode: 0o700 });
      appendFileSync(join(process.cwd(), ".bounty", "timings.jsonl"), JSON.stringify(timings) + "\n");
    } catch {}
    console.log(`Timings: scope ${timings.scope_ms}ms, guard ${timings.guard_ms}ms, strix ${timings.strix_ms}ms, parse ${timings.parse_ms}ms, total ${timings.total_ms}ms.`);
  };
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
  printScope(scope.ok, scope.reason);
  if (!scope.ok) {
    try { logAudit({ command: "run", target, program: program.name, result: "blocked" }); } catch {}
    // Harus kembalikan bentuk hasil {code,...}; cmdRun membaca r.code.
    // Mengembalikan angka telanjang bikin r.code undefined -> exit 0 (bug:
    // scope gate gagal tapi dilaporkan sukses).
    return { code: 2, usd: 0, added: 0, findings: [] };
  }
  mark.scope = Date.now();

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
  console.log(phaseLine("Budget", `${formatUsd(budget)} | Role: ${profile.role} | Rate: ${program.rateLimit}/detik`));

  // 3. Strix binary check
  const strix = findBinary("strix");
  if (!strix) {
    console.log("Strix tidak ditemukan di PATH — jalankan mode --dry-run atau install Strix via curl resmi");
    console.log("  Jalankan: bounty install --strix   (menampilkan perintah resmi, tanpa auto-run)");
    console.log("  Baru menginstal Strix? Muat ulang PATH dulu: source ~/.bashrc (atau buka terminal baru).");
    if (args["dry-run"]) {
      console.log(`[dry-run] skills-dir: ${SKILLS_DIR} (akan diteruskan ke Strix via env STRIX_SKILLS_DIR — flag --skills-dir tidak ada di Strix terinstal)`);
      console.log("[dry-run] Instruksi yang akan dikirim ke Strix:");
      console.log(buildInstruction(program, role));
      return { code: done(0, "dry-run"), usd: 0, added: 0, findings: [] };
    }
    return { code: done(2, "error"), usd: 0, added: 0, findings: [] };
  }

  // 3b. Pre-flight config Strix: nilai STRIX_WEB_SEARCH_PROVIDER tak
  // valid ('custom') bikin Strix crash saat start (ValidationError) —
  // padahal run belum mulai. Nilai di file dihapus otomatis (fallback
  // 'auto'); nilai dari env shell tidak bisa diperbaiki — batalkan run
  // dengan petunjuk yang persis.
  const strixConfig = checkStrixConfig(join(homedir(), ".strix", "cli-config.json"), process.env);
  if (strixConfig.fixed) console.log(`Config Strix diperbaiki: ${STRIX_CONFIG_KEY}='${strixConfig.value}' dihapus dari ~/.strix/cli-config.json (bukan nilai valid — fallback 'auto').`);
  if (!strixConfig.ok) {
    console.error(`Config Strix tidak valid: ${strixConfig.key || STRIX_CONFIG_KEY}='${strixConfig.value}' (${strixConfig.source === "env" ? "dari env shell" : "dari ~/.strix/cli-config.json"}) — nilai valid: auto, perplexity, exa.`);
    if (strixConfig.source === "env") console.error(`Perbaiki: unset ${strixConfig.key || STRIX_CONFIG_KEY}  (atau set ke auto), lalu ulangi run.`);
    else console.error(`Perbaiki: hapus kunci ${STRIX_CONFIG_KEY} dari ~/.strix/cli-config.json, lalu ulangi run.`);
    return { code: done(2, "error"), usd: 0, added: 0, findings: [] };
  }

  // 3c. Provider tersimpan -> teruskan ke Strix via env (env menang atas
  // file) + perbaiki file config bila bentuknya masih flat/lama. Tanpa
  // ini Strix bilang "STRIX_LLM is not set" meski `bounty provider`
  // sudah jalan — karena file flat tidak dibaca loader Strix. Provider
  // tersimpan di .bounty/providers (cwd) adalah sumber yang dipakai;
  // STRIX_LLM dari shell (bila ada) ditimpa olehnya di run ini.
  let providerEnv = {};
  try {
    const creds = loadProviderCreds();
    if (creds?.model && creds?.apiKey) {
      providerEnv = buildStrixEnv(creds);
      const synced = syncStrixConfig(creds.model, creds.baseUrl, creds.apiKey, creds.type);
      if (synced.changed) console.log(`Config Strix diperbaiki: model ditulis ke ${synced.path} (bentuk env).`);
    }
  } catch {}

  // 4. Pre-exec guard + rate limiter
  // Rate limiter: TokenBucket menegakkan rate request WRAPPER (pre/post
  // run). Request internal Strix TIDAK lewat bucket ini — Strix dibatasi
  // lewat --max-budget / --max-turns + instruksi rate di bawah, dan
  // itu ditulis jujur di README (bukan klaim penegakan penuh).
  const rate = Number(program.rateLimit) || 10;
  const bucket = new TokenBucket(rate, rate);
  const maxTurns = Number(args["max-turns"] ?? DEFAULT_MAX_TURNS);
  const skillsDir = existsSync(SKILLS_DIR) ? SKILLS_DIR : null;
  // Flag Strix diverifikasi dari usage Strix asli di laptop (24 Nov 2026):
  // --budget TIDAK ADA (dugaan kita), --skills-dir hanya ada di Strix
  // upstream terbaru (bukan di build terinstal) — skill diteruskan lewat
  // env STRIX_SKILLS_DIR (upstream: strix/skills/__init__.py,
  // SKILLS_DIR_ENV). Budget: --max-budget (di usage); --max-budget-usd
  // juga diterima build terinstal, tapi --max-budget yang terdokumentasi.
  const strixArgs = ["--target", target, "--max-budget", String(budget), "--max-turns", String(maxTurns)];
  const cmd = `strix ${strixArgs.join(" ")}`;
  // Guard workspace = cwd pengguna (boleh jalan dari folder mana saja),
  // plus folder instal tool sendiri (skills/ tinggal di sana).
  const guard = checkCommand(cmd, process.cwd(), { allowRoots: [REPO_ROOT] });
  if (!guard.allowed) {
    console.error(`Perintah diblokir guard: ${guard.reason}`);
    return { code: done(2, "blocked"), usd: 0, added: 0, findings: [] };
  }
  await bucket.acquire();
  mark.guard = Date.now();

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
    env: { ...process.env, ...(skillsDir ? { STRIX_SKILLS_DIR: skillsDir } : {}), ...providerEnv, STRIX_TELEMETRY: "0" },
  });
  if (res.error) { console.error(`Gagal menjalankan strix: ${res.error.message}`); return { code: done(2, "error"), usd: 0, added: 0, findings: [] }; }
  mark.strix = Date.now();
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
  // Error argumen Strix (mis. flag tidak dikenal di versi Strix terinstal)
  // keluar dengan exit 2 juga — jangan disangka "temuan ditemukan".
  // Ciri: usage/error argparse di output. Laporkan sebagai error, tanpa
  // ringkasan sukses dan tanpa mencatat run.
  const combinedOut = stdout + "\n" + stderr;
  if (/unrecognized arguments|usage: strix|strix: error:/i.test(combinedOut)) {
    console.error("\nStrix menolak argumen perintah (flag tidak dikenal di versi Strix terinstal).");
    console.error("Ini bug wrapper, bukan target — perbaiki flag di bounty/bin/bounty.mjs, lalu ulangi run.");
    return { code: done(2, "error"), usd: 0, added: 0, findings: [] };
  }
  // Strix crash saat start (mis. config tidak valid, traceback Python)
  // juga keluar non-zero dan tidak menghasilkan temuan — jangan cetak
  // ringkasan sukses. Exit 2 yang sah (temuan ditemukan) tidak punya
  // traceback, jadi tetap lolos sebagai sukses.
  const crashed = (code !== 0 && code !== 2) || /Traceback \(most recent call last\)|validation error for \w+Settings|Failed to execute script/i.test(combinedOut);
  if (crashed) {
    console.error(`\nStrix gagal jalan (exit ${code}).`);
    if (/MISSING REQUIRED ENVIRONMENT VARIABLES/i.test(combinedOut)) {
      console.error("Strix butuh model/provider (STRIX_LLM belum disetel): jalankan `bounty provider` untuk menyimpan provider, lalu ulangi run.");
    } else {
      console.error("Lihat traceback di atas — bila menyebut ValidationError / cli-config.json, perbaiki config Strix lalu ulangi run.");
    }
    return { code: done(2, "error"), usd: 0, added: 0, findings: [] };
  }
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
  // P1-5: HTTP evidence ID ala Strix 1.7 — ID request (Caido/proxy) yang
  // dibawa temuan Strix disimpan sebagai evidence agar temuan bisa
  // dilacak ke request aslinya. Hanya field request-id eksplisit yang
  // dipakai (requestId/request_id/http_request_id/caido_request_id).
  const withEvidenceId = (f) => ({ ...f, httpEvidenceId: f.requestId ?? f.request_id ?? f.http_request_id ?? f.caido_request_id ?? null });
  const findings = [...parsed.findings, ...artifacts.findings.map((f) => ({ ...f, program: program.name })), ...sarifFindings].map(withEvidenceId);
      const usd = artifacts.usd > 0 ? artifacts.usd : parsed.usd;
      if (artifacts.findings.length > 0) console.log(`Artefak Strix: ${artifacts.findings.length} temuan dari strix_runs/vulnerabilities.json${artifacts.usd > 0 ? `, biaya $${artifacts.usd} dari run.json` : ""}.`);
      const existing = store.listCandidates(program.name, "candidate")
        .map((c) => ({ endpoint: c.endpoint, method: c.method, param: c.param, vuln_class: c.vuln_class, cwe: c.cwe }));
      const { unique } = dedupCandidates([...existing, ...findings]);
      const fresh = unique.slice(existing.length);
      let added = 0;
      for (const f of fresh) {
        const cid = store.addCandidate({ program: program.name, endpoint: f.endpoint, method: f.method, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe });
        if (f.httpEvidenceId) {
          try { store.addEvidence(cid, "http-request-id", String(f.httpEvidenceId)); } catch {}
        }
        added++;
      }
      store.addRun({ version: "bounty", target, lab: program.name, tp: 0, fp: 0, fn: 0, timeMs: Date.now() - startedAt, usd });
      runUsd = usd; runAdded = added; runFindings = fresh;
      // v1.3 cost tracking nyata: peringatan saat mendekati budget.
      const bs = budgetStatus({ spent: usd, budget });
      if (bs.exceeded) console.log(`Peringatan: biaya $${usd} sudah MELEBIHI budget $${budget} untuk target ini.`);
      else if (bs.warn) console.log(`Peringatan: biaya $${usd} sudah ${Math.round(bs.pct * 100)}% dari budget $${budget}.`);
      console.log("");
      console.log(summaryBox([
        `Target: ${target}`,
        `Temuan dari Strix: ${findings.length}`,
        `${added} kandidat baru masuk store (duplikat: ${findings.length - added})`,
        `Biaya: ${formatUsd(usd)} dari budget ${formatUsd(budget)}`,
        added > 0 ? "Status: ada kandidat baru — review dulu sebelum dipakai" : "Status: tidak ada kandidat baru",
      ], { title: "Ringkasan run" }));
      console.log(`Lihat antrean: bounty review  |  bounty findings --program ${program.name}`);
      // v1.2 memori: episode per run + coverage kelas yang diperiksa +
      // peringatan bila pola serupa pernah ditolak (FP) oleh reviewer.
      try {
        for (const f of fresh) recordCoverage(store.db, program.name, f.endpoint, f.vulnClass, "examined");
        const rejectedIds = new Set(store.listCandidates(program.name, "rejected").map((c) => c.id));
        for (const f of fresh) {
          const similar = findSimilarV2(store.db, { endpoint: f.endpoint, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe }, 3)
            .filter((s) => rejectedIds.has(s.id));
          if (similar.length > 0) console.log(`Peringatan: pola serupa pernah DITOLAK (FP) — kandidat #${similar[0].id} ${similar[0].endpoint} (${similar[0].vulnClass}). Verifikasi ekstra sebelum approve.`);
        }
        recordEpisode(store.db, { program: program.name, target, kind: "run", summary: `${added} kandidat baru, ${findings.length} temuan parse, $${usd}` });
      } catch (e) { console.error(`Peringatan: gagal menulis memori: ${e.message}`); }
    } finally { store.close(); }
  } catch (e) { console.error(`Peringatan: gagal menyimpan hasil ke store: ${e.message}`); }
  recordTimings();
  return { code: done(strixOk ? 0 : code, strixOk ? (code === 2 ? "ok-findings" : "ok") : "failed"), usd: runUsd, added: runAdded, findings: runFindings };
}

// v1.3 multi-target: `bounty run --targets url1,url2` menjalankan target
// satu per satu (bukan paralel) dengan satu pool budget --budget; antrean
// berhenti bila biaya total mencapai budget. Satu target = perilaku lama.
// P1-5: --fail-on <sev> (exit 3 bila temuan >= ambang), --pause (tulis
// state jeda bila budget habis, exit 4), --resume <file> (lanjutkan sisa).
async function cmdRun(args) {
  // Tanpa argumen target/program/targets/resume di TTY -> picker program.
  // Non-TTY dibiarkan ke perilaku default lama (tidak menggantung di prompt).
  if (!args.target && !args.program && !args.targets && !args.resume && process.stdin.isTTY && process.stdout.isTTY) {
    const picked = await pickRunInteractive();
    if (picked === null) return 0;
    if (picked.code) return picked.code;
    args = { ...args, program: picked.program, target: picked.target };
  }
  const failOn = String(args["fail-on"] ?? "").toLowerCase();
  if (failOn && !["low", "medium", "high", "critical"].includes(failOn)) {
    console.error("--fail-on wajib: low | medium | high | critical.");
    return 2;
  }
  const failCheck = (findings) => {
    if (!failOn) return 0;
    const hit = checkFailOn(findings, failOn);
    if (!hit.triggered) return 0;
    console.log(`--fail-on ${failOn} terpicu: ${hit.count} temuan >= ${failOn} (terparah: ${hit.worst}). Exit 3.`);
    return 3;
  };
  if (args.resume) {
    const pauseFile = resolve(String(args.resume));
    if (!existsSync(pauseFile)) { console.error(`File jeda tidak ditemukan: ${pauseFile}`); return 2; }
    const paused = JSON.parse(readFileSync(pauseFile, "utf8"));
    if (!paused.remaining?.length) { console.log("Tidak ada target tersisa di file jeda."); return 0; }
    const remainingBudget = Number(paused.budget ?? 0) - Number(paused.spent ?? 0);
    if (remainingBudget <= 0) { console.error(`Budget sudah habis ($${paused.spent ?? 0}/$${paused.budget ?? 0}) — naikkan budget atau mulai antrean baru.`); return 2; }
    console.log(`Melanjutkan ${paused.remaining.length} target tersisa (budget sisa $${remainingBudget}).`);
    args = { ...args, targets: paused.remaining.join(","), budget: String(remainingBudget), program: paused.program ?? args.program };
  }
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
    const allFindings = [];
    const summary = await runQueue(targets, async (t) => {
      const r = await runSingleTarget({ ...args, target: t }, t);
      allFindings.push(...(r.findings ?? []));
      return { status: r.code === 0 ? "ok" : "failed", usd: r.usd, findings: r.findings };
    }, {
      budget,
      onProgress: (p) => console.log(`${progressBar(p.done, p.total)} ${p.target}: ${p.status}, ${formatUsd(p.usd)} (total ${formatUsd(p.totalUsd)})`),
    });
    console.log(`Antrean selesai: ${summary.done}/${summary.total} target, total biaya $${summary.totalUsd}${summary.stopped ? " (berhenti: budget habis)" : ""}.`);
    console.log(summaryBox([
      `Target selesai: ${summary.done}/${summary.total}`,
      `Total biaya: ${formatUsd(summary.totalUsd)} dari budget ${formatUsd(budget)}`,
      summary.stopped ? "Berhenti: budget habis — pakai --pause untuk jeda" : "Semua target selesai",
    ], { title: "Ringkasan antrean" }));
    if (summary.stopped && args.pause) {
      const remaining = targets.slice(summary.done);
      const pauseFile = join(process.cwd(), ".bounty", `pause-${Date.now()}.json`);
      mkdirSync(join(process.cwd(), ".bounty"), { recursive: true, mode: 0o700 });
      writeFileSync(pauseFile, JSON.stringify({ program: args.program || "programs/example.md", budget, spent: summary.totalUsd, remaining, at: new Date().toISOString() }, null, 2), { mode: 0o600 });
      console.log(`Jeda: ${remaining.length} target tersisa disimpan ke ${pauseFile}. Lanjutkan: bounty run --resume ${pauseFile}`);
      return 4;
    }
    const failCode = failCheck(allFindings);
    if (failCode) return failCode;
    return summary.stopped || summary.results.every((r) => r.status === "ok" || r.status === "done") ? 0 : 2;
  }
  const r = await runSingleTarget(args);
  const failCode = failCheck(r.findings ?? []);
  if (failCode) return failCode;
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
      console.log(row ? color(`Kandidat #${row.id} disetujui (approved).`, "green") : color(`Kandidat #${args.approve} tidak ditemukan.`, "red"));
      auditLog(row ? "ok" : "error", `#${args.approve}`);
      if (row) { try { addLesson(store.db, { skill: expectedSkillFor(row.vuln_class), vulnClass: row.vuln_class, outcome: "confirmed", note: `review approve #${row.id}` }); recordEpisode(store.db, { program: row.program, target: row.endpoint, kind: "review", summary: `approve #${row.id} ${row.vuln_class}` }); } catch (e) { console.error(`Peringatan: gagal menulis memori: ${e.message}`); } }
      return row ? 0 : 2;
    }
    if (args.reject) {
      const row = store.rejectCandidate(Number(args.reject));
      console.log(row ? color(`Kandidat #${row.id} ditolak (rejected).`, "yellow") : color(`Kandidat #${args.reject} tidak ditemukan.`, "red"));
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
    const queueRows = list.map((c) => [`#${c.id}`, c.program, c.method, c.endpoint, c.param || "-", `${severityBadge(severityFor(c))} ${c.vuln_class}`, c.cwe || "-"]);
    console.log(table(queueRows, ["ID", "Program", "Method", "Endpoint", "Param", "Kelas", "CWE"]));
    console.log(`Total: ${list.length} kandidat menunggu review.`);
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
  const rows = [];
  for (const f of files) {
    try {
      const prog = loadProgramFile(join(dir, f));
      // Nama kanonik sering diambil dari judul H1 "# Program: X" — buang
      // prefiks "Program:" agar tidak menduplikasi header kolom "Program".
      const label = (prog.name || f.replace(/\.md$/, "")).replace(/^Program:\s*/i, "");
      rows.push([label, prog.allowedHosts.join(", ") || "-", formatUsd(prog.maxBudgetUsd ?? 5), `${prog.rateLimit}/detik`, prog.roles.join(", ")]);
    } catch (e) { rows.push([f, "(gagal dibaca)", "-", "-", "-"]); }
  }
  console.log(table(rows, ["Program", "Scope", "Budget", "Rate", "Roles"]));
  return 0;
}

function cmdFindings(args) {
  const store = new Store();
  try {
    // --similar <id>: temuan serupa dari memori (FTS5 + RRF + vektor hash, v1.11).
    if (args.similar) {
      const row = store.db.prepare("SELECT * FROM candidate WHERE id = ?").get(Number(args.similar));
      if (!row) { console.log(`Kandidat #${args.similar} tidak ditemukan.`); return 2; }
      console.log(`Serupa dengan #${row.id} ${row.method} ${row.endpoint} (${row.vuln_class}):`);
      const similar = findSimilarV2(store.db, { endpoint: row.endpoint, param: row.param, vulnClass: row.vuln_class, cwe: row.cwe }, 5)
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
    const tableRows = rows.map((c) => [`#${c.id}`, c.status, c.program, c.method, c.endpoint, c.param || "-", `${severityBadge(severityFor(c))} ${c.vuln_class}`, c.cwe || "-"]);
    console.log(table(tableRows, ["ID", "Status", "Program", "Method", "Endpoint", "Param", "Kelas", "CWE"]));
    console.log(`Total: ${rows.length} temuan (${candidates.length} kandidat, ${approved.length} disetujui).`);
    return 0;
  } finally { store.close(); }
}

function cmdMemory(args) {
  const store = new Store();
  try {
    if (args["track-record"]) {
      const record = skillTrackRecord(store.db);
      const rows = Object.values(record).filter((r) => r.total >= 3);
      if (rows.length === 0) { console.log("Belum ada track record (butuh ≥3 verdict per skill)."); return 0; }
      const tableRows = rows
        .sort((a, b) => b.precision - a.precision)
        .map((r) => [r.skill, String(r.confirmed), String(r.falsePositive), `${Math.round(r.precision * 100)}%`, r.weight > 0 ? `+${r.weight.toFixed(2)}` : r.weight.toFixed(2)]);
      console.log(table(tableRows, ["Skill", "Terkonfirmasi", "False positive", "Presisi", "Bobot"]));
      console.log("Bobot dipakai router: skill presisi tinggi naik, presisi rendah turun (max ±0.3).");
      return 0;
    }
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

const SCAN_TOOLS = [...SUPPORTED_TOOLS, "jsluice", "sourcemapper", "garak-agent-breaker", "pyrit", "mobsf", "jadx"];

// Simpan temuan ke store (dedup vs kandidat yang sudah ada). Dipakai
// cmdScan + perintah P1 (graphql/cloud/reverse) agar polanya sama.
function storeFindings(program, findings = []) {
  const store = new Store();
  try {
    const existing = store.listCandidates(program.name, "candidate")
      .map((c) => ({ endpoint: c.endpoint, method: c.method, param: c.param, vuln_class: c.vuln_class, cwe: c.cwe }));
    const { unique } = dedupCandidates([...existing, ...findings]);
    const fresh = unique.slice(existing.length);
    let added = 0;
    for (const f of fresh) {
      store.addCandidate({ program: program.name, endpoint: f.endpoint, method: f.method, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe });
      added++;
    }
    return { added, total: findings.length };
  } finally { store.close(); }
}

async function cmdScan(args) {
  const tool = String(args.tool ?? "").toLowerCase();
  const target = args.target;
  const programPath = args.program || resolve(process.cwd(), "programs/example.md");
  if (!SCAN_TOOLS.includes(tool)) {
    console.error(`--tool wajib: ${SCAN_TOOLS.join(" | ")} (dapat: "${tool || ""}")`);
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
  // jsluice/mobsf/jadx boleh menarget file lokal (bukan URL) — scope gate
  // URL ditangani lib masing-masing; file lokal adalah input pengguna.
  const isLocalJs = (tool === "jsluice" && !/^https?:\/\//i.test(String(target))) || tool === "mobsf" || tool === "jadx";
  const scope = isLocalJs ? { ok: true } : checkScope(program, target);
  printScope(scope.ok, scope.reason);
  if (!scope.ok) {
    try { logAudit({ command: "scan", tool, target, program: program.name, result: "blocked" }); } catch {}
    return 2;
  }
  try { logAudit({ command: "scan", tool, target, program: program.name, result: "started" }); } catch {}
  const timeoutMs = Number(args["timeout-ms"] ?? 120000);
  let result;
  if (SUPPORTED_TOOLS.includes(tool)) {
    result = runTool(tool, {
      target,
      program,
      timeoutMs,
      wordlist: args.wordlist,
      localPath: args.path,
      model: args.model,
    });
  } else if (tool === "jsluice") {
    result = runJsluice(target, { program, timeoutMs });
  } else if (tool === "sourcemapper") {
    result = runSourcemapper(target, { program, timeoutMs, mapUrl: args["map-url"] ?? "", outputDir: args["output-dir"] ?? "" });
  } else if (tool === "garak-agent-breaker") {
    result = runGarakAgentBreaker(target, { program, timeoutMs, model: args.model, generatorConfig: args["generator-config"] });
  } else if (tool === "pyrit") {
    if (!args.objective) {
      console.error("--objective wajib untuk pyrit (tujuan serangan, mis. \"bypass filter prompt\").");
      return 2;
    }
    result = runPyrit(target, { program, timeoutMs, strategy: args.strategy ?? "crescendo", objective: args.objective, model: args.model, maxTurns: Number(args["max-turns"] ?? 10) });
  } else if (tool === "mobsf") {
    // P1-4: MobSF async (fetch REST). File APK/IPA lokal, program dicek
    // resolveProgram di lib (basename harus terdaftar bila apps ada).
    result = await runMobsf(target, { program, timeoutMs, mobsfUrl: args["mobsf-url"], useDocker: args.docker === "true" || args.docker === true });
  } else if (tool === "jadx") {
    result = runJadx(target, { program, timeoutMs });
  }
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
  if (tool === "sourcemapper") {
    console.log(`[sourcemapper] ${result.files.length} file sumber diekstrak ke ${result.outDir || "(dihapus: kosong)"}.`);
    if (result.files.length) for (const f of result.files.slice(0, 20)) console.log(`  ${f}`);
    try { logAudit({ command: "scan", tool, target, program: program.name, result: "ok" }); } catch {}
    return 0;
  }
  const findings = result.findings ?? [];
  // Simpan kandidat ke store (dedup vs yang sudah ada di program ini).
  const store = new Store();
  try {
    const existing = store.listCandidates(program.name, "candidate")
      .map((c) => ({ endpoint: c.endpoint, method: c.method, param: c.param, vuln_class: c.vuln_class, cwe: c.cwe }));
    const { unique } = dedupCandidates([...existing, ...findings]);
    const fresh = unique.slice(existing.length);
    let added = 0;
    for (const f of fresh) {
      store.addCandidate({ program: program.name, endpoint: f.endpoint, method: f.method, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe });
      added++;
    }
    console.log(`[${tool}] ${result.rawCount} temuan mentah, ${added} kandidat baru masuk store (dedup: ${findings.length - added} duplikat) dalam ${result.time_ms} ms.`);
    console.log(`Lihat antrean: bounty review  |  bounty findings --program ${program.name}`);
  } finally { store.close(); }
  try { logAudit({ command: "scan", tool, target, program: program.name, result: "ok" }); } catch {}
  return 0;
}

async function cmdRecon(args) {
  if (args["update-templates"]) {
    const r = updateNucleiTemplates({});
    if (r.skipped) { console.log(`Dilewati: ${r.reason}`); return 0; }
    if (r.error) { console.error(r.error); return 2; }
    console.log(`Template nuclei diperbarui${r.version ? ` (versi ${r.version})` : ""}.`);
    return 0;
  }
  const tool = String(args.tool ?? "").toLowerCase();
  const target = args.target;
  const programPath = args.program || resolve(process.cwd(), "programs/example.md");
  if (!RECON_TOOLS.includes(tool)) {
    console.error(`--tool wajib: ${RECON_TOOLS.join(" | ")} (dapat: "${tool || ""}")`);
    return 2;
  }
  if (!target) { console.error("--target DOMAIN atau URL wajib."); return 2; }
  if (!existsSync(programPath)) { console.error(`Program tidak ditemukan: ${programPath}`); return 2; }
  const program = loadProgramFile(programPath);
  const timeoutMs = Number(args["timeout-ms"] ?? 120000);
  let result;
  if (tool === "subfinder") result = runSubfinder(target, { program, timeoutMs });
  else if (tool === "dnsx") result = runDnsx(String(target).split(","), { program, timeoutMs });
  else if (tool === "httpx") result = runHttpx(String(target).split(","), { program, timeoutMs });
  else if (tool === "katana") result = runKatana(target, { program, timeoutMs });
  else if (tool === "nuclei-kev") result = runNucleiKev(target, { program, timeoutMs });
  else if (tool === "crtsh") result = await crtsh(target, { program });
  if (result.error) { console.error(result.error); return 2; }
  if (result.blocked) { printScope(false, result.reason); return 2; }
  if (result.skipped) { console.log(`Dilewati: ${result.reason}`); return 0; }
  const results = result.results ?? [];
  console.log(`[${tool}] ${results.length} hasil dalam ${result.time_ms} ms.`);
  for (const r of results.slice(0, 20)) console.log(`  ${typeof r === "string" ? r : JSON.stringify(r)}`);
  if (results.length > 20) console.log(`  ... dan ${results.length - 20} lagi.`);
  // v1.12: daftarkan surface hasil recon ke planner (max 20/run) supaya
  // `bounty plan` bisa merencanakan hunt ke host/URL yang baru ditemukan
  // — bukan hanya yang sudah punya kandidat. recordSurface hanya menulis
  // baris yang belum ada, jadi pemanggilan ulang aman.
  const surfaces = [...new Set(results.map((r) => (typeof r === "string" ? r : r?.url ?? r?.endpoint ?? r?.subdomain ?? r?.host ?? "")).filter(Boolean))].slice(0, 20);
  if (surfaces.length > 0) {
    const storeS = new Store();
    try {
      let added = 0;
      for (const s of surfaces) { if (recordSurface(storeS.db, program.name, s) > 0) added += 1; }
      if (added > 0) console.log(`${added} surface baru didaftarkan ke planner. Lihat: bounty plan --program ${program.name}`);
    } catch (e) { console.error(`Peringatan: gagal mendaftarkan surface: ${e.message}`); }
    finally { storeS.close(); }
  }
  const findings = result.findings ?? [];
  if (!findings.length) return 0;
  const store = new Store();
  try {
    const existing = store.listCandidates(program.name, "candidate")
      .map((c) => ({ endpoint: c.endpoint, method: c.method, param: c.param, vuln_class: c.vuln_class, cwe: c.cwe }));
    const { unique } = dedupCandidates([...existing, ...findings]);
    const fresh = unique.slice(existing.length);
    for (const f of fresh) store.addCandidate({ program: program.name, endpoint: f.endpoint, method: f.method, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe });
    console.log(`${fresh.length} kandidat baru masuk store. Lihat: bounty review | bounty findings --program ${program.name}`);
  } finally { store.close(); }
  return 0;
}

async function cmdOast(args) {
  const sub = String(args._[1] ?? "");
  const sessionFile = join(process.cwd(), ".bounty", "oast-session.json");
  if (sub === "start") {
    const session = await startInteractsh({ server: args.server ?? "", token: args.token ?? "", number: Number(args.number ?? 1) });
    if (session.skipped) { console.log(`Dilewati: ${session.reason}`); return 0; }
    if (session.error) { console.error(session.error); return 2; }
    mkdirSync(join(process.cwd(), ".bounty"), { recursive: true, mode: 0o700 });
    const { proc, ...saved } = session;
    writeFileSync(sessionFile, JSON.stringify({ ...saved, _seen: 0 }, null, 2), { mode: 0o600 });
    console.log(`OAST siap: ${session.domain}`);
    console.log(`Payload: ${session.payload}`);
    console.log("Suntikkan payload ke target in-scope, lalu baca callback dari terminal lain: bounty oast poll");
    console.log("Tekan Ctrl-C untuk berhenti.");
    process.on("SIGINT", () => { try { stopInteractsh(session); } catch {} process.exit(0); });
    for (;;) {
      await new Promise((r) => setTimeout(r, 5000));
      const polled = pollInteractsh(session);
      for (const cb of polled.callbacks ?? []) console.log(`[callback] ${JSON.stringify(cb)}`);
    }
  }
  if (sub === "poll") {
    if (!existsSync(sessionFile)) { console.error("Tidak ada sesi OAST (.bounty/oast-session.json) — jalankan 'bounty oast start' dulu."); return 2; }
    const saved = JSON.parse(readFileSync(sessionFile, "utf8"));
    const polled = pollInteractsh(saved);
    if (polled.error) { console.error(polled.error); return 2; }
    console.log(`${polled.callbacks.length} callback baru (total ${polled.total}).`);
    for (const cb of polled.callbacks) console.log(`  ${JSON.stringify(cb)}`);
    return 0;
  }
  if (sub === "stop") {
    if (!existsSync(sessionFile)) { console.log("Tidak ada sesi OAST yang berjalan."); return 0; }
    const saved = JSON.parse(readFileSync(sessionFile, "utf8"));
    try { stopInteractsh(saved); } catch {}
    if (saved.pid) { try { process.kill(saved.pid, "SIGTERM"); } catch {} }
    try { (await import("node:fs")).unlinkSync(sessionFile); } catch {}
    console.log("Sesi OAST dihentikan.");
    return 0;
  }
  console.error("Pakai: bounty oast start [--server URL] [--number N] | bounty oast poll | bounty oast stop");
  return 2;
}

async function cmdPlatform(args) {
  const sub = String(args._[1] ?? "");
  const platform = String(args.platform ?? "hackerone").toLowerCase();
  if (sub === "scope") {
    const handle = args.handle;
    if (!handle) { console.error("--handle NAMA program wajib."); return 2; }
    const res = await getProgramScope(platform, handle, {});
    if (res.error) { console.error(`Gagal: ${res.error}`); return 2; }
    console.log(`Scope ${platform}/${handle}: ${res.assets.length} aset.`);
    for (const a of res.assets.slice(0, 30)) console.log(`  ${a.type}: ${a.identifier}${a.eligible === false ? " (tidak eligible)" : ""}`);
    return 0;
  }
  if (sub === "hacktivity") {
    const res = await searchHacktivity(platform, args.query ?? "", {});
    if (res.error) { console.error(`Gagal: ${res.error}`); return 2; }
    console.log(`${res.length} laporan publik ditemukan.`);
    for (const r of res.slice(0, 10)) console.log(`  [${r.state}] ${r.title} — ${r.url}`);
    return 0;
  }
  if (sub === "draft") {
    const id = Number(args.finding);
    if (!id) { console.error("--finding <id> wajib (id kandidat dari 'bounty findings')."); return 2; }
    const store = new Store();
    try {
      const row = store.listCandidates(null, "candidate").find((c) => c.id === id);
      if (!row) { console.error(`Kandidat id ${id} tidak ditemukan.`); return 2; }
      const out = args.out ? resolve(String(args.out)) : null;
      const text = draftReport({ title: row.vuln_class, endpoint: row.endpoint, vulnClass: row.vuln_class, cwe: row.cwe, severity: "medium", evidence: `Kandidat #${row.id} program ${row.program}`, steps: "Lihat bounty trace / review untuk langkah reproduksi." });
      if (out) { writeFileSync(out, text); console.log(`Draf ditulis ke ${out} (DRAFT — kirim manual setelah review).`); }
      else console.log(text);
      return 0;
    } finally { store.close(); }
  }
  if (sub === "sync-scope") {
    const handle = args.handle;
    const programPath = args.program;
    if (!handle || !programPath) { console.error("--handle NAMA dan --program programs/<nama>.md wajib."); return 2; }
    const res = await syncScopeToProgram(platform, handle, programPath, {});
    if (res.error) { console.error(`Gagal: ${res.error}`); return 2; }
    console.log(`Scope ${platform}/${handle} vs ${programPath}:`);
    console.log(`  + ${res.added.length} aset baru di platform (belum di program lokal)`);
    for (const a of res.added.slice(0, 10)) console.log(`    + ${a}`);
    console.log(`  - ${res.removed.length} aset di program lokal tapi tidak di platform`);
    for (const a of res.removed.slice(0, 10)) console.log(`    - ${a}`);
    console.log(`  = ${res.unchanged.length} aset sama. Hanya perbandingan — file tidak diubah.`);
    return 0;
  }
  console.error("Pakai: bounty platform scope|hacktivity|draft|sync-scope ... (read-only, tanpa auto-submit)");
  return 2;
}

function cmdDedup(args) {
  const store = new Store();
  try {
    const program = args.program ? String(args.program) : null;
    const list = store.listCandidates(program, "candidate");
    const groups = new Map();
    for (const c of list) {
      const k = canonicalKey({ endpoint: c.endpoint, method: c.method, param: c.param, vulnClass: c.vuln_class, cwe: c.cwe });
      groups.set(k, (groups.get(k) ?? []).concat(c));
    }
    const dupes = [...groups.entries()].filter(([, v]) => v.length > 1);
    console.log(`Dedup: ${list.length} kandidat, ${groups.size} kunci unik, ${dupes.length} kunci duplikat.`);
    for (const [k, v] of dupes.slice(0, 10)) {
      console.log(`  DUPLIKAT x${v.length}: ${k} (id: ${v.map((c) => c.id).join(", ")})`);
    }
    if (dupes.length === 0) console.log("Validasi lolos: tidak ada kunci duplikat di store.");
    return dupes.length === 0 ? 0 : 1;
  } finally { store.close(); }
}

function cmdCodesearch(args) {
  const dir = args.dir ? resolve(String(args.dir)) : null;
  const pattern = args.pattern ? String(args.pattern) : "";
  if (!dir || !pattern) { console.error("Pakai: bounty codesearch --dir <dir> --pattern <regex> [--max N]"); return 2; }
  const r = searchCode(dir, pattern, { maxResults: Number(args.max ?? 50) });
  if (r.error) { console.error(r.error); return 2; }
  console.log(`[${r.tool}] ${r.results.length} kecocokan dalam ${r.time_ms} ms.`);
  for (const hit of r.results) console.log(`  ${hit.file}:${hit.line}: ${hit.text}`);
  return 0;
}

// ---- P1 commands ----

async function cmdGraphql(args) {
  const target = args.target;
  const programPath = args.program || resolve(process.cwd(), "programs/example.md");
  if (!target) { console.error("Pakai: bounty graphql --target URL [--program programs/<nama>.md] [--field user]"); return 2; }
  if (!existsSync(programPath)) { console.error(`Program tidak ditemukan: ${programPath}`); return 2; }
  const program = loadProgramFile(programPath);
  const fp = await fingerprintGraphql(target, { program });
  if (fp.error) { console.error(fp.error); return 2; }
  if (!fp.isGraphql) { console.log("Bukan endpoint GraphQL (tidak merespons query GraphQL)."); return 0; }
  console.log(`GraphQL terdeteksi. Introspeksi: ${fp.introspectionEnabled === true ? "aktif" : fp.introspectionEnabled === false ? "dimatikan" : "tidak diketahui"}.`);
  let schema = null;
  if (fp.introspectionEnabled) {
    const intro = await introspectSchema(target, { program });
    if (intro.error) console.error(`Introspeksi gagal: ${intro.error}`);
    else schema = intro.schema;
  }
  if (!schema) {
    console.log("Introspeksi tidak tersedia — rebuild schema gaya clairvoyance (tebakan, partial).");
    const rebuilt = await rebuildSchemaFromClairvoyance(target, { program });
    if (rebuilt.error) { console.error(rebuilt.error); return 2; }
    schema = rebuilt.schema;
    console.log(`Schema hasil tebakan: ${schema.types?.length ?? 0} type, confidence: ${rebuilt.confidence}.`);
  }
  const bola = await testBola(target, schema, { program, field: args.field ?? "", ownId: args["own-id"] ?? "1", otherId: args["other-id"] ?? "2" });
  if (bola.error) { console.error(bola.error); return 2; }
  for (const c of bola.checks ?? []) console.log(`  - ${c.name}: ${c.result}`);
  const { added, total } = storeFindings(program, bola.findings ?? []);
  console.log(`GraphQL: ${total} temuan kandidat, ${added} baru masuk store.`);
  if (added > 0) console.log(`Lihat antrean: bounty review  |  bounty findings --program ${program.name}`);
  return 0;
}

function cmdCloud(args) {
  const tool = String(args.tool ?? "").toLowerCase();
  const target = args.target;
  const programPath = args.program || resolve(process.cwd(), "programs/example.md");
  if (!CLOUD_TOOLS.includes(tool) && tool !== "takeover") {
    console.error(`--tool wajib: takeover | ${CLOUD_TOOLS.join(" | ")} (dapat: "${tool || ""}")`);
    return 2;
  }
  if (!target) { console.error("--target wajib (domain / bucket / CNAME / URL)."); return 2; }
  if (!existsSync(programPath)) { console.error(`Program tidak ditemukan: ${programPath}`); return 2; }
  const program = loadProgramFile(programPath);
  let result;
  if (tool === "takeover") {
    // checkTakeover async (fetch body opsional) — tanpa fetch hanya kenali layanan.
    return checkTakeover(target, { program }).then((r) => {
      if (r.error) { console.error(r.error); return 2; }
      console.log(`CNAME ${target}: layanan ${r.service ?? "(tidak dikenal)"}, vulnerable: ${r.vulnerable}, claimable: ${r.claimable ?? "?"}.`);
      if (r.vulnerable) console.log("  VERIFIKASI MANUAL dulu sebelum melapor — fingerprint bukan bukti klaim.");
      return 0;
    });
  }
  if (tool === "cloud-enum") result = runCloudEnum(target, { program });
  else if (tool === "s3scanner") result = runS3Scanner(target, { program });
  else if (tool === "aws-s3-ls") result = runAwsS3Ls(target, { program });
  else result = runNucleiTakeovers(target, { program });
  if (result.error) { console.error(result.error); return 2; }
  if (result.skipped) { console.log(`Dilewati: ${result.reason}`); return 0; }
  const { added, total } = storeFindings(program, result.findings ?? []);
  console.log(`Cloud [${tool}]: ${total} temuan kandidat, ${added} baru masuk store.`);
  if (added > 0) console.log(`Lihat antrean: bounty review  |  bounty findings --program ${program.name}`);
  return 0;
}

async function cmdReverse(args) {
  const tool = String(args.tool ?? "").toLowerCase();
  const file = args.file;
  if (!["ghidra-mcp", "rea", "jadx"].includes(tool)) { console.error("--tool wajib: ghidra-mcp | rea | jadx"); return 2; }
  if (!file) { console.error("--file <path binary/APK> wajib."); return 2; }
  if (args.confirm !== true && args.confirm !== "true") {
    console.error("RE gated: tambahkan --confirm true — Anda memastikan file ini dalam scope program dan boleh dianalisis.");
    return 2;
  }
  let result;
  if (tool === "ghidra-mcp") result = await runGhidraMcp(file, { confirmed: true });
  else if (tool === "rea") result = runRea(file, { confirmed: true });
  else result = runJadxApk(file, { confirmed: true });
  if (result.error) { console.error(result.error); return 2; }
  if (result.skipped) { console.log(`Dilewati: ${result.reason}`); return 0; }
  const programName = args.program ? loadProgramFile(args.program).name : "reverse";
  const { added, total } = storeFindings({ name: programName }, result.findings ?? []);
  console.log(`RE [${tool}]: ${total} temuan kandidat, ${added} baru masuk store (nilai secret tidak pernah disimpan).`);
  if (added > 0) console.log(`Lihat antrean: bounty review  |  bounty findings --program ${programName}`);
  return 0;
}

async function cmdCaido(args) {
  // One-shot: start MCP -> list/replay -> stop. Read/replay saja.
  const session = await startCaidoMcp({ mcpPath: args["mcp-path"] ?? null, caidoUrl: args["caido-url"] ?? undefined });
  if (session.skipped) { console.log(`Dilewati: ${session.reason}`); return 0; }
  if (session.error) { console.error(session.error); return 2; }
  try {
    if (args.replay) {
      const r = await replayRequest(session, String(args.replay));
      if (r.error) { console.error(r.error); return 2; }
      console.log(`Replay #${args.replay}: HTTP ${r.status}`);
      console.log(String(r.bodyPreview ?? "").slice(0, 2000));
      return 0;
    }
    const list = await listRequests(session, { filter: args.filter ?? "", limit: Number(args.limit ?? 20) });
    if (list.error) { console.error(list.error); return 2; }
    console.log(`Caido: ${list.requests?.length ?? 0} request (tool: ${list.tool ?? "?"}).`);
    for (const q of list.requests ?? []) console.log(`  #${q.id} ${q.method} ${q.url} -> ${q.status ?? "?"}`);
    return 0;
  } finally { stopCaidoMcp(session); }
}

const FIRMWARE_TOOLS = ["binwalk-ng", "unblob", "cve-bin-tool"];
async function cmdFirmware(args) {
  const tool = String(args.tool ?? "").toLowerCase();
  const file = args.file || args.target;
  const programPath = args.program || resolve(process.cwd(), "programs/example.md");
  if (!FIRMWARE_TOOLS.includes(tool)) {
    console.error(`--tool wajib: ${FIRMWARE_TOOLS.join(" | ")} (dapat: "${tool || ""}")`);
    return 2;
  }
  if (!file) {
    console.error("--file wajib (path image firmware lokal).");
    return 2;
  }
  if (!existsSync(programPath)) {
    console.error(`Program tidak ditemukan: ${programPath}`);
    return 2;
  }
  const program = loadProgramFile(programPath);
  let result;
  if (tool === "binwalk-ng") result = runBinwalkNg(file, {});
  else if (tool === "unblob") result = runUnblob(file, {});
  else result = runCveBinTool(file, { sbomFile: args["sbom-file"] ?? null });
  if (result.skipped) {
    console.log(`Dilewati: ${tool} belum terinstal — lihat docs/firmware.md (scripts/install-tools.sh).`);
    return 0;
  }
  if (result.error) {
    console.error(`Error ${tool}: ${result.error}`);
    return 2;
  }
  console.log(`${tool}: ${result.findings?.length ?? 0} temuan (${result.duplicates ?? 0} duplikat dibuang).`);
  const stored = storeFindings(program, result.findings ?? []);
  console.log(`Disimpan ke bounty.db: ${stored.added} kandidat baru.`);
  if (stored.added > 0) console.log(`Lihat antrean: bounty review  |  bounty findings --program ${program.name}`);
  return 0;
}

function cmdPromptfooGate(args) {
  const resultsPath = args.results;
  if (!resultsPath) {
    console.error("--results <hasil promptfoo .json> wajib.");
    return 2;
  }
  const minPassRate = Number(args["min-pass-rate"] ?? 0.8);
  const results = readPromptfooResults(resultsPath);
  const gate = gateResults(results, { minPassRate });
  if (results.error) {
    console.log(`Promptfoo gate: GAGAL — ${results.error} (fail-closed, bukan lolos).`);
    return 1;
  }
  console.log(`Promptfoo gate: ${results.passed}/${results.total} lolos (${(results.passRate * 100).toFixed(0)}%, ambang ${(minPassRate * 100).toFixed(0)}%) — ${gate.pass ? "LOLOS" : "GAGAL"}.`);
  if (!gate.pass && results.failures?.length) {
    for (const f of results.failures.slice(0, 10)) console.log(`  - gagal: ${f.prompt} — ${f.assertion} (${f.reason})`);
  }
  return gate.pass ? 0 : 1;
}

function cmdGraphGate(args) {
  const baselinePath = args.baseline || resolve(process.cwd(), "eval/results/baseline.json");
  let baseline = null;
  if (existsSync(baselinePath)) {
    try { baseline = JSON.parse(readFileSync(baselinePath, "utf8")); } catch (e) {
      console.error(`baseline.json rusak: ${e.message}`);
      return 2;
    }
  }
  const stats = {};
  try {
    const store = new Store();
    try {
      const lessons = listLessons(store.db);
      const fpByClass = {};
      for (const l of lessons) {
        const outcome = String(l.outcome ?? l.verdict ?? "").toLowerCase();
        if (outcome === "false_positive" || outcome === "false-positive" || outcome === "fp") {
          fpByClass[String(l.vuln_class ?? l.skill ?? "")] = (fpByClass[String(l.vuln_class ?? l.skill ?? "")] ?? 0) + 1;
        }
      }
      stats.repeatedFpClasses = Object.values(fpByClass).filter((n) => n >= 3).length;
      stats.openCoverage = listCoverage(store.db).filter((c) => c.status === "open").length;
      const all = store.listCandidates(null, "candidate");
      stats.totalFindings = all.length;
      try {
        const row = store.db.prepare("SELECT COUNT(*) AS n FROM candidate c WHERE NOT EXISTS (SELECT 1 FROM evidence e WHERE e.finding_id = c.id)").get();
        stats.untracedFindings = Number(row?.n ?? 0);
      } catch { stats.untracedFindings = 0; }
    } finally { store.close(); }
  } catch { /* statistik opsional — gerbang tetap jalan tanpa baseline */ }
  const decision = decideGraphUpgrade({ baseline, stats });
  console.log(`Graph gate: ${decision.recommend === "upgrade" ? "UPGRADE" : "TETAP SQL"}`);
  console.log(decision.reason);
  for (const s of decision.signals) console.log(`  - ${s.name}: ${s.detail}`);
  return 0;
}

function cmdPatterns(args) {
  const patterns = loadPatterns();
  const cited = citedPatterns(patterns);
  const skill = args.skill ? String(args.skill) : "";
  if (skill) {
    const ev = patternEvidence(skill, "", patterns);
    console.log(`Pola untuk ${skill}: ${ev.total} total, ${ev.cited} bersitasi, ${ev.uncited} tanpa sitasi.`);
    for (const p of patterns.filter((x) => x.skill === skill && !x.uncited)) {
      console.log(`  - ${p.subclass} (${p.cwe ?? "-"}) — ${p.link}`);
    }
    return 0;
  }
  console.log(`Pustaka pola laporan: ${patterns.length} total, ${cited.length} bersitasi, ${patterns.length - cited.length} tanpa sitasi.`);
  const bySkill = {};
  for (const p of patterns) {
    bySkill[p.skill] ??= { total: 0, cited: 0 };
    bySkill[p.skill].total++;
    if (!p.uncited) bySkill[p.skill].cited++;
  }
  for (const [s, v] of Object.entries(bySkill).sort((a, b) => b[1].cited - a[1].cited)) {
    console.log(`  ${s}: ${v.cited}/${v.total} bersitasi`);
  }
  return 0;
}

function loadSkillsIndex() {
  const candidates = [
    resolve(SKILLS_DIR, "skills-index.json"),
    resolve(process.cwd(), "skills/bounty/skills-index.json"),
    resolve(REPO_ROOT, "skills/bounty/skills-index.json"),
  ];
  for (const p of candidates) {
    try { return JSON.parse(readFileSync(p, "utf8")); } catch { /* coba berikut */ }
  }
  return null;
}

function cmdSkills(args) {
  const index = loadSkillsIndex();
  if (!index) { console.error("skills-index.json tidak ditemukan."); return 2; }
  const name = args.skill ? String(args.skill) : "";
  if (name) {
    const entry = index.find((e) => e.name === name);
    if (!entry) { console.error(`Skill tidak ditemukan: ${name}`); return 2; }
    let text;
    try { text = readFileSync(resolve(SKILLS_DIR, entry.file), "utf8"); }
    catch { console.error(`File skill tidak bisa dibaca: ${entry.file}`); return 2; }
    process.stdout.write(text);
    if (!text.endsWith("\n")) console.log();
    return 0;
  }
  const rows = index.map((e) => [e.name, e.vuln_class || "-", e.cwe || "-"]);
  console.log(table(rows, ["Skill", "Kelas", "CWE"]));
  console.log(`Total: ${index.length} skill.`);
  return 0;
}

function cmdPlan(args) {
  const program = args.program ? String(args.program) : "";
  if (!program) { console.error("Pakai: bounty plan --program <nama> [--limit N] [--record <surface>]"); return 2; }
  const store = new Store();
  try {
    if (args.record) {
      const n = recordSurface(store.db, program, String(args.record));
      console.log(`Surface didaftarkan: ${args.record} (${n} baris coverage baru).`);
    }
    const sum = coverageSummary(store.db, program);
    console.log(summaryBox([
      `Coverage ${program}`,
      `Surface: ${sum.surfaces} | Diperiksa: ${sum.examined} | Terbuka: ${sum.open} | Dikesampingkan: ${sum.ruledOut}`,
      `Cakupan: ${sum.pct}%`,
    ], { title: "Rencana hunt" }));
    if (sum.surfaces === 0) {
      console.log(`Belum ada surface untuk program ${program}.`);
      console.log(`Daftarkan lewat: bounty plan --program ${program} --record <surface>`);
      console.log(`atau jalankan dulu: bounty run --program programs/${program}.md`);
      return 0;
    }
    const limit = Number(args.limit ?? 10);
    const plan = planNext(store.db, program, { limit: Number.isFinite(limit) ? limit : 10 });
    if (plan.length === 0) {
      console.log("Semua pasangan (surface, kelas) sudah diperiksa/dikesampingkan. Tidak ada rencana baru.");
      return 0;
    }
    const rows = plan.map((p) => [p.surface, p.vulnClass, p.reason]);
    console.log(table(rows, ["Surface", "Kelas", "Alasan"]));
    console.log(`Total: ${plan.length} pasangan (surface, kelas) — hunt yang belum tersentuh.`);
    console.log(`Lanjut hunt: bounty scan --tool nuclei --target <surface> --program programs/${program}.md`);
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
  console.log("  curl -sSL https://strix.ai/install | bash   # verifikasi URL resmi dulu sebelum menjalankan");
  console.log("  strix --version");
  console.log("");
  console.log("Catatan: wrapper memblokir pipe-to-shell otomatis (guard). Jalankan manual");
  console.log("setelah memverifikasi URL instalasi resmi Strix.");
  return 0;
}

function cmdUpdate(args) {
  const dir = findRepoDir({ source: args.source || args["source-dir"] || null });
  if (!dir) {
    console.error("Clone muse-bug-bounty tidak ditemukan.");
    console.error("Jalankan dari dalam folder clone, atau: bounty update --source ~/muse-bug-bounty");
    return 2;
  }
  if (args["dry-run"]) {
    const plan = runUpdate({ dir, dryRun: true });
    console.log(`Repo: ${plan.dir}`);
    console.log(`Versi saat ini: v${plan.from ?? "?"}`);
    if (plan.dirty.length > 0) {
      console.log(`Perubahan lokal (akan di-stash dulu, ${plan.dirty.length} file):`);
      plan.dirty.forEach((l) => console.log(`  ${l}`));
    }
    console.log("Rencana: git pull --ff-only, lalu npm install -g --ignore-scripts.");
    console.log("(dry-run: tidak ada yang diubah.)");
    return 0;
  }
  console.log(`Repo: ${dir}`);
  const before = runUpdate({ dir, dryRun: true });
  if (before.dirty.length > 0) {
    console.log(`Perubahan lokal terdeteksi (${before.dirty.length} file) — di-stash dulu, dikembalikan setelah pull.`);
  }
  console.log("Menarik update (git pull --ff-only)...");
  let result;
  try {
    result = runUpdate({ dir });
  } catch (e) {
    console.error(String(e.message || e));
    return 2;
  }
  if (result.stashed && result.stashRestored === false) {
    console.error("Catatan: stash tidak bisa dikembalikan otomatis (bentrok dengan update).");
    console.error(`Perubahan lokalmu aman di stash — pulihkan manual: git -C ${dir} stash pop`);
  }
  console.log(`Selesai: v${result.from ?? "?"} -> v${result.to ?? "?"} (global sudah diinstal ulang).`);
  console.log("Cek: bounty --version");
  return 0;
}

const COMMANDS = [
  "setup", "provider", "run", "view", "review", "programs", "findings", "memory",
  "graph", "trace", "report", "bench", "scan", "recon", "oast", "platform",
  "patterns", "skills", "plan", "dedup", "codesearch", "graphql", "cloud", "reverse", "caido",
  "firmware", "promptfoo-gate", "graph-gate", "install", "update",
];

// Jarak edit Levenshtein untuk saran "maksud Anda ...".
function editDistance(a, b) {
  const m = a.length, n = b.length;
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return d[m][n];
}

function suggestCommand(cmd) {
  const ranked = COMMANDS.map((c) => ({ c, d: editDistance(String(cmd), c) })).sort((a, b) => a.d - b.d);
  const best = ranked[0];
  return best && best.d <= Math.max(2, Math.floor(String(cmd).length / 2)) ? best.c : null;
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
    case "setup": return await cmdSetup(args);
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
    case "recon": return await cmdRecon(args);
    case "oast": return await cmdOast(args);
    case "platform": return await cmdPlatform(args);
    case "patterns": return cmdPatterns(args);
    case "skills": return cmdSkills(args);
    case "plan": return cmdPlan(args);
    case "dedup": return cmdDedup(args);
    case "codesearch": return cmdCodesearch(args);
    case "graphql": return await cmdGraphql(args);
    case "cloud": return await cmdCloud(args);
    case "reverse": return await cmdReverse(args);
    case "caido": return await cmdCaido(args);
    case "firmware": return await cmdFirmware(args);
    case "promptfoo-gate": return cmdPromptfooGate(args);
    case "graph-gate": return cmdGraphGate(args);
    case "install": return cmdInstall(args);
    case "update": return cmdUpdate(args);
    default: {
      console.error(`Perintah tidak dikenal: ${cmd}`);
      const hint = suggestCommand(cmd);
      if (hint) console.error(`Maksud Anda: bounty ${hint}?`);
      console.error(`\nPerintah tersedia: ${COMMANDS.join(", ")}.`);
      console.error("Jalankan 'bounty --help' untuk detail tiap perintah.");
      return 2;
    }
  }
}

// isMain harus tahan symlink (instal global npm: argv[1] = path symlink,
// import.meta.url = path asli) dan spasi di path (pathname URL = %20).
// resolve() saja tidak cukup: pakai realpathSync + fileURLToPath (decode %20).
let isMain = false;
try {
  isMain = !!process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
} catch {
  isMain = !!process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}
if (isMain) {
  main().then((code) => { process.exitCode = code; }).catch((e) => {
    console.error(e?.message ?? e);
    process.exitCode = 2;
  });
}
