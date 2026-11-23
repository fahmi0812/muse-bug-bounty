// eval/dvlaa-export.mjs — ubah temuan bounty/Strix menjadi findings.jsonl
// untuk eval DVLAA (Tcotl/DVLAA).
//
// JUJUR (best-effort): DVLAA adalah training range, BUKAN benchmark
// harness — README upstream (dibaca 23 Nov 2026) tidak mendefinisikan
// format pengiriman temuan agen, runner eval otomatis, atau scorer.
// Satu-satunya hasil yang diakui DVLAA adalah Flag per tantangan yang
// disubmit lewat UI web. Jadi file ini memakai field kompatibel
// EthiBench (title/description/steps/cwe/severity/url — lihat
// eval/ethibench-export.mjs, kontrak inputnya sama) ditambah field
// `challenge`: petunjuk tantangan DVLAA yang relevan (LLM01..LLM10,
// ASI01..ASI10, AWDP05/AWDP07/AWDP09). `challenge` adalah petunjuk
// pemetaan kelas vuln -> tantangan; penilai (manusia/LLM-judge) yang
// memutuskan apakah temuan itu benar menjawab tantangannya.
// Layout: <out>/run_<n>/<target>/findings.jsonl (sama seperti EthiBench).
// Cara pakai:
//   node eval/dvlaa-export.mjs --in findings.json --target dvlaa --run 1 --out eval/results/dvlaa
// Input: JSON array temuan [{vulnClass|title, endpoint|url, cwe, severity,
// description, steps, program}]. Bila description/steps kosong, dibuat
// dari field yang ada — jangan kirim baris kosong.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

// Pemetaan kelas vuln -> tantangan DVLAA (petunjuk, bukan klaim).
// LLM01-10 = OWASP LLM Top 10 2026; ASI01-10 = OWASP Agentic Top 10
// 2026; AWDP = soal yang README DVLAA petakan ke CVE publik
// (AWDP05 Flowise auth bypass CVE-2024-8181, AWDP07 Open WebUI blind
// SSRF CVE-2024-30256, AWDP09 RAGFlow IDOR CVE-2025-25282).
const CLASS_TO_CHALLENGE = [
  [["prompt injection"], "LLM01"],
  [["sensitive information disclosure", "sensitive data exposure"], "LLM02"],
  [["excessive agency", "over-permissioned tool"], "LLM03"],
  [["supply chain", "dependency confusion", "typosquat"], "LLM04"],
  [["data poisoning", "model poisoning", "rag poisoning", "backdoor"], "LLM05"],
  [["unbounded consumption", "denial of service", "dos", "resource exhaustion"], "LLM06"],
  [["misinformation", "hallucination", "sycophancy"], "LLM07"],
  [["hidden context", "system prompt leak", "system prompt extraction"], "LLM08"],
  [["vector", "embedding weakness", "retrieval"], "LLM09"],
  [["improper output handling", "output handling"], "LLM10"],
  [["agent goal hijack", "goal hijack"], "ASI01"],
  [["tool misuse", "tool abuse", "confused deputy"], "ASI02"],
  [["identity abuse", "privilege abuse"], "ASI03"],
  [["agentic supply chain"], "ASI04"],
  [["unexpected code execution", "remote code execution", "rce", "code injection"], "ASI05"],
  [["memory poisoning", "context poisoning"], "ASI06"],
  [["inter-agent communication"], "ASI07"],
  [["cascading failure"], "ASI08"],
  [["human-agent trust"], "ASI09"],
  [["rogue agent"], "ASI10"],
  [["server-side request forgery", "ssrf"], "AWDP07"],
  [["broken object level authorization", "idor", "bola"], "AWDP09"],
  [["authentication bypass", "auth bypass"], "AWDP05"],
];

export function challengeFor(f = {}) {
  const text = `${f.vulnClass ?? f.vuln_class ?? ""} ${f.title ?? ""}`.toLowerCase();
  for (const [keys, challenge] of CLASS_TO_CHALLENGE) {
    if (keys.some((k) => text.includes(k))) return challenge;
  }
  return undefined;
}

export function toFindingLine(f = {}) {
  const title = String(f.title ?? f.vulnClass ?? f.vuln_class ?? "Unknown finding").trim();
  const url = String(f.url ?? f.endpoint ?? "").trim();
  const cwe = String(f.cwe ?? "").trim() || undefined;
  const severityRaw = String(f.severity ?? "medium").toLowerCase().trim();
  const severity = SEVERITY_ORDER.includes(severityRaw) ? severityRaw : "medium";
  const description = String(
    f.description ??
      `${title} di ${url || "target"}. Kelas: ${title}${cwe ? ` (${cwe})` : ""}.`
  ).trim();
  const steps = String(
    f.steps ??
      `1. Buka ${url || "target"}\n2. Amati perilaku ${title.toLowerCase()}\n3. Bandingkan dengan perilaku normal (akun test).`
  ).trim();
  const challenge = f.challenge ?? challengeFor(f);
  const line = { title, description, steps, severity };
  if (cwe) line.cwe = cwe;
  if (url) line.url = url;
  if (challenge) line.challenge = challenge;
  return line;
}

export function exportFindings(findings = [], { target, run = 1, outDir }) {
  if (!target) throw new Error("--target wajib (mis. dvlaa)");
  if (!outDir) throw new Error("--out wajib (direktori eksperimen)");
  const list = Array.isArray(findings) ? findings : [];
  const dir = join(outDir, `run_${run}`, target);
  mkdirSync(dir, { recursive: true });
  const lines = list.map((f) => JSON.stringify(toFindingLine(f))).join("\n");
  const file = join(dir, "findings.jsonl");
  writeFileSync(file, lines.length ? lines + "\n" : "");
  return { file, count: list.length, target, run };
}

export function main(argv = process.argv.slice(2)) {
  const arg = (name, def = undefined) => {
    const hit = argv.find((a) => a.startsWith(`--${name}=`));
    return hit ? hit.split("=")[1] : def;
  };
  const inFile = arg("in");
  const target = arg("target");
  const run = Number(arg("run", "1"));
  const outDir = arg("out", join("eval", "results", "dvlaa"));
  if (!inFile || !target) {
    console.error("Pakai: node eval/dvlaa-export.mjs --in findings.json --target dvlaa [--run 1] [--out eval/results/dvlaa]");
    return 2;
  }
  const findings = JSON.parse(readFileSync(inFile, "utf8"));
  const res = exportFindings(findings, { target, run, outDir });
  console.log(`Ditulis ${res.count} temuan -> ${res.file}`);
  console.log("Lanjut di laptop: mainkan tantangan DVLAA (lihat eval/benchmarks/dvlaa.md), kumpulkan Flag, lalu nilai temuan per tantangan.");
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main());
export default { toFindingLine, exportFindings, challengeFor, main };
