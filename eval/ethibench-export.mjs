// eval/ethibench-export.mjs — ubah temuan bounty/Strix menjadi findings.jsonl
// format EthiBench (ethiack/ethibench, MIT): satu baris JSON per temuan,
// field yang dipakai LLM matcher: title, description, steps (paling penting),
// plus cwe, severity, url (opsional tapi dianjurkan).
// Layout eksperimen EthiBench:
//   <out>/run_<n>/<target>/findings.jsonl
// Cara pakai:
//   node eval/ethibench-export.mjs --in findings.json --target vuln-bank --run 1 --out eval/results/ethibench
// Input: JSON array temuan [{vulnClass|title, endpoint|url, cwe, severity,
// description, steps, program}]. Bila description/steps kosong, dibuat
// dari field yang ada (judul + endpoint + kelas) — matcher butuh teks,
// jadi jangan kirim baris kosong.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

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
  const line = { title, description, steps, severity };
  if (cwe) line.cwe = cwe;
  if (url) line.url = url;
  return line;
}

export function exportFindings(findings = [], { target, run = 1, outDir }) {
  if (!target) throw new Error("--target wajib (vuln-bank | paygoat | xben-090)");
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
  const outDir = arg("out", join("eval", "results", "ethibench"));
  if (!inFile || !target) {
    console.error("Pakai: node eval/ethibench-export.mjs --in findings.json --target vuln-bank|paygoat|xben-090 [--run 1] [--out eval/results/ethibench]");
    return 2;
  }
  const findings = JSON.parse(readFileSync(inFile, "utf8"));
  const res = exportFindings(findings, { target, run, outDir });
  console.log(`Ditulis ${res.count} temuan -> ${res.file}`);
  console.log("Lanjut di laptop: ethibench evaluate <out> --dataset <ethibench>/examples/dataset.yaml");
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main());
export default { toFindingLine, exportFindings, main };
