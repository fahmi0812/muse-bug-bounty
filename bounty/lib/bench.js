// bounty/lib/bench.js — scoring + benchmark runner.
import { routeSkills, loadSkillsIndex } from "./router.js";

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

// --- Akurasi router (plan v3.1 perbaikan #7) ---
// Untuk tiap entri oracle, route top-5 skill dari konteks
// "<vuln_class> <endpoint> <cwe>" lalu cek apakah skill hunt yang
// sesuai ada di top-5. Skor = hit rate. Bukan latensi (ms) — latensi
// tidak membuktikan router memilih skill yang benar.
const CLASS_TO_SKILL = {
  "sql injection": "hunt-sqli",
  "cross-site scripting": "hunt-xss",
  "reflected xss": "hunt-xss",
  "stored xss": "hunt-xss",
  "dom xss": "hunt-dom",
  "server-side request forgery": "hunt-ssrf",
  ssrf: "hunt-ssrf",
  "insecure direct object reference": "hunt-idor",
  idor: "hunt-idor",
  "broken object level authorization": "hunt-api-bola",
  bola: "hunt-api-bola",
  "broken access control": "hunt-broken-access",
  "authentication bypass": "hunt-auth-bypass",
  "broken authentication": "hunt-auth-bypass",
  jwt: "hunt-jwt",
  "cross-site request forgery": "hunt-csrf",
  csrf: "hunt-csrf",
  "path traversal": "hunt-path-traversal",
  "directory traversal": "hunt-path-traversal",
  "open redirect": "hunt-open-redirect",
  "unrestricted file upload": "hunt-file-upload",
  "remote code execution": "hunt-rce",
  "command injection": "hunt-rce",
  "server-side template injection": "hunt-ssti",
  ssti: "hunt-ssti",
  "xml external entity": "hunt-xxe",
  xxe: "hunt-xxe",
  "insecure deserialization": "hunt-deserialization",
  "prototype pollution": "hunt-prototype-pollution",
  "race condition": "hunt-race-condition",
  "graphql": "hunt-graphql",
  "prompt injection": "hunt-llm-ai",
  "indirect prompt injection": "hunt-llm-ai",
  "sensitive data exfiltration": "hunt-llm-ai",
  "excessive agency": "hunt-llm-ai",
  "rag data leakage": "hunt-llm-ai",
  "system prompt leakage": "hunt-llm-ai",
  llm: "hunt-llm-ai",
  "exposed secrets": "hunt-secrets",
  "business logic": "hunt-business-logic",
};

const GENERIC_WORDS = new Set(["broken", "missing", "weak", "sensitive", "unrestricted", "via", "the", "and", "or", "of", "in", "on", "a", "an", "data", "exposure"]);

export function expectedSkillFor(vulnClass = "") {
  const lower = String(vulnClass).toLowerCase().trim();
  if (CLASS_TO_SKILL[lower]) return CLASS_TO_SKILL[lower];
  // Kelas oracle sering majemuk: "<spesifik> / <umum>" (mis.
  // "JWT / Broken Authentication"). Segmen pertama adalah yang paling
  // spesifik — cek itu dulu, baru seluruh string.
  const first = lower.split("/")[0].trim();
  if (CLASS_TO_SKILL[first]) return CLASS_TO_SKILL[first];
  for (const [key, skill] of Object.entries(CLASS_TO_SKILL)) {
    if (first.includes(key)) return skill;
  }
  for (const [key, skill] of Object.entries(CLASS_TO_SKILL)) {
    if (lower.includes(key)) return skill;
  }
  // Fallback: token khas pertama -> hunt-<token> (mis. "nosql injection" -> hunt-nosql).
  const tokens = lower.split(/[^a-z0-9]+/).filter((t) => t.length > 2 && !GENERIC_WORDS.has(t));
  return tokens.length ? `hunt-${tokens[0]}` : "triage-generic";
}

// Skill pengganti yang sah untuk satu kelas: mis. JWT bisa dijawab
// hunt-jwt maupun hunt-jwt-crypto (perdalamannya). Metrik hit bila
// salah satunya ada di top-5 — bukan regresi bila skill yang lebih
// dalam yang terpilih.
const SKILL_ALTERNATIVES = {
  "hunt-jwt": ["hunt-jwt-crypto"],
  "hunt-llm-prompt-injection": ["hunt-llm-ai"],
  "hunt-xss": ["hunt-dom"],
};

export function routerAccuracy(oracle = [], routeFn = null, skills = null) {
  const router = routeFn ?? ((ctx) => routeSkills(ctx, skills ?? loadSkillsIndex()));
  const perEntry = [];
  let hit = 0;
  for (const v of oracle ?? []) {
    const vulnClass = String(v.vuln_class ?? v.vulnClass ?? "");
    const context = `${vulnClass} ${v.endpoint ?? v.path ?? ""} ${v.cwe ?? ""}`.trim();
    const selected = router(context).map((s) => String(s?.name ?? s).toLowerCase());
    const expected = expectedSkillFor(vulnClass);
    const isHit = selected.includes(expected) || (SKILL_ALTERNATIVES[expected] ?? []).some((a) => selected.includes(a));
    if (isHit) hit += 1;
    perEntry.push({ endpoint: v.endpoint ?? v.path ?? "", vuln_class: vulnClass, expected, selected, hit: isHit });
  }
  const total = perEntry.length;
  return { hit, total, accuracy: total === 0 ? 0 : hit / total, perEntry };
}

export default { scoreFindings, median, runBench, routerAccuracy, expectedSkillFor };
