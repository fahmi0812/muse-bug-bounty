// bounty/lib/strix-output.js — parse output Strix (stdout) menjadi kandidat
// store + biaya. Strix tidak menjamin satu format output, jadi parser ini
// toleran: JSON array, JSONL, lalu Markdown/teks bebas.
// Aturan: tidak ada temuan yang dijamin — hasil parse selalu berstatus
// "candidate" (UNVERIFIED) sampai reviewer menyetujui di `bounty review`.
// Biaya: dicari pola $X.XX / "cost: $X" / "total cost $X" di output.
import { canonicalKey } from "./dedup.js";

export const VULN_CLASSES = [
  ["sql injection", "SQL Injection", "CWE-89"],
  ["sqli", "SQL Injection", "CWE-89"],
  ["cross-site scripting", "Cross-Site Scripting (XSS)", "CWE-79"],
  ["xss", "Cross-Site Scripting (XSS)", "CWE-79"],
  ["ssrf", "Server-Side Request Forgery (SSRF)", "CWE-918"],
  ["server-side request forgery", "Server-Side Request Forgery (SSRF)", "CWE-918"],
  ["idor", "Insecure Direct Object Reference (IDOR)", "CWE-639"],
  ["broken object level authorization", "Broken Object Level Authorization (BOLA)", "CWE-862"],
  ["bola", "Broken Object Level Authorization (BOLA)", "CWE-862"],
  ["broken access control", "Broken Access Control", "CWE-862"],
  ["auth bypass", "Authentication Bypass", "CWE-287"],
  ["broken authentication", "Broken Authentication", "CWE-287"],
  ["jwt", "JWT Vulnerability", "CWE-287"],
  ["csrf", "Cross-Site Request Forgery (CSRF)", "CWE-352"],
  ["open redirect", "Open Redirect", "CWE-601"],
  ["path traversal", "Path Traversal", "CWE-22"],
  ["directory traversal", "Path Traversal", "CWE-22"],
  ["file upload", "Unrestricted File Upload", "CWE-434"],
  ["rce", "Remote Code Execution (RCE)", "CWE-78"],
  ["remote code execution", "Remote Code Execution (RCE)", "CWE-78"],
  ["command injection", "Command Injection", "CWE-78"],
  ["ssti", "Server-Side Template Injection (SSTI)", "CWE-94"],
  ["template injection", "Server-Side Template Injection (SSTI)", "CWE-94"],
  ["xxe", "XML External Entity (XXE)", "CWE-611"],
  ["xml external entity", "XML External Entity (XXE)", "CWE-611"],
  ["deserialization", "Insecure Deserialization", "CWE-502"],
  ["prototype pollution", "Prototype Pollution", "CWE-1321"],
  ["race condition", "Race Condition", "CWE-362"],
  ["graphql", "GraphQL Vulnerability", "CWE-200"],
  ["prompt injection", "Prompt Injection", "CWE-74"],
  ["secrets", "Exposed Secrets", "CWE-200"],
  ["business logic", "Business Logic Flaw", "CWE-840"],
];

export function classifyVuln(text = "") {
  const lower = String(text).toLowerCase();
  for (const [kw, vulnClass, cwe] of VULN_CLASSES) {
    if (lower.includes(kw)) return { vulnClass, cwe };
  }
  return null;
}

export function parseCost(text = "") {
  const patterns = [
    /(?:total\s+)?cost[:\s]+\$?\s*(\d+(?:\.\d{1,4})?)/i,
    /\$(\d+(?:\.\d{1,4})?)\s*(?:usd|spent|used)?/i,
  ];
  for (const re of patterns) {
    const m = String(text).match(re);
    if (m) {
      const v = Number(m[1]);
      if (Number.isFinite(v) && v >= 0 && v < 10000) return v;
    }
  }
  return 0;
}

function normFinding(raw) {
  const endpoint = String(raw.endpoint ?? raw.path ?? raw.url ?? "").trim();
  if (!endpoint) return null;
  const vulnClass = String(raw.vuln_class ?? raw.vulnClass ?? raw.vulnerability ?? raw.class ?? "").trim();
  const cwe = String(raw.cwe ?? "").trim().toUpperCase();
  // Kanonikalisasi: "auth bypass" -> "Authentication Bypass", dst.
  const canonical = vulnClass ? classifyVuln(vulnClass) : null;
  const classified = canonical ?? classifyVuln(`${raw.title ?? ""} ${raw.description ?? ""} ${endpoint}`);
  return {
    endpoint: endpoint.replace(/^https?:\/\/[^/]+/i, "") || "/",
    method: String(raw.method ?? "GET").toUpperCase(),
    param: String(raw.param ?? raw.parameter ?? "").trim(),
    vulnClass: canonical?.vulnClass || vulnClass || classified?.vulnClass || "Unclassified Finding",
    cwe: cwe || canonical?.cwe || classified?.cwe || "",
    severity: String(raw.severity ?? "medium").toLowerCase(),
    evidence: String(raw.evidence ?? raw.proof ?? raw.description ?? "").slice(0, 2000),
  };
}

function tryJson(text) {
  const out = [];
  // JSON array utuh
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) {
      for (const item of parsed) { const f = normFinding(item); if (f) out.push(f); }
      if (out.length) return out;
    } else if (parsed && typeof parsed === "object") {
      const arr = parsed.findings ?? parsed.results ?? parsed.vulnerabilities ?? [];
      for (const item of arr) { const f = normFinding(item); if (f) out.push(f); }
      if (out.length) return out;
    }
  } catch {}
  // JSONL: satu objek / satu array per baris
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{") && !t.startsWith("[")) continue;
    try {
      const parsed = JSON.parse(t);
      if (Array.isArray(parsed)) {
        for (const item of parsed) { const f = normFinding(item); if (f) out.push(f); }
      } else {
        const f = normFinding(parsed);
        if (f) out.push(f);
      }
    } catch {}
  }
  return out;
}

function tryMarkdown(text) {
  const out = [];
  // Heading "## [XSS] /api/search?param=q" atau "### SQL Injection — /rest/..."
  const re = /^#{1,4}\s*(?:\[([^\]]+)\]\s*)?(.{3,120})$/gm;
  for (const m of String(text).matchAll(re)) {
    const head = `${m[1] ?? ""} ${m[2]}`.trim();
    const pathMatch = head.match(/(\/[A-Za-z0-9\-_./?=&%#]+)/);
    if (!pathMatch) continue;
    const classified = classifyVuln(head);
    if (!classified && !m[1]) continue;
    out.push({
      endpoint: pathMatch[1],
      method: /post/i.test(head) ? "POST" : "GET",
      param: "",
      vulnClass: m[1]?.trim() || classified?.vulnClass || "Unclassified Finding",
      cwe: classified?.cwe || "",
      severity: "medium",
      evidence: head.slice(0, 500),
    });
  }
  return out;
}

export function parseStrixOutput(text = "", program = "") {
  const found = [...tryJson(text), ...tryMarkdown(text)];
  // Dedup internal (endpoint+method+param+kelas+CWE) sebelum masuk store.
  const seen = new Set();
  const unique = [];
  for (const f of found) {
    const key = canonicalKey({ endpoint: f.endpoint, method: f.method, param: f.param, vulnClass: f.vulnClass, cwe: f.cwe });
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push({ ...f, program });
  }
  return { findings: unique, usd: parseCost(text) };
}

export default { parseStrixOutput, parseCost, classifyVuln };
