// bounty/lib/failon.js — --fail-on ala Strix: exit code bila temuan
// mencapai ambang severity. Severity di sini HEURISTIK dari kelas vuln
// (bukan penilaian CVSS) — dipetakan dari nama kelas + CWE; kelas yang
// tidak dikenal = medium. Dipakai `bounty run --fail-on high|critical`
// (exit 3 bila terpicu) dan `bounty review` di masa depan.
const SEVERITY_ORDER = ["low", "medium", "high", "critical"];

const CLASS_SEVERITY = [
  [["remote code execution", "rce"], "critical"],
  [["authentication bypass", "auth bypass", "account takeover", "ato"], "critical"],
  [["sql injection", "sqli"], "high"],
  [["server-side request forgery", "ssrf"], "high"],
  [["broken object level authorization", "idor", "bola"], "high"],
  [["cross-site scripting", "xss"], "high"],
  [["server-side template injection", "ssti"], "high"],
  [["xml external entity", "xxe"], "high"],
  [["local file inclusion", "lfi"], "high"],
  [["deserialization"], "high"],
  [["command injection"], "high"],
  [["path traversal"], "high"],
  [["cross-site request forgery", "csrf"], "medium"],
  [["open redirect"], "medium"],
  [["sensitive data exposure", "information disclosure"], "medium"],
  [["security misconfiguration"], "medium"],
  [["broken access control"], "high"],
  [["jwt", "session fixation", "session"], "medium"],
  [["oauth"], "medium"],
  [["cors"], "low"],
  [["subdomain takeover"], "high"],
  [["public cloud storage"], "high"],
  [["hardcoded secret", "exposed secret"], "high"],
  [["weak crypto"], "medium"],
  [["crawled endpoint", "hidden endpoint", "subdomain", "enumeration"], "low"],
];

export function severityFor(finding = {}) {
  const text = `${finding.vulnClass ?? finding.vuln_class ?? ""} ${finding.cwe ?? ""}`.toLowerCase();
  for (const [keys, sev] of CLASS_SEVERITY) {
    if (keys.some((k) => text.includes(k))) return sev;
  }
  return "medium";
}

export function meetsThreshold(severity, failOn) {
  const s = String(severity ?? "medium").toLowerCase();
  const f = String(failOn ?? "").toLowerCase();
  if (!SEVERITY_ORDER.includes(f)) return false;
  return SEVERITY_ORDER.indexOf(s) >= SEVERITY_ORDER.indexOf(f);
}

export function checkFailOn(findings = [], failOn = "") {
  if (!failOn) return { triggered: false, failOn, worst: null, count: 0 };
  const scored = findings.map((f) => ({ ...f, severity: severityFor(f) }));
  const hit = scored.filter((f) => meetsThreshold(f.severity, failOn));
  const worst = hit.length
    ? hit.reduce((a, b) => (SEVERITY_ORDER.indexOf(a.severity) >= SEVERITY_ORDER.indexOf(b.severity) ? a : b)).severity
    : null;
  return { triggered: hit.length > 0, failOn, worst, count: hit.length, findings: hit };
}

export default { severityFor, meetsThreshold, checkFailOn, SEVERITY_ORDER };
