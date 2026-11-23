// bounty/lib/sarif.js — Baca findings.sarif Strix (v1.3, 3.6).
// JANGAN bangun generator SARIF sendiri — Strix sudah menulis
// findings.sarif (SARIF 2.1.0). Modul ini hanya membaca:
// runs[].results[] -> [{endpoint, method, param, vulnClass, cwe,
// severity, evidence}]. ruleId dipetakan ke kelas via classifyVuln
// (strix-output.js); lokasi dari
// locations[].physicalLocation.artifactLocation.uri.
import { readFileSync } from "node:fs";
import { classifyVuln } from "./strix-output.js";

function resultToFinding(r = {}) {
  const ruleId = String(r.ruleId ?? r.rule?.id ?? "");
  const message = String(r.message?.text ?? "");
  const classified = classifyVuln(`${ruleId} ${message}`);
  const loc = r.locations?.[0]?.physicalLocation;
  const uri = String(loc?.artifactLocation?.uri ?? "");
  const region = loc?.region ?? {};
  const level = String(r.level ?? "warning").toLowerCase();
  const severity = level === "error" ? "high" : level === "warning" ? "medium" : "low";
  return {
    endpoint: uri,
    method: "GET",
    param: "",
    vulnClass: classified?.vulnClass ?? ruleId ?? "Unclassified Finding",
    cwe: classified?.cwe ?? "",
    severity,
    evidence: [
      message,
      region.startLine ? `line ${region.startLine}` : "",
      r.rule?.id ? `rule: ${r.rule.id}` : "",
    ].filter(Boolean).join(" | ").slice(0, 500),
  };
}

// pathOrObj: path file .sarif ATAU objek SARIF yang sudah diparse.
export function readSarif(pathOrObj) {
  const sarif = typeof pathOrObj === "string"
    ? JSON.parse(readFileSync(pathOrObj, "utf8"))
    : pathOrObj;
  if (!sarif || typeof sarif !== "object" || !Array.isArray(sarif.runs)) return [];
  const out = [];
  for (const run of sarif.runs) {
    if (!Array.isArray(run.results)) continue;
    for (const r of run.results) out.push(resultToFinding(r));
  }
  return out;
}

export default { readSarif };
