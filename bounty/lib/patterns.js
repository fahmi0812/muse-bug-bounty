// bounty/lib/patterns.js — pola laporan sebagai DATA terstruktur (v1.2, 2.6).
// Bukan prose: tiap pola {skill, subclass, cwe, cve, h1_report_id, tahun,
// payout, uncited, link} (+ vuln_class untuk pencocokan bukti).
// ATURAN JUJUR: h1_report_id/link/cve/tahun/payout HANYA diisi bila laporan
// HackerOne/CVE itu nyata dan dikenal dari riset; bila tidak yakin, isi
// null dan uncited=true. Jangan pernah mengarang ID laporan, CVE, tahun,
// atau payout. Seed v1.2 berisi 12 pola (8 skill Tier 1 + sqli/xss/idor/
// ssrf), semuanya uncited — pola bersitasi ditambahkan belakangan hanya
// dari laporan yang terverifikasi.
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const REQUIRED = ["skill", "subclass", "cwe", "cve", "h1_report_id", "tahun", "payout", "uncited", "link"];

export function validatePattern(p) {
  if (!p || typeof p !== "object") throw new Error("pola harus berupa object");
  for (const f of REQUIRED) {
    if (!(f in p)) throw new Error(`pola kehilangan field wajib: ${f}`);
  }
  if (typeof p.skill !== "string" || !p.skill) throw new Error("pola.skill harus string tak kosong");
  if (typeof p.subclass !== "string" || !p.subclass) throw new Error("pola.subclass harus string tak kosong");
  if (typeof p.cwe !== "string" || !/^CWE-\d+$/.test(p.cwe)) throw new Error(`pola.cwe tidak valid: ${p.cwe}`);
  if (typeof p.uncited !== "boolean") throw new Error("pola.uncited harus boolean");
  // Konsistensi sitasi: tanpa h1_report_id -> wajib uncited; dengan
  // h1_report_id -> wajib bersitasi (uncited=false) + link.
  if (p.h1_report_id == null && p.uncited !== true) {
    throw new Error(`pola ${p.skill}/${p.subclass}: tanpa h1_report_id harus uncited=true`);
  }
  if (p.h1_report_id != null) {
    if (p.uncited !== false) throw new Error(`pola ${p.skill}/${p.subclass}: ada h1_report_id tapi uncited=true`);
    if (!p.link) throw new Error(`pola ${p.skill}/${p.subclass}: ada h1_report_id tapi tanpa link`);
  }
  // Tidak ada payout tanpa tahun (payout tanpa konteks waktu = klaim kosong).
  if (p.payout != null && p.tahun == null) {
    throw new Error(`pola ${p.skill}/${p.subclass}: payout tanpa tahun`);
  }
  return true;
}

export function loadPatterns() {
  const candidates = [
    resolve(__dirname, "../data/report-patterns.json"),
    resolve(process.cwd(), "bounty/data/report-patterns.json"),
    resolve(process.cwd(), "data/report-patterns.json"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      try {
        const data = JSON.parse(readFileSync(p, "utf8"));
        const list = Array.isArray(data) ? data : data.patterns ?? [];
        for (const pat of list) validatePattern(pat);
        return list;
      } catch (e) {
        if (e.message.startsWith("pola ")) throw e;
        return [];
      }
    }
  }
  return [];
}

export function patternsForSkill(skill, patterns = null) {
  const list = patterns ?? loadPatterns();
  return list.filter((p) => p?.skill === skill);
}

function normClass(v) {
  return String(v ?? "").trim().toLowerCase();
}

// Bukti untuk router: berapa pola BERSITASI vs uncited untuk satu skill
// (dan vuln_class bila diberikan). Hanya pola bersitasi yang dihitung
// sebagai bukti oleh router; pola uncited = 0 bukti.
export function patternEvidence(skill, vulnClass = "", patterns = null) {
  const list = patternsForSkill(skill, patterns);
  const wanted = normClass(vulnClass);
  const scoped = wanted
    ? list.filter((p) => !p.vuln_class || normClass(p.vuln_class) === wanted)
    : list;
  let cited = 0;
  let uncited = 0;
  for (const p of scoped) {
    if (p.uncited === false && (p.h1_report_id || p.link)) cited += 1;
    else uncited += 1;
  }
  return { skill, vulnClass: vulnClass || "", cited, uncited, total: cited + uncited };
}

export default { loadPatterns, validatePattern, patternsForSkill, patternEvidence };
