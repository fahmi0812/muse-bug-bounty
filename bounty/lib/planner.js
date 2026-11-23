// bounty/lib/planner.js — Planner berbasis coverage ala ARTEX (v1.10).
// Ringan: hanya SQLite, zero-dep, TANPA Postgres/Neo4j, TANPA dependensi baru.
// Ide yang diambil dari ARTEX (AGPL — hanya idenya, bukan kodenya):
// peta permukaan dulu (surface x kelas vuln), lalu rencanakan hunt ke
// pasangan (surface, kelas) yang masih 'open', dengan noise governor
// (max 3 kelas per surface) supaya satu surface tidak dibanjiri.
//
// Universe kelas: semua vuln_class unik dari skills/bounty/skills-index.json
// (89 entri, dibaca 23 Nov 2026) KECUALI 14 skill meta/metodologi yang
// bukan kelas vuln dan tidak bisa "di-hunt" di sebuah endpoint:
//   "Attack Surface Mapping", "Audit Context Building", "Audit Review",
//   "Evidence Hygiene", "Ghostsecurity Loop", "JS Bundle Analysis",
//   "Methodology", "Navigation", "PR Security Review", "Reporting",
//   "SQL Injection Wordlist", "Triage", "Verification", "White-box Tracing".
// Hasilnya 72 kelas. Bila index bertambah, tambah kelas baru di sini
// (hardcode sengaja — planner tidak membaca file saat runtime).
//
// Status per (surface, kelas):
// - 'examined': ada candidate/finding kelas itu di surface itu, ATAU ada
//   baris memory_coverage status examined. Bukti temuan menang atas baris
//   ruled_out yang kedaluwarsa (kelas yang sudah ada temuannya = sudah
//   diperiksa, apa pun status catatannya).
// - 'ruled_out': ada baris memory_coverage status ruled_out (dan tidak ada
//   candidate kelas itu di surface itu).
// - 'open': sisanya — belum pernah diperiksa, kandidat rencana hunt.
// Kelas di candidate/coverage yang tidak ada di SURFACE_CLASSES tetap
// muncul di peta (union) supaya tidak ada bukti yang hilang diam-diam.

import { recordCoverage, listCoverage } from "./memory.js";

// Semua vuln_class unik dari skills-index.json minus 14 skill meta
// (lihat header). Urutan abjad (sort default JS).
export const SURFACE_CLASSES = [
  "AI Code Vulnerabilities (21 types)",
  "API Misconfiguration",
  "ASP.NET Misconfiguration",
  "Account Takeover",
  "Agentic AI Vulnerability",
  "Authentication Bypass",
  "Broken Access Control",
  "Broken Object Level Authorization (API)",
  "Business Logic Flaw",
  "CI/CD Pipeline Abuse",
  "CORS Misconfiguration",
  "Clickjacking",
  "Cloud IAM Privilege Escalation",
  "Cloud Misconfiguration",
  "Cross-Site Request Forgery",
  "Cross-Site Scripting",
  "DOM Cross-Site Scripting",
  "Entra ID / M365 Misconfiguration",
  "Error Message Disclosure",
  "Exposed Secrets",
  "Fintech GraphQL Logic Flaw",
  "GraphQL Abuse",
  "HTML Injection",
  "HTTP Request Smuggling",
  "Host Header Injection",
  "Insecure Defaults",
  "Insecure Deserialization",
  "Insecure Direct Object Reference",
  "JS Bundle Exposure",
  "JWT Authentication Bypass",
  "JWT Weakness",
  "Kubernetes Misconfiguration",
  "LDAP Injection",
  "LLM Prompt Injection",
  "LLM Top 10 2026",
  "Laravel Debug Exposure",
  "Local File Inclusion",
  "MFA Bypass",
  "Missing Brute-Force Protection",
  "Missing CAPTCHA Enforcement",
  "NTLM Information Disclosure",
  "Next.js Misconfiguration",
  "NoSQL Injection",
  "Node.js Application Weakness",
  "OAuth Flaws",
  "Okta Identity Misconfiguration",
  "Open Redirect",
  "Password Recovery",
  "Path Traversal",
  "Prototype Pollution",
  "RAG/Vector DB Exposure",
  "Race Condition",
  "Remote Code Execution",
  "SAML Flaws",
  "SPA API Exposure",
  "SQL Injection",
  "SSL-VPN Vulnerability Chain",
  "Server-Side Request Forgery",
  "Server-Side Template Injection",
  "Session Management",
  "Shadow API",
  "SharePoint Vulnerability Chain",
  "Source Code Disclosure",
  "Spring Boot Actuator Exposure",
  "Subdomain Takeover",
  "TLS/Network Misconfiguration",
  "Unrestricted File Upload",
  "Web Cache Poisoning",
  "WebSocket Flaws",
  "XML External Entity",
  "gRPC Abuse",
  "vCenter Vulnerability Chain",
];

// Kelas meta yang sengaja TIDAK direncanakan (bukan kelas vuln).
export const EXCLUDED_META_CLASSES = [
  "Attack Surface Mapping",
  "Audit Context Building",
  "Audit Review",
  "Evidence Hygiene",
  "Ghostsecurity Loop",
  "JS Bundle Analysis",
  "Methodology",
  "Navigation",
  "PR Security Review",
  "Reporting",
  "SQL Injection Wordlist",
  "Triage",
  "Verification",
  "White-box Tracing",
];

// Terima Store (punya .db) atau DatabaseSync mentah, seperti graph.js.
function handle(db) {
  return db && db.db ? db.db : db;
}

function safeAll(h, sql, ...params) {
  try {
    return h.prepare(sql).all(...params);
  } catch {
    return [];
  }
}

// Surface = endpoint unik dari tabel candidate untuk program itu,
// DIGABUNG dengan surface yang pernah didaftarkan lewat recordSurface
// (baris memory_coverage) — supaya surface hasil recon yang belum punya
// kandidat tetap terlihat di peta dan bisa direncanakan. Bila keduanya
// kosong, surfaces = [].
export function buildCoverageMap(db, program) {
  const prog = program ?? "";
  if (!prog) return { program: prog, surfaces: [] };
  const h = handle(db);
  const surfaceSet = new Set(
    safeAll(
      h,
      "SELECT DISTINCT endpoint FROM candidate WHERE program = ? ORDER BY endpoint",
      prog
    ).map((r) => r.endpoint).filter(Boolean)
  );

  // Kelas yang pernah muncul sebagai candidate per surface.
  const seenBySurface = new Map();
  for (const r of safeAll(
    h,
    "SELECT endpoint, vuln_class FROM candidate WHERE program = ?",
    prog
  )) {
    if (!seenBySurface.has(r.endpoint)) seenBySurface.set(r.endpoint, new Set());
    seenBySurface.get(r.endpoint).add(r.vuln_class);
  }

  // Status yang dicatat di memory_coverage (bila tabelnya ada).
  const recordedBySurface = new Map();
  try {
    for (const r of listCoverage(h, prog)) {
      if (!recordedBySurface.has(r.surface)) recordedBySurface.set(r.surface, new Map());
      recordedBySurface.get(r.surface).set(r.vuln_class, r.status);
      surfaceSet.add(r.surface);
    }
  } catch {
    // DB lama tanpa memory_coverage: semua status dari candidate saja.
  }
  const surfaces = [...surfaceSet].sort();
  if (surfaces.length === 0) return { program: prog, surfaces: [] };

  // Universe kelas = SURFACE_CLASSES + kelas lain yang terlihat di data
  // (candidate/coverage) supaya bukti tidak hilang diam-diam.
  const extra = new Set();
  for (const set of seenBySurface.values()) for (const c of set) extra.add(c);
  for (const map of recordedBySurface.values()) for (const c of map.keys()) extra.add(c);
  const universe = [...new Set([...SURFACE_CLASSES, ...extra])].sort();

  const out = [];
  for (const surface of surfaces) {
    const seen = seenBySurface.get(surface) ?? new Set();
    const recorded = recordedBySurface.get(surface) ?? new Map();
    const classes = {};
    for (const cls of universe) {
      if (seen.has(cls)) {
        classes[cls] = "examined"; // bukti temuan menang atas ruled_out usang
      } else if (recorded.has(cls)) {
        classes[cls] = recorded.get(cls);
      } else {
        classes[cls] = "open";
      }
    }
    out.push({ surface, classes });
  }
  return { program: prog, surfaces: out };
}

// Rencana hunt berikutnya: pasangan (surface, kelas) yang masih 'open',
// terurut: surface terpanas (kandidat terbanyak) dulu, lalu kelas yang
// paling sering jadi temuan valid (candidate status approved) di program
// itu, lalu abjad. Max 3 kelas per surface (noise governor).
// [] bila tidak ada surface sama sekali — bukan error.
export function planNext(db, program, { limit = 10 } = {}) {
  const prog = program ?? "";
  if (!prog) return [];
  const h = handle(db);
  const map = buildCoverageMap(h, prog);
  if (map.surfaces.length === 0) return [];

  const hotness = new Map();
  for (const r of safeAll(
    h,
    "SELECT endpoint, COUNT(*) AS n FROM candidate WHERE program = ? GROUP BY endpoint",
    prog
  )) {
    hotness.set(r.endpoint, Number(r.n));
  }
  const approvedByClass = new Map();
  for (const r of safeAll(
    h,
    "SELECT vuln_class, COUNT(*) AS n FROM candidate WHERE program = ? AND status = 'approved' GROUP BY vuln_class",
    prog
  )) {
    approvedByClass.set(r.vuln_class, Number(r.n));
  }

  // Kumpulkan item open per surface, lalu ambil max 3 per surface
  // (diurutkan dulu per surface: kelas terkonfirmasi dulu, lalu abjad).
  const perSurface = [];
  for (const { surface, classes } of map.surfaces) {
    const open = Object.entries(classes)
      .filter(([, status]) => status === "open")
      .map(([vulnClass]) => vulnClass)
      .sort((a, b) => (approvedByClass.get(b) ?? 0) - (approvedByClass.get(a) ?? 0) || (a < b ? -1 : a > b ? 1 : 0));
    const top = open.slice(0, 3).map((vulnClass) => {
      const approved = approvedByClass.get(vulnClass) ?? 0;
      return {
        surface,
        vulnClass,
        priority: (hotness.get(surface) ?? 0) * 1000 + approved,
        reason:
          `surface panas (${hotness.get(surface) ?? 0} kandidat)` +
          (approved > 0 ? ` · kelas ini ${approved}× terkonfirmasi di program ini` : ` · kelas ini belum pernah diperiksa di surface ini`),
      };
    });
    perSurface.push(...top);
  }

  // Urutan global: surface terpanas dulu, lalu kelas terkonfirmasi,
  // lalu abjad (surface, lalu kelas) supaya deterministik.
  perSurface.sort((a, b) =>
    (hotness.get(b.surface) ?? 0) - (hotness.get(a.surface) ?? 0) ||
    (approvedByClass.get(b.vulnClass) ?? 0) - (approvedByClass.get(a.vulnClass) ?? 0) ||
    (a.surface < b.surface ? -1 : a.surface > b.surface ? 1 : 0) ||
    (a.vulnClass < b.vulnClass ? -1 : a.vulnClass > b.vulnClass ? 1 : 0)
  );
  return perSurface.slice(0, Math.max(limit, 0));
}

// Daftarkan satu surface baru: tulis baris memory_coverage status 'open'
// untuk surface itu x semua SURFACE_CLASSES yang BELUM punya baris.
// Upsert TIDAK dipakai di sini — baris yang sudah ada (examined/ruled_out)
// tidak boleh ditimpa jadi 'open'. Kembalikan jumlah baris baru.
// Bila tabel memory_coverage tidak ada: no-op, kembalikan 0, tanpa throw.
export function recordSurface(db, program, surface) {
  const prog = program ?? "";
  if (!prog || !surface) return 0;
  const h = handle(db);
  let existing;
  try {
    existing = new Set(
      listCoverage(h, prog)
        .filter((r) => r.surface === surface)
        .map((r) => r.vuln_class)
    );
  } catch {
    return 0; // tabel memory_coverage tidak ada (db lama)
  }
  let written = 0;
  for (const cls of SURFACE_CLASSES) {
    if (existing.has(cls)) continue;
    try {
      recordCoverage(h, prog, surface, cls, "open");
      written++;
    } catch {
      // Satu baris gagal (mis. race) tidak menggagalkan sisanya.
    }
  }
  return written;
}

// Ringkasan coverage satu program.
// { program, surfaces, examined, open, ruledOut, pct }
export function coverageSummary(db, program) {
  const prog = program ?? "";
  const empty = { program: prog, surfaces: 0, examined: 0, open: 0, ruledOut: 0, pct: 0 };
  if (!prog) return empty;
  const map = buildCoverageMap(handle(db), prog);
  let examined = 0;
  let open = 0;
  let ruledOut = 0;
  for (const { classes } of map.surfaces) {
    for (const status of Object.values(classes)) {
      if (status === "examined") examined++;
      else if (status === "ruled_out") ruledOut++;
      else open++;
    }
  }
  const total = examined + open + ruledOut;
  return {
    program: prog,
    surfaces: map.surfaces.length,
    examined,
    open,
    ruledOut,
    pct: total === 0 ? 0 : Math.round((examined / total) * 100),
  };
}

export default {
  SURFACE_CLASSES,
  EXCLUDED_META_CLASSES,
  buildCoverageMap,
  planNext,
  recordSurface,
  coverageSummary,
};
