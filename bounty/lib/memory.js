// bounty/lib/memory.js — Memori + peta ringan (v1.2 M0+M1, plan-power-v1.1).
// Zero-dep, node:sqlite, semua di bounty.db. Prinsip:
// - memory_episode: append-only (tidak ada API UPDATE/DELETE).
// - memory_fact: bi-temporal — invalidasi = set valid_until, BUKAN delete.
// - memory_lesson: hanya dari verdict manusia (confirmed/false_positive).
// - memory_coverage: upsert per (program, surface, vuln_class).
// - M1: finding_fts (FTS5, external-content atas tabel candidate) +
//   trigger sinkronisasi + findSimilar() dengan RRF:
//   0.5*BM25 (FTS5 rank dinormalisasi) + 0.3*cosine TF-IDF (dihitung di
//   JS, tanpa sqlite-vec — vec0 tidak ada di VM) + 0.2*boost bila
//   vuln_class + CWE sama.

const VALID_KINDS = new Set(["run", "review"]);
const VALID_OUTCOMES = new Set(["confirmed", "false_positive"]);
const VALID_COVERAGE = new Set(["examined", "ruled_out", "open"]);

const SCHEMA = `
CREATE TABLE IF NOT EXISTS memory_episode (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL CHECK(kind IN ('run', 'review')),
  summary TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS memory_fact (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT NOT NULL,
  predicate TEXT NOT NULL,
  object TEXT NOT NULL,
  valid_from TEXT NOT NULL DEFAULT (datetime('now')),
  valid_until TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS memory_lesson (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  skill TEXT NOT NULL,
  vuln_class TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('confirmed', 'false_positive')),
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS memory_coverage (
  program TEXT NOT NULL,
  surface TEXT NOT NULL,
  vuln_class TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('examined', 'ruled_out', 'open')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (program, surface, vuln_class)
);
-- FTS5 external-content atas tabel candidate (id = rowid).
CREATE VIRTUAL TABLE IF NOT EXISTS finding_fts USING fts5(
  endpoint, param, vuln_class, cwe,
  content='candidate', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS finding_fts_ai AFTER INSERT ON candidate BEGIN
  INSERT INTO finding_fts(rowid, endpoint, param, vuln_class, cwe)
  VALUES (new.id, new.endpoint, new.param, new.vuln_class, new.cwe);
END;
CREATE TRIGGER IF NOT EXISTS finding_fts_ad AFTER DELETE ON candidate BEGIN
  INSERT INTO finding_fts(finding_fts, rowid, endpoint, param, vuln_class, cwe)
  VALUES ('delete', old.id, old.endpoint, old.param, old.vuln_class, old.cwe);
END;
CREATE TRIGGER IF NOT EXISTS finding_fts_au AFTER UPDATE ON candidate BEGIN
  INSERT INTO finding_fts(finding_fts, rowid, endpoint, param, vuln_class, cwe)
  VALUES ('delete', old.id, old.endpoint, old.param, old.vuln_class, old.cwe);
  INSERT INTO finding_fts(rowid, endpoint, param, vuln_class, cwe)
  VALUES (new.id, new.endpoint, new.param, new.vuln_class, new.cwe);
END;
`;

export function ensureMemorySchema(db) {
  db.exec(SCHEMA);
  // Sinkronkan FTS dengan kandidat yang sudah ada sebelum trigger dibuat.
  try { db.exec("INSERT INTO finding_fts(finding_fts) VALUES('rebuild')"); } catch {}
  return true;
}

export function recordEpisode(db, { program, target = "", kind, summary = "" }) {
  if (!VALID_KINDS.has(kind)) throw new Error(`kind episode tidak valid: ${kind} (harus 'run'|'review')`);
  if (!program) throw new Error("recordEpisode butuh program");
  const info = db.prepare(
    "INSERT INTO memory_episode (program, target, kind, summary) VALUES (?, ?, ?, ?)"
  ).run(program, target, kind, summary);
  return Number(info.lastInsertRowid);
}

export function listEpisodes(db, program = null) {
  if (program) {
    return db.prepare("SELECT * FROM memory_episode WHERE program = ? ORDER BY id").all(program);
  }
  return db.prepare("SELECT * FROM memory_episode ORDER BY id").all();
}

export function addFact(db, subject, predicate, object) {
  if (!subject || !predicate || object === undefined || object === null) {
    throw new Error("addFact butuh subject, predicate, object");
  }
  const info = db.prepare(
    "INSERT INTO memory_fact (subject, predicate, object) VALUES (?, ?, ?)"
  ).run(String(subject), String(predicate), String(object));
  return Number(info.lastInsertRowid);
}

export function getFact(db, id) {
  return db.prepare("SELECT * FROM memory_fact WHERE id = ?").get(id) ?? null;
}

// Invalidasi bi-temporal: set valid_until, baris TETAP ada (bukan delete).
export function invalidateFact(db, id) {
  db.prepare(
    "UPDATE memory_fact SET valid_until = datetime('now') WHERE id = ? AND valid_until IS NULL"
  ).run(id);
  return getFact(db, id);
}

export function listFacts(db, { activeOnly = false } = {}) {
  if (activeOnly) {
    return db.prepare("SELECT * FROM memory_fact WHERE valid_until IS NULL ORDER BY id").all();
  }
  return db.prepare("SELECT * FROM memory_fact ORDER BY id").all();
}

// Hanya verdict manusia: outcome di luar confirmed/false_positive ditolak.
export function addLesson(db, { skill, vulnClass, outcome, note = "" }) {
  if (!VALID_OUTCOMES.has(outcome)) {
    throw new Error(`outcome lesson tidak valid: ${outcome} (harus 'confirmed'|'false_positive')`);
  }
  if (!skill || !vulnClass) throw new Error("addLesson butuh skill dan vulnClass");
  const info = db.prepare(
    "INSERT INTO memory_lesson (skill, vuln_class, outcome, note) VALUES (?, ?, ?, ?)"
  ).run(String(skill), String(vulnClass), outcome, String(note));
  return Number(info.lastInsertRowid);
}

export function listLessons(db) {
  return db.prepare("SELECT * FROM memory_lesson ORDER BY id").all();
}

export function recordCoverage(db, program, surface, vulnClass, status) {
  if (!VALID_COVERAGE.has(status)) {
    throw new Error(`status coverage tidak valid: ${status} (harus 'examined'|'ruled_out'|'open')`);
  }
  db.prepare(
    `INSERT INTO memory_coverage (program, surface, vuln_class, status, updated_at)
     VALUES (?, ?, ?, ?, datetime('now'))
     ON CONFLICT(program, surface, vuln_class)
     DO UPDATE SET status = excluded.status, updated_at = datetime('now')`
  ).run(program, surface, vulnClass, status);
  return db.prepare(
    "SELECT * FROM memory_coverage WHERE program = ? AND surface = ? AND vuln_class = ?"
  ).get(program, surface, vulnClass);
}

export function listCoverage(db, program = null) {
  if (program) {
    return db.prepare("SELECT * FROM memory_coverage WHERE program = ? ORDER BY surface, vuln_class").all(program);
  }
  return db.prepare("SELECT * FROM memory_coverage ORDER BY program, surface, vuln_class").all();
}

// --- M1: pencarian temuan mirip (FTS5 BM25 + cosine TF-IDF + boost) ---

function tokenize(text = "") {
  return String(text).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function termFreq(tokens) {
  const tf = new Map();
  for (const t of tokens) tf.set(t, (tf.get(t) ?? 0) + 1);
  return tf;
}

function cosineTfIdf(queryTf, docTf, idf) {
  let dot = 0;
  let qNorm = 0;
  let dNorm = 0;
  for (const [t, q] of queryTf) {
    const w = idf.get(t) ?? 0;
    qNorm += (q * w) ** 2;
    const d = docTf.get(t);
    if (d) dot += q * w * d * w;
  }
  for (const [t, d] of docTf) {
    const w = idf.get(t) ?? 0;
    dNorm += (d * w) ** 2;
  }
  if (qNorm === 0 || dNorm === 0) return 0;
  return dot / (Math.sqrt(qNorm) * Math.sqrt(dNorm));
}

export function findSimilar(db, { endpoint = "", param = "", vulnClass = "", cwe = "" } = {}, limit = 5) {
  const queryText = [endpoint, param, vulnClass, cwe].join(" ");
  const queryTokens = [...new Set(tokenize(queryText))];
  if (queryTokens.length === 0) return [];
  // FTS5 MATCH: tiap token dikutip, digabung OR. Token sudah [a-z0-9]+
  // jadi aman dari injeksi sintaks MATCH.
  const matchExpr = queryTokens.map((t) => `"${t}"`).join(" OR ");
  let rows;
  try {
    rows = db.prepare(
      "SELECT rowid, rank FROM finding_fts WHERE finding_fts MATCH ?"
    ).all(matchExpr);
  } catch {
    return [];
  }
  if (rows.length === 0) return [];
  const ids = rows.map((r) => r.id ?? r.rowid);
  const placeholders = ids.map(() => "?").join(",");
  const docs = db.prepare(
    `SELECT id, endpoint, param, vuln_class, cwe FROM candidate WHERE id IN (${placeholders})`
  ).all(...ids);
  const byId = new Map(docs.map((d) => [d.id, d]));
  // IDF dari himpunan dokumen yang cocok (corpus kecil, dihitung di JS).
  const docTokens = new Map();
  const df = new Map();
  for (const d of docs) {
    const toks = [...new Set(tokenize([d.endpoint, d.param, d.vuln_class, d.cwe].join(" ")))];
    docTokens.set(d.id, toks);
    for (const t of toks) df.set(t, (df.get(t) ?? 0) + 1);
  }
  const n = Math.max(docs.length, 1);
  const idf = new Map([...df.entries()].map(([t, d]) => [t, Math.log(1 + n / d)]));
  const queryTf = termFreq(queryTokens);
  const maxBm25 = Math.max(...rows.map((r) => -r.rank), 0.0001);
  const normClass = String(vulnClass).trim().toLowerCase();
  const normCwe = String(cwe).trim().toUpperCase();
  const scored = [];
  for (const r of rows) {
    const id = r.id ?? r.rowid;
    const d = byId.get(id);
    if (!d) continue;
    const bm25n = (-r.rank) / maxBm25; // 0..1, 1 = paling relevan menurut FTS5
    const cos = cosineTfIdf(queryTf, termFreq(docTokens.get(id) ?? []), idf);
    const sameClass = normClass && String(d.vuln_class).trim().toLowerCase() === normClass;
    const sameCwe = normCwe && String(d.cwe).trim().toUpperCase() === normCwe;
    const boost = sameClass && sameCwe ? 1 : 0;
    const score = 0.5 * bm25n + 0.3 * cos + 0.2 * boost;
    scored.push({ id: d.id, endpoint: d.endpoint, vulnClass: d.vuln_class, score: Math.round(score * 10000) / 10000 });
  }
  scored.sort((a, b) => b.score - a.score || a.id - b.id);
  return scored.slice(0, Math.max(limit, 0));
}

export default {
  ensureMemorySchema,
  recordEpisode,
  listEpisodes,
  addFact,
  getFact,
  invalidateFact,
  listFacts,
  addLesson,
  listLessons,
  recordCoverage,
  listCoverage,
  findSimilar,
};
