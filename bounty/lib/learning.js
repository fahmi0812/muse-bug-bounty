// bounty/lib/learning.js — Ingatan yang belajar lintas run (v1.11).
// Zero-dep, JS saja, TANPA sqlite-vec, TANPA Postgres/Neo4j.
// Dua hal:
//   1. Track record per skill dari memory_lesson (verdict manusia):
//      skill yang sering terkonfirmasi naik, yang sering false-positive
//      turun — di atas nudge lesson v1.2 yang sudah ada.
//   2. Similarity vektor ringan (feature hashing, FNV-1a, 128 dimensi)
//      sebagai sinyal keempat di findSimilarV2, di samping BM25 FTS5 +
//      cosine TF-IDF + boost kelas/CWE.
//
// CATATAN INTEGRASI (v1.12): scoreAll/topWithFallback/scoreWithBonuses
// di router.js kini diekspor, jadi routeWithTrackRecord menerapkan bonus
// track-record ke SEMUA skill sebelum top-5 dipotong — skill peringkat 6
// bisa dipromosikan (batas v1.11 sudah tidak berlaku).
// - tokenize/cosineTfIdf di memory.js juga lokal, jadi helper kecil itu
//   ditulis ulang di sini untuk findSimilarV2 (rumus sama persis).

import { scoreWithBonuses, topWithFallback } from "./router.js";

// --- Vektor hash ringan (feature hashing) ---

function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

function tokenize(text = "") {
  return String(text).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

// Embedding ringan: tiap token di-hash (FNV-1a) ke satu bucket,
// bobot = 1 + log(tf), lalu L2-normalize. Deterministik, pure.
// Teks tanpa token -> vektor nol (semua 0).
export function hashVector(text, dim = 128) {
  const d = Math.max(1, Math.floor(dim) || 128);
  const vec = new Array(d).fill(0);
  const tf = new Map();
  for (const t of tokenize(text)) tf.set(t, (tf.get(t) ?? 0) + 1);
  for (const [t, c] of tf) vec[fnv1a(t) % d] += 1 + Math.log(c);
  const norm = Math.sqrt(vec.reduce((a, x) => a + x * x, 0));
  if (norm === 0) return vec;
  return vec.map((x) => x / norm);
}

// Cosine similarity dua vektor. 0 bila salah satu vektor nol atau
// panjangnya tidak sama.
export function vectorCosine(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length || a.length === 0) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

// --- Track record per skill dari memory_lesson ---

// Terima Store (punya .db) atau DatabaseSync mentah, seperti planner.js.
function handle(db) {
  return db && db.db ? db.db : db;
}

function round4(n) {
  return Math.round(n * 10000) / 10000;
}

// Per skill: { skill, confirmed, falsePositive, total, precision, weight }.
// precision = confirmed/total (total 0 -> null, tidak terjadi dari query
// GROUP BY tapi dijaga). weight = clamp((precision - 0.5) * 2, -1, 1);
// total < 3 -> weight 0 (data terlalu sedikit = tidak berpendapat).
// DB tanpa tabel memory_lesson -> {} (bukan throw).
export function skillTrackRecord(db) {
  const out = {};
  let rows;
  try {
    rows = handle(db).prepare(
      "SELECT skill, outcome, COUNT(*) AS n FROM memory_lesson GROUP BY skill, outcome"
    ).all();
  } catch {
    return out;
  }
  for (const r of rows ?? []) {
    const skill = String(r.skill ?? "").trim();
    if (!skill) continue;
    out[skill] ??= { skill, confirmed: 0, falsePositive: 0, total: 0, precision: null, weight: 0 };
    if (r.outcome === "confirmed") out[skill].confirmed += Number(r.n);
    else if (r.outcome === "false_positive") out[skill].falsePositive += Number(r.n);
  }
  for (const rec of Object.values(out)) {
    rec.total = rec.confirmed + rec.falsePositive;
    rec.precision = rec.total > 0 ? round4(rec.confirmed / rec.total) : null;
    rec.weight = 0;
    if (rec.total >= 3 && rec.precision !== null) {
      rec.weight = round4(Math.max(-1, Math.min(1, (rec.precision - 0.5) * 2)));
    }
  }
  return out;
}

// Normalisasi argumen trackRecord: objek hasil skillTrackRecord, Map,
// atau null/undefined -> objek { skill: { weight } } (angka polos
// dianggap weight langsung).
function normTrackRecord(trackRecord) {
  if (!trackRecord) return {};
  if (trackRecord instanceof Map) return Object.fromEntries(trackRecord);
  if (typeof trackRecord === "object") return trackRecord;
  return {};
}

const TRACK_STEP = 0.3;
const TRACK_CAP = 0.3;

// Perluasan routeWithLessons: skor akhir = skor keyword + nudge lesson
// v1.2 (±0.15, cap ±0.45, rumus tidak diubah) + bonus track-record
// (weight skill x 0.3, clamp ±0.3). Bonus hanya bila weight != 0.
// v1.12: bonus diterapkan ke SEMUA skill sebelum top-5 dipotong, jadi
// skill peringkat 6 bisa dipromosikan ke top-5.
// Tanpa lessons + tanpa trackRecord + tanpa patterns -> hasil
// deepEqual-identik dengan routeSkills().
export function routeWithTrackRecord(contextText, lessons = [], trackRecord = null, patterns = null, skills = null) {
  const ctx = String(contextText ?? "").trim();
  const record = normTrackRecord(trackRecord);
  const weights = new Map();
  for (const [name, rec] of Object.entries(record)) {
    const w = typeof rec === "number" ? rec : Number(rec?.weight ?? 0);
    if (Number.isFinite(w) && w !== 0) weights.set(name, w);
  }
  const scored = scoreWithBonuses(ctx, lessons, patterns, skills).map((entry) => {
    const w = weights.get(entry.name);
    if (w === undefined) return entry;
    const bonus = Math.round(Math.max(-TRACK_CAP, Math.min(TRACK_CAP, w * TRACK_STEP)) * 100) / 100;
    if (bonus === 0) return entry;
    const score = Math.round((entry.score + bonus) * 100) / 100;
    return { ...entry, score, reason: `${entry.reason} +track ${bonus > 0 ? "+" : ""}${bonus}` };
  });
  return topWithFallback(scored, ctx);
}

// --- findSimilarV2: BM25 + TF-IDF + vektor hash + boost ---

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

// Kontrak sama seperti findSimilar di memory.js, fusion baru:
//   0.4*BM25 (FTS5 rank dinormalisasi) + 0.2*cosine TF-IDF
//   + 0.2*vectorCosine(hashVector query, hashVector kandidat)
//   + 0.2*boost bila vuln_class DAN CWE sama.
// Vektor query dibangun dari gabungan endpoint + param + vulnClass.
// Query kosong -> []. DB tanpa tabel FTS/kandidat -> [] (bukan throw).
export function findSimilarV2(db, { endpoint = "", param = "", vulnClass = "", cwe = "" } = {}, limit = 5) {
  const queryText = [endpoint, param, vulnClass, cwe].join(" ");
  const queryTokens = [...new Set(tokenize(queryText))];
  if (queryTokens.length === 0) return [];
  const matchExpr = queryTokens.map((t) => `"${t}"`).join(" OR ");
  let rows;
  try {
    rows = handle(db).prepare(
      "SELECT rowid, rank FROM finding_fts WHERE finding_fts MATCH ?"
    ).all(matchExpr);
  } catch {
    return [];
  }
  if (rows.length === 0) return [];
  const ids = rows.map((r) => r.id ?? r.rowid);
  const placeholders = ids.map(() => "?").join(",");
  let docs;
  try {
    docs = handle(db).prepare(
      `SELECT id, endpoint, param, vuln_class, cwe FROM candidate WHERE id IN (${placeholders})`
    ).all(...ids);
  } catch {
    return [];
  }
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
  const queryVec = hashVector([endpoint, param, vulnClass].join(" "));
  const maxBm25 = Math.max(...rows.map((r) => -r.rank), 0.0001);
  const normClass = String(vulnClass).trim().toLowerCase();
  const normCwe = String(cwe).trim().toUpperCase();
  const scored = [];
  for (const r of rows) {
    const id = r.id ?? r.rowid;
    const d = byId.get(id);
    if (!d) continue;
    const bm25n = (-r.rank) / maxBm25;
    const cos = cosineTfIdf(queryTf, termFreq(docTokens.get(id) ?? []), idf);
    const vecCos = vectorCosine(queryVec, hashVector([d.endpoint, d.param, d.vuln_class].join(" ")));
    const sameClass = normClass && String(d.vuln_class).trim().toLowerCase() === normClass;
    const sameCwe = normCwe && String(d.cwe).trim().toUpperCase() === normCwe;
    const boost = sameClass && sameCwe ? 1 : 0;
    const score = 0.4 * bm25n + 0.2 * cos + 0.2 * vecCos + 0.2 * boost;
    scored.push({ id: d.id, endpoint: d.endpoint, vulnClass: d.vuln_class, score: Math.round(score * 10000) / 10000 });
  }
  scored.sort((a, b) => b.score - a.score || a.id - b.id);
  return scored.slice(0, Math.max(limit, 0));
}

export default {
  hashVector,
  vectorCosine,
  skillTrackRecord,
  routeWithTrackRecord,
  findSimilarV2,
};
