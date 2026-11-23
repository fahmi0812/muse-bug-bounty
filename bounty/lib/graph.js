// bounty/lib/graph.js — M3 graf sebagai VIEW + M4 trace ala Shannon.
// Zero-dep, node:sqlite. TIDAK ada tabel baru, TIDAK ada migrasi: semua
// graf adalah VIEW di atas tabel store yang sudah ada (program, asset,
// endpoint, candidate, finding, evidence, chain, run) + memory_coverage
// bila tabel itu sudah ada (dibuat M2). Jalankan ulang ensureGraphViews
// setiap kali skema berubah — DROP VIEW IF EXISTS lalu CREATE VIEW.
//
// Node id memakai prefix agar unik lintas jenis:
//   program:<name>  asset:<id>  endpoint:<id>  finding:<id>
// Edge kind: program->asset, asset->endpoint, endpoint->finding,
// finding->finding (langkah berurutan di chain.steps_json).
//
// Catatan jujur:
// - Tabel asset/endpoint hanya terisi bila pemanggil mengisinya; alur
//   run->store saat ini menyimpan endpoint sebagai teks di candidate /
//   finding. Node endpoint dari tabel endpoint bisa kosong — node
//   finding tetap membawa endpoint teksnya sendiri.
// - Edge asset->endpoint digabung per program (endpoint tidak punya
//   kolom host) — aproksimasi, bukan bukti kepemilikan host.
// - v_coverage fallback (tanpa memory_coverage): kelas yang pernah
//   muncul di candidate/finding = examined, sisanya open. Status
//   ruled_out hanya ada bila memory_coverage (M2) mencatatnya.

import { VULN_CLASSES } from "./strix-output.js";

function handle(db) {
  return db && db.db ? db.db : db;
}

function escapeLiteral(s) {
  return String(s).replace(/'/g, "''");
}

// Langkah chain bisa berupa: angka (finding id), objek
// {finding_id|finding|id}, atau string label (diabaikan untuk edge).
// Ekstrak finding id dari satu nilai json_each sebagai ekspresi SQL.
// json_valid() menjaga string label biasa (bukan JSON) agar tidak error.
const STEP_FINDING_ID = `
  CASE
    WHEN typeof(value) = 'integer' THEN CAST(value AS INTEGER)
    WHEN json_valid(value) AND json_type(value) = 'object' THEN CAST(COALESCE(
      json_extract(value, '$.finding_id'),
      json_extract(value, '$.finding'),
      json_extract(value, '$.id')) AS INTEGER)
    ELSE NULL
  END
`;

// Edge finding->finding: tiap langkah finding dihubungkan ke langkah
// finding BERIKUTNYA dalam satu chain (langkah string label di tengah
// dilewati, bukan pemutus rantai).
const CHAIN_EDGES = `
  WITH step_findings AS (
    SELECT c.id AS chain_id, c.program AS program,
           CAST(je.key AS INTEGER) AS idx, (${STEP_FINDING_ID}) AS fid
    FROM chain c, json_each(c.steps_json) je
  )
  SELECT a.fid AS from_id, b.fid AS to_id, a.program AS program
  FROM step_findings a
  JOIN step_findings b
    ON b.chain_id = a.chain_id
   AND b.idx = (
     SELECT MIN(s.idx) FROM step_findings s
     WHERE s.chain_id = a.chain_id AND s.idx > a.idx AND s.fid IS NOT NULL
   )
  WHERE a.fid IS NOT NULL AND b.fid IS NOT NULL
`;

function coverageSql(db) {
  const h = handle(db);
  try {
    const cols = h.prepare("PRAGMA table_info(memory_coverage)").all().map((r) => r.name);
    if (cols.includes("program") && cols.includes("vuln_class") && cols.includes("status")) {
      // M2 sudah ada: pakai status yang dicatat (examined / ruled_out / open).
      return `CREATE VIEW v_coverage AS
        SELECT program, vuln_class, status,
               COUNT(*) AS n
        FROM memory_coverage
        GROUP BY program, vuln_class, status`;
    }
  } catch {}
  // Fallback: universe kelas = VULN_CLASSES + kelas yang sudah muncul
  // di candidate/finding; kelas yang pernah muncul = examined, sisanya open.
  const seen = new Set();
  try {
    for (const r of h.prepare("SELECT DISTINCT vuln_class FROM candidate").all()) seen.add(r.vuln_class);
    for (const r of h.prepare("SELECT DISTINCT vuln_class FROM finding").all()) seen.add(r.vuln_class);
  } catch {}
  const universe = [...new Set([...VULN_CLASSES.map((v) => v[1]), ...seen])].sort();
  const values = universe.map((c) => `('${escapeLiteral(c)}')`).join(", ");
  return `CREATE VIEW v_coverage AS
    WITH classes(vuln_class) AS (VALUES ${values || "('')"}),
    programs(program) AS (SELECT DISTINCT program FROM candidate UNION SELECT DISTINCT program FROM finding),
    seen(program, vuln_class, n) AS (
      SELECT program, vuln_class, COUNT(*) FROM candidate GROUP BY program, vuln_class
      UNION ALL
      SELECT program, vuln_class, COUNT(*) FROM finding GROUP BY program, vuln_class
    )
    SELECT p.program AS program, c.vuln_class AS vuln_class,
           CASE WHEN EXISTS (SELECT 1 FROM seen s WHERE s.program = p.program AND s.vuln_class = c.vuln_class)
             THEN 'examined' ELSE 'open' END AS status,
           COALESCE((SELECT SUM(n) FROM seen s WHERE s.program = p.program AND s.vuln_class = c.vuln_class), 0) AS n
    FROM programs p CROSS JOIN classes c`;
}

export function ensureGraphViews(db) {
  const h = handle(db);
  h.exec(`
    DROP VIEW IF EXISTS v_graph_node;
    CREATE VIEW v_graph_node AS
      SELECT 'program:' || name AS id, 'program' AS kind, name AS label, name AS program FROM program
      UNION ALL
      SELECT 'asset:' || id, 'asset', host, program FROM asset
      UNION ALL
      SELECT 'endpoint:' || id, 'endpoint', method || ' ' || path, program FROM endpoint
      UNION ALL
      SELECT 'finding:' || id, 'finding', vuln_class || ' @ ' || endpoint, program FROM finding
      UNION ALL
      -- Kandidat ikut jadi node: tabel asset/endpoint hampir tidak pernah
      -- terisi oleh alur saat ini, jadi tanpa ini graf kosong setelah run.
      SELECT 'candidate:' || id, 'candidate', vuln_class || ' @ ' || endpoint, program FROM candidate;

    DROP VIEW IF EXISTS v_graph_edge;
    CREATE VIEW v_graph_edge AS
      SELECT 'program:' || a.program AS from_id, 'asset:' || a.id AS to_id,
             'program->asset' AS kind, a.program AS program FROM asset a
      UNION ALL
      SELECT 'asset:' || a.id, 'endpoint:' || e.id,
             'asset->endpoint', a.program FROM asset a JOIN endpoint e ON e.program = a.program
      UNION ALL
      SELECT 'endpoint:' || e.id, 'finding:' || f.id,
             'endpoint->finding', f.program
        FROM endpoint e JOIN finding f
          ON f.program = e.program AND instr(f.endpoint, e.path) > 0
      UNION ALL
      SELECT 'program:' || c.program, 'candidate:' || c.id,
             'program->candidate', c.program FROM candidate c
      UNION ALL
      SELECT 'endpoint:' || e.id, 'candidate:' || c.id,
             'endpoint->candidate', c.program
        FROM endpoint e JOIN candidate c
          ON c.program = e.program AND instr(c.endpoint, e.path) > 0
      UNION ALL
      SELECT 'finding:' || from_id, 'finding:' || to_id,
             'finding->finding', program FROM (${CHAIN_EDGES});

    DROP VIEW IF EXISTS v_finding_chain;
    CREATE VIEW v_finding_chain AS
      SELECT from_id, to_id, program, 'finding->finding' AS kind FROM (${CHAIN_EDGES});

    DROP VIEW IF EXISTS v_hot_asset;
    CREATE VIEW v_hot_asset AS
      SELECT a.id AS asset_id, a.program AS program, a.host AS host,
             COUNT(f.id) AS finding_count,
             COUNT(DISTINCT c.id) AS candidate_count
      FROM asset a LEFT JOIN finding f
        ON f.program = a.program AND instr(f.endpoint, a.host) > 0
      LEFT JOIN candidate c
        ON c.program = a.program AND instr(c.endpoint, a.host) > 0
      GROUP BY a.id, a.program, a.host
      ORDER BY finding_count DESC;

    DROP VIEW IF EXISTS v_coverage;
    ${coverageSql(db)};
  `);
  return true;
}

export function listNodes(db, program = null) {
  const h = handle(db);
  if (program) {
    return h.prepare("SELECT id, kind, label, program FROM v_graph_node WHERE program = ? ORDER BY kind, id").all(program);
  }
  return h.prepare("SELECT id, kind, label, program FROM v_graph_node ORDER BY kind, id").all();
}

export function listEdges(db, program = null) {
  const h = handle(db);
  if (program) {
    return h.prepare("SELECT from_id, to_id, kind, program FROM v_graph_edge WHERE program = ? ORDER BY kind, from_id, to_id").all(program);
  }
  return h.prepare("SELECT from_id, to_id, kind, program FROM v_graph_edge ORDER BY kind, from_id, to_id").all();
}

// Chain rekursif (WITH RECURSIVE) dari satu finding, depth dibatasi.
// Kembalikan langkah [{id, depth, vuln_class, endpoint, program}]
// diurutkan depth lalu id; depth 0 = finding awal.
export function findChain(db, findingId, maxDepth = 5) {
  const h = handle(db);
  const rows = h.prepare(`
    WITH RECURSIVE edges(from_id, to_id) AS (
      SELECT from_id, to_id FROM v_finding_chain
    ),
    walk(id, depth) AS (
      SELECT ? AS id, 0 AS depth
      UNION
      SELECT e.to_id, w.depth + 1
      FROM walk w JOIN edges e ON e.from_id = w.id
      WHERE w.depth < ?
    )
    SELECT w.id AS id, w.depth AS depth,
           f.vuln_class AS vuln_class, f.endpoint AS endpoint, f.program AS program
    FROM walk w LEFT JOIN finding f ON f.id = w.id
    ORDER BY w.depth, w.id
  `).all(Number(findingId), Number(maxDepth));
  return rows;
}

// Pendahulu (ancestors) satu finding: berjalan mundur lewat edge
// finding->finding sampai ke source, depth dibatasi. Kembalikan
// langkah diurutkan source dulu (depth 0 = source, terakhir = finding).
function findAncestors(db, findingId, maxDepth = 5) {
  const h = handle(db);
  const rows = h.prepare(`
    WITH RECURSIVE edges(from_id, to_id) AS (
      SELECT from_id, to_id FROM v_finding_chain
    ),
    walk(id, depth) AS (
      SELECT ? AS id, 0 AS depth
      UNION
      SELECT e.from_id, w.depth + 1
      FROM walk w JOIN edges e ON e.to_id = w.id
      WHERE w.depth < ?
    )
    SELECT w.id AS id, w.depth AS depth,
           f.vuln_class AS vuln_class, f.endpoint AS endpoint, f.program AS program
    FROM walk w LEFT JOIN finding f ON f.id = w.id
    ORDER BY w.depth DESC, w.id
  `).all(Number(findingId), Number(maxDepth));
  return rows.map((r, i) => ({ ...r, depth: i }));
}

// M4 — trace ala Shannon: source -> ... -> sink untuk satu finding.
// source = endpoint/param langkah pertama chain, sink = finding itu
// sendiri. Path dibangun dari chain + evidence yang sudah ada di store.
// Bila tidak ada chain/evidence: path minimal [endpoint -> finding]
// dengan traced:false — bukan bukti taint, hanya penanda lokasi.
export function traceFinding(db, findingId) {
  const h = handle(db);
  const finding = h.prepare("SELECT * FROM finding WHERE id = ?").get(Number(findingId));
  if (!finding) {
    return { finding: null, path: [], evidence: [], traced: false, note: "finding tidak ditemukan di store" };
  }
  const chain = findAncestors(db, findingId, 5);
  const ids = chain.map((s) => s.id);
  const steps = chain.map((s, i) => ({
    finding_id: s.id,
    depth: s.depth,
    endpoint: s.endpoint ?? "",
    param: "",
    vuln_class: s.vuln_class ?? "",
    role: i === 0 ? "source" : i === chain.length - 1 ? "sink" : "step",
  }));
  // Lengkapi param langkah dari tabel finding.
  for (const st of steps) {
    const row = h.prepare("SELECT param FROM finding WHERE id = ?").get(st.finding_id);
    if (row) st.param = row.param ?? "";
  }
  // Evidence: baris evidence untuk semua finding di chain + kolom
  // evidence teks di finding itu sendiri.
  const evidence = [];
  if (ids.length > 0) {
    const marks = ids.map(() => "?").join(", ");
    for (const e of h.prepare(`SELECT id, finding_id, kind, content FROM evidence WHERE finding_id IN (${marks}) ORDER BY id`).all(...ids)) {
      evidence.push(e);
    }
  }
  if (finding.evidence) evidence.push({ id: null, finding_id: finding.id, kind: "finding.evidence", content: finding.evidence });
  const traced = steps.length > 1 || evidence.length > 0;
  // Bila tidak ada chain/evidence: path minimal [endpoint -> finding].
  const path = traced ? steps : [
    { finding_id: null, depth: 0, endpoint: finding.endpoint, param: finding.param, vuln_class: "", role: "source" },
    { finding_id: finding.id, depth: 1, endpoint: finding.endpoint, param: finding.param, vuln_class: finding.vuln_class, role: "sink" },
  ];
  const first = path[0];
  const last = path[path.length - 1];
  return {
    finding,
    path,
    evidence,
    traced,
    source: { endpoint: first.endpoint, param: first.param ?? finding.param },
    sink: { finding_id: last.finding_id ?? finding.id, vuln_class: finding.vuln_class },
    note: traced
      ? "trace dari chain + evidence yang tercatat di store (bukan taint analysis dinamis)"
      : "tidak ada chain/evidence di store — path minimal endpoint -> finding; butuh run/scan yang mencatat langkah eksploitasi untuk trace penuh",
  };
}

export default { ensureGraphViews, listNodes, listEdges, findChain, traceFinding };
