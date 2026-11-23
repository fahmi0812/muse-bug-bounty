// tests/graph.test.js — M3 graf sebagai view + M4 trace Shannon.
// Database(':memory:') + skema minimal yang disalin dari store.js
// (jangan import Store — test ini menguji graph.js sendiri).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { ensureGraphViews, listNodes, listEdges, findChain, traceFinding } from '../bounty/lib/graph.js';

const SCHEMA = `
CREATE TABLE program (name TEXT PRIMARY KEY, scope_json TEXT NOT NULL DEFAULT '{}', policy_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE asset (id INTEGER PRIMARY KEY AUTOINCREMENT, program TEXT NOT NULL, host TEXT NOT NULL);
CREATE TABLE endpoint (id INTEGER PRIMARY KEY AUTOINCREMENT, program TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, param TEXT NOT NULL DEFAULT '');
CREATE TABLE candidate (id INTEGER PRIMARY KEY AUTOINCREMENT, program TEXT NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL, param TEXT NOT NULL DEFAULT '', vuln_class TEXT NOT NULL, cwe TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'candidate');
CREATE TABLE finding (id INTEGER PRIMARY KEY AUTOINCREMENT, program TEXT NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL, param TEXT NOT NULL DEFAULT '', vuln_class TEXT NOT NULL, cwe TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'medium', verdict TEXT NOT NULL DEFAULT 'candidate', evidence TEXT NOT NULL DEFAULT '', chain_id INTEGER);
CREATE TABLE evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL, kind TEXT NOT NULL, content TEXT NOT NULL);
CREATE TABLE chain (id INTEGER PRIMARY KEY AUTOINCREMENT, program TEXT NOT NULL, steps_json TEXT NOT NULL DEFAULT '[]');
CREATE TABLE run (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '', lab TEXT NOT NULL DEFAULT '', tp INTEGER NOT NULL DEFAULT 0, fp INTEGER NOT NULL DEFAULT 0, fn INTEGER NOT NULL DEFAULT 0, time_ms INTEGER NOT NULL DEFAULT 0, usd REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')));
`;

function freshDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(SCHEMA);
  return db;
}

function seedBasic(db) {
  db.prepare("INSERT INTO program (name) VALUES ('Example Program')").run();
  db.prepare("INSERT INTO asset (program, host) VALUES ('Example Program', 'example.com')").run();
  db.prepare("INSERT INTO endpoint (program, method, path) VALUES ('Example Program', 'GET', '/api/users')").run();
  const f1 = db.prepare(
    "INSERT INTO finding (program, endpoint, method, param, vuln_class, cwe) VALUES ('Example Program', 'https://example.com/api/users?id=1', 'GET', 'id', 'SQL Injection', 'CWE-89')"
  ).run().lastInsertRowid;
  db.prepare("INSERT INTO candidate (program, endpoint, method, param, vuln_class, cwe) VALUES ('Example Program', 'https://example.com/api/users?id=1', 'GET', 'id', 'SQL Injection', 'CWE-89')").run();
  return { f1: Number(f1) };
}

test('graph: view terbentuk (tanpa tabel baru) dan bisa dibuat ulang', () => {
  const db = freshDb();
  assert.equal(ensureGraphViews(db), true);
  const views = db.prepare("SELECT name FROM sqlite_master WHERE type = 'view'").all().map((r) => r.name);
  for (const v of ['v_graph_node', 'v_graph_edge', 'v_coverage', 'v_hot_asset', 'v_finding_chain']) {
    assert.ok(views.includes(v), `view ${v} tidak ada`);
  }
  assert.equal(ensureGraphViews(db), true); // idempotent
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);
  assert.ok(!tables.some((t) => t.startsWith('graph_') || t.startsWith('v_')), 'tidak boleh ada tabel graf baru');
  db.close();
});

test('graph: node + edge mencerminkan data store', () => {
  const db = freshDb();
  const { f1 } = seedBasic(db);
  ensureGraphViews(db);
  const nodes = listNodes(db, 'Example Program');
  const kinds = new Set(nodes.map((n) => n.kind));
  assert.deepEqual([...kinds].sort(), ['asset', 'candidate', 'endpoint', 'finding', 'program']);
  assert.ok(nodes.some((n) => n.id === `finding:${f1}` && n.label.includes('SQL Injection')));
  const edges = listEdges(db, 'Example Program');
  assert.ok(edges.some((e) => e.kind === 'program->asset' && e.to_id === 'asset:1'));
  assert.ok(edges.some((e) => e.kind === 'endpoint->finding' && e.to_id === `finding:${f1}`));
  // Filter program lain -> kosong
  assert.equal(listNodes(db, 'Tidak Ada').length, 0);
  assert.equal(listEdges(db, 'Tidak Ada').length, 0);
  db.close();
});

test('graph: findChain rekursif berhenti di depth 5', () => {
  const db = freshDb();
  db.prepare("INSERT INTO program (name) VALUES ('P')").run();
  const ids = [];
  for (let i = 0; i < 8; i++) {
    const id = db.prepare(
      "INSERT INTO finding (program, endpoint, method, vuln_class) VALUES ('P', '/api/x', 'GET', 'SQL Injection')"
    ).run().lastInsertRowid;
    ids.push(Number(id));
  }
  // Chain 8 langkah berurutan: ids[0] -> ids[1] -> ... -> ids[7]
  const chainId = db.prepare("INSERT INTO chain (program, steps_json) VALUES ('P', ?)").run(JSON.stringify(ids)).lastInsertRowid;
  db.prepare("UPDATE finding SET chain_id = ? WHERE id = ?").run(Number(chainId), ids[0]);
  ensureGraphViews(db);
  const chain = findChain(db, ids[0]);
  assert.equal(Math.max(...chain.map((s) => s.depth)), 5, 'depth maks harus 5');
  assert.equal(chain.length, 6, 'depth 0..5 = 6 langkah');
  assert.deepEqual(chain.map((s) => s.id), ids.slice(0, 6));
  // v_finding_chain berisi edge berurutan
  const vedges = db.prepare("SELECT * FROM v_finding_chain").all();
  assert.equal(vedges.length, 7, '8 langkah = 7 edge');
  assert.ok(vedges.some((e) => e.from_id === ids[0] && e.to_id === ids[1]));
  db.close();
});

test('graph: findChain dengan langkah objek {finding_id} + string label', () => {
  const db = freshDb();
  db.prepare("INSERT INTO program (name) VALUES ('P')").run();
  const a = Number(db.prepare("INSERT INTO finding (program, endpoint, method, vuln_class) VALUES ('P', '/a', 'GET', 'SQL Injection')").run().lastInsertRowid);
  const b = Number(db.prepare("INSERT INTO finding (program, endpoint, method, vuln_class) VALUES ('P', '/b', 'GET', 'Cross-Site Scripting (XSS)')").run().lastInsertRowid);
  db.prepare("INSERT INTO chain (program, steps_json) VALUES ('P', ?)").run(
    JSON.stringify([{ finding_id: a }, 'catatan manual', { finding_id: b }]));
  ensureGraphViews(db);
  const chain = findChain(db, a);
  assert.deepEqual(chain.map((s) => s.id), [a, b]);
  db.close();
});

test('graph: traceFinding dengan chain + evidence -> traced true', () => {
  const db = freshDb();
  const { f1 } = seedBasic(db);
  const f2 = Number(db.prepare(
    "INSERT INTO finding (program, endpoint, method, param, vuln_class, cwe) VALUES ('Example Program', 'https://example.com/api/users?id=1', 'GET', 'id', 'Broken Access Control', 'CWE-862')"
  ).run().lastInsertRowid);
  db.prepare("INSERT INTO chain (program, steps_json) VALUES ('Example Program', ?)").run(JSON.stringify([f1, f2]));
  db.prepare("INSERT INTO evidence (finding_id, kind, content) VALUES (?, 'request', 'GET /api/users?id=1 UNION SELECT')").run(f1);
  db.prepare("INSERT INTO evidence (finding_id, kind, content) VALUES (?, 'response', '200 data user lain')").run(f2);
  ensureGraphViews(db);
  const t = traceFinding(db, f2);
  assert.equal(t.traced, true);
  assert.equal(t.path.length, 2);
  assert.equal(t.path[0].role, 'source');
  assert.equal(t.path[1].role, 'sink');
  assert.equal(t.source.endpoint, 'https://example.com/api/users?id=1');
  assert.equal(t.source.param, 'id');
  assert.equal(t.sink.finding_id, f2);
  assert.equal(t.evidence.length, 2);
  assert.ok(t.evidence.some((e) => e.content.includes('UNION SELECT')));
  db.close();
});

test('graph: traceFinding tanpa chain/evidence -> path minimal + traced false', () => {
  const db = freshDb();
  const { f1 } = seedBasic(db);
  ensureGraphViews(db);
  const t = traceFinding(db, f1);
  assert.equal(t.traced, false);
  assert.equal(t.path.length, 2);
  assert.equal(t.path[0].role, 'source');
  assert.equal(t.path[0].endpoint, 'https://example.com/api/users?id=1');
  assert.equal(t.path[1].role, 'sink');
  assert.equal(t.path[1].finding_id, f1);
  assert.deepEqual(t.evidence, []);
  assert.match(t.note, /tidak ada chain\/evidence/);
  // finding tidak ada
  const missing = traceFinding(db, 9999);
  assert.equal(missing.traced, false);
  assert.equal(missing.finding, null);
  db.close();
});

test('graph: v_coverage fallback — kelas muncul = examined, sisanya open', () => {
  const db = freshDb();
  seedBasic(db);
  ensureGraphViews(db);
  const rows = db.prepare("SELECT * FROM v_coverage WHERE program = 'Example Program'").all();
  const byClass = new Map(rows.map((r) => [r.vuln_class, r]));
  assert.equal(byClass.get('SQL Injection').status, 'examined');
  assert.ok(byClass.get('SQL Injection').n >= 1);
  assert.equal(byClass.get('Cross-Site Scripting (XSS)').status, 'open');
  assert.equal(byClass.get('Cross-Site Scripting (XSS)').n, 0);
  db.close();
});

test('graph: v_coverage memakai memory_coverage bila tabelnya ada (M2)', () => {
  const db = freshDb();
  seedBasic(db);
  db.exec(`CREATE TABLE memory_coverage (
    program TEXT NOT NULL, vuln_class TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open')`);
  db.prepare("INSERT INTO memory_coverage (program, vuln_class, status) VALUES ('Example Program', 'SQL Injection', 'examined')").run();
  db.prepare("INSERT INTO memory_coverage (program, vuln_class, status) VALUES ('Example Program', 'Cross-Site Scripting (XSS)', 'ruled_out')").run();
  ensureGraphViews(db);
  const rows = db.prepare("SELECT * FROM v_coverage WHERE program = 'Example Program' ORDER BY vuln_class").all();
  assert.deepEqual(rows.map((r) => [r.vuln_class, r.status]), [
    ['Cross-Site Scripting (XSS)', 'ruled_out'],
    ['SQL Injection', 'examined'],
  ]);
  db.close();
});

test('graph: v_hot_asset mengurutkan aset dengan finding terbanyak', () => {
  const db = freshDb();
  db.prepare("INSERT INTO program (name) VALUES ('P')").run();
  db.prepare("INSERT INTO asset (program, host) VALUES ('P', 'a.example.com')").run();
  db.prepare("INSERT INTO asset (program, host) VALUES ('P', 'b.example.com')").run();
  for (let i = 0; i < 3; i++) {
    db.prepare("INSERT INTO finding (program, endpoint, method, vuln_class) VALUES ('P', 'https://a.example.com/x', 'GET', 'SQL Injection')").run();
  }
  db.prepare("INSERT INTO finding (program, endpoint, method, vuln_class) VALUES ('P', 'https://b.example.com/x', 'GET', 'SQL Injection')").run();
  ensureGraphViews(db);
  const hot = db.prepare("SELECT * FROM v_hot_asset").all();
  assert.equal(hot[0].host, 'a.example.com');
  assert.equal(hot[0].finding_count, 3);
  assert.equal(hot[1].host, 'b.example.com');
  assert.equal(hot[1].finding_count, 1);
  db.close();
});

test('graph: kandidat ikut jadi node + edge program->candidate (graf tidak kosong setelah run)', () => {
  const db = freshDb();
  db.prepare("INSERT INTO program (name) VALUES ('P')").run();
  db.prepare("INSERT INTO candidate (program, endpoint, method, vuln_class, cwe) VALUES ('P', '/api/users?id=1', 'GET', 'SQL Injection', 'CWE-89')").run();
  ensureGraphViews(db);
  const nodes = listNodes(db, 'P');
  assert.ok(nodes.some((n) => n.kind === 'candidate'), 'kandidat harus jadi node');
  const edges = listEdges(db, 'P');
  assert.ok(edges.some((e) => e.kind === 'program->candidate'), 'harus ada edge program->candidate');
  db.close();
});
