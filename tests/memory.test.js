// tests/memory.test.js — v1.2 M0+M1: memori + FTS5 + findSimilar.
// node:test, tanpa dependensi. Database ':memory:' langsung (tanpa Store);
// tabel candidate dibuat di setup seperti skema store.js.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import {
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
} from "../bounty/lib/memory.js";

const CANDIDATE_SCHEMA = `
CREATE TABLE candidate (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  param TEXT NOT NULL DEFAULT '',
  vuln_class TEXT NOT NULL,
  cwe TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'candidate'
);`;

let db;
beforeEach(() => {
  db = new DatabaseSync(":memory:");
  db.exec(CANDIDATE_SCHEMA);
  ensureMemorySchema(db);
});

function addCandidate(program, endpoint, param, vulnClass, cwe) {
  const info = db.prepare(
    "INSERT INTO candidate (program, endpoint, method, param, vuln_class, cwe) VALUES (?, ?, 'GET', ?, ?, ?)"
  ).run(program, endpoint, param, vulnClass, cwe);
  return Number(info.lastInsertRowid);
}

test("M0 episode: tercatat dan bisa difilter per program", () => {
  const id = recordEpisode(db, { program: "juice-shop", target: "http://localhost:3000", kind: "run", summary: "run 1: 9 TP" });
  assert.equal(typeof id, "number");
  recordEpisode(db, { program: "dvwa", kind: "review", summary: "review antrean" });
  assert.equal(listEpisodes(db).length, 2);
  assert.equal(listEpisodes(db, "juice-shop").length, 1);
  assert.equal(listEpisodes(db, "juice-shop")[0].kind, "run");
  assert.throws(() => recordEpisode(db, { program: "x", kind: "hapus", summary: "" }), /kind episode tidak valid/);
});

test("M0 fact: invalidasi set valid_until, baris TETAP ada (bukan delete)", () => {
  const id = addFact(db, "juice-shop", "has_endpoint", "/api/users");
  assert.equal(getFact(db, id).valid_until, null);
  const row = invalidateFact(db, id);
  assert.ok(row.valid_until, "valid_until harus terisi setelah invalidasi");
  assert.equal(getFact(db, id).subject, "juice-shop", "baris tidak boleh hilang");
  assert.equal(listFacts(db).length, 1);
  assert.equal(listFacts(db, { activeOnly: true }).length, 0, "fact yang diinvalidasi tidak aktif lagi");
});

test("M0 lesson: hanya verdict manusia, outcome lain ditolak", () => {
  const id = addLesson(db, { skill: "hunt-sqli", vulnClass: "SQL Injection", outcome: "confirmed", note: "replay sukses" });
  assert.equal(typeof id, "number");
  addLesson(db, { skill: "hunt-xss", vulnClass: "Cross-Site Scripting (XSS)", outcome: "false_positive", note: "reflected tapi self-XSS" });
  assert.equal(listLessons(db).length, 2);
  assert.throws(
    () => addLesson(db, { skill: "hunt-sqli", vulnClass: "SQL Injection", outcome: "maybe", note: "" }),
    /outcome lesson tidak valid/
  );
  assert.throws(
    () => addLesson(db, { skill: "hunt-sqli", vulnClass: "SQL Injection", outcome: "candidate", note: "" }),
    /outcome lesson tidak valid/
  );
  assert.equal(listLessons(db).length, 2, "lesson yang ditolak tidak masuk");
});

test("M0 coverage: upsert per kunci, tidak duplikat", () => {
  recordCoverage(db, "juice-shop", "/api/users", "SQL Injection", "open");
  recordCoverage(db, "juice-shop", "/api/users", "SQL Injection", "examined");
  const rows = listCoverage(db, "juice-shop");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].status, "examined", "status terbaru menang");
  recordCoverage(db, "juice-shop", "/api/users", "Cross-Site Scripting (XSS)", "open");
  assert.equal(listCoverage(db, "juice-shop").length, 2, "kelas vuln berbeda = baris berbeda");
  assert.throws(
    () => recordCoverage(db, "juice-shop", "/api/users", "SQL Injection", "done"),
    /status coverage tidak valid/
  );
});

test("M1 findSimilar: kandidat mirip di top-5, kelas+CWE sama skornya lebih tinggi", () => {
  const same = addCandidate("juice-shop", "/api/users?id=1", "id", "SQL Injection", "CWE-89");
  const diffClass = addCandidate("juice-shop", "/api/users?name=x", "name", "Cross-Site Scripting (XSS)", "CWE-79");
  addCandidate("dvwa", "/login?user=admin", "user", "Broken Authentication", "CWE-287");
  const results = findSimilar(db, { endpoint: "/api/users?id=2", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" }, 5);
  assert.ok(results.length >= 2, `diharapkan >=2 hasil, dapat ${results.length}`);
  assert.equal(results[0].id, same, "kandidat kelas+CWE sama harus di posisi 1");
  const sameRow = results.find((r) => r.id === same);
  const diffRow = results.find((r) => r.id === diffClass);
  assert.ok(sameRow.score > diffRow.score, `skor sama (${sameRow.score}) harus > beda kelas (${diffRow.score})`);
  assert.equal(sameRow.endpoint, "/api/users?id=1");
  assert.equal(sameRow.vulnClass, "SQL Injection");
});

test("M1 findSimilar: limit dihormati dan query kosong kembalikan []", () => {
  for (let i = 0; i < 6; i++) addCandidate("juice-shop", `/api/items?id=${i}`, "id", "SQL Injection", "CWE-89");
  assert.equal(findSimilar(db, { endpoint: "/api/items?id=99", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" }, 3).length, 3);
  assert.deepEqual(findSimilar(db, { endpoint: "", param: "", vulnClass: "", cwe: "" }), []);
  // Query tanpa token yang tumpang tindih sama sekali (tanpa CWE, karena
  // token "cwe" sendiri ada di semua kandidat).
  assert.deepEqual(findSimilar(db, { endpoint: "/qqqq-wwww", param: "qqqq", vulnClass: "Zzzzz Qqqq", cwe: "" }), []);
});

test("M1 FTS: trigger sinkronisasi insert/update/delete pada candidate", () => {
  const id = addCandidate("juice-shop", "/api/search?q=x", "q", "Cross-Site Scripting (XSS)", "CWE-79");
  let found = findSimilar(db, { endpoint: "/api/search?q=y", param: "q", vulnClass: "Cross-Site Scripting (XSS)", cwe: "CWE-79" });
  assert.ok(found.some((r) => r.id === id), "insert harus masuk FTS");
  db.prepare("UPDATE candidate SET vuln_class = 'SQL Injection', cwe = 'CWE-89' WHERE id = ?").run(id);
  found = findSimilar(db, { endpoint: "/api/search?q=y", param: "q", vulnClass: "SQL Injection", cwe: "CWE-89" });
  assert.ok(found.some((r) => r.id === id), "update harus tercermin di FTS");
  assert.equal(found.find((r) => r.id === id).vulnClass, "SQL Injection");
  db.prepare("DELETE FROM candidate WHERE id = ?").run(id);
  found = findSimilar(db, { endpoint: "/api/search?q=y", param: "q", vulnClass: "SQL Injection", cwe: "CWE-89" });
  assert.ok(!found.some((r) => r.id === id), "delete harus hilang dari FTS");
});

test("M0+M1: ensureMemorySchema idempotent dan FTS rebuild tidak duplikat", () => {
  addCandidate("juice-shop", "/api/users?id=1", "id", "SQL Injection", "CWE-89");
  ensureMemorySchema(db);
  ensureMemorySchema(db);
  const results = findSimilar(db, { endpoint: "/api/users?id=2", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" });
  assert.equal(results.length, 1, "rebuild tidak boleh menggandakan baris FTS");
});
