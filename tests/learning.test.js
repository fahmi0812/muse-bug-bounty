// tests/learning.test.js — v1.11: router belajar lintas run + similarity
// vektor ringan (feature hashing). node:test, tanpa dependensi.
// Store sementara (BOUNTY_DB ke file temp, pola seperti tests/planner.test.js).
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { Store } from "../bounty/lib/store.js";
import { addLesson } from "../bounty/lib/memory.js";
import { routeSkills } from "../bounty/lib/router.js";
import {
  hashVector,
  vectorCosine,
  skillTrackRecord,
  routeWithTrackRecord,
  findSimilarV2,
} from "../bounty/lib/learning.js";

let dir;
let store;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "bounty-learning-"));
  process.env.BOUNTY_DB = join(dir, "bounty.db");
  store = new Store(join(dir, "bounty.db"));
});

afterEach(() => {
  try { store.close(); } catch {}
  delete process.env.BOUNTY_DB;
  rmSync(dir, { recursive: true, force: true });
});

// Skill buatan tangan untuk menguji pengurutan router tanpa skills-index.
// Konteks "sql injection xss scripting": hunt-sqli cocok sql+injection (2),
// hunt-xss cocok xss+scripting (2) -> seri; hunt-ssrf tidak cocok (0).
const SKILLS = [
  { name: "hunt-sqli", vuln_class: "SQL Injection", cwe: "CWE-89", keywords: ["sql", "injection", "sqli"], when: "SQL injection" },
  { name: "hunt-xss", vuln_class: "Cross-Site Scripting", cwe: "CWE-79", keywords: ["xss", "cross-site", "scripting"], when: "XSS" },
  { name: "hunt-ssrf", vuln_class: "Server-Side Request Forgery", cwe: "CWE-918", keywords: ["ssrf", "server-side", "request"], when: "SSRF" },
];

test("learning: hashVector deterministik + ternormalisasi; vectorCosine identik=1, tanpa token sama=0", () => {
  const a = hashVector("api users id sql injection");
  const b = hashVector("api users id sql injection");
  assert.deepEqual(a, b);
  assert.equal(a.length, 128);
  const norm = Math.sqrt(a.reduce((s, x) => s + x * x, 0));
  assert.ok(Math.abs(norm - 1) < 1e-9, `norm=${norm}`);
  // Cosine vektor identik = 1 dalam toleransi floating-point.
  assert.ok(Math.abs(vectorCosine(a, b) - 1) < 1e-9, `cos=${vectorCosine(a, b)}`);
  // Vektor nol untuk teks tanpa token.
  assert.ok(hashVector("!!! ---").every((x) => x === 0));
  assert.equal(vectorCosine(hashVector("!!!"), hashVector("abc")), 0);
  // Teks tanpa token sama: 0 (teks ini diverifikasi memberi 0 di dim 128).
  const c = hashVector("zebra xylophone quantum");
  const d = hashVector("apple banana cherry");
  assert.equal(vectorCosine(c, d), 0);
  // Vektor buatan tangan (bukan hash): ortogonal = 0, sama = 1.
  assert.equal(vectorCosine([1, 0, 0], [0, 1, 0]), 0);
  assert.equal(vectorCosine([1, 0, 0], [1, 0, 0]), 1);
  assert.equal(vectorCosine([1, 0], [1, 0, 0]), 0); // panjang beda
});

test("learning: skillTrackRecord — precision, weight, dan ambang data minim", () => {
  // hunt-sqli: 3 confirmed + 1 fp -> precision 0.75, weight 0.5.
  addLesson(store.db, { skill: "hunt-sqli", vulnClass: "SQL Injection", outcome: "confirmed" });
  addLesson(store.db, { skill: "hunt-sqli", vulnClass: "SQL Injection", outcome: "confirmed" });
  addLesson(store.db, { skill: "hunt-sqli", vulnClass: "SQL Injection", outcome: "confirmed" });
  addLesson(store.db, { skill: "hunt-sqli", vulnClass: "SQL Injection", outcome: "false_positive" });
  // hunt-xss: total 2 -> weight 0 (data terlalu sedikit).
  addLesson(store.db, { skill: "hunt-xss", vulnClass: "Cross-Site Scripting", outcome: "confirmed" });
  addLesson(store.db, { skill: "hunt-xss", vulnClass: "Cross-Site Scripting", outcome: "false_positive" });
  // hunt-ssrf: 3 fp -> precision 0, weight -1.
  addLesson(store.db, { skill: "hunt-ssrf", vulnClass: "Server-Side Request Forgery", outcome: "false_positive" });
  addLesson(store.db, { skill: "hunt-ssrf", vulnClass: "Server-Side Request Forgery", outcome: "false_positive" });
  addLesson(store.db, { skill: "hunt-ssrf", vulnClass: "Server-Side Request Forgery", outcome: "false_positive" });
  const rec = skillTrackRecord(store.db);
  assert.deepEqual(rec["hunt-sqli"], { skill: "hunt-sqli", confirmed: 3, falsePositive: 1, total: 4, precision: 0.75, weight: 0.5 });
  assert.equal(rec["hunt-xss"].weight, 0);
  assert.equal(rec["hunt-xss"].precision, 0.5);
  assert.equal(rec["hunt-ssrf"].weight, -1);
  assert.equal(rec["hunt-ssrf"].precision, 0);
  // Menerima Store maupun DatabaseSync mentah; db tanpa tabel -> {}.
  assert.deepEqual(skillTrackRecord(store), rec);
  const empty = new DatabaseSync(":memory:");
  try { assert.deepEqual(skillTrackRecord(empty), {}); } finally { empty.close(); }
});

test("learning: routeWithTrackRecord kosong -> identik routeSkills", () => {
  const ctx = "sql injection xss";
  const base = routeSkills(ctx, SKILLS);
  assert.deepEqual(routeWithTrackRecord(ctx, [], {}, null, SKILLS), base);
  assert.deepEqual(routeWithTrackRecord(ctx, [], null, null, SKILLS), base);
  assert.deepEqual(routeWithTrackRecord(ctx, [], new Map(), null, SKILLS), base);
});

test("learning: routeWithTrackRecord — track record positif naikkan, negatif turunkan", () => {
  const ctx = "sql injection xss scripting";
  // Seri 2-2 tanpa track record: urutan stabil = hunt-sqli dulu.
  const base = routeWithTrackRecord(ctx, [], {}, null, SKILLS);
  assert.equal(base[0].name, "hunt-sqli");
  assert.equal(base[1].name, "hunt-xss");
  // Track record positif untuk hunt-xss (weight 1 -> +0.3): xss naik ke atas.
  const up = routeWithTrackRecord(ctx, [], { "hunt-xss": { weight: 1 } }, null, SKILLS);
  assert.equal(up[0].name, "hunt-xss");
  assert.equal(up[0].score, 2.3);
  assert.match(up[0].reason, /\+track \+0\.3/);
  assert.equal(up[1].name, "hunt-sqli");
  // Track record negatif untuk hunt-sqli (weight -1 -> -0.3): sqli turun.
  const down = routeWithTrackRecord(ctx, [], { "hunt-sqli": { weight: -1 } }, null, SKILLS);
  assert.equal(down[0].name, "hunt-xss");
  assert.equal(down[1].name, "hunt-sqli");
  assert.equal(down[1].score, 1.7);
  // Bonus di-clamp ±0.3 meski weight di luar [-1, 1].
  const clamped = routeWithTrackRecord(ctx, [], { "hunt-xss": { weight: 5 } }, null, SKILLS);
  assert.equal(clamped[0].score, 2.3);
  // Nudge lesson v1.2 tetap jalan berdampingan dengan track record.
  const both = routeWithTrackRecord(ctx, [{ skill: "hunt-xss", vuln_class: "Cross-Site Scripting", outcome: "confirmed" }], { "hunt-xss": { weight: 1 } }, null, SKILLS);
  assert.equal(both[0].name, "hunt-xss");
  assert.equal(both[0].score, 2.45); // 2 + 0.15 lesson + 0.3 track
  // Konteks kosong: fallback triage-generic tetap pertama.
  const fb = routeWithTrackRecord("", [], { "hunt-xss": { weight: 1 } }, null, SKILLS);
  assert.equal(fb[0].name, "triage-generic");
});

test("learning: findSimilarV2 menemukan near-duplicate di top-3; query kosong -> []", () => {
  const a = store.addCandidate({ program: "p1", endpoint: "/api/users", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" });
  store.addCandidate({ program: "p1", endpoint: "/api/users", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" });
  store.addCandidate({ program: "p1", endpoint: "/api/search", method: "GET", param: "q", vulnClass: "Cross-Site Scripting", cwe: "CWE-79" });
  const hits = findSimilarV2(store.db, { endpoint: "/api/users", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" });
  assert.ok(hits.length >= 2, `hits=${hits.length}`);
  const topIds = hits.slice(0, 3).map((h) => h.id);
  assert.ok(topIds.includes(a), `top-3=${JSON.stringify(topIds)}`);
  assert.equal(hits[0].endpoint, "/api/users");
  assert.ok(hits[0].score > 0 && hits[0].score <= 1);
  // Skor menurun (terurut) dan dibatasi limit.
  assert.deepEqual(findSimilarV2(store.db, { endpoint: "/api/users", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" }, 1).length, 1);
  // Query kosong -> [].
  assert.deepEqual(findSimilarV2(store.db, {}), []);
  assert.deepEqual(findSimilarV2(store.db, { endpoint: "!!!", param: "---" }), []);
  // DB tanpa tabel FTS -> [] (bukan throw).
  const empty = new DatabaseSync(":memory:");
  try { assert.deepEqual(findSimilarV2(empty, { endpoint: "/api/users" }), []); } finally { empty.close(); }
});
