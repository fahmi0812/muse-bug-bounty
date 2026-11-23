// tests/planner.test.js — v1.10: planner berbasis coverage ala ARTEX.
// node:test, tanpa dependensi. Store sementara (BOUNTY_DB ke file temp,
// pola seperti tests/integration-v12.test.js).
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { Store } from "../bounty/lib/store.js";
import { recordCoverage } from "../bounty/lib/memory.js";
import {
  SURFACE_CLASSES,
  EXCLUDED_META_CLASSES,
  buildCoverageMap,
  planNext,
  recordSurface,
  coverageSummary,
} from "../bounty/lib/planner.js";

let dir;
let store;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "bounty-planner-"));
  process.env.BOUNTY_DB = join(dir, "bounty.db");
  store = new Store(join(dir, "bounty.db"));
});

afterEach(() => {
  try { store.close(); } catch {}
  delete process.env.BOUNTY_DB;
  rmSync(dir, { recursive: true, force: true });
});

function seedCandidates() {
  // /api/users panas (3 kandidat), /api/login (1), /api/admin (1, XSS disetujui).
  const sqli = store.addCandidate({ program: "p1", endpoint: "/api/users", method: "GET", param: "id", vulnClass: "SQL Injection", cwe: "CWE-89" });
  store.addCandidate({ program: "p1", endpoint: "/api/users", method: "GET", param: "q", vulnClass: "Cross-Site Scripting", cwe: "CWE-79" });
  store.addCandidate({ program: "p1", endpoint: "/api/users", method: "POST", param: "url", vulnClass: "Server-Side Request Forgery", cwe: "CWE-918" });
  store.addCandidate({ program: "p1", endpoint: "/api/login", method: "POST", param: "user", vulnClass: "Session Management", cwe: "CWE-384" });
  const xssAdmin = store.addCandidate({ program: "p1", endpoint: "/api/admin", method: "GET", param: "q", vulnClass: "Cross-Site Scripting", cwe: "CWE-79" });
  store.approveCandidate(xssAdmin);
  return { sqli, xssAdmin };
}

test("planner: SURFACE_CLASSES = kelas vuln dari index, tanpa skill meta, tanpa duplikat", () => {
  assert.ok(SURFACE_CLASSES.length > 50, `terlalu sedikit: ${SURFACE_CLASSES.length}`);
  assert.ok(SURFACE_CLASSES.includes("SQL Injection"));
  assert.ok(SURFACE_CLASSES.includes("Cross-Site Scripting"));
  assert.ok(SURFACE_CLASSES.includes("gRPC Abuse"));
  assert.ok(SURFACE_CLASSES.includes("vCenter Vulnerability Chain"));
  for (const meta of EXCLUDED_META_CLASSES) {
    assert.ok(!SURFACE_CLASSES.includes(meta), `kelas meta ikut terencana: ${meta}`);
  }
  assert.equal(new Set(SURFACE_CLASSES).size, SURFACE_CLASSES.length);
});

test("planner: buildCoverageMap menandai examined dari candidate + ruled_out dari coverage", () => {
  seedCandidates();
  recordCoverage(store.db, "p1", "/api/users", "Remote Code Execution", "ruled_out");
  recordCoverage(store.db, "p1", "/api/login", "SQL Injection", "examined");
  const map = buildCoverageMap(store.db, "p1");
  assert.equal(map.program, "p1");
  assert.deepEqual(map.surfaces.map((s) => s.surface), ["/api/admin", "/api/login", "/api/users"]);
  const users = map.surfaces.find((s) => s.surface === "/api/users").classes;
  assert.equal(users["SQL Injection"], "examined"); // dari candidate
  assert.equal(users["Cross-Site Scripting"], "examined"); // dari candidate
  assert.equal(users["Remote Code Execution"], "ruled_out"); // dari coverage
  assert.equal(users["Race Condition"], "open");
  const login = map.surfaces.find((s) => s.surface === "/api/login").classes;
  assert.equal(login["Session Management"], "examined"); // dari candidate
  assert.equal(login["SQL Injection"], "examined"); // dari baris coverage examined
  assert.equal(login["Race Condition"], "open");
});

test("planner: buildCoverageMap program kosong/tidak ada -> struktur kosong, bukan throw", () => {
  assert.deepEqual(buildCoverageMap(store.db, "tidak-ada"), { program: "tidak-ada", surfaces: [] });
  assert.deepEqual(buildCoverageMap(store.db, null), { program: "", surfaces: [] });
  const empty = new Store(join(dir, "kosong.db"));
  try {
    assert.deepEqual(buildCoverageMap(empty.db, "p1"), { program: "p1", surfaces: [] });
  } finally {
    empty.close();
  }
});

test("planner: planNext mengurutkan aset panas dulu + max 3 per surface + lewati examined/ruled_out", () => {
  seedCandidates();
  recordCoverage(store.db, "p1", "/api/login", "Remote Code Execution", "ruled_out");
  const plan = planNext(store.db, "p1", { limit: 10 });
  assert.ok(plan.length > 0);
  // Item pertama dari surface terpanas (/api/users, 3 kandidat).
  assert.equal(plan[0].surface, "/api/users");
  // Max 3 kelas per surface (noise governor).
  const perSurface = new Map();
  for (const item of plan) perSurface.set(item.surface, (perSurface.get(item.surface) ?? 0) + 1);
  for (const [surface, n] of perSurface) assert.ok(n <= 3, `${surface} dapat ${n} item`);
  // Kelas yang sudah examined/ruled_out tidak pernah direncanakan.
  for (const item of plan) {
    assert.notEqual(item.vulnClass, "SQL Injection", "SQLi sudah examined di /api/users");
    if (item.surface === "/api/login") assert.notEqual(item.vulnClass, "Remote Code Execution");
    if (item.surface === "/api/login") assert.notEqual(item.vulnClass, "Session Management");
  }
  // Di /api/login, XSS (1x terkonfirmasi di program ini) didahulukan
  // atas kelas abjad yang belum pernah terkonfirmasi.
  const loginItems = plan.filter((i) => i.surface === "/api/login");
  assert.equal(loginItems[0].vulnClass, "Cross-Site Scripting");
  assert.match(plan[0].reason, /surface panas/);
  // Limit dipatuhi.
  assert.ok(planNext(store.db, "p1", { limit: 2 }).length <= 2);
});

test("planner: planNext tanpa surface -> [] (bukan error)", () => {
  assert.deepEqual(planNext(store.db, "tidak-ada"), []);
  assert.deepEqual(planNext(store.db, null), []);
});

test("planner: recordSurface menulis baris open tanpa duplikat (2x panggil tetap 1 baris/kelas)", () => {
  const first = recordSurface(store.db, "p1", "/api/baru");
  assert.equal(first, SURFACE_CLASSES.length);
  const second = recordSurface(store.db, "p1", "/api/baru");
  assert.equal(second, 0);
  const rows = store.db.prepare(
    "SELECT COUNT(*) AS n FROM memory_coverage WHERE program = ? AND surface = ?"
  ).get("p1", "/api/baru");
  assert.equal(rows.n, SURFACE_CLASSES.length);
  // Baris yang sudah ada (examined) tidak ditimpa jadi 'open'.
  recordCoverage(store.db, "p1", "/api/baru", "SQL Injection", "examined");
  recordSurface(store.db, "p1", "/api/baru");
  const sqli = store.db.prepare(
    "SELECT status FROM memory_coverage WHERE program = ? AND surface = ? AND vuln_class = ?"
  ).get("p1", "/api/baru", "SQL Injection");
  assert.equal(sqli.status, "examined");
});

test("planner: recordSurface tanpa tabel memory_coverage -> no-op tanpa throw", () => {
  const bare = new DatabaseSync(":memory:");
  bare.exec(`CREATE TABLE candidate (
    id INTEGER PRIMARY KEY AUTOINCREMENT, program TEXT NOT NULL,
    endpoint TEXT NOT NULL, method TEXT NOT NULL, param TEXT NOT NULL DEFAULT '',
    vuln_class TEXT NOT NULL, cwe TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'candidate'
  );`);
  try {
    assert.equal(recordSurface(bare, "p1", "/api/x"), 0);
  } finally {
    bare.close();
  }
});

test("planner: coverageSummary pct benar (18 examined dari 72 total -> 25)", () => {
  recordSurface(store.db, "p1", "/api/satu");
  for (const cls of SURFACE_CLASSES.slice(0, 18)) {
    recordCoverage(store.db, "p1", "/api/satu", cls, "examined");
  }
  const s = coverageSummary(store.db, "p1");
  assert.equal(s.program, "p1");
  assert.equal(s.surfaces, 1);
  assert.equal(s.examined, 18);
  assert.equal(s.open, SURFACE_CLASSES.length - 18);
  assert.equal(s.ruledOut, 0);
  assert.equal(s.pct, 25);
});

test("planner: coverageSummary program kosong -> semua nol, pct 0", () => {
  assert.deepEqual(coverageSummary(store.db, "tidak-ada"), {
    program: "tidak-ada",
    surfaces: 0,
    examined: 0,
    open: 0,
    ruledOut: 0,
    pct: 0,
  });
});
