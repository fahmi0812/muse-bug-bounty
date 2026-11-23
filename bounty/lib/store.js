// bounty/lib/store.js — SQLite persistence (node:sqlite, zero deps).
// Default DB: ./.bounty/bounty.db (or BOUNTY_DB env). Dir 0700, file 0600.
import { DatabaseSync } from "node:sqlite";
import { mkdirSync, chmodSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";

export const DEFAULT_DB_PATH = resolve(process.cwd(), ".bounty", "bounty.db");

const SCHEMA = `
CREATE TABLE IF NOT EXISTS program (
  name TEXT PRIMARY KEY,
  scope_json TEXT NOT NULL DEFAULT '{}',
  policy_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS asset (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL,
  host TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoint (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  param TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS candidate (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  param TEXT NOT NULL DEFAULT '',
  vuln_class TEXT NOT NULL,
  cwe TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'candidate'
);
CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  param TEXT NOT NULL DEFAULT '',
  vuln_class TEXT NOT NULL,
  cwe TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'medium',
  verdict TEXT NOT NULL DEFAULT 'candidate',
  evidence TEXT NOT NULL DEFAULT '',
  chain_id INTEGER
);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  content TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program TEXT NOT NULL,
  steps_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS run (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  lab TEXT NOT NULL DEFAULT '',
  tp INTEGER NOT NULL DEFAULT 0,
  fp INTEGER NOT NULL DEFAULT 0,
  fn INTEGER NOT NULL DEFAULT 0,
  time_ms INTEGER NOT NULL DEFAULT 0,
  usd REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

export class Store {
  constructor(path = process.env.BOUNTY_DB || DEFAULT_DB_PATH) {
    this.path = resolve(path);
    const dir = dirname(this.path);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // Harden existing dir permissions (best effort).
    try { chmodSync(dir, 0o700); } catch {}
    this.db = new DatabaseSync(this.path);
    this.db.exec(SCHEMA);
    try { chmodSync(this.path, 0o600); } catch {}
  }

  upsertProgram(name, scope = {}, policy = {}) {
    const stmt = this.db.prepare(
      `INSERT INTO program (name, scope_json, policy_json) VALUES (?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET scope_json=excluded.scope_json, policy_json=excluded.policy_json`
    );
    stmt.run(name, JSON.stringify(scope), JSON.stringify(policy));
    return this.getProgram(name);
  }

  getProgram(name) {
    const row = this.db.prepare("SELECT * FROM program WHERE name = ?").get(name);
    if (!row) return null;
    return { name: row.name, scope: JSON.parse(row.scope_json), policy: JSON.parse(row.policy_json) };
  }

  addCandidate({ program, endpoint, method, param = "", vulnClass, cwe = "" }) {
    const stmt = this.db.prepare(
      "INSERT INTO candidate (program, endpoint, method, param, vuln_class, cwe) VALUES (?, ?, ?, ?, ?, ?)"
    );
    const info = stmt.run(program, endpoint, method, param, vulnClass, cwe);
    return Number(info.lastInsertRowid);
  }

  addFinding({ program, endpoint, method, param = "", vulnClass, cwe = "", severity = "medium", verdict = "candidate", evidence = "", chainId = null }) {
    const stmt = this.db.prepare(
      "INSERT INTO finding (program, endpoint, method, param, vuln_class, cwe, severity, verdict, evidence, chain_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    const info = stmt.run(program, endpoint, method, param, vulnClass, cwe, severity, verdict, evidence, chainId);
    return Number(info.lastInsertRowid);
  }

  addEvidence(findingId, kind, content) {
    const info = this.db.prepare(
      "INSERT INTO evidence (finding_id, kind, content) VALUES (?, ?, ?)"
    ).run(findingId, kind, content);
    return Number(info.lastInsertRowid);
  }

  addChain(program, steps = []) {
    const info = this.db.prepare(
      "INSERT INTO chain (program, steps_json) VALUES (?, ?)"
    ).run(program, JSON.stringify(steps));
    return Number(info.lastInsertRowid);
  }

  listCandidates(program = null, status = "candidate") {
    if (program) {
      return this.db.prepare(
        "SELECT * FROM candidate WHERE program = ? AND status = ? ORDER BY id"
      ).all(program, status);
    }
    return this.db.prepare(
      "SELECT * FROM candidate WHERE status = ? ORDER BY id"
    ).all(status);
  }

  approveCandidate(id) {
    this.db.prepare("UPDATE candidate SET status = 'approved' WHERE id = ?").run(id);
    return this.db.prepare("SELECT * FROM candidate WHERE id = ?").get(id) ?? null;
  }

  rejectCandidate(id) {
    this.db.prepare("UPDATE candidate SET status = 'rejected' WHERE id = ?").run(id);
    return this.db.prepare("SELECT * FROM candidate WHERE id = ?").get(id) ?? null;
  }

  addRun({ version = "", target = "", lab = "", tp = 0, fp = 0, fn = 0, timeMs = 0, usd = 0 }) {
    const info = this.db.prepare(
      "INSERT INTO run (version, target, lab, tp, fp, fn, time_ms, usd) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(version, target, lab, tp, fp, fn, timeMs, usd);
    return Number(info.lastInsertRowid);
  }

  listRuns(limit = 50) {
    return this.db.prepare("SELECT * FROM run ORDER BY id DESC LIMIT ?").all(limit);
  }

  close() {
    this.db.close();
  }
}

export default Store;
