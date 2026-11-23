// bounty/lib/audit.js — audit trail append-only (P1-1).
// Setiap perintah bounty yang berdampak (run/review/report) dicatat ke
// .bounty/audit.jsonl: { ts, actor, command, target, program, budget, result }.
// File 0600, dir 0700, masuk .gitignore (.bounty/). Append-only: fungsi di
// sini tidak pernah menghapus atau menimpa entri lama.
import { appendFileSync, mkdirSync, chmodSync, readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";

export function defaultAuditDir() {
  return resolve(process.cwd(), ".bounty");
}

export function auditFilePath(dir = process.env.BOUNTY_DIR || defaultAuditDir()) {
  return join(resolve(dir), "audit.jsonl");
}

function ensureDir(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { chmodSync(dir, 0o700); } catch {}
}

/**
 * logAudit(entry, dir?) — tambah satu entri ke audit.jsonl.
 * entry: { ts?, actor?, command, target?, program?, budget?, result }.
 * Mengembalikan entri yang ditulis (dengan ts + actor terisi).
 * Tidak pernah melempar bila dir/file bermasalah? Melempar tetap dibiarkan
 * ke pemanggil (CLI membungkus dengan try/catch supaya audit gagal tidak
 * menggagalkan perintah utama).
 */
export function logAudit(entry = {}, dir) {
  const targetDir = resolve(dir ?? process.env.BOUNTY_DIR ?? defaultAuditDir());
  ensureDir(targetDir);
  const record = {
    ts: entry.ts ?? new Date().toISOString(),
    actor: entry.actor ?? process.env.USER ?? process.env.USERNAME ?? "unknown",
    command: entry.command ?? "",
    target: entry.target ?? "",
    program: entry.program ?? "",
    budget: entry.budget ?? null,
    result: entry.result ?? "",
  };
  const file = join(targetDir, "audit.jsonl");
  appendFileSync(file, JSON.stringify(record) + "\n", { mode: 0o600 });
  try { chmodSync(file, 0o600); } catch {}
  return record;
}

/**
 * listAudit({ dir, limit }) — baca semua entri (urut file = urut waktu).
 * Baris yang rusak dilewati, bukan menggagalkan baca. limit>0 ambil N
 * entri terakhir.
 */
export function listAudit({ dir, limit = 0 } = {}) {
  const file = auditFilePath(dir);
  if (!existsSync(file)) return [];
  const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
  const out = [];
  for (const line of lines) {
    try { out.push(JSON.parse(line)); } catch { /* baris rusak dilewati */ }
  }
  return limit > 0 ? out.slice(-limit) : out;
}

export default { logAudit, listAudit, auditFilePath, defaultAuditDir };
