// tests/audit.test.js — lib baru: bounty/lib/audit.js (P1-1)
// logAudit(entry, dir) append ke .bounty/audit.jsonl (0600);
// listAudit({ dir, limit }) baca kembali. Append-only, tanpa network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { logAudit, listAudit } from '../bounty/lib/audit.js';

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'bounty-audit-'));
}

test('audit: logAudit tulis entri lengkap + file 0600', () => {
  const dir = tmpDir();
  const rec = logAudit({ command: 'run', target: 'https://example.com', program: 'example', budget: 5, result: 'started' }, dir);
  assert.equal(rec.command, 'run');
  assert.equal(rec.target, 'https://example.com');
  assert.equal(rec.program, 'example');
  assert.equal(rec.budget, 5);
  assert.equal(rec.result, 'started');
  assert.match(rec.ts, /^\d{4}-\d{2}-\d{2}T/);
  assert.ok(rec.actor.length > 0);
  const file = join(dir, 'audit.jsonl');
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(JSON.parse(readFileSync(file, 'utf8').trim()).command, 'run');
});

test('audit: append-only — dua entri tercatat berurutan', () => {
  const dir = tmpDir();
  logAudit({ command: 'run', target: 'https://example.com', program: 'example', budget: 5, result: 'started' }, dir);
  logAudit({ command: 'run', target: 'https://example.com', program: 'example', budget: 5, result: 'ok' }, dir);
  const rows = listAudit({ dir });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].result, 'started');
  assert.equal(rows[1].result, 'ok');
});

test('audit: listAudit limit ambil N terakhir; dir kosong -> []', () => {
  const dir = tmpDir();
  assert.deepEqual(listAudit({ dir }), []);
  for (const r of ['started', 'blocked', 'ok']) {
    logAudit({ command: 'review', result: r }, dir);
  }
  assert.equal(listAudit({ dir, limit: 2 }).length, 2);
  assert.equal(listAudit({ dir, limit: 2 })[1].result, 'ok');
  assert.equal(listAudit({ dir }).length, 3);
});
