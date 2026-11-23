// tests/store.test.js — lib nyata: bounty/lib/store.js
// class Store(path) — SQLite via node:sqlite (bounty.db).
// upsertProgram(name, scope, policy) / getProgram(name)
// addCandidate({program, endpoint, method, param, vulnClass, cwe})
// listCandidates(program, status) / approveCandidate(id) / rejectCandidate(id)
// addFinding({program, endpoint, method, param, vulnClass, cwe, severity, ...})
// addRun({version, target, lab, tp, fp, fn, timeMs, usd}) / listRuns(limit) / close()
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../bounty/lib/store.js';

function withStore(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'bounty-store-'));
  const store = new Store(join(dir, 'bounty.db'));
  try {
    return fn(store);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test('store: upsert + get program', () => withStore((s) => {
  const p = s.upsertProgram('example', { hosts: ['example.com'] }, { budget: 5 });
  assert.equal(p.name, 'example');
  assert.deepEqual(p.scope, { hosts: ['example.com'] });
  assert.equal(s.getProgram('example').name, 'example');
  assert.equal(s.getProgram('tidak-ada'), null);
}));

test('store: upsert program yang sama update, bukan duplikat', () => withStore((s) => {
  s.upsertProgram('example', { hosts: ['example.com'] }, {});
  s.upsertProgram('example', { hosts: ['example.com', 'api.example.com'] }, {});
  assert.deepEqual(s.getProgram('example').scope.hosts, ['example.com', 'api.example.com']);
}));

test('store: candidate add + list + approve/reject', () => withStore((s) => {
  const id = s.addCandidate({
    program: 'example', endpoint: '/rest/user/login', method: 'POST',
    vulnClass: 'SQL Injection', cwe: 'CWE-89',
  });
  assert.ok(Number.isInteger(id));
  const list = s.listCandidates('example');
  assert.equal(list.length, 1);
  assert.equal(list[0].endpoint, '/rest/user/login');
  assert.equal(list[0].vuln_class, 'SQL Injection');
  const approved = s.approveCandidate(id);
  assert.equal(approved.status, 'approved');
  assert.equal(s.listCandidates('example').length, 0, 'candidate approved tak lagi di list default');
  assert.equal(s.listCandidates('example', 'approved').length, 1);
  const id2 = s.addCandidate({ program: 'example', endpoint: '/x', method: 'GET', vulnClass: 'XSS', cwe: 'CWE-79' });
  assert.equal(s.rejectCandidate(id2).status, 'rejected');
}));

test('store: finding add kembalikan id', () => withStore((s) => {
  const id = s.addFinding({
    program: 'example', endpoint: '/rest/user/login', method: 'POST',
    vulnClass: 'SQL Injection', cwe: 'CWE-89', severity: 'high',
  });
  assert.ok(Number.isInteger(id) && id > 0);
}));

test('store: run add + list', () => withStore((s) => {
  const id = s.addRun({ lab: 'juice-shop', tp: 7, fp: 1, fn: 1, timeMs: 1234, usd: 0.5 });
  assert.ok(Number.isInteger(id));
  const runs = s.listRuns();
  assert.equal(runs.length, 1);
  assert.equal(runs[0].lab, 'juice-shop');
  assert.equal(runs[0].tp, 7);
  assert.equal(runs[0].fp, 1);
  assert.equal(runs[0].fn, 1);
}));

test('store: data bertahan setelah close + open ulang (file)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bounty-store-'));
  const dbPath = join(dir, 'bounty.db');
  try {
    const s1 = new Store(dbPath);
    s1.upsertProgram('persist', { hosts: ['x.example'] }, {});
    s1.close();
    const s2 = new Store(dbPath);
    assert.equal(s2.getProgram('persist').name, 'persist');
    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
