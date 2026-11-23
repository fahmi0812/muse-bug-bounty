// tests/scope.test.js — lib nyata: bounty/lib/scope.js
// checkScope(program, targetUrl) -> { ok, reason }.
// program: { allowedHosts, allowedPaths, deniedPaths }.
// Fail-closed: scope kosong / host tak dikenal / URL tak valid = ditolak.
// Catatan lib: subdomain ikut lolos bila parent host di-allow
// (hostMatches: h === a || h.endsWith('.' + a)).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkScope, parseProgram } from '../bounty/lib/scope.js';

const PROGRAM = {
  name: 'example',
  allowedHosts: ['example.com'],
  allowedPaths: [],
  deniedPaths: ['/admin', '/.git'],
};

test('scope: host di luar scope diblokir', () => {
  const r = checkScope(PROGRAM, 'https://evil.com/login');
  assert.equal(r.ok, false);
  assert.match(r.reason, /di luar scope/i);
});

test('scope: path denied diblokir walau host benar', () => {
  assert.equal(checkScope(PROGRAM, 'https://example.com/admin').ok, false);
  assert.equal(checkScope(PROGRAM, 'https://example.com/admin/users').ok, false);
  assert.equal(checkScope(PROGRAM, 'https://example.com/.git/config').ok, false);
});

test('scope: host benar + path biasa lolos', () => {
  const r = checkScope(PROGRAM, 'https://example.com/products/search?q=x');
  assert.equal(r.ok, true);
  assert.equal(r.reason, 'Scope OK');
});

test('scope: subdomain parent host lolos, subdomain host lain diblokir', () => {
  assert.equal(checkScope(PROGRAM, 'https://api.example.com/v1/users').ok, true);
  assert.equal(checkScope(PROGRAM, 'https://api.evil.com/v1/users').ok, false);
});

test('scope: allowedPaths non-kosong membatasi path', () => {
  const p = { ...PROGRAM, allowedPaths: ['/api', '/login'] };
  assert.equal(checkScope(p, 'https://example.com/api/users').ok, true);
  assert.equal(checkScope(p, 'https://example.com/other').ok, false);
});

test('scope: scope kosong / URL tak valid fail-closed', () => {
  assert.equal(checkScope({ allowedHosts: [] }, 'https://example.com/').ok, false);
  assert.equal(checkScope({}, 'https://example.com/').ok, false);
  assert.equal(checkScope(null, 'https://example.com/').ok, false);
  assert.equal(checkScope(PROGRAM, 'notaurl').ok, false);
});

test('scope: parseProgram baca Scope/Denied/Budget dari markdown', () => {
  const prog = parseProgram('# example\nScope: example.com, api.example.com\nDenied: /admin\nBudget: 5\n');
  assert.equal(prog.name, 'example');
  assert.deepEqual(prog.allowedHosts, ['example.com', 'api.example.com']);
  assert.deepEqual(prog.deniedPaths, ['/admin']);
  assert.equal(prog.maxBudgetUsd, 5);
});
