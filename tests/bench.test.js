// tests/bench.test.js — lib nyata: bounty/lib/bench.js
// scoreFindings(findings, oracleArray) -> {tp, fp, fn, precision, recall, fpRate}.
// Kunci cocok: endpoint+method+vuln_class+cwe (case-insensitive).
// median(values) -> median. runBench({labs, runs, runFn}) -> ringkasan per lab.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreFindings, median, runBench, routerAccuracy, expectedSkillFor } from '../bounty/lib/bench.js';
import { routeSkills } from '../bounty/lib/router.js';

const ORACLE = [
  { endpoint: '/rest/user/login', method: 'POST', vuln_class: 'SQL Injection', cwe: 'CWE-89' },
  { endpoint: '/api/Feedbacks', method: 'POST', vuln_class: 'Stored XSS', cwe: 'CWE-79' },
  { endpoint: '/rest/basket/:id', method: 'GET', vuln_class: 'IDOR / Broken Access Control', cwe: 'CWE-639' },
];

test('bench: TP/FP/FN dasar', () => {
  const s = scoreFindings([
    { endpoint: '/rest/user/login', method: 'POST', vuln_class: 'SQL Injection', cwe: 'CWE-89' },
    { endpoint: '/nope', method: 'GET', vuln_class: 'SSRF', cwe: 'CWE-918' },
  ], ORACLE);
  assert.equal(s.tp, 1);
  assert.equal(s.fp, 1);
  assert.equal(s.fn, 2);
});

test('bench: precision/recall benar', () => {
  const s = scoreFindings([
    { endpoint: '/rest/user/login', method: 'POST', vuln_class: 'SQL Injection', cwe: 'CWE-89' },
    { endpoint: '/api/Feedbacks', method: 'POST', vuln_class: 'Stored XSS', cwe: 'CWE-79' },
    { endpoint: '/nope', method: 'GET', vuln_class: 'SSRF', cwe: 'CWE-918' },
  ], ORACLE);
  assert.equal(s.tp, 2);
  assert.equal(s.fp, 1);
  assert.equal(s.fn, 1);
  assert.ok(Math.abs(s.precision - 2 / 3) < 1e-9);
  assert.ok(Math.abs(s.recall - 2 / 3) < 1e-9);
});

test('bench: skor sempurna 1.0/1.0', () => {
  const s = scoreFindings(ORACLE.map((v) => ({ ...v })), ORACLE);
  assert.equal(s.tp, 3);
  assert.equal(s.fp, 0);
  assert.equal(s.fn, 0);
  assert.equal(s.precision, 1);
  assert.equal(s.recall, 1);
});

test('bench: duplikat temuan yang sama dihitung FP kedua dst', () => {
  const f = { endpoint: '/rest/user/login', method: 'POST', vuln_class: 'SQL Injection', cwe: 'CWE-89' };
  const s = scoreFindings([f, { ...f }, { ...f, endpoint: '/rest/user/login/' }], ORACLE);
  assert.equal(s.tp, 1);
  assert.equal(s.fp, 2);
});

test('bench: cwe beda = bukan TP', () => {
  const s = scoreFindings([
    { endpoint: '/rest/user/login', method: 'POST', vuln_class: 'SQL Injection', cwe: 'CWE-79' },
  ], ORACLE);
  assert.equal(s.tp, 0);
  assert.equal(s.fp, 1);
});

test('bench: findings kosong -> TP 0, FN = semua oracle', () => {
  const s = scoreFindings([], ORACLE);
  assert.equal(s.tp, 0);
  assert.equal(s.fp, 0);
  assert.equal(s.fn, 3);
  assert.equal(s.precision, 0);
  assert.equal(s.recall, 0);
});

test('bench: median ganjil & genap & kosong', () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([1, 2, 3, 4]), 2.5);
  assert.equal(median([5]), 5);
  assert.equal(median([]), 0);
});

test('bench: runBench lib jalan dengan runFn mock, median benar', async () => {
  const labs = [{ name: 'mini', oracle: ORACLE }];
  const runFn = async (_lab, i) => ({
    findings: i === 0
      ? ORACLE.slice(0, 2).map((v) => ({ ...v }))
      : ORACLE.map((v) => ({ ...v })),
    time_ms: 100 + i,
    usd: 0,
  });
  const results = await runBench({ labs, runs: 3, runFn });
  assert.equal(results.length, 1);
  assert.equal(results[0].lab, 'mini');
  assert.equal(results[0].runs, 3);
  // per run TP: 2,3,3 -> median 3; FP 0; FN 1,0,0 -> median 0
  assert.equal(results[0].median.tp, 3);
  assert.equal(results[0].median.fp, 0);
  assert.equal(results[0].median.fn, 0);
  assert.equal(results[0].median.recall, 1);
});

test('bench: expectedSkillFor memetakan kelas vuln ke hunt-<kelas>', () => {
  assert.equal(expectedSkillFor('SQL Injection'), 'hunt-sqli');
  assert.equal(expectedSkillFor('Reflected XSS'), 'hunt-xss');
  assert.equal(expectedSkillFor('Stored XSS'), 'hunt-xss');
  assert.equal(expectedSkillFor('IDOR / Broken Access Control'), 'hunt-idor');
  assert.equal(expectedSkillFor('JWT / Broken Authentication'), 'hunt-jwt');
  assert.equal(expectedSkillFor('Path Traversal'), 'hunt-path-traversal');
  assert.equal(expectedSkillFor('CSRF / Missing Authorization'), 'hunt-csrf');
  assert.equal(expectedSkillFor('GraphQL BOLA / Broken Object Level Authorization'), 'hunt-api-bola');
  // v1.12: 3 kelas juice-shop yang tadinya tak terpetakan (fallback hunt-<token>).
  assert.equal(expectedSkillFor('Weak Credentials / Hardcoded'), 'hunt-auth-bypass');
  assert.equal(expectedSkillFor('Sensitive Data Exposure'), 'hunt-secrets');
  assert.equal(expectedSkillFor('DoS via query / Unrestricted Resource Consumption'), 'hunt-dos');
  assert.equal(expectedSkillFor('GraphQL Query Batching / DoS'), 'hunt-graphql'); // graphql menang atas dos
  // v1.12 (lanjutan): mapping yang tadinya jatuh ke fallback hunt-<token>.
  assert.equal(expectedSkillFor('Local File Inclusion'), 'hunt-lfi');
  assert.equal(expectedSkillFor('Excessive Data Exposure'), 'hunt-secrets');
  assert.equal(expectedSkillFor('Broken Function Level Authorization'), 'hunt-broken-access');
});

test('bench: routerAccuracy hit rate dengan router nyata + oracle Juice Shop', () => {
  const acc = routerAccuracy(ORACLE);
  assert.equal(acc.total, 3);
  assert.ok(acc.hit >= 2, `diharapkan >= 2 hit, dapat ${acc.hit}: ${JSON.stringify(acc.perEntry)}`);
  assert.ok(acc.accuracy >= 2 / 3);
  for (const e of acc.perEntry) {
    assert.equal(e.selected.length, 5, 'top-5 selalu 5 skill');
    assert.equal(typeof e.hit, 'boolean');
  }
});

test('bench: routerAccuracy dengan router palsu -> hit rate dihitung benar', () => {
  const fakeRoute = (ctx) => {
    if (ctx.toLowerCase().includes('sql')) return [{ name: 'hunt-sqli' }, { name: 'hunt-xss' }];
    return [{ name: 'triage-generic' }];
  };
  const acc = routerAccuracy(ORACLE, fakeRoute);
  assert.equal(acc.total, 3);
  assert.equal(acc.hit, 1, 'hanya SQL Injection yang hit');
  assert.ok(Math.abs(acc.accuracy - 1 / 3) < 1e-9);
  assert.equal(routerAccuracy([]).accuracy, 0);
  assert.equal(routerAccuracy([], fakeRoute).total, 0);
});
