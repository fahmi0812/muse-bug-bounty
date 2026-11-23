// tests/router.test.js — lib nyata: bounty/lib/router.js
// routeSkills(contextText, skills) -> [{name, score, reason}] maks 5.
// Fallback 'triage-generic' bila konteks kosong atau skor terbaik < 2.
// routerAccuracy(selected, expectedClasses) -> {hit, total, accuracy}.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { routeSkills, routerAccuracy } from '../bounty/lib/router.js';

const CATALOG = [
  { name: 'sqli', keywords: ['sql', 'injection', 'sqli', 'database'] },
  { name: 'xss', keywords: ['xss', 'cross-site', 'script', 'dom'] },
  { name: 'idor', keywords: ['idor', 'object', 'access', 'authorization'] },
  { name: 'ssrf', keywords: ['ssrf', 'server-side', 'request', 'url'] },
  { name: 'auth-bypass', keywords: ['auth', 'login', 'jwt', 'session'] },
  { name: 'file-upload', keywords: ['upload', 'file', 'multipart'] },
  { name: 'triage-generic', keywords: ['triage', 'recon', 'generic'] },
];

test('router: top-5, urut skor desc, maks 5 skill', () => {
  const top = routeSkills('sql injection in login database query', CATALOG);
  assert.equal(top.length, 5);
  assert.equal(top[0].name, 'sqli');
  assert.ok(top[0].score >= 2);
  for (let i = 1; i < top.length; i += 1) {
    assert.ok(top[i - 1].score >= top[i].score, 'skor harus desc');
  }
});

test('router: konteks XSS memilih xss di atas', () => {
  const top = routeSkills('reflected cross-site scripting dom', CATALOG);
  assert.equal(top[0].name, 'xss');
});

test('router: konteks IDOR/auth memilih idor di top-2', () => {
  const top = routeSkills('broken object authorization on user id', CATALOG);
  const names = top.slice(0, 2).map((s) => s.name);
  assert.ok(names.includes('idor'), `top-2 harus berisi idor, dapat ${names}`);
});

test('router: konteks kosong fallback ke triage-generic', () => {
  assert.equal(routeSkills('', CATALOG)[0].name, 'triage-generic');
  assert.equal(routeSkills('   ', CATALOG)[0].name, 'triage-generic');
  assert.equal(routeSkills(null, CATALOG)[0].name, 'triage-generic');
});

test('router: konteks lemah (skor terbaik < 2) fallback ke triage-generic', () => {
  const top = routeSkills('hello world', CATALOG);
  assert.equal(top[0].name, 'triage-generic');
});

test('router: akurasi — routerAccuracy hitung benar', () => {
  const top = routeSkills('blind sql injection database', CATALOG);
  const acc = routerAccuracy(top, ['sqli']);
  assert.equal(acc.hit, 1);
  assert.equal(acc.total, 1);
  assert.equal(acc.accuracy, 1);
  const acc2 = routerAccuracy(top, ['sqli', 'nosuchskill']);
  assert.equal(acc2.accuracy, 0.5, 'hanya sqli yang ada di top-5');
  assert.equal(routerAccuracy(top, []).accuracy, 0);
});
