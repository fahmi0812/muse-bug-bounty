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

import { routeWithLessons, lessonStats } from '../bounty/lib/router.js';

test('router belajar: lessons confirmed menaikkan ranking skill yang sesuai', () => {
  // 'sql database auth login' -> sqli 2, auth-bypass 2 (seri, sqli dulu).
  const base = routeSkills('sql database auth login', CATALOG);
  assert.equal(base[0].name, 'sqli');
  const lessons = [
    { skill: 'auth-bypass', outcome: 'confirmed' },
    { skill: 'auth-bypass', outcome: 'confirmed' },
    { skill: 'auth-bypass', outcome: 'confirmed' },
  ];
  const top = routeWithLessons('sql database auth login', lessons, null, CATALOG);
  assert.equal(top[0].name, 'auth-bypass');
  assert.equal(top[0].score, 2.45);
});

test('router belajar: lessons false_positive menurunkannya', () => {
  const lessons = [
    { skill: 'sqli', outcome: 'false_positive' },
    { skill: 'sqli', outcome: 'false_positive' },
    { skill: 'sqli', outcome: 'false_positive' },
  ];
  const top = routeWithLessons('sql database auth login', lessons, null, CATALOG);
  assert.equal(top[0].name, 'auth-bypass');
  const sqli = top.find((s) => s.name === 'sqli');
  assert.equal(sqli.score, 1.55);
});

test('router belajar: bonus dibatasi maks +0.45 / -0.45', () => {
  const five = Array.from({ length: 5 }, () => ({ skill: 'auth-bypass', outcome: 'confirmed' }));
  const top = routeWithLessons('sql database auth login', five, null, CATALOG);
  assert.equal(top.find((s) => s.name === 'auth-bypass').score, 2.45);
});

test('router belajar: lesson vuln_class berbeda tidak dihitung', () => {
  const catalog = [
    { name: 'a', vuln_class: 'SQL Injection', keywords: ['sql', 'injection'] },
    { name: 'b', vuln_class: 'Cross-Site Scripting', keywords: ['sql', 'xss'] },
    { name: 'triage-generic', keywords: ['triage'] },
  ];
  const lessons = [
    { skill: 'b', vuln_class: 'SQL Injection', outcome: 'confirmed' },
    { skill: 'b', vuln_class: 'SQL Injection', outcome: 'confirmed' },
    { skill: 'b', vuln_class: 'SQL Injection', outcome: 'confirmed' },
  ];
  const top = routeWithLessons('sql injection', lessons, null, catalog);
  // 'b' kelasnya XSS, lesson kelas SQL Injection tidak berlaku -> skor tetap 1.
  assert.equal(top.find((s) => s.name === 'b').score, 1);
  // Lesson tanpa vuln_class berlaku untuk skill itu di kelas apa pun.
  const top2 = routeWithLessons('sql injection', [{ skill: 'b', outcome: 'confirmed' }], null, catalog);
  assert.equal(top2.find((s) => s.name === 'b').score, 1.15);
});

test('router belajar: tanpa lessons hasil IDENTIK dengan routeSkills()', () => {
  for (const ctx of ['sql injection in login database query', 'reflected cross-site scripting dom', 'hello world', '']) {
    assert.deepEqual(
      routeWithLessons(ctx, [], null, CATALOG),
      routeSkills(ctx, CATALOG),
      `harus identik untuk konteks: ${JSON.stringify(ctx)}`,
    );
    assert.deepEqual(routeWithLessons(ctx, null, null, CATALOG), routeSkills(ctx, CATALOG));
  }
});

test('router belajar: lessonStats menghitung confirmed/falsePositive per skill', () => {
  const stats = lessonStats([
    { skill: 'hunt-sqli', outcome: 'confirmed' },
    { skill: 'hunt-sqli', outcome: 'confirmed' },
    { skill: 'hunt-sqli', outcome: 'false_positive' },
    { skill: 'hunt-xss', outcome: 'false_positive' },
    { skill: 'hunt-xss', outcome: 'bogus' },
    { skill: '', outcome: 'confirmed' },
  ]);
  assert.deepEqual(stats, {
    'hunt-sqli': { confirmed: 2, falsePositive: 1 },
    'hunt-xss': { confirmed: 0, falsePositive: 1 },
  });
});

test('router belajar: hanya pola BERSITASI menambah skor bukti', () => {
  const cited = [{ skill: 'sqli', uncited: false, h1_report_id: '123456', link: 'https://hackerone.com/reports/123456' }];
  const top = routeWithLessons('sql database auth login', [], cited, CATALOG);
  assert.equal(top[0].name, 'sqli');
  assert.equal(top[0].score, 2.05);
  const uncited = [{ skill: 'sqli', uncited: true, h1_report_id: null, link: null }];
  assert.deepEqual(
    routeWithLessons('sql database auth login', [], uncited, CATALOG),
    routeSkills('sql database auth login', CATALOG),
  );
});
