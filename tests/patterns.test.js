// tests/patterns.test.js — pola laporan sebagai data terstruktur (v1.2, 2.6).
// Aturan jujur: h1_report_id/link/CVE/tahun/payout hanya bila terverifikasi;
// tanpa h1_report_id -> uncited=true; payout tanpa tahun dilarang.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPatterns, validatePattern, patternsForSkill, patternEvidence } from '../bounty/lib/patterns.js';

const REQUIRED = ['skill', 'subclass', 'cwe', 'cve', 'h1_report_id', 'tahun', 'payout', 'uncited', 'link'];

test('patterns: file dimuat, 151 pola (12 seed uncited + 139 bersitasi P0-2/v1.9/batch-1A/1B)', () => {
  const list = loadPatterns();
  assert.equal(list.length, 151);
  assert.equal(list.filter((p) => p.uncited === false).length, 139);
  assert.equal(list.filter((p) => p.uncited === true).length, 12);
  const skills = new Set(list.map((p) => p.skill));
  for (const s of ['hunt-oauth', 'hunt-ato', 'hunt-session', 'hunt-forgot-password', 'hunt-saml', 'hunt-cors', 'hunt-cache-poison', 'hunt-websocket', 'hunt-sqli', 'hunt-xss', 'hunt-idor', 'hunt-ssrf']) {
    assert.ok(skills.has(s), `pola untuk ${s} hilang`);
  }
  for (const s of ['hunt-csrf', 'hunt-rce', 'hunt-ssti', 'hunt-graphql', 'hunt-race-condition', 'hunt-business-logic', 'hunt-file-upload', 'hunt-lfi']) {
    assert.ok(skills.has(s), `pola bersitasi untuk ${s} hilang`);
  }
});

test('patterns: semua pola punya field wajib + CWE valid', () => {
  for (const p of loadPatterns()) {
    for (const f of REQUIRED) assert.ok(f in p, `pola ${p.skill} kehilangan ${f}`);
    assert.match(p.cwe, /^CWE-\d+$/);
    assert.equal(validatePattern(p), true);
  }
});

const SEED_SUBCLASSES = new Set([
  'OAuth Redirect URI Validation Bypass',
  'Account Takeover via Password Reset',
  'Session Fixation',
  'Password Reset Token Not Invalidated After Use',
  'SAML Assertion Signature Bypass',
  'CORS Wildcard Origin with Credentials',
  'Web Cache Poisoning via Unkeyed Header',
  'Cross-Site WebSocket Hijacking',
  'Union-Based SQL Injection',
  'Reflected Cross-Site Scripting',
  'IDOR via Predictable Object ID',
  'SSRF via URL Parameter',
]);

test('patterns: 12 pola seed v1.2 tetap uncited (tanpa h1/link/cve/tahun/payout)', () => {
  const seeds = loadPatterns().filter((p) => SEED_SUBCLASSES.has(p.subclass));
  assert.equal(seeds.length, 12);
  for (const p of seeds) {
    assert.equal(p.h1_report_id, null, `seed tidak boleh mengarang h1_report_id: ${p.skill}`);
    assert.equal(p.link, null);
    assert.equal(p.cve, null);
    assert.equal(p.tahun, null);
    assert.equal(p.payout, null);
    assert.equal(p.uncited, true);
  }
});

test('patterns: validatePattern menolak payout tanpa tahun', () => {
  const bad = { skill: 'hunt-sqli', subclass: 'X', cwe: 'CWE-89', cve: null, h1_report_id: null, tahun: null, payout: 500, uncited: true, link: null };
  assert.throws(() => validatePattern(bad), /payout tanpa tahun/);
});

test('patterns: validatePattern menolak h1_report_id tanpa link / uncited salah / link bukan URL', () => {
  const noLink = { skill: 'hunt-sqli', subclass: 'X', cwe: 'CWE-89', cve: null, h1_report_id: '123', tahun: 2024, payout: null, uncited: false, link: null };
  assert.throws(() => validatePattern(noLink), /tanpa link/);
  const wrongFlag = { skill: 'hunt-sqli', subclass: 'X', cwe: 'CWE-89', cve: null, h1_report_id: null, tahun: null, payout: null, uncited: false, link: null };
  assert.throws(() => validatePattern(wrongFlag), /uncited=true/);
  const badLink = { skill: 'hunt-sqli', subclass: 'X', cwe: 'CWE-89', cve: null, h1_report_id: '123', tahun: 2024, payout: null, uncited: false, link: 'bukan-url' };
  assert.throws(() => validatePattern(badLink), /link tidak valid/);
  const missing = { skill: 'hunt-sqli', subclass: 'X' };
  assert.throws(() => validatePattern(missing), /field wajib/);
});

test('patterns: patternsForSkill + patternEvidence per skill', () => {
  const list = loadPatterns();
  // hunt-oauth: 1 seed uncited + 5 bersitasi P0-2.
  assert.equal(patternsForSkill('hunt-oauth', list).length, 6);
  assert.equal(patternsForSkill('hunt-oauth', list)[0].subclass, 'OAuth Redirect URI Validation Bypass');
  assert.deepEqual(patternEvidence('hunt-oauth', '', list), { skill: 'hunt-oauth', vulnClass: '', cited: 5, uncited: 1, total: 6 });
  // Kelas yang cocok dihitung, kelas yang salah -> 0.
  assert.equal(patternEvidence('hunt-oauth', 'OAuth Flaws', list).total, 6);
  assert.equal(patternEvidence('hunt-oauth', 'SQL Injection', list).total, 0);
  assert.deepEqual(patternEvidence('hunt-tidak-ada', '', list), { skill: 'hunt-tidak-ada', vulnClass: '', cited: 0, uncited: 0, total: 0 });
});
