// tests/patterns.test.js — pola laporan sebagai data terstruktur (v1.2, 2.6).
// Aturan jujur: h1_report_id/link/CVE/tahun/payout hanya bila terverifikasi;
// tanpa h1_report_id -> uncited=true; payout tanpa tahun dilarang.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPatterns, validatePattern, patternsForSkill, patternEvidence } from '../bounty/lib/patterns.js';

const REQUIRED = ['skill', 'subclass', 'cwe', 'cve', 'h1_report_id', 'tahun', 'payout', 'uncited', 'link'];

test('patterns: file dimuat, 12 pola seed (8 Tier 1 + sqli/xss/idor/ssrf)', () => {
  const list = loadPatterns();
  assert.equal(list.length, 12);
  const skills = new Set(list.map((p) => p.skill));
  for (const s of ['hunt-oauth', 'hunt-ato', 'hunt-session', 'hunt-forgot-password', 'hunt-saml', 'hunt-cors', 'hunt-cache-poison', 'hunt-websocket', 'hunt-sqli', 'hunt-xss', 'hunt-idor', 'hunt-ssrf']) {
    assert.ok(skills.has(s), `pola untuk ${s} hilang`);
  }
});

test('patterns: semua pola punya field wajib + CWE valid', () => {
  for (const p of loadPatterns()) {
    for (const f of REQUIRED) assert.ok(f in p, `pola ${p.skill} kehilangan ${f}`);
    assert.match(p.cwe, /^CWE-\d+$/);
    assert.equal(validatePattern(p), true);
  }
});

test('patterns: uncited=true bila h1_report_id null (seed v1.2 semuanya uncited)', () => {
  for (const p of loadPatterns()) {
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

test('patterns: validatePattern menolak h1_report_id tanpa link / uncited salah', () => {
  const noLink = { skill: 'hunt-sqli', subclass: 'X', cwe: 'CWE-89', cve: null, h1_report_id: '123', tahun: 2024, payout: null, uncited: false, link: null };
  assert.throws(() => validatePattern(noLink), /tanpa link/);
  const wrongFlag = { skill: 'hunt-sqli', subclass: 'X', cwe: 'CWE-89', cve: null, h1_report_id: null, tahun: null, payout: null, uncited: false, link: null };
  assert.throws(() => validatePattern(wrongFlag), /uncited=true/);
  const missing = { skill: 'hunt-sqli', subclass: 'X' };
  assert.throws(() => validatePattern(missing), /field wajib/);
});

test('patterns: patternsForSkill + patternEvidence per skill', () => {
  const list = loadPatterns();
  assert.equal(patternsForSkill('hunt-oauth', list).length, 1);
  assert.equal(patternsForSkill('hunt-oauth', list)[0].subclass, 'OAuth Redirect URI Validation Bypass');
  assert.deepEqual(patternEvidence('hunt-oauth', '', list), { skill: 'hunt-oauth', vulnClass: '', cited: 0, uncited: 1, total: 1 });
  // Kelas yang cocok dihitung, kelas yang salah -> 0.
  assert.equal(patternEvidence('hunt-oauth', 'OAuth Flaws', list).total, 1);
  assert.equal(patternEvidence('hunt-oauth', 'SQL Injection', list).total, 0);
  assert.deepEqual(patternEvidence('hunt-tidak-ada', '', list), { skill: 'hunt-tidak-ada', vulnClass: '', cited: 0, uncited: 0, total: 0 });
});
