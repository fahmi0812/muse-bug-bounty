// tests/patterns-cited.test.js — pola BERSITASI P0-2 + v1.9 (112 pola, 21 skill).
// Aturan: tiap pola bersitasi wajib punya h1_report_id + link
// https://hackerone.com/reports/<id> yang cocok dengan ID-nya; pola
// uncited wajib tanpa link; tidak boleh ada (skill, h1_report_id) ganda.
// Sumber: Claude-BugHunter docs/disclosed-reports/*.md (CC-BY-4.0).
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadPatterns, citedPatterns, patternEvidence, validatePattern } from "../bounty/lib/patterns.js";

const EXPECTED_CITED_PER_SKILL = {
  "hunt-ato": 7,
  "hunt-ssrf": 6,
  "hunt-graphql": 6,
  "hunt-business-logic": 6,
  "hunt-oauth": 5,
  "hunt-csrf": 5,
  "hunt-rce": 5,
  "hunt-race-condition": 5,
  "hunt-file-upload": 5,
  "hunt-lfi": 5,
  "hunt-forgot-password": 5,
  "hunt-saml": 5,
  "hunt-sqli": 4,
  "hunt-ssti": 4,
  "hunt-idor": 6,
  "hunt-dom": 6,
  "hunt-jwt-crypto": 5,
  "hunt-mfa-bypass": 5,
  "hunt-cache-poison": 5,
  "hunt-http-smuggling": 8,
  "hunt-auth-bypass": 4,
};

test("cited: 112 pola bersitasi dari 21 skill, semuanya lolos validatePattern", () => {
  const list = loadPatterns();
  const cited = citedPatterns(list);
  assert.equal(cited.length, 112);
  for (const p of cited) assert.equal(validatePattern(p), true);
  const perSkill = {};
  for (const p of cited) perSkill[p.skill] = (perSkill[p.skill] ?? 0) + 1;
  assert.deepEqual(perSkill, EXPECTED_CITED_PER_SKILL);
});

test("cited: tiap pola punya h1_report_id + link H1 yang cocok dengan ID-nya", () => {
  for (const p of citedPatterns()) {
    assert.equal(p.uncited, false);
    assert.match(String(p.h1_report_id), /^\d+$/);
    assert.equal(p.link, `https://hackerone.com/reports/${p.h1_report_id}`);
  }
});

test("cited: tidak ada (skill, h1_report_id) ganda", () => {
  const seen = new Set();
  for (const p of citedPatterns()) {
    const key = `${p.skill}/${p.h1_report_id}`;
    assert.ok(!seen.has(key), `duplikat: ${key}`);
    seen.add(key);
  }
});

test("cited: pola uncited tetap tanpa link dan tanpa h1_report_id", () => {
  const list = loadPatterns();
  const uncited = list.filter((p) => p.uncited === true);
  assert.equal(uncited.length, 12);
  for (const p of uncited) {
    assert.equal(p.link, null);
    assert.equal(p.h1_report_id, null);
  }
});

test("cited: patternEvidence menghitung bukti bersitasi per skill", () => {
  const list = loadPatterns();
  // hunt-ato: 1 seed uncited + 7 bersitasi -> router bonus penuh (3+ pola).
  assert.deepEqual(patternEvidence("hunt-ato", "", list), { skill: "hunt-ato", vulnClass: "", cited: 7, uncited: 1, total: 8 });
  assert.deepEqual(patternEvidence("hunt-ssti", "", list), { skill: "hunt-ssti", vulnClass: "", cited: 4, uncited: 0, total: 4 });
  // Skill tanpa pola bersitasi tetap 0 bukti (mis. hunt-xss hanya seed).
  assert.deepEqual(patternEvidence("hunt-xss", "", list), { skill: "hunt-xss", vulnClass: "", cited: 0, uncited: 1, total: 1 });
});

test("cited: payout hanya ada bila tahun terverifikasi (2 laporan dicek live)", () => {
  const list = loadPatterns();
  const withPayout = list.filter((p) => p.payout != null);
  assert.deepEqual(
    withPayout.map((p) => [p.h1_report_id, p.tahun, p.payout]),
    [["745324", 2019, 20000], ["925585", 2020, 30000]]
  );
  for (const p of list) {
    if (p.payout != null) assert.notEqual(p.tahun, null);
  }
});
