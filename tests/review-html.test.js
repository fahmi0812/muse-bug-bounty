// tests/review-html.test.js — lib baru: bounty/lib/review-html.js (P1-2)
// buildReviewHtml(candidates) -> string HTML statis (tanpa dependensi/server).
// Tanpa network/Docker/Strix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildReviewHtml } from '../bounty/lib/review-html.js';

const CANDIDATES = [
  { id: 1, program: 'example', method: 'GET', endpoint: '/rest/basket/:id', vuln_class: 'IDOR / Broken Access Control', cwe: 'CWE-639', status: 'candidate' },
  { id: 2, program: 'example', method: 'POST', endpoint: '/api/Feedbacks', vuln_class: 'Stored XSS', cwe: 'CWE-79', status: 'candidate' },
];

test('review-html: berisi kandidat (id/program/method/endpoint/kelas/CWE/status)', () => {
  const html = buildReviewHtml(CANDIDATES);
  for (const needle of ['/rest/basket/:id', 'IDOR / Broken Access Control', 'CWE-639', '/api/Feedbacks', 'Stored XSS', 'CWE-79', 'example', 'candidate']) {
    assert.ok(html.includes(needle), `hilang: ${needle}`);
  }
  assert.match(html, /<table>/);
  assert.match(html, /<th>ID<\/th>/);
});

test('review-html: instruksi approve/reject via CLI ada', () => {
  const html = buildReviewHtml(CANDIDATES);
  assert.ok(html.includes('bounty review --approve'));
  assert.ok(html.includes('bounty review --reject'));
  assert.ok(html.includes('bounty review --queue'));
});

test('review-html: escape HTML — endpoint jahat tidak jadi tag', () => {
  const html = buildReviewHtml([
    { id: 9, program: 'x', method: 'GET', endpoint: '/q?a=<script>alert(1)</script>', vuln_class: 'XSS', cwe: 'CWE-79', status: 'candidate' },
  ]);
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('review-html: daftar kosong tetap halaman valid dengan pesan', () => {
  const html = buildReviewHtml([]);
  assert.match(html, /<!DOCTYPE html>/);
  assert.ok(html.includes('Tidak ada kandidat'));
  assert.ok(html.includes('bounty review --approve'));
});
