// tests/dedup.test.js — lib nyata: bounty/lib/dedup.js
// canonicalKey({endpoint, method, param, vulnClass, cwe}) -> string stabil.
// dedupCandidates(list) -> { unique, duplicates }.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalKey, dedupCandidates } from '../bounty/lib/dedup.js';

const base = {
  endpoint: '/rest/user/login',
  method: 'POST',
  param: '',
  vulnClass: 'SQL Injection',
  cwe: 'CWE-89',
};

test('dedup: key sama untuk variasi case method/endpoint/kelas', () => {
  assert.equal(canonicalKey({ ...base, method: 'post' }), canonicalKey(base));
  assert.equal(canonicalKey({ ...base, endpoint: '/REST/User/Login' }), canonicalKey(base));
  assert.equal(canonicalKey({ ...base, vulnClass: 'sql injection' }), canonicalKey(base));
  assert.equal(canonicalKey({ ...base, cwe: 'cwe-89' }), canonicalKey(base));
});

test('dedup: key sama untuk trailing slash', () => {
  assert.equal(
    canonicalKey({ ...base, endpoint: '/rest/user/login/' }),
    canonicalKey(base),
  );
});

test('dedup: key sama bila param sama, beda bila param beda', () => {
  assert.equal(
    canonicalKey({ ...base, param: 'q' }),
    canonicalKey({ ...base, param: 'q' }),
  );
  assert.notEqual(
    canonicalKey({ ...base, param: 'q' }),
    canonicalKey({ ...base, param: 'id' }),
  );
});

test('dedup: key beda untuk endpoint / kelas / method berbeda', () => {
  assert.notEqual(canonicalKey({ ...base, endpoint: '/api/Feedbacks' }), canonicalKey(base));
  assert.notEqual(canonicalKey({ ...base, vulnClass: 'Reflected XSS' }), canonicalKey(base));
  assert.notEqual(canonicalKey({ ...base, method: 'GET' }), canonicalKey(base));
});

test('dedup: dedupCandidates pisah unik vs duplikat', () => {
  const list = [
    { endpoint: '/rest/user/login', method: 'POST', vulnClass: 'SQL Injection', cwe: 'CWE-89' },
    { endpoint: '/rest/user/login/', method: 'post', vulnClass: 'sql injection', cwe: 'cwe-89' },
    { endpoint: '/rest/user/login', method: 'POST', vulnClass: 'SQL Injection', cwe: 'CWE-89' },
    { endpoint: '/api/Feedbacks', method: 'POST', vulnClass: 'Stored XSS', cwe: 'CWE-79' },
  ];
  const { unique, duplicates } = dedupCandidates(list);
  assert.equal(unique.length, 2);
  assert.equal(duplicates.length, 2);
});

test('dedup: dedupCandidates list tanpa duplikat -> duplicates kosong', () => {
  const { unique, duplicates } = dedupCandidates([
    { endpoint: '/a', method: 'GET', vulnClass: 'XSS', cwe: 'CWE-79' },
    { endpoint: '/b', method: 'GET', vulnClass: 'XSS', cwe: 'CWE-79' },
  ]);
  assert.equal(unique.length, 2);
  assert.equal(duplicates.length, 0);
});
