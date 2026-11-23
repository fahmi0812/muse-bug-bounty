// tests/auth.test.js — lib nyata: bounty/lib/auth.js
// getRoleProfile(program, role) -> {role, cookie, token, header, program}.
// buildInstruction(program, role='low') -> string instruksi grey-box.
// Role 'low' vs 'high' berbeda; instruksi menyebut role + scope + budget.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getRoleProfile, buildInstruction } from '../bounty/lib/auth.js';

const PROGRAM = {
  name: 'example',
  allowedHosts: ['example.com'],
  deniedPaths: ['/admin'],
  maxBudgetUsd: 5,
};

test('auth: instruksi low vs high berbeda', () => {
  const low = buildInstruction(PROGRAM, 'low');
  const high = buildInstruction(PROGRAM, 'high');
  assert.notEqual(low, high);
  assert.match(low, /Role: low/);
  assert.match(high, /Role: high/);
});

test('auth: instruksi mengandung scope host + denied path + budget', () => {
  const text = buildInstruction(PROGRAM, 'low');
  assert.match(text, /example\.com/);
  assert.match(text, /\/admin/);
  assert.match(text, /\$5/);
});

test('auth: instruksi melarang submit / bayar / deposit', () => {
  for (const role of ['low', 'high']) {
    const text = buildInstruction(PROGRAM, role);
    assert.match(text, /Jangan submit/i);
    assert.match(text, /jangan bayar/i);
  }
});

test('auth: getRoleProfile kembalikan role + placeholder bila env kosong', () => {
  delete process.env.BOUNTY_COOKIE_LOW;
  delete process.env.BOUNTY_TOKEN_LOW;
  const p = getRoleProfile(PROGRAM, 'low');
  assert.equal(p.role, 'low');
  assert.equal(p.program, 'example');
  assert.equal(p.cookie, 'REPLACE-ME');
  assert.equal(p.token, 'REPLACE-ME');
  assert.match(p.header, /Cookie: REPLACE-ME/);
});

test('auth: getRoleProfile high baca env BOUNTY_COOKIE_HIGH', () => {
  process.env.BOUNTY_COOKIE_HIGH = 'sess=abc';
  process.env.BOUNTY_TOKEN_HIGH = 'tok-xyz';
  try {
    const p = getRoleProfile(PROGRAM, 'high');
    assert.equal(p.role, 'high');
    assert.equal(p.cookie, 'sess=abc');
    assert.equal(p.token, 'tok-xyz');
  } finally {
    delete process.env.BOUNTY_COOKIE_HIGH;
    delete process.env.BOUNTY_TOKEN_HIGH;
  }
});

test('auth: role tak dikenal default ke low', () => {
  const p = getRoleProfile(PROGRAM, 'admin');
  assert.equal(p.role, 'low');
  assert.match(buildInstruction(PROGRAM), /Role: low/);
});
