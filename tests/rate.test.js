// tests/rate.test.js — lib nyata: bounty/lib/rate.js
// TokenBucket(ratePerSec, burst) — token bucket, refill pakai Date.now.
// backoffDelay(attempt) = min(1000 * 2^attempt, 30000).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TokenBucket, backoffDelay } from '../bounty/lib/rate.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('rate: burst 10 habis setelah 10 tryAcquire di saat yang sama', () => {
  const lim = new TokenBucket(10, 10);
  for (let i = 0; i < 10; i += 1) assert.equal(lim.tryAcquire(), true, `acquire #${i + 1}`);
  assert.equal(lim.tryAcquire(), false, 'acquire #11 harus gagal');
});

test('rate: token terisi lagi setelah 1 detik (10/s)', async () => {
  const lim = new TokenBucket(10, 1);
  assert.equal(lim.tryAcquire(), true);
  assert.equal(lim.tryAcquire(), false);
  await sleep(150);
  assert.equal(lim.tryAcquire(), true, 'setelah ~150ms, 1 token terisi (rate 10/s)');
});

test('rate: refill parsial — setelah ~600ms, >= 5 token baru', async () => {
  const lim = new TokenBucket(10, 10);
  for (let i = 0; i < 10; i += 1) lim.tryAcquire();
  await sleep(600);
  let ok = 0;
  for (let i = 0; i < 10; i += 1) if (lim.tryAcquire()) ok += 1;
  assert.ok(ok >= 5, `minimal 5 token setelah 600ms, dapat ${ok}`);
});

test('rate: backoffDelay naik eksponensial', () => {
  assert.equal(backoffDelay(0), 1000);
  assert.equal(backoffDelay(1), 2000);
  assert.equal(backoffDelay(2), 4000);
  assert.equal(backoffDelay(3), 8000);
  assert.ok(backoffDelay(4) > backoffDelay(3));
});

test('rate: backoffDelay dibatasi 30000', () => {
  assert.equal(backoffDelay(10), 30000);
  assert.equal(backoffDelay(100), 30000);
});

test('rate: default TokenBucket() = 10/s, burst 10', () => {
  const lim = new TokenBucket();
  assert.equal(lim.ratePerSec, 10);
  assert.equal(lim.capacity, 10);
  for (let i = 0; i < 10; i += 1) assert.equal(lim.tryAcquire(), true);
  assert.equal(lim.tryAcquire(), false);
});
