// tests/stdio.test.js — lib nyata: bounty/lib/stdio.js
// chooseStrixStdio: TTY -> inherit (UI live bawaan Strix tampil penuh),
// bukan TTY -> pipe (output diparse + spinner). Override env menang.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chooseStrixStdio } from '../bounty/lib/stdio.js';

test('stdio: TTY pilih inherit, bukan TTY pilih pipe', () => {
  assert.equal(chooseStrixStdio({ stdoutTTY: true, override: '' }), 'inherit');
  assert.equal(chooseStrixStdio({ stdoutTTY: false, override: '' }), 'pipe');
  assert.equal(chooseStrixStdio({ stdoutTTY: false }), 'pipe');
});

test('stdio: override BOUNTY_STRIX_STDIO menang atas TTY', () => {
  assert.equal(chooseStrixStdio({ stdoutTTY: true, override: 'pipe' }), 'pipe');
  assert.equal(chooseStrixStdio({ stdoutTTY: false, override: 'inherit' }), 'inherit');
  assert.equal(chooseStrixStdio({ stdoutTTY: true, override: 'PIPE' }), 'pipe');
  assert.equal(chooseStrixStdio({ stdoutTTY: true, override: 'ngawur' }), 'inherit', 'override tidak dikenal -> ikut aturan TTY');
});
