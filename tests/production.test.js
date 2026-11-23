// tests/production.test.js — Slice C: produksi v1.12.0.
// Cek dokumen produksi + .env.example + CI, tanpa network/Docker/Strix.
// Pola secret: cari awalan key asli (sk-, AKIA, ghp_) — placeholder
// REPLACE-ME dan contoh palsu (example.invalid) bukan secret asli.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const nonEmpty = (p) => {
  assert.ok(existsSync(join(ROOT, p)), `${p} harus ada`);
  assert.ok(statSync(join(ROOT, p)).size > 0, `${p} tidak boleh kosong`);
};

test('production: .env.example hanya placeholder, tanpa secret asli', () => {
  const env = read('.env.example');
  assert.ok(env.length > 0);
  assert.match(env, /REPLACE-ME/);
  // Awalan secret asli yang umum — tidak boleh muncul sebagai nilai.
  // (REPLACE-ME / example.invalid dikecualikan: itu placeholder.)
  assert.doesNotMatch(env, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(env, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(env, /ghp_[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(env, /xox[baprs]-[A-Za-z0-9-]{10,}/);
});

test('production: CHANGELOG menyebut 1.12.0', () => {
  const log = read('CHANGELOG.md');
  assert.match(log, /\[1.12.0\]/);
  assert.match(log, /\[1\.1\.0\]/);
  assert.match(log, /2026-11-23/);
});

test('production: ci.yml valid YAML sederhana dan menjalankan npm test', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /npm test/);
  assert.match(ci, /node-version:\s*24/);
  assert.match(ci, /gitleaks/i);
  assert.match(ci, /node --check/);
  // Parse manual sederhana: tiap baris non-kosong bukan tab, dan
  // kunci 'name:' / 'on:' / 'jobs:' ada (struktur minimal YAML).
  for (const line of ci.split('\n')) {
    assert.doesNotMatch(line, /^\t/, 'YAML tidak boleh pakai tab');
  }
  assert.match(ci, /^name:/m);
  assert.match(ci, /^on:/m);
  assert.match(ci, /^jobs:/m);
});

test('production: TEAM.md, SECURITY.md, CONTRIBUTING.md ada dan tidak kosong', () => {
  for (const p of ['docs/TEAM.md', 'SECURITY.md', 'CONTRIBUTING.md']) {
    nonEmpty(p);
  }
  assert.match(read('docs/TEAM.md'), /\$5/);
  assert.match(read('docs/TEAM.md'), /10\/detik|10 req\/detik/);
  assert.match(read('SECURITY.md'), /auto-submit/i);
  assert.match(read('CONTRIBUTING.md'), /REPLACE-ME/);
});

test('production: package.json version 1.13.0', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.version, '1.13.0');
});

test('production: docs P2 ada dan tidak kosong', () => {
  for (const p of [
    'docs/p2-fork-core.md',
    'docs/p2-pentagi.md',
    'docs/p2-mcp-platforms.md',
    'docs/p2-re.md',
    'docs/p2-mobile.md',
    'docs/p2-llm-redteam.md',
    'docs/p2-capture-2fa.md',
  ]) {
    nonEmpty(p);
  }
  assert.match(read('docs/p2-mcp-platforms.md'), /tanpa auto-submit/i);
  assert.match(read('docs/p2-capture-2fa.md'), /bukan bypass|captcha solving/i);
});
