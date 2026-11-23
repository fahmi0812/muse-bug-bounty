// tests/skills-index.test.js — Slice B (P1-5): index skill + wordlist SQL.
// node:test, tanpa dependensi. Cek: index JSON valid, semua file yang
// dirujuk ada, tidak ada entri duplikat, wordlist bersih (tanpa deret
// angka 1-1000, tanpa payload destruktif DROP TABLE / DELETE FROM).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SKILLS_DIR = join(ROOT, 'skills', 'bounty');
const INDEX_PATH = join(SKILLS_DIR, 'skills-index.json');
const WORDLIST_PATH = join(SKILLS_DIR, 'data', 'sql-wordlist-curated.txt');

function loadIndex() {
  return JSON.parse(readFileSync(INDEX_PATH, 'utf8'));
}

test('skills-index: JSON valid dan berupa array tak kosong', () => {
  const index = loadIndex();
  assert.ok(Array.isArray(index), 'index harus array');
  assert.ok(index.length >= 30, `index harus >= 30 entri (lama), dapat ${index.length}`);
});

test('skills-index: semua entri punya field wajib', () => {
  const index = loadIndex();
  for (const e of index) {
    assert.equal(typeof e.name, 'string', `name harus string: ${JSON.stringify(e)}`);
    assert.ok(e.name.length > 0);
    assert.equal(typeof e.file, 'string', `file harus string: ${e.name}`);
    assert.equal(typeof e.vuln_class, 'string', `vuln_class harus string: ${e.name}`);
    assert.equal(typeof e.when, 'string', `when harus string: ${e.name}`);
    assert.ok(Array.isArray(e.keywords), `keywords harus array: ${e.name}`);
  }
});

test('skills-index: semua file skill yang dirujuk ada', () => {
  const index = loadIndex();
  const missing = index
    .filter((e) => !existsSync(join(SKILLS_DIR, e.file)))
    .map((e) => `${e.name} -> ${e.file}`);
  assert.deepEqual(missing, [], `file hilang: ${missing.join(', ')}`);
});

test('skills-index: tidak ada entri duplikat (name dan file)', () => {
  const index = loadIndex();
  const names = index.map((e) => e.name);
  const files = index.map((e) => e.file);
  assert.equal(new Set(names).size, names.length, 'nama duplikat');
  assert.equal(new Set(files).size, files.length, 'file duplikat');
});

test('skills-index: skill baru Slice B terdaftar', () => {
  const index = loadIndex();
  const names = new Set(index.map((e) => e.name));
  for (const n of ['vbsec-21', 'ghost-loop', 'trailofbits', 'review-pr', 'mindmap', 'shannon-tracing', 'sql-wordlist']) {
    assert.ok(names.has(n), `skill baru ${n} harus ada di index`);
  }
});

test('sql-wordlist: file ada dan tidak kosong', () => {
  assert.ok(existsSync(WORDLIST_PATH), 'wordlist harus ada');
  const lines = readFileSync(WORDLIST_PATH, 'utf8').split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
  assert.ok(lines.length >= 10, `wordlist terlalu pendek: ${lines.length} baris`);
  assert.ok(lines.length <= 60, `wordlist harus max ~60 baris payload, dapat ${lines.length}`);
});

test('sql-wordlist: tidak mengandung baris angka 1-1000 berurutan', () => {
  const lines = readFileSync(WORDLIST_PATH, 'utf8')
    .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  const numeric = lines.filter((l) => /^\d+$/.test(l)).map(Number);
  assert.equal(numeric.length, 0, `baris angka murni tidak boleh ada: ${numeric.slice(0, 5).join(', ')}`);
  // Deret berurutan panjang (mis. 1,2,3,...) juga dilarang walau tercampur.
  let run = 1;
  for (let i = 1; i < lines.length; i += 1) {
    if (/^\d+$/.test(lines[i]) && /^\d+$/.test(lines[i - 1]) && Number(lines[i]) === Number(lines[i - 1]) + 1) {
      run += 1;
      assert.ok(run < 10, 'deret angka berurutan terdeteksi di wordlist');
    } else {
      run = 1;
    }
  }
});

test('sql-wordlist: tidak mengandung payload destruktif', () => {
  const text = readFileSync(WORDLIST_PATH, 'utf8');
  assert.ok(!/DROP\s+TABLE/i.test(text), 'wordlist mengandung DROP TABLE');
  assert.ok(!/DELETE\s+FROM/i.test(text), 'wordlist mengandung DELETE FROM');
  assert.ok(!/TRUNCATE\s+TABLE/i.test(text), 'wordlist mengandung TRUNCATE TABLE');
});
