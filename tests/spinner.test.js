// tests/spinner.test.js — lib nyata: bounty/lib/spinner.js
// Spinner satu baris (stderr, TTY saja): frame berputar + waktu berjalan
// + baris terakhir output anak. Di pipe/CI diam total.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Spinner, isInformative, phaseText } from '../bounty/lib/spinner.js';

function fakeStream() {
  const writes = [];
  return {
    writes,
    isTTY: true,
    columns: 80,
    write(s) { writes.push(String(s)); return true; },
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('spinner: start tulis frame, update ganti teks, stop bersihkan baris + berhenti', async () => {
  const stream = fakeStream();
  const sp = new Spinner({ stream, enabled: true });
  sp.start('Strix sedang bekerja…');
  await sleep(250);
  sp.update('Pulling image ghcr.io/usestrix/strix-sandbox:1.4.1');
  await sleep(250);
  sp.stop();
  const joined = stream.writes.join('');
  assert.match(joined, /Strix sedang bekerja/);
  assert.match(joined, /Pulling image/);
  assert.match(joined, /dtk\)/);
  assert.ok(joined.includes('\x1b[2K'), 'stop harus bersihkan baris');
  const countAfterStop = stream.writes.length;
  await sleep(250);
  assert.equal(stream.writes.length, countAfterStop, 'tidak ada tulis lagi setelah stop');
});

test('spinner: disabled (pipe/CI) tidak menulis apa-apa', async () => {
  const stream = fakeStream();
  const sp = new Spinner({ stream, enabled: false });
  sp.start('Strix sedang bekerja…');
  sp.update('Pulling image');
  await sleep(250);
  sp.stop();
  assert.equal(stream.writes.length, 0);
});

test('spinner: teks panjang dipotong sesuai lebar terminal', () => {
  const stream = fakeStream();
  stream.columns = 40;
  const sp = new Spinner({ stream, enabled: true });
  sp.start('x'.repeat(200));
  const line = stream.writes.join('').split('\r').filter(Boolean).pop();
  assert.ok(line.length <= 42, `baris spinner tidak boleh meluber: ${line.length}`);
  assert.match(line, /…/);
  sp.stop();
});

test('spinner: stop sebelum start tidak menulis apa-apa (tidak hapus baris Strix)', () => {
  const stream = fakeStream();
  const sp = new Spinner({ stream, enabled: true });
  sp.stop();
  assert.equal(stream.writes.length, 0);
});

test('spinner: printLine cetak baris sendiri di atas spinner, lalu spinner lanjut', async () => {
  const stream = fakeStream();
  const sp = new Spinner({ stream, enabled: true });
  sp.start('Strix sedang bekerja…');
  await sleep(150);
  sp.printLine('Scanning endpoints…');
  const joined = stream.writes.join('');
  assert.ok(joined.includes('Scanning endpoints…\n'), 'baris live harus tercetak + newline');
  const countAfter = stream.writes.length;
  await sleep(250);
  assert.ok(stream.writes.length > countAfter, 'spinner harus tetap jalan setelah printLine');
  sp.stop();
});

test('spinner: printLine diam bila disabled (pipe/CI)', () => {
  const stream = fakeStream();
  const sp = new Spinner({ stream, enabled: false });
  sp.start('Strix sedang bekerja…');
  sp.printLine('Scanning endpoints…');
  sp.stop();
  assert.equal(stream.writes.length, 0);
});

// Kasus nyata 24 Nov 2026: spinner menampilkan "garis doang" — baris
// output Strix selagi pull image adalah garis simbol, bukan kata-kata.
test('spinner: isInformative tolak garis simbol, terima baris berk kata', () => {
  assert.equal(isInformative('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'), false);
  assert.equal(isInformative('────────────────────────────────────────'), false);
  assert.equal(isInformative('[██████████----------] 12MB/45MB'), false);
  assert.equal(isInformative('====='), false);
  assert.equal(isInformative('ok'), false);
  assert.equal(isInformative('   '), false);
  assert.equal(isInformative('Pulling fs layer'), true);
  assert.equal(isInformative('Scanning endpoints…'), true);
  assert.equal(isInformative('Strix sedang bekerja…'), true);
  assert.equal(isInformative('Found 3 endpoints'), true);
});

test('spinner: phaseText kenali fase pull image Docker', () => {
  assert.equal(phaseText('Pulling fs layer'), 'Menarik image Docker Strix…');
  assert.equal(phaseText('Pulling image ghcr.io/usestrix/strix-sandbox:1.4.1'), 'Menarik image Docker Strix…');
  assert.equal(phaseText('Scanning endpoints…'), null);
});
