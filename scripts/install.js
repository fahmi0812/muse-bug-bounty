// scripts/install.js — installer Node interaktif, dipanggil `bounty install`.
// Tanya Docker 1/2 via readline, simpan ke .bounty/config.json, cetak ringkasan.
// Wizard provider (Mode 2) hanya mencetak langkah berikutnya; key tidak
// pernah diminta di sini tanpa persetujuan user dan tidak pernah di-log.
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import readline from 'node:readline';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

export function parseDockerAnswer(ans) {
  const a = String(ans ?? '').trim().toLowerCase();
  if (a === '2' || a === 'tidak' || a === 'no' || a === 'n') return false;
  return true; // default 1 / Ya
}

export function loadConfig() {
  const p = join(ROOT, '.bounty', 'config.json');
  if (!existsSync(p)) return {};
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return {};
  }
}

export function saveConfig(patch) {
  const dir = join(ROOT, '.bounty');
  mkdirSync(dir, { recursive: true });
  const cfg = { ...loadConfig(), ...patch, installed_at: new Date().toISOString() };
  writeFileSync(join(dir, 'config.json'), JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  return cfg;
}

export function dockerPrompt() {
  return [
    'Pakai Docker untuk lab eval lokal (Juice Shop/DVWA/VAmPI)?',
    '  [1] Ya (default)',
    '  [2] Tidak — bench jalan mode no-docker',
  ].join('\n');
}

export async function runInstaller({ input = process.stdin, output = process.stdout } = {}) {
  const rl = readline.createInterface({ input, output });
  const ask = (q) => new Promise((resolve) => rl.question(q, resolve));

  console.log('== bounty install ==');
  console.log(dockerPrompt());
  const ans = await ask('Pilihan [1/2]: ');
  const useDocker = parseDockerAnswer(ans);
  rl.close();

  const cfg = saveConfig({ docker: useDocker });
  console.log(`\nDocker: ${useDocker ? 'Ya' : 'Tidak (mode no-docker)'}`);
  console.log('Pilihan disimpan di .bounty/config.json');
  console.log('\nRingkasan:');
  console.log(`  - Node: ${process.version}`);
  console.log(`  - Docker: ${useDocker ? 'ya' : 'tidak'}`);
  console.log(`  - Config: ${join(ROOT, '.bounty', 'config.json')}`);
  console.log('\nLangkah berikutnya (Mode 2 — Standalone CLI):');
  console.log('  1. Instal Strix: curl -sSL https://strix.ai/install | bash');
  console.log('  2. Pilih provider saat pertama run (wizard provider);');
  console.log('     key disimpan lokal mode 0600, tidak pernah di-commit.');
  console.log('  3. Coba kering: bounty run --target https://example.com --program example --dry-run');
  return cfg;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const nonInteractive = process.argv.includes('--no-docker')
    ? false
    : process.argv.includes('--docker');
  if (process.argv.includes('--docker') || process.argv.includes('--no-docker')) {
    const cfg = saveConfig({ docker: nonInteractive });
    console.log(`Docker: ${nonInteractive ? 'Ya' : 'Tidak (mode no-docker)'} — disimpan non-interaktif.`);
    console.log(JSON.stringify(cfg, null, 2));
  } else {
    await runInstaller();
  }
}
