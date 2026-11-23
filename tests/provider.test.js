// tests/provider.test.js — lib nyata: bounty/lib/provider.js
// detectModels({type, baseUrl, apiKey, fetchImpl, timeoutMs}) -> {models}
//   atau {models: [], warning} bila 0 model. Error: 401/403, 404, HTTP lain,
//   timeout -> pesan klasifikasi. fetch di-mock, TANPA network nyata.
// saveProvider({name, type, baseUrl, apiKey, model, dir}) tulis
//   providers.json (meta, tanpa key) + credentials.json, mode 0600.
// loadProviders(dir) -> meta atau null.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, rmSync, readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { detectModels, saveProvider, loadProviders, loadProviderCreds, buildStrixEnv, writeStrixConfig, syncStrixConfig } from '../bounty/lib/provider.js';

const okJson = (data, status = 200) => async () => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => data,
});

test('provider: detect OpenAI kembalikan daftar models', async () => {
  const fetchMock = okJson({ data: [{ id: 'gpt-4o' }, { id: 'gpt-4o-mini' }] });
  const out = await detectModels({
    type: 'openai', baseUrl: 'https://api.openai.com/v1', apiKey: 'sk-test', fetchImpl: fetchMock,
  });
  assert.deepEqual(out.models, ['gpt-4o', 'gpt-4o-mini']);
});

test('provider: detect Anthropic ikuti paginasi (after_id)', async () => {
  const calls = [];
  const fetchMock = async (url) => {
    calls.push(String(url));
    if (String(url).includes('after_id=')) {
      return okJson({ data: [{ id: 'claude-sonnet-4' }], has_more: false })();
    }
    return okJson({ data: [{ id: 'claude-opus-4' }], has_more: true, last_id: 'claude-opus-4' })();
  };
  const out = await detectModels({
    type: 'anthropic', baseUrl: 'https://api.anthropic.com', apiKey: 'sk-ant-test', fetchImpl: fetchMock,
  });
  assert.deepEqual(out.models, ['claude-opus-4', 'claude-sonnet-4']);
  assert.ok(calls.length >= 2, 'harus panggil halaman kedua');
  assert.ok(calls[1].includes('after_id=claude-opus-4'));
});

test('provider: error 401 dilempar sebagai key ditolak', async () => {
  const fetchMock = okJson({ error: { message: 'bad key' } }, 401);
  await assert.rejects(
    () => detectModels({ type: 'openai', baseUrl: 'https://api.openai.com/v1', apiKey: 'sk-bad', fetchImpl: fetchMock }),
    /401/,
  );
});

test('provider: error 404 dilempar sebagai endpoint tidak ditemukan', async () => {
  const fetchMock = okJson({}, 404);
  await assert.rejects(
    () => detectModels({ type: 'anthropic', baseUrl: 'https://api.anthropic.com', apiKey: 'sk-x', fetchImpl: fetchMock }),
    /404/,
  );
});

test('provider: timeout (AbortError) diklasifikasi, bukan hang', async () => {
  const err = new Error('The operation was aborted');
  err.name = 'AbortError';
  const fetchMock = async () => { throw err; };
  await assert.rejects(
    () => detectModels({ type: 'openai', baseUrl: 'https://api.openai.com/v1', apiKey: 'sk-test', fetchImpl: fetchMock, timeoutMs: 50 }),
    /timeout|tidak merespons/i,
  );
});

test('provider: 0 model kembalikan warning, bukan throw', async () => {
  const out = await detectModels({
    type: 'openai', baseUrl: 'https://api.openai.com/v1', apiKey: 'sk-test',
    fetchImpl: okJson({ data: [] }),
  });
  assert.deepEqual(out.models, []);
  assert.equal(out.warning, '0 model');
});

test('provider: save/load round-trip, file 0600, key tidak di providers.json', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bounty-provider-'));
  try {
    saveProvider({
      name: 'openai', type: 'openai', baseUrl: 'https://api.openai.com/v1',
      apiKey: 'sk-SECRET', model: 'gpt-4o', dir,
    });
    const metaPath = join(dir, 'providers.json');
    const credPath = join(dir, 'credentials.json');
    assert.equal(statSync(metaPath).mode & 0o777, 0o600, 'providers.json harus 0600');
    assert.equal(statSync(credPath).mode & 0o777, 0o600, 'credentials.json harus 0600');
    assert.ok(!readFileSync(metaPath, 'utf8').includes('sk-SECRET'), 'key tidak boleh di providers.json');
    assert.ok(readFileSync(credPath, 'utf8').includes('sk-SECRET'));
    const loaded = loadProviders(dir);
    assert.equal(loaded.name, 'openai');
    assert.equal(loaded.model, 'gpt-4o');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('provider: loadProviders dir kosong kembalikan null', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bounty-provider-'));
  try {
    assert.equal(loadProviders(dir), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('provider: loadProviderCreds baca apiKey dari credentials.json', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bounty-provider-'));
  try {
    saveProvider({
      name: 'openai', type: 'openai', baseUrl: 'http://127.0.0.1:20128/v1',
      apiKey: 'test-key-123', model: 'kr/claude-opus-4.8-thinking-agentic', dir,
    });
    const creds = loadProviderCreds(dir);
    assert.equal(creds.model, 'kr/claude-opus-4.8-thinking-agentic');
    assert.equal(creds.apiKey, 'test-key-123');
    assert.equal(creds.baseUrl, 'http://127.0.0.1:20128/v1');
    assert.equal(loadProviderCreds(join(tmpdir(), 'bounty-provider-kosong-')), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('provider: buildStrixEnv bentuk STRIX_LLM openai/<model>', () => {
  assert.deepEqual(
    buildStrixEnv({ type: 'openai', model: 'kr/claude-opus-4.8-thinking-agentic', baseUrl: 'http://127.0.0.1:20128/v1', apiKey: 'test-key-123' }),
    { STRIX_LLM: 'openai/kr/claude-opus-4.8-thinking-agentic', LLM_API_BASE: 'http://127.0.0.1:20128/v1', LLM_API_KEY: 'test-key-123' },
  );
  assert.equal(buildStrixEnv({ type: 'anthropic', model: 'claude-opus-4-8', baseUrl: '', apiKey: '' }).STRIX_LLM, 'anthropic/claude-opus-4-8');
});

// writeStrixConfig/syncStrixConfig menulis ke ~/.strix — HOME diarahkan
// ke temp dir selama tes ini (dikembalikan setelahnya).
test('provider: writeStrixConfig tulis bentuk {"env": ...}, kunci lain dipertahankan', () => {
  const home = mkdtempSync(join(tmpdir(), 'bounty-home-'));
  const savedHome = process.env.HOME;
  try {
    process.env.HOME = home;
    const cfgPath = join(home, '.strix', 'cli-config.json');
    mkdirSync(join(home, '.strix'), { recursive: true });
    writeFileSync(cfgPath, JSON.stringify({ env: { STRIX_WEB_SEARCH_PROVIDER: 'auto', STRIX_LLM: 'openai/lama' } }, null, 2));
    writeStrixConfig('kr/claude-opus-4.8-thinking-agentic', 'http://127.0.0.1:20128/v1', 'test-key-123', 'openai');
    const data = JSON.parse(readFileSync(cfgPath, 'utf8'));
    assert.equal(data.env.STRIX_LLM, 'openai/kr/claude-opus-4.8-thinking-agentic');
    assert.equal(data.env.LLM_API_BASE, 'http://127.0.0.1:20128/v1');
    assert.equal(data.env.LLM_API_KEY, 'test-key-123');
    assert.equal(data.env.STRIX_WEB_SEARCH_PROVIDER, 'auto', 'kunci lain dipertahankan');
    assert.equal('STRIX_LLM' in data, false, 'tidak ada lagi kunci flat di top-level');
  } finally {
    process.env.HOME = savedHome;
    rmSync(home, { recursive: true, force: true });
  }
});

test('provider: writeStrixConfig migrasi file flat lama ke bentuk env', () => {
  const home = mkdtempSync(join(tmpdir(), 'bounty-home-'));
  const savedHome = process.env.HOME;
  try {
    process.env.HOME = home;
    const cfgPath = join(home, '.strix', 'cli-config.json');
    mkdirSync(join(home, '.strix'), { recursive: true });
    writeFileSync(cfgPath, JSON.stringify({ STRIX_LLM: 'openai/lama', LLM_API_BASE: 'http://lama/v1', LLM_API_KEY: 'lama' }, null, 2));
    writeStrixConfig('gpt-4o', 'https://api.openai.com/v1', 'test-key-123', 'openai');
    const data = JSON.parse(readFileSync(cfgPath, 'utf8'));
    assert.equal(data.env.STRIX_LLM, 'openai/gpt-4o');
    assert.equal(data.env.LLM_API_KEY, 'test-key-123');
  } finally {
    process.env.HOME = savedHome;
    rmSync(home, { recursive: true, force: true });
  }
});

test('provider: syncStrixConfig no-op bila sudah sama, tulis bila beda', () => {
  const home = mkdtempSync(join(tmpdir(), 'bounty-home-'));
  const savedHome = process.env.HOME;
  try {
    process.env.HOME = home;
    writeStrixConfig('gpt-4o', 'https://api.openai.com/v1', 'test-key-123', 'openai');
    const cfgPath = join(home, '.strix', 'cli-config.json');
    const before = readFileSync(cfgPath, 'utf8');
    assert.equal(syncStrixConfig('gpt-4o', 'https://api.openai.com/v1', 'test-key-123', 'openai').changed, false);
    assert.equal(readFileSync(cfgPath, 'utf8'), before, 'file tidak ditulis ulang bila sudah sama');
    assert.equal(syncStrixConfig('gpt-4o-mini', 'https://api.openai.com/v1', 'test-key-123', 'openai').changed, true);
    assert.equal(JSON.parse(readFileSync(cfgPath, 'utf8')).env.STRIX_LLM, 'openai/gpt-4o-mini');
  } finally {
    process.env.HOME = savedHome;
    rmSync(home, { recursive: true, force: true });
  }
});
