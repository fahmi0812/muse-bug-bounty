// tests/strix-config.test.js — lib nyata: bounty/lib/strix-config.js
// Pre-flight config Strix: STRIX_WEB_SEARCH_PROVIDER tak valid ('custom')
// bikin Strix crash saat start (ValidationError IntegrationSettings).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkStrixConfig } from "../bounty/lib/strix-config.js";

function tmpConfig(obj) {
  const dir = mkdtempSync(join(tmpdir(), "bounty-strixcfg-"));
  const path = join(dir, "cli-config.json");
  if (obj !== null) writeFileSync(path, JSON.stringify(obj, null, 2) + "\n");
  return path;
}

test("strix-config: nilai 'custom' di blok env dihapus, kunci lain dipertahankan", () => {
  const path = tmpConfig({ env: { STRIX_LLM: "openai/x", STRIX_WEB_SEARCH_PROVIDER: "custom" } });
  const r = checkStrixConfig(path, {});
  assert.equal(r.ok, true);
  assert.equal(r.fixed, true);
  assert.equal(r.source, "file");
  assert.equal(r.value, "custom");
  const after = JSON.parse(readFileSync(path, "utf8"));
  assert.equal(after.env.STRIX_LLM, "openai/x");
  assert.equal("STRIX_WEB_SEARCH_PROVIDER" in after.env, false);
});

test("strix-config: nilai 'custom' flat + kunci lowercase ikut dibersihkan", () => {
  const flat = tmpConfig({ STRIX_LLM: "openai/x", STRIX_WEB_SEARCH_PROVIDER: "custom" });
  assert.equal(checkStrixConfig(flat, {}).fixed, true);
  assert.equal("STRIX_WEB_SEARCH_PROVIDER" in JSON.parse(readFileSync(flat, "utf8")), false);
  const lower = tmpConfig({ env: { strix_web_search_provider: "custom" } });
  assert.equal(checkStrixConfig(lower, {}).fixed, true);
  assert.equal("strix_web_search_provider" in JSON.parse(readFileSync(lower, "utf8")).env, false);
});

test("strix-config: nilai valid tidak disentuh; file hilang/rusak tidak memblokir", () => {
  const valid = tmpConfig({ env: { STRIX_WEB_SEARCH_PROVIDER: "exa" } });
  const r = checkStrixConfig(valid, {});
  assert.equal(r.ok, true);
  assert.equal(r.fixed, false);
  assert.equal(JSON.parse(readFileSync(valid, "utf8")).env.STRIX_WEB_SEARCH_PROVIDER, "exa");
  assert.equal(checkStrixConfig(join(tmpdir(), "tidak-ada-cli-config.json"), {}).ok, true);
  const corrupt = tmpConfig(null);
  writeFileSync(corrupt, "{bukan json");
  assert.equal(checkStrixConfig(corrupt, {}).ok, true);
});

test("strix-config: nilai tak valid dari env shell dilaporkan, file tidak disentuh", () => {
  const path = tmpConfig({ env: { STRIX_LLM: "openai/x" } });
  const r = checkStrixConfig(path, { STRIX_WEB_SEARCH_PROVIDER: "custom" });
  assert.equal(r.ok, false);
  assert.equal(r.source, "env");
  assert.equal(r.value, "custom");
  assert.equal(r.fixed, false);
  assert.equal(JSON.parse(readFileSync(path, "utf8")).env.STRIX_LLM, "openai/x");
});

test("strix-config: nama field tanpa prefix (WEB_SEARCH_PROVIDER) juga ditangkap — env + file nested", () => {
  // Jebakan v1.13.3: pydantic-settings populate_by_name membaca nama field
  // tanpa prefix STRIX_ juga — nilai 'custom' lolos lewat jalur ini.
  const envOnly = checkStrixConfig(join(tmpdir(), "tidak-ada-cli-config.json"), { WEB_SEARCH_PROVIDER: "custom" });
  assert.equal(envOnly.ok, false);
  assert.equal(envOnly.source, "env");
  assert.equal(envOnly.key, "WEB_SEARCH_PROVIDER");
  const lowerEnv = checkStrixConfig(join(tmpdir(), "tidak-ada-cli-config.json"), { web_search_provider: "custom" });
  assert.equal(lowerEnv.ok, false);
  assert.equal(lowerEnv.source, "env");
  const nested = tmpConfig({ integrations: { web_search_provider: "custom" }, env: { STRIX_LLM: "openai/x" } });
  const r = checkStrixConfig(nested, {});
  assert.equal(r.ok, true);
  assert.equal(r.fixed, true);
  const after = JSON.parse(readFileSync(nested, "utf8"));
  assert.equal("web_search_provider" in after.integrations, false);
  assert.equal(after.env.STRIX_LLM, "openai/x");
});
