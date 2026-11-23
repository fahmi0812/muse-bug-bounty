// bounty/lib/strix-config.js — pre-flight config Strix sebelum run.
//
// Masalah nyata (24 Nov 2026): Strix crash saat start dengan
// `ValidationError: IntegrationSettings.web_search_provider — Input should
// be 'auto', 'perplexity' or 'exa'` karena nilainya 'custom'. Nilai itu
// TIDAK PERNAH ditulis wrapper (writeStrixConfig hanya menulis 3 kunci
// LLM) — asalnya dari file ~/.strix/cli-config.json (blok {"env": ...}
// yang ditulis Strix persist_current / versi Strix lama) atau dari env
// shell. Upstream: strix/config/settings.py (Literal auto|perplexity|exa,
// default auto, alias STRIX_WEB_SEARCH_PROVIDER) + strix/config/loader.py
// (env menang, lalu file {"env": ...}, lalu default).
//
// Jebakan yang bikin v1.13.3 belum cukup: pydantic-settings membaca env
// dengan `populate_by_name=True` + `case_sensitive=False`, jadi field ini
// bisa masuk lewat DUA nama env — `STRIX_WEB_SEARCH_PROVIDER` (alias)
// maupun `WEB_SEARCH_PROVIDER` (nama field, tanpa prefix) — dalam huruf
// besar/kecil apa pun. v1.13.3 hanya memeriksa nama alias; nilai 'custom'
// di laptop Fahmi lolos lewat nama field. Karena itu pemeriksaan di sini
// memindai SEMUA kunci env (case-insensitive) untuk kedua nama itu, dan
// di file memeriksa bentuk flat, blok {"env": ...}, DAN bentuk nested
// {"integrations": {...}} (loader versi terinstal bisa membaca bentuk ini).
//
// Perbaikan: nilai tak valid di FILE dihapus otomatis (fallback ke default
// 'auto' — 'custom' tidak bisa jalan di Strix mana pun, jadi tidak ada
// niat pengguna yang hilang). Nilai tak valid dari ENV SHELL tidak bisa
// diperbaiki wrapper — run dibatalkan dengan petunjuk unset yang persis.

import { existsSync, readFileSync, writeFileSync } from "node:fs";

export const STRIX_CONFIG_KEY = "STRIX_WEB_SEARCH_PROVIDER";
export const VALID_WEB_SEARCH_PROVIDERS = ["auto", "perplexity", "exa"];
// Nama env yang bisa mengisi field ini (alias + nama field, case-insensitive).
const ENV_KEY_UPPERS = new Set(["STRIX_WEB_SEARCH_PROVIDER", "WEB_SEARCH_PROVIDER"]);
// Nama kunci file yang bisa mengisi field ini (alias + nama field).
const FILE_KEY_UPPERS = new Set(["STRIX_WEB_SEARCH_PROVIDER", "WEB_SEARCH_PROVIDER"]);

function isValidProvider(value) {
  return typeof value === "string" && VALID_WEB_SEARCH_PROVIDERS.includes(value.toLowerCase());
}

// Cari kunci (case-insensitive) di satu blok objek; kembalikan [key, value]
// atau null bila tidak ada. wanted: Set berisi nama upper yang diterima.
function findKey(block, wanted) {
  if (!block || typeof block !== "object") return null;
  for (const key of Object.keys(block)) {
    if (wanted.has(key.toUpperCase())) return [key, block[key]];
  }
  return null;
}

// Pindai env (case-insensitive) untuk kunci yang mengisi field ini.
function findEnv(env = process.env) {
  if (!env || typeof env !== "object") return null;
  for (const key of Object.keys(env)) {
    if (ENV_KEY_UPPERS.has(key.toUpperCase())) return [key, env[key]];
  }
  return null;
}

// Periksa config Strix; sanitasi file bila nilainya tak valid.
// configPath: path ke ~/.strix/cli-config.json (boleh tidak ada).
// env: objek env (default process.env) — untuk tes, kirim env palsu.
// Kembalikan { ok, source: 'file'|'env'|null, value, fixed, key? }.
// - ok:false + source 'env' -> wrapper harus batalkan run (tidak bisa diperbaiki).
// - ok:false + source 'file' -> tulis file gagal (batalkan run juga).
// - ok:true + fixed:true -> kunci tak valid sudah dihapus dari file.
export function checkStrixConfig(configPath, env = process.env) {
  const envHit = findEnv(env);
  if (envHit && envHit[1] !== undefined && envHit[1] !== "" && !isValidProvider(envHit[1])) {
    return { ok: false, source: "env", value: String(envHit[1]), fixed: false, key: envHit[0] };
  }
  if (!configPath || !existsSync(configPath)) {
    return { ok: true, source: null, value: null, fixed: false };
  }
  let data;
  try {
    data = JSON.parse(readFileSync(configPath, "utf8"));
  } catch {
    // File rusak: Strix sendiri mengabaikannya (loader kembalikan {}).
    return { ok: true, source: null, value: null, fixed: false };
  }
  if (!data || typeof data !== "object") {
    return { ok: true, source: null, value: null, fixed: false };
  }
  // Bentuk file yang diperiksa: flat {STRIX_WEB_SEARCH_PROVIDER: ...}
  // (ditulis wrapper lama), {"env": {...}} (ditulis Strix
  // persist_current), dan {"integrations": {...}} (bentuk nested).
  const blocks = [data, data.env, data.integrations];
  let badValue = null;
  for (const block of blocks) {
    const found = findKey(block, FILE_KEY_UPPERS);
    if (found && !isValidProvider(found[1])) {
      badValue = found[1];
      delete block[found[0]];
    }
  }
  if (badValue === null) {
    return { ok: true, source: null, value: null, fixed: false };
  }
  try {
    // writeFileSync mempertahankan mode file yang sudah ada (0600).
    writeFileSync(configPath, JSON.stringify(data, null, 2) + "\n", "utf8");
  } catch {
    return { ok: false, source: "file", value: String(badValue), fixed: false };
  }
  return { ok: true, source: "file", value: String(badValue), fixed: true };
}
