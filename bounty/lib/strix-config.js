// bounty/lib/strix-config.js — pre-flight config Strix sebelum run.
//
// Masalah nyata (24 Nov 2026): Strix crash saat start dengan
// `ValidationError: IntegrationSettings.web_search_provider — Input should
// be 'auto', 'perplexity' or 'exa'` karena nilainya 'custom'. Nilai itu
// TIDAK PERNAH ditulis wrapper (writeStrixConfig hanya menulis 3 kunci
// LLM) — asalnya dari file ~/.strix/cli-config.json (blok {"env": ...}
// yang ditulis Strix persist_current / versi Strix lama) atau dari env
// shell STRIX_WEB_SEARCH_PROVIDER. Upstream: strix/config/settings.py
// (Literal auto|perplexity|exa, default auto, alias
// STRIX_WEB_SEARCH_PROVIDER) + strix/config/loader.py (env menang, lalu
// file {"env": ...}, lalu default; kunci dibaca case-insensitive).
//
// Perbaikan: nilai tak valid di FILE dihapus otomatis (fallback ke default
// 'auto' — 'custom' tidak bisa jalan di Strix mana pun, jadi tidak ada
// niat pengguna yang hilang). Nilai tak valid dari ENV SHELL tidak bisa
// diperbaiki wrapper — run dibatalkan dengan petunjuk unset yang persis.

import { existsSync, readFileSync, writeFileSync } from "node:fs";

export const STRIX_CONFIG_KEY = "STRIX_WEB_SEARCH_PROVIDER";
export const VALID_WEB_SEARCH_PROVIDERS = ["auto", "perplexity", "exa"];

function isValidProvider(value) {
  return typeof value === "string" && VALID_WEB_SEARCH_PROVIDERS.includes(value.toLowerCase());
}

// Cari kunci (case-insensitive) di satu blok objek; kembalikan [key, value]
// atau null bila tidak ada.
function findKey(block, wantedUpper) {
  if (!block || typeof block !== "object") return null;
  for (const key of Object.keys(block)) {
    if (key.toUpperCase() === wantedUpper) return [key, block[key]];
  }
  return null;
}

// Periksa config Strix; sanitasi file bila nilainya tak valid.
// configPath: path ke ~/.strix/cli-config.json (boleh tidak ada).
// env: objek env (default process.env) — untuk tes, kirim env palsu.
// Kembalikan { ok, source: 'file'|'env'|null, value, fixed }.
// - ok:false + source 'env' -> wrapper harus batalkan run (tidak bisa diperbaiki).
// - ok:false + source 'file' -> tulis file gagal (batalkan run juga).
// - ok:true + fixed:true -> kunci tak valid sudah dihapus dari file.
export function checkStrixConfig(configPath, env = process.env) {
  const envVal = env?.[STRIX_CONFIG_KEY];
  if (envVal !== undefined && envVal !== "" && !isValidProvider(envVal)) {
    return { ok: false, source: "env", value: String(envVal), fixed: false };
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
  // Dua bentuk file: flat {STRIX_WEB_SEARCH_PROVIDER: ...} (ditulis
  // wrapper lama) dan {"env": {...}} (ditulis Strix persist_current).
  const blocks = [data, data.env];
  let badValue = null;
  for (const block of blocks) {
    const found = findKey(block, STRIX_CONFIG_KEY);
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
