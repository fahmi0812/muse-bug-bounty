// bounty/lib/provider.js — provider picker: detect models, save provider, Strix config.
import { mkdirSync, writeFileSync, readFileSync, renameSync, existsSync, chmodSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";

export const NINE_ROUTER_BASE = "http://127.0.0.1:20128/v1";
export const NINE_ROUTER_DOCKER_BASE = "http://host.docker.internal:20128/v1";

function withTimeout(fetchImpl, ms) {
  return async (url, opts) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    try {
      return await fetchImpl(url, { ...opts, signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
    }
  };
}

function classifyError(err, type) {
  const msg = String(err?.message ?? err ?? "");
  const code = err?.code ?? err?.cause?.code ?? "";
  if (err?.name === "AbortError" || /abort|timeout|timed out/i.test(msg)) {
    return new Error("server tidak merespons (timeout)");
  }
  if (code === "ECONNREFUSED" || /ECONNREFUSED|connect ECONNREFUSED/i.test(msg)) {
    return new Error("server tidak berjalan (ECONNREFUSED)");
  }
  return err instanceof Error ? err : new Error(msg || "gagal memanggil provider");
}

export async function detectModels({ type, baseUrl, apiKey, fetchImpl = globalThis.fetch, timeoutMs = 15000 }) {
  const base = String(baseUrl ?? "").replace(/\/+$/, "");
  const t = String(type ?? "openai").toLowerCase();
  const doFetch = withTimeout(fetchImpl, timeoutMs);
  let url;
  let headers = {};
  if (t === "anthropic") {
    url = `${base}/v1/models`;
    headers = { "x-api-key": apiKey, "anthropic-version": "2023-06-01" };
  } else {
    url = `${base}/models`;
    headers = { Authorization: `Bearer ${apiKey}` };
  }

  const models = [];
  let after = null;
  let pages = 0;
  try {
    while (pages < 20) {
      pages += 1;
      const pageUrl = after ? `${url}${url.includes("?") ? "&" : "?"}after_id=${encodeURIComponent(after)}` : url;
      const res = await doFetch(pageUrl, { headers });
      if (res.status === 401 || res.status === 403) {
        throw new Error("key ditolak (401/403)");
      }
      if (res.status === 404) {
        throw new Error("endpoint /models tidak ditemukan (404)");
      }
      if (!res.ok) {
        throw new Error(`provider error HTTP ${res.status}`);
      }
      const body = await res.json();
      const items = body?.data ?? body?.models ?? [];
      for (const item of items) {
        const id = typeof item === "string" ? item : item.id;
        if (id) models.push(id);
      }
      const next = body?.has_more ? (body?.last_id ?? items.at(-1)?.id) : null;
      if (!next || items.length === 0) break;
      after = next;
    }
  } catch (err) {
    throw classifyError(err, t);
  }
  if (models.length === 0) return { models: [], warning: "0 model" };
  return { models };
}

function atomicWrite(path, content, mode = 0o600) {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, content, { mode });
  renameSync(tmp, path);
  try { chmodSync(path, mode); } catch {}
}

export function saveProvider({ name, type, baseUrl, apiKey, model, dir }) {
  const targetDir = resolve(dir ?? join(process.cwd(), ".bounty", "providers"));
  mkdirSync(targetDir, { recursive: true, mode: 0o700 });
  try { chmodSync(targetDir, 0o700); } catch {}
  const meta = { name, type, baseUrl, model, updatedAt: new Date().toISOString() };
  const creds = { name, type, baseUrl, model, apiKey };
  atomicWrite(join(targetDir, "providers.json"), JSON.stringify(meta, null, 2) + "\n");
  atomicWrite(join(targetDir, "credentials.json"), JSON.stringify(creds, null, 2) + "\n");
  // Key TIDAK pernah di-log — caller must not console.log apiKey.
  return { dir: targetDir, metaPath: join(targetDir, "providers.json") };
}

export function loadProviders(dir) {
  const targetDir = resolve(dir ?? join(process.cwd(), ".bounty", "providers"));
  const metaPath = join(targetDir, "providers.json");
  if (!existsSync(metaPath)) return null;
  try {
    return JSON.parse(readFileSync(metaPath, "utf8"));
  } catch {
    return null;
  }
}

export function writeStrixConfig(model, baseUrl, apiKey, type = "openai") {
  const dir = join(homedir(), ".strix");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const t = String(type).toLowerCase() === "anthropic" ? "anthropic" : "openai";
  const config = {
    STRIX_LLM: `${t}/${model}`,
    LLM_API_BASE: baseUrl,
    LLM_API_KEY: apiKey,
  };
  const path = join(dir, "cli-config.json");
  atomicWrite(path, JSON.stringify(config, null, 2) + "\n");
  return path;
}

export default { detectModels, saveProvider, loadProviders, writeStrixConfig, NINE_ROUTER_BASE, NINE_ROUTER_DOCKER_BASE };
