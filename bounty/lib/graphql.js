// bounty/lib/graphql.js — P1-1 GraphQL schema recovery: fingerprint,
// introspection, clairvoyance (rebuild saat introspection dimatikan),
// lalu tes BOLA / alias / batching. Melengkapi runner graphql-cop di
// lib/runners.js (file ini baru, runners.js tidak disentuh).
//
// Kontrak sama seperti runner lain:
//   - scope gate dulu: target di luar scope program -> { blocked: true }.
//   - gagal jaringan / non-2xx -> { error }, BUKAN throw.
//   - hasil berupa kandidat status "candidate" (UNVERIFIED) — butuh
//     review manusia sebelum dilaporkan.
//   - tes BOLA HANYA memakai dua akun test milik pemanggil (ownId vs
//     otherId, default "1" vs "2"); jangan pernah memakai ID user lain.
//
// Catatan jujur (best-effort, belum terverifikasi live — tidak ada
// server GraphQL di VM ini, semua dites lewat stub fetch):
//   - Bentuk error GraphQL ("Cannot query field ...") mengikuti
//     spesifikasi GraphQL dan dipakai clairvoyance untuk menebak field;
//     server yang memformat error berbeda bisa membuat tebakan meleset
//     (ditandai confidence "partial").
//   - Query introspection yang dipakai adalah subset ringkas dari
//     introspection query standar (queryType/mutationType/types/fields).
//   - Nama field/type di wordlist adalah nama umum (user, post, order,
//     ...); schema dengan nama domain-spesifik tidak akan ketemu oleh
//     clairvoyance — itu batas metode ini, bukan bug.
import { checkScope } from "./scope.js";

export const DEFAULT_TIMEOUT_MS = 15000;
export const TOOL = "graphql";

// Nama umum untuk clairvoyance: ditebak lewat error "Cannot query field"
// (field) dan __type(name:) (type). Bukan unduhan wordlist — built-in.
export const FIELD_WORDLIST = [
  "user", "users", "me", "account", "profile", "post", "posts",
  "comment", "comments", "order", "orders", "product", "products",
  "customer", "customers", "file", "files", "document", "documents",
  "node", "viewer", "search", "feed", "article", "articles", "page",
  "media", "image", "video", "event", "booking", "ticket", "invoice",
  "invoices", "payment", "payments", "session", "token", "role",
  "roles", "permission", "permissions", "group", "groups", "team",
  "organization", "project", "projects", "task", "tasks", "issue",
  "issues", "message", "messages", "notification", "notifications",
  "setting", "settings", "address", "card", "subscription", "plan",
  "coupon", "review", "rating", "category", "tag",
];

export const TYPE_WORDLIST = [
  "User", "Account", "Post", "Comment", "Order", "Product", "Customer",
  "Admin", "Profile", "File", "Document", "Invoice", "Payment",
  "Session", "Token", "Role", "Permission", "Group", "Team",
  "Organization", "Project", "Task", "Issue", "Message",
  "Notification", "Setting", "Address", "Card", "Subscription",
  "Plan", "Coupon", "Review", "Rating", "Category", "Tag", "Article",
  "Page", "Media", "Image", "Video", "Event", "Booking", "Ticket",
  "Query", "Mutation",
];

const INTROSPECTION_QUERY = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind ofType { name kind } } } }
        type { name kind ofType { name kind ofType { name kind } } }
      }
      inputFields { name type { name kind ofType { name kind } } }
      enumValues(includeDeprecated: true) { name }
    }
  }
}`;

function scopeCheck(program, target) {
  if (!program) return { ok: true, reason: "tanpa program — scope tidak dicek" };
  return checkScope(program, target);
}

function blocked(reason) {
  return { tool: TOOL, skipped: false, blocked: true, reason, findings: [], time_ms: 0 };
}

async function readJson(res) {
  if (typeof res.json === "function") {
    try { return await res.json(); } catch { /* jatuh ke text */ }
  }
  const text = typeof res.text === "function" ? await res.text() : "";
  try { return JSON.parse(text); } catch { return null; }
}

// Satu POST GraphQL. Kembalikan { data, errors } atau { error }.
async function gqlPost(url, query, { fetchFn = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS, variables } = {}) {
  const body = { query };
  if (variables !== undefined) body.variables = variables;
  let res;
  try {
    res = await fetchFn(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    return { error: `GraphQL POST gagal: ${e.message}` };
  }
  if (!res || !res.ok) return { error: `GraphQL HTTP ${res ? res.status : "tanpa respons"}` };
  const json = await readJson(res);
  if (!json || typeof json !== "object") return { error: "GraphQL mengembalikan bukan-JSON" };
  return { data: json.data ?? null, errors: Array.isArray(json.errors) ? json.errors : [] };
}

async function gqlGet(url, query, { fetchFn = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const full = `${url}${url.includes("?") ? "&" : "?"}query=${encodeURIComponent(query)}`;
  let res;
  try {
    res = await fetchFn(full, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    return { error: `GraphQL GET gagal: ${e.message}` };
  }
  if (!res || !res.ok) return { error: `GraphQL HTTP ${res ? res.status : "tanpa respons"}` };
  const json = await readJson(res);
  if (!json || typeof json !== "object") return { error: "GraphQL mengembalikan bukan-JSON" };
  return { data: json.data ?? null, errors: Array.isArray(json.errors) ? json.errors : [] };
}

// --- Fingerprint: apakah ini endpoint GraphQL? Apakah introspection hidup? ---
export async function fingerprintGraphql(url, { program, fetchFn = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const started = Date.now();
  const scope = scopeCheck(program, url);
  if (!scope.ok) return blocked(scope.reason);
  const probe = await gqlPost(url, "{ __typename }", { fetchFn, timeoutMs });
  let isGraphql = false;
  if (!probe.error && probe.data && probe.data.__typename === "Query") isGraphql = true;
  if (!isGraphql) {
    const get = await gqlGet(url, "{ __typename }", { fetchFn, timeoutMs });
    if (!get.error && get.data && get.data.__typename === "Query") isGraphql = true;
  }
  if (!isGraphql) {
    return { tool: TOOL, skipped: false, blocked: false, isGraphql: false, introspectionEnabled: null, endpoint: url, time_ms: Date.now() - started };
  }
  const intro = await gqlPost(url, "query { __schema { queryType { name } } }", { fetchFn, timeoutMs });
  let introspectionEnabled = null;
  if (!intro.error && intro.data && intro.data.__schema) introspectionEnabled = true;
  else if (!intro.error && intro.errors.length) {
    const msg = intro.errors.map((e) => String(e.message ?? "")).join(" ").toLowerCase();
    if (msg.includes("introspect")) introspectionEnabled = false;
  }
  return { tool: TOOL, skipped: false, blocked: false, isGraphql: true, introspectionEnabled, endpoint: url, time_ms: Date.now() - started };
}

// --- Introspection penuh -> schema ringkas ---
export function parseIntrospectionResult(data) {
  const schema = data?.__schema;
  if (!schema || typeof schema !== "object") return null;
  const types = (Array.isArray(schema.types) ? schema.types : [])
    .filter((t) => t && typeof t.name === "string" && !t.name.startsWith("__"))
    .map((t) => ({
      name: t.name,
      kind: t.kind ?? "",
      fields: (Array.isArray(t.fields) ? t.fields : []).map((f) => ({
        name: f.name,
        args: (Array.isArray(f.args) ? f.args : []).map((a) => a.name),
        type: f.type?.name ?? f.type?.ofType?.name ?? "",
      })),
    }));
  return {
    queryType: schema.queryType?.name ?? "",
    mutationType: schema.mutationType?.name ?? "",
    subscriptionType: schema.subscriptionType?.name ?? "",
    types,
  };
}

export async function introspectSchema(url, { program, fetchFn = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const started = Date.now();
  const scope = scopeCheck(program, url);
  if (!scope.ok) return blocked(scope.reason);
  const res = await gqlPost(url, INTROSPECTION_QUERY, { fetchFn, timeoutMs });
  if (res.error) return { tool: TOOL, skipped: false, blocked: false, error: res.error, time_ms: Date.now() - started };
  if (res.errors.length) {
    const msg = res.errors.map((e) => String(e.message ?? "")).join(" ").toLowerCase();
    if (msg.includes("introspect")) {
      return { tool: TOOL, skipped: false, blocked: false, disabled: true, reason: "introspection dimatikan server", time_ms: Date.now() - started };
    }
    return { tool: TOOL, skipped: false, blocked: false, error: `introspection error: ${res.errors[0].message ?? "unknown"}`, time_ms: Date.now() - started };
  }
  const schema = parseIntrospectionResult(res.data);
  if (!schema) return { tool: TOOL, skipped: false, blocked: false, error: "introspection tidak mengembalikan __schema", time_ms: Date.now() - started };
  return { tool: TOOL, skipped: false, blocked: false, schema, time_ms: Date.now() - started };
}

// --- Clairvoyance: tebak schema saat introspection dimatikan ---
// Field: kirim `{ a0: <field> { __typename } }` — error "Cannot query
// field" = tidak ada; error lain yang menyebut field itu = ada.
// Type: kirim `{ t0: __type(name: "<Type>") { name kind } }` — null = tidak ada.
function classifyFieldErrors(errors, candidates) {
  const absent = new Set();
  const present = new Set();
  for (const e of errors) {
    const msg = String(e.message ?? "");
    const m = msg.match(/"([^"]+)"/);
    if (!m) continue;
    const name = m[1];
    if (!candidates.includes(name)) continue;
    if (/cannot query field/i.test(msg)) absent.add(name);
    else present.add(name);
  }
  // Field yang tidak disebut di error sama sekali = tidak bisa diputuskan.
  return { present: [...present], absent: [...absent] };
}

export async function rebuildSchemaFromClairvoyance(url, { program, fetchFn = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS, fieldWordlist = FIELD_WORDLIST, typeWordlist = TYPE_WORDLIST, batchSize = 8 } = {}) {
  const started = Date.now();
  const scope = scopeCheck(program, url);
  if (!scope.ok) return blocked(scope.reason);
  const fields = [];
  const unknownFields = [];
  for (let i = 0; i < fieldWordlist.length; i += batchSize) {
    const batch = fieldWordlist.slice(i, i + batchSize);
    const query = `{ ${batch.map((f, j) => `a${j}: ${f} { __typename }`).join(" ")} }`;
    const res = await gqlPost(url, query, { fetchFn, timeoutMs });
    if (res.error) return { tool: TOOL, skipped: false, blocked: false, error: res.error, time_ms: Date.now() - started };
    const { present, absent } = classifyFieldErrors(res.errors, batch);
    fields.push(...present);
    for (const f of batch) if (!present.includes(f) && !absent.includes(f)) unknownFields.push(f);
  }
  const types = [];
  for (let i = 0; i < typeWordlist.length; i += batchSize) {
    const batch = typeWordlist.slice(i, i + batchSize);
    const query = `{ ${batch.map((t, j) => `t${j}: __type(name: "${t}") { name kind }`).join(" ")} }`;
    const res = await gqlPost(url, query, { fetchFn, timeoutMs });
    if (res.error) return { tool: TOOL, skipped: false, blocked: false, error: res.error, time_ms: Date.now() - started };
    if (res.data) {
      batch.forEach((t, j) => {
        const hit = res.data[`t${j}`];
        if (hit && typeof hit === "object" && hit.name) types.push({ name: hit.name, kind: hit.kind ?? "", fields: [] });
      });
    }
  }
  return {
    tool: TOOL, skipped: false, blocked: false,
    schema: { queryType: "Query", mutationType: "", subscriptionType: "", types },
    fields,
    unknownFields,
    confidence: "partial — schema hasil tebakan, verifikasi sebelum dipakai menguji",
    time_ms: Date.now() - started,
  };
}

// --- Tes BOLA / alias / batching ---
// opts.field: field Query yang mengembalikan satu objek (mis. "user").
// opts.idArg: nama argumen ID (default "id"). opts.ownId / opts.otherId:
// ID dua akun test milik pemanggil. opts.subfields: subfield yang diminta.
export async function testBola(url, schema, { program, fetchFn = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS, field = "", idArg = "id", ownId = "1", otherId = "2", subfields = ["id"], aliasCount = 10 } = {}) {
  const started = Date.now();
  const scope = scopeCheck(program, url);
  if (!scope.ok) return blocked(scope.reason);
  const targetField = field || pickBolaField(schema);
  if (!targetField) {
    return { tool: TOOL, skipped: false, blocked: false, error: "field objek tidak ditemukan di schema dan opts.field kosong — berikan field, mis. { field: \"user\" }", findings: [], checks: [], time_ms: Date.now() - started };
  }
  const findings = [];
  const checks = [];
  const sub = subfields.join(" ");
  const q = (id) => `{ ${targetField}(${idArg}: "${id}") { ${sub} } }`;
  const own = await gqlPost(url, q(ownId), { fetchFn, timeoutMs });
  if (own.error) return { tool: TOOL, skipped: false, blocked: false, error: own.error, findings: [], checks: [], time_ms: Date.now() - started };
  const ownObj = own.data?.[targetField] ?? null;
  checks.push({ name: "own-object", result: ownObj ? "ok" : "null", detail: `objek sendiri (id ${ownId}) ${ownObj ? "terbaca" : "null"}` });
  if (ownObj) {
    const other = await gqlPost(url, q(otherId), { fetchFn, timeoutMs });
    if (!other.error && other.data?.[targetField]) {
      const got = other.data[targetField];
      const gotId = String(got.id ?? got[idArg] ?? "");
      if (gotId === String(otherId)) {
        findings.push({
          endpoint: new URL(url).pathname, method: "POST", param: `${targetField}.${idArg}`,
          vulnClass: "Broken Object Level Authorization", cwe: "CWE-639", severity: "high",
          evidence: `query ${targetField}(${idArg}:"${otherId}") mengembalikan objek id ${otherId} tanpa otorisasi pemilik — kandidat, perlu review manusia`,
          status: "candidate",
        });
        checks.push({ name: "bola", result: "candidate", detail: `objek id ${otherId} terbaca dari akun id ${ownId}` });
      } else {
        checks.push({ name: "bola", result: "no", detail: `objek id ${otherId} tidak terbaca (id kembali: ${gotId || "kosong"})` });
      }
    } else {
      checks.push({ name: "bola", result: "no", detail: `objek id ${otherId} tidak terbaca (${other.error ?? "null/error"})` });
    }
  }
  // Alias: field yang sama di-alias N kali dalam 1 request.
  const aliasQuery = `{ ${Array.from({ length: aliasCount }, (_, i) => `a${i}: ${targetField}(${idArg}: "${ownId}") { ${sub} }`).join(" ")} }`;
  const aliasRes = await gqlPost(url, aliasQuery, { fetchFn, timeoutMs });
  if (!aliasRes.error && aliasRes.data) {
    const got = Object.keys(aliasRes.data).length;
    if (got >= aliasCount) {
      findings.push({
        endpoint: new URL(url).pathname, method: "POST", param: targetField,
        vulnClass: "GraphQL Aliasing Allowed", cwe: "CWE-400", severity: "low",
        evidence: `${got}/${aliasCount} alias field ${targetField} berhasil dalam 1 request — memungkinkan bypass rate limit / resource exhaustion; kandidat, perlu review`,
        status: "candidate",
      });
      checks.push({ name: "aliasing", result: "allowed", detail: `${got}/${aliasCount} alias berhasil` });
    } else {
      checks.push({ name: "aliasing", result: "limited", detail: `hanya ${got}/${aliasCount} alias berhasil` });
    }
  } else {
    checks.push({ name: "aliasing", result: "unknown", detail: aliasRes.error ?? "error" });
  }
  // Batching: kirim array 2 query dalam 1 POST.
  let batchRes;
  try {
    const res = await fetchFn(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify([{ query: "{ __typename }" }, { query: "{ __typename }" }]),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res && res.ok) {
      const json = await readJson(res);
      batchRes = Array.isArray(json) ? json : null;
    }
  } catch { batchRes = null; }
  if (batchRes && batchRes.length >= 2) {
    findings.push({
      endpoint: new URL(url).pathname, method: "POST", param: "",
      vulnClass: "GraphQL Batching Allowed", cwe: "CWE-400", severity: "low",
      evidence: "server menerima array 2 query dalam 1 POST — batching aktif, memungkinkan bypass rate limit; kandidat, perlu review",
      status: "candidate",
    });
    checks.push({ name: "batching", result: "allowed", detail: "array 2 query diterima" });
  } else {
    checks.push({ name: "batching", result: "no", detail: "server tidak menerima batch array" });
  }
  return { tool: TOOL, skipped: false, blocked: false, findings, checks, field: targetField, time_ms: Date.now() - started };
}

function pickBolaField(schema) {
  const query = schema?.types?.find((t) => t.name === (schema.queryType || "Query"));
  if (!query || !Array.isArray(query.fields)) return "";
  // Pilih field yang namanya seperti pengambil satu objek (bukan jamak).
  const single = query.fields.find((f) => FIELD_WORDLIST.includes(f.name) && !f.name.endsWith("s") && f.name !== "me");
  if (single) return single.name;
  const withId = query.fields.find((f) => (f.args ?? []).includes("id"));
  return withId ? withId.name : "";
}

export default { fingerprintGraphql, introspectSchema, parseIntrospectionResult, rebuildSchemaFromClairvoyance, testBola, FIELD_WORDLIST, TYPE_WORDLIST };
