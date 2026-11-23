// tests/graphql.test.js — P1-1 GraphQL schema recovery. Semua tes pakai
// stub fetch (tidak ada target nyata, tidak ada jaringan).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  fingerprintGraphql,
  introspectSchema,
  parseIntrospectionResult,
  rebuildSchemaFromClairvoyance,
  testBola,
  FIELD_WORDLIST,
  TYPE_WORDLIST,
} from "../bounty/lib/graphql.js";

const PROGRAM = { allowedHosts: ["example.com"], deniedPaths: [] };
const URL = "https://example.com/graphql";

function stubFetch(handler) {
  return async (url, init = {}) => {
    const body = init.body ? JSON.parse(init.body) : null;
    const out = handler({ url, method: init.method ?? "GET", body });
    return { ok: out.status !== 500, status: out.status ?? 200, json: async () => out.json, text: async () => JSON.stringify(out.json) };
  };
}

test("wordlist built-in: field + type cukup untuk tebakan (~80 entri)", () => {
  assert.ok(FIELD_WORDLIST.length >= 50);
  assert.ok(TYPE_WORDLIST.length >= 30);
  assert.ok(FIELD_WORDLIST.includes("user") && FIELD_WORDLIST.includes("order"));
  assert.ok(TYPE_WORDLIST.includes("User") && TYPE_WORDLIST.includes("Order"));
});

test("fingerprint: GraphQL + introspection hidup", async () => {
  const fetchFn = stubFetch(({ body }) => {
    if (body?.query?.includes("__schema")) return { json: { data: { __schema: { queryType: { name: "Query" } } } } };
    return { json: { data: { __typename: "Query" } } };
  });
  const r = await fingerprintGraphql(URL, { program: PROGRAM, fetchFn });
  assert.equal(r.isGraphql, true);
  assert.equal(r.introspectionEnabled, true);
});

test("fingerprint: introspection dimatikan terdeteksi; bukan GraphQL terdeteksi", async () => {
  const off = stubFetch(({ body }) => {
    if (body?.query?.includes("__schema")) return { json: { data: null, errors: [{ message: "Introspection is disabled" }] } };
    return { json: { data: { __typename: "Query" } } };
  });
  const r1 = await fingerprintGraphql(URL, { program: PROGRAM, fetchFn: off });
  assert.equal(r1.isGraphql, true);
  assert.equal(r1.introspectionEnabled, false);

  const notGql = stubFetch(() => ({ json: { data: null, errors: [{ message: "Not found" }] } }));
  const r2 = await fingerprintGraphql(URL, { program: PROGRAM, fetchFn: notGql });
  assert.equal(r2.isGraphql, false);
});

test("introspect: schema ter-parse; disabled -> {disabled:true}; gagal jaringan -> {error}", async () => {
  const ok = stubFetch(() => ({
    json: {
      data: {
        __schema: {
          queryType: { name: "Query" },
          mutationType: null,
          subscriptionType: null,
          types: [
            { name: "Query", kind: "OBJECT", fields: [{ name: "user", args: [{ name: "id" }], type: { name: "User", kind: "OBJECT" } }] },
            { name: "User", kind: "OBJECT", fields: [{ name: "id", args: [], type: { name: "ID", kind: "SCALAR" } }] },
            { name: "__Schema", kind: "OBJECT", fields: [] },
          ],
        },
      },
    },
  }));
  const r = await introspectSchema(URL, { program: PROGRAM, fetchFn: ok });
  assert.equal(r.schema.queryType, "Query");
  assert.equal(r.schema.types.length, 2); // __Schema dibuang
  assert.deepEqual(r.schema.types[0].fields[0].args, ["id"]);

  const disabled = stubFetch(() => ({ json: { data: null, errors: [{ message: "Introspection is disabled for this server" }] } }));
  const r2 = await introspectSchema(URL, { program: PROGRAM, fetchFn: disabled });
  assert.equal(r2.disabled, true);

  const failing = async () => { throw new Error("ECONNREFUSED"); };
  const r3 = await introspectSchema(URL, { program: PROGRAM, fetchFn: failing });
  assert.match(r3.error, /gagal/);
});

test("parseIntrospectionResult: tanpa __schema -> null", () => {
  assert.equal(parseIntrospectionResult({}), null);
  assert.equal(parseIntrospectionResult(null), null);
});

test("clairvoyance: field ada/tidak dari error, type dari __type", async () => {
  const fetchFn = stubFetch(({ body }) => {
    const q = body?.query ?? "";
    if (q.includes("__type(name:")) {
      const data = {};
      const names = [...q.matchAll(/t(\d+): __type\(name: "([^"]+)"\)/g)];
      for (const [, idx, name] of names) data[`t${idx}`] = name === "User" ? { name: "User", kind: "OBJECT" } : null;
      return { json: { data } };
    }
    // Tebak field: "user" ada (butuh subfield), "users"/"nope" tidak ada.
    const fields = [...q.matchAll(/a\d+: (\w+) \{ __typename \}/g)].map((m) => m[1]);
    const errors = fields.map((f) => f === "user"
      ? { message: `Field "user" of type "Query" must have a selection of subfields` }
      : { message: `Cannot query field "${f}" on type "Query"` });
    return { json: { data: null, errors } };
  });
  const r = await rebuildSchemaFromClairvoyance(URL, {
    program: PROGRAM, fetchFn,
    fieldWordlist: ["user", "users", "nope"],
    typeWordlist: ["User", "Nope"],
  });
  assert.deepEqual(r.fields, ["user"]);
  assert.deepEqual(r.schema.types.map((t) => t.name), ["User"]);
  assert.match(r.confidence, /partial/);
});

test("testBola: otherId terbaca -> kandidat BOLA high + alias + batching", async () => {
  const fetchFn = stubFetch(({ body }) => {
    if (Array.isArray(body)) return { json: [{ data: { __typename: "Query" } }, { data: { __typename: "Query" } }] };
    const q = body?.query ?? "";
    if (q.includes("a9:")) {
      const data = {};
      for (let i = 0; i < 10; i++) data[`a${i}`] = { id: "1" };
      return { json: { data } };
    }
    if (q.includes('"2"')) return { json: { data: { user: { id: "2" } } } };
    return { json: { data: { user: { id: "1" } } } };
  });
  const r = await testBola(URL, null, { program: PROGRAM, fetchFn, field: "user" });
  assert.equal(r.findings.length, 3);
  const bola = r.findings.find((f) => f.vulnClass === "Broken Object Level Authorization");
  assert.equal(bola.cwe, "CWE-639");
  assert.equal(bola.severity, "high");
  assert.equal(bola.status, "candidate");
  assert.ok(r.findings.some((f) => f.vulnClass === "GraphQL Aliasing Allowed"));
  assert.ok(r.findings.some((f) => f.vulnClass === "GraphQL Batching Allowed"));
});

test("testBola: otherId null -> tidak ada kandidat BOLA, alias/batching tetap dicek", async () => {
  const fetchFn = stubFetch(({ body }) => {
    if (Array.isArray(body)) return { json: [{ data: { __typename: "Query" } }, { data: { __typename: "Query" } }] };
    const q = body?.query ?? "";
    if (q.includes("a9:")) {
      const data = {};
      for (let i = 0; i < 10; i++) data[`a${i}`] = { id: "1" };
      return { json: { data } };
    }
    if (q.includes('"2"')) return { json: { data: { user: null } } };
    return { json: { data: { user: { id: "1" } } } };
  });
  const r = await testBola(URL, null, { program: PROGRAM, fetchFn, field: "user" });
  assert.equal(r.findings.some((f) => f.vulnClass === "Broken Object Level Authorization"), false);
  assert.equal(r.checks.find((c) => c.name === "bola").result, "no");
  assert.equal(r.findings.length, 2); // alias + batching
});

test("testBola: tanpa field dan tanpa schema -> error jelas", async () => {
  const fetchFn = stubFetch(() => ({ json: { data: {} } }));
  const r = await testBola(URL, null, { program: PROGRAM, fetchFn });
  assert.match(r.error, /field objek tidak ditemukan/);
});

test("scope gate: URL di luar scope -> blocked di semua fungsi", async () => {
  const evil = "https://evil.com/graphql";
  const fetchFn = stubFetch(() => ({ json: { data: { __typename: "Query" } } }));
  assert.equal((await fingerprintGraphql(evil, { program: PROGRAM, fetchFn })).blocked, true);
  assert.equal((await introspectSchema(evil, { program: PROGRAM, fetchFn })).blocked, true);
  assert.equal((await rebuildSchemaFromClairvoyance(evil, { program: PROGRAM, fetchFn })).blocked, true);
  assert.equal((await testBola(evil, null, { program: PROGRAM, fetchFn, field: "user" })).blocked, true);
});

test("gagal jaringan -> error object, bukan throw", async () => {
  const failing = async () => { throw new Error("timeout"); };
  const r = await fingerprintGraphql(URL, { program: PROGRAM, fetchFn: failing });
  assert.equal(r.isGraphql, false); // probe gagal = bukan GraphQL terkonfirmasi
  const r2 = await introspectSchema(URL, { program: PROGRAM, fetchFn: failing });
  assert.match(r2.error, /gagal/);
});
