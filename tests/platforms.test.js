// tests/platforms.test.js — integrasi platform read-only (stub fetchFn).
// Semua token di sini fiktif ("TOKEN_CONTOH") — tidak ada token asli.
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  getProgramScope,
  searchHacktivity,
  draftReport,
  syncScopeToProgram,
} from "../bounty/lib/platforms.js";

const ENV_H1 = { HACKERONE_USERNAME: "peneliti-contoh", HACKERONE_TOKEN: "TOKEN_CONTOH" };
const ENV_BC = { BUGCROWD_TOKEN: "TOKEN_CONTOH" };

function stubFetch(handler) {
  return async (url, opts = {}) => handler(String(url), opts);
}
function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const H1_PROGRAM = {
  data: {
    id: "1234",
    type: "program",
    relationships: {
      structured_scopes: {
        data: [
          { id: "1", type: "structured-scope", attributes: { asset_identifier: "api.example.com", asset_type: "URL", max_severity: "critical", eligible_for_bounty: true } },
          { id: "2", type: "structured-scope", attributes: { asset_identifier: "*.app.example.com", asset_type: "URL", max_severity: "high", eligible_for_bounty: true } },
          { id: "3", type: "structured-scope", attributes: { asset_identifier: "old.example.com", asset_type: "URL", max_severity: "medium", eligible_for_bounty: false } },
        ],
      },
    },
  },
};

test("getProgramScope hackerone: parse structured_scopes tertanam", async () => {
  const fetchFn = stubFetch((url, opts) => {
    assert.match(url, /api\.hackerone\.com\/v1\/hackers\/programs\/acme/);
    assert.match(opts.headers.Authorization, /^Basic /);
    assert.doesNotMatch(opts.headers.Authorization, /TOKEN_CONTOH/); // token tidak dikirim mentah
    return jsonResponse(200, H1_PROGRAM);
  });
  const res = await getProgramScope("hackerone", "acme", { fetchFn, env: ENV_H1 });
  assert.equal(res.platform, "hackerone");
  assert.equal(res.assets.length, 3);
  assert.deepEqual(res.assets[0], { type: "url", identifier: "api.example.com", eligible: true, maxSeverity: "critical" });
  assert.equal(res.assets[2].eligible, false);
});

test("getProgramScope hackerone: fallback ke /programs/{id}/structured_scopes bila tidak tertanam", async () => {
  const seen = [];
  const fetchFn = stubFetch((url) => {
    seen.push(url);
    if (url.includes("/hackers/programs/acme")) return jsonResponse(200, { data: { id: "1234", type: "program" } });
    if (url.includes("/programs/1234/structured_scopes")) {
      return jsonResponse(200, { data: [{ id: "9", attributes: { asset_identifier: "api2.example.com", asset_type: "URL", max_severity: "high" } }] });
    }
    return jsonResponse(404, { errors: [] });
  });
  const res = await getProgramScope("hackerone", "acme", { fetchFn, env: ENV_H1 });
  assert.equal(seen.length, 2);
  assert.deepEqual(res.assets.map((a) => a.identifier), ["api2.example.com"]);
});

test("getProgramScope bugcrowd: parse target_groups (best-effort)", async () => {
  const fetchFn = stubFetch((url, opts) => {
    assert.match(url, /api\.bugcrowd\.com\/programs\/uuid-contoh/);
    assert.match(opts.headers.Authorization, /^Token /);
    assert.equal(opts.headers.Accept, "application/vnd.bugcrowd+json");
    return jsonResponse(200, {
      data: {
        id: "uuid-contoh",
        type: "program",
        attributes: {
          code: "acme",
          current_brief: {
            target_groups: [
              { name: "Web", targets: [{ name: "app.example.com" }, { name: "api.example.com" }] },
            ],
          },
        },
      },
    });
  });
  const res = await getProgramScope("bugcrowd", "uuid-contoh", { fetchFn, env: ENV_BC });
  assert.equal(res.platform, "bugcrowd");
  assert.deepEqual(res.assets.map((a) => a.identifier).sort(), ["api.example.com", "app.example.com"]);
});

test("getProgramScope: token hilang -> error, HTTP 401 -> error object (bukan throw)", async () => {
  const empty = await getProgramScope("hackerone", "acme", { fetchFn: stubFetch(() => jsonResponse(200, {})), env: {} });
  assert.match(empty.error, /token belum diset/);
  const unauth = await getProgramScope("hackerone", "acme", {
    fetchFn: stubFetch(() => jsonResponse(401, { errors: [{ status: 401 }] })),
    env: ENV_H1,
  });
  assert.equal(unauth.status, 401);
  assert.match(unauth.error, /HTTP 401/);
  const unknown = await getProgramScope("intigriti", "acme", { fetchFn: stubFetch(() => jsonResponse(200, {})), env: {} });
  assert.match(unknown.error, /platform tidak dikenal/);
});

test("searchHacktivity hackerone: parse daftar laporan publik", async () => {
  const fetchFn = stubFetch((url) => {
    assert.match(url, /hackerone\.com\/hacktivity\.json\?query=SQL%20injection/);
    return jsonResponse(200, {
      reports: [
        { id: 123, title: "SQL Injection in login", state: "resolved" },
        { id: 456, title: "Blind SQLi in search", state: "triaged" },
      ],
    });
  });
  const res = await searchHacktivity("hackerone", "SQL injection", { fetchFn });
  assert.equal(res.results.length, 2);
  assert.equal(res.results[0].url, "https://hackerone.com/reports/123");
  assert.equal(res.results[0].state, "resolved");
});

test("searchHacktivity bugcrowd: tidak didukung (tanpa throw)", async () => {
  const res = await searchHacktivity("bugcrowd", "XSS", { fetchFn: stubFetch(() => jsonResponse(200, {})) });
  assert.match(res.error, /tidak punya pencarian laporan publik/);
});

test("draftReport: header DRAFT + field temuan + tanpa kata auto-submit", () => {
  const md = draftReport({
    title: "IDOR di /api/users/2",
    endpoint: "https://api.example.com/api/users/2",
    vulnClass: "IDOR",
    cwe: "CWE-639",
    severity: "high",
    evidence: "Respons berisi data user lain (id 2).",
    steps: "1. Login akun A.\n2. GET /api/users/2.",
  });
  assert.match(md, /DRAFT — belum dikirim, kirim manual setelah review/);
  assert.match(md, /IDOR di \/api\/users\/2/);
  assert.match(md, /CWE-639/);
  assert.match(md, /Respons berisi data user lain/);
  assert.match(md, /## Steps to Reproduce/);
  assert.match(md, /## Impact/);
  assert.match(md, /## Remediation/);
  assert.match(md, /TIDAK pernah mengirim/);
  assert.doesNotMatch(md, /dikirim otomatis|kirim otomatis|submit\(\)/i);
});

test("syncScopeToProgram: diff added/removed/unchanged, tanpa menulis file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-platforms-"));
  try {
    const progPath = join(dir, "acme.md");
    writeFileSync(progPath, "# Acme\nScope: api.example.com, legacy.example.com\nAllowed: /api/\nDenied: /admin\nBudget: 5\nRate: 10\nRoles: low\n");
    const fetchFn = stubFetch(() => jsonResponse(200, H1_PROGRAM));
    const res = await syncScopeToProgram("hackerone", "acme", progPath, { fetchFn, env: ENV_H1 });
    // H1: api.example.com, *.app.example.com, old.example.com
    // Lokal: api.example.com, legacy.example.com
    assert.deepEqual(res.added, ["app.example.com", "old.example.com"]);
    assert.deepEqual(res.removed, ["legacy.example.com"]);
    assert.deepEqual(res.unchanged, ["api.example.com"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("syncScopeToProgram: token hilang -> error, file hilang -> error", async () => {
  const fetchFn = stubFetch(() => jsonResponse(200, H1_PROGRAM));
  const noToken = await syncScopeToProgram("hackerone", "acme", "programs/example.md", { fetchFn, env: {} });
  assert.match(noToken.error, /token belum diset/);
  const noFile = await syncScopeToProgram("hackerone", "acme", "/tidak/ada.md", { fetchFn, env: ENV_H1 });
  assert.match(noFile.error, /gagal membaca file program/);
});
