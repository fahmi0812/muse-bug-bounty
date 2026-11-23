// tests/jsmining.test.js — bounty/lib/jsmining.js (P0-4: jsluice + sourcemapper).
// Tool palsu (shell script di PATH) mencetak JSONL palsu, jadi tidak butuh
// jsluice/sourcemapper asli. Semua hasil = candidate. Nilai secret di
// fixture adalah placeholder EXAMPLE atau dirakit saat runtime (bukan
// secret asli) — dan nilai secret TIDAK PERNAH masuk evidence/store.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseJsluiceUrls, parseJsluiceSecrets, classifySecret, toCandidates, runJsluice, runSourcemapper } from "../bounty/lib/jsmining.js";
import { parseProgram } from "../bounty/lib/scope.js";

const ROOT = resolve(import.meta.dirname, "..");

const JS_PROGRAM = parseProgram(`Nama: JS Program
Scope: example.com
Allowed: /
Budget: $5
Rate: 10 req/detik
Roles: low, high
`);
const JS_URL = "https://example.com/static/app.js";

// --- Parser unit ---

test("jsmining: parseJsluiceUrls -> absolut + relatif (resolve) + lewati data:/mailto:", () => {
  const text = [
    JSON.stringify({ url: "/api/v1/users?role=EXPR", method: "GET" }),
    JSON.stringify({ url: "https://api.example.com/v1/admin", type: "fetch" }),
    JSON.stringify({ url: "data:text/javascript,alert(1)" }),
    JSON.stringify({ url: "mailto:contact@example.com" }),
    "bukan json, dilewati",
    JSON.stringify({ noUrl: true }),
  ].join("\n");
  const f = parseJsluiceUrls(text, JS_URL);
  assert.equal(f.length, 2);
  assert.equal(f[0].url, "https://example.com/api/v1/users?role=EXPR");
  assert.equal(f[0].endpoint, "/api/v1/users");
  assert.equal(f[0].param, "role");
  assert.equal(f[1].url, "https://api.example.com/v1/admin");
  assert.equal(f[1].endpoint, "/v1/admin");
  assert.deepEqual(parseJsluiceUrls("bukan json"), []);
});

test("jsmining: parseJsluiceSecrets -> kind + data + varian field", () => {
  const text = [
    JSON.stringify({ kind: "AWSAccessKey", data: { key: "AKIAEXAMPLEKEY00001", secret: "EXAMPLESECRET00000000000000000000000001" }, severity: "high" }),
    JSON.stringify({ kind: "GenericAPIKey", secret: "api_key=EXAMPLE-TOKEN-abc123", severity: "medium" }),
    JSON.stringify({ kind: "SlackToken", value: "xoxb-EXAMPLE-000000000000" }),
    "bukan json",
    JSON.stringify({ kind: "TanpaNilai" }),
  ].join("\n");
  const f = parseJsluiceSecrets(text);
  assert.equal(f.length, 3);
  assert.equal(f[0].kind, "AWSAccessKey");
  assert.equal(f[0].value, "EXAMPLESECRET00000000000000000000000001");
  assert.equal(f[1].kind, "GenericAPIKey");
  assert.equal(f[2].kind, "SlackToken");
  assert.deepEqual(parseJsluiceSecrets("bukan json"), []);
});

test("jsmining: classifySecret -> format dikenal = high, sisanya medium + perlu verifikasi", () => {
  // Kunci contoh AWS dari dokumentasi, dirakit saat runtime (bukan secret asli).
  const awsKey = "AKIA" + "IOSFODNN7EXAMPLE";
  const known = classifySecret({ kind: "AWSAccessKey", value: awsKey });
  assert.equal(known.severity, "high");
  assert.equal(known.knownFormat, "aws-access-key");
  const unknown = classifySecret({ kind: "GenericAPIKey", value: "EXAMPLE-TOKEN-abc123" });
  assert.equal(unknown.severity, "medium");
  assert.equal(unknown.knownFormat, "");
  assert.match(unknown.note, /perlu verifikasi/);
  assert.equal(classifySecret({ kind: "X", value: "" }).severity, "medium");
});

test("jsmining: toCandidates -> endpoint low (bukan vuln) + secret CWE-798 tanpa nilai di evidence", () => {
  const awsKey = "AKIA" + "IOSFODNN7EXAMPLE";
  const f = toCandidates({
    endpoints: [{ url: "https://example.com/api/v1/users", endpoint: "/api/v1/users", param: "", method: "GET" }],
    secrets: [
      { kind: "AWSAccessKey", value: awsKey },
      { kind: "GenericAPIKey", value: "EXAMPLE-TOKEN-abc123" },
    ],
  }, JS_URL);
  assert.equal(f.length, 3);
  assert.equal(f[0].vulnClass, "Hidden Endpoint / API Discovery");
  assert.equal(f[0].severity, "low");
  assert.equal(f[0].status, "candidate");
  assert.equal(f[1].vulnClass, "Exposed Secret in JS");
  assert.equal(f[1].cwe, "CWE-798");
  assert.equal(f[1].severity, "high");
  assert.equal(f[2].severity, "medium");
  // Nilai secret tidak boleh bocor ke evidence / kandidat.
  for (const c of f) {
    assert.ok(!c.evidence.includes(awsKey), "evidence tidak boleh berisi nilai secret");
    assert.ok(!c.evidence.includes("EXAMPLE-TOKEN-abc123"), "evidence tidak boleh berisi nilai secret");
  }
  assert.deepEqual(toCandidates({}, JS_URL), []);
});

// --- Runner: binary hilang / scope / tool palsu ---

function fakeToolDir() {
  const dir = mkdtempSync(join(tmpdir(), "bounty-fake-jsmining-"));
  writeFileSync(join(dir, "jsluice"), `#!/bin/sh
if [ "$1" = "urls" ]; then
  echo '{"url": "/api/v1/users?role=EXPR", "method": "GET"}'
  echo '{"url": "https://api.example.com/v1/admin", "type": "fetch"}'
  echo '{"url": "/api/v1/users?role=EXPR", "method": "GET"}'
else
  echo '{"kind": "GenericAPIKey", "secret": "api_key=EXAMPLE-TOKEN-abc123", "severity": "medium"}'
fi
`, { mode: 0o755 });
  writeFileSync(join(dir, "sourcemapper"), `#!/bin/sh
out=""
prev=""
for a in "$@"; do if [ "$prev" = "-output" ]; then out="$a"; fi; prev="$a"; done
mkdir -p "$out/webpack"
echo 'const apiKey = "EXAMPLE";' > "$out/webpack/app.js"
echo '{"version":3}' > "$out/webpack/app.js.map"
`, { mode: 0o755 });
  return dir;
}

test("jsmining: jsluice tanpa binary -> skipped:true; sourcemapper tanpa binary -> skipped:true", () => {
  const emptyDir = mkdtempSync(join(tmpdir(), "bounty-empty-path-"));
  const env = { PATH: emptyDir };
  const j = runJsluice(JS_URL, { program: JS_PROGRAM, env });
  assert.equal(j.skipped, true);
  assert.match(j.reason, /jsluice/);
  assert.deepEqual(j.findings, []);
  const s = runSourcemapper(JS_URL, { program: JS_PROGRAM, env });
  assert.equal(s.skipped, true);
  assert.match(s.reason, /sourcemapper/);
  assert.deepEqual(s.files, []);
});

test("jsmining: JS di luar scope -> blocked (jsluice + sourcemapper)", () => {
  const j = runJsluice("https://evil.com/static/app.js", { program: JS_PROGRAM });
  assert.equal(j.blocked, true);
  assert.match(j.reason, /Scope|Allowed/i);
  assert.deepEqual(j.findings, []);
  const s = runSourcemapper("https://evil.com/static/app.js", { program: JS_PROGRAM });
  assert.equal(s.blocked, true);
  const m = runSourcemapper(JS_URL, { program: JS_PROGRAM, mapUrl: "https://evil.com/static/app.js.map" });
  assert.equal(m.blocked, true, "URL .map di luar scope juga diblokir");
});

test("jsmining: jsluice palsu -> endpoint + secret, duplikat di-dedup", () => {
  const dir = fakeToolDir();
  const env = { PATH: `${dir}:${process.env.PATH}` };
  const r = runJsluice(JS_URL, { program: JS_PROGRAM, env });
  assert.equal(r.skipped, false);
  assert.equal(r.tool, "jsluice");
  assert.equal(r.endpoints.length, 3, "3 baris urls (1 duplikat)");
  assert.equal(r.secrets.length, 1);
  assert.equal(r.rawCount, 4);
  assert.equal(r.findings.length, 3, "duplikat endpoint di-dedup");
  assert.equal(r.duplicates.length, 1);
  assert.ok(r.findings.some((f) => f.vulnClass === "Hidden Endpoint / API Discovery" && f.severity === "low"));
  assert.ok(r.findings.some((f) => f.vulnClass === "Exposed Secret in JS" && f.severity === "medium"));
});

test("jsmining: jsluice file lokal tidak ada -> error (bukan skipped)", () => {
  const r = runJsluice("/tidak/ada/app.js", { program: JS_PROGRAM });
  assert.equal(r.skipped, false);
  assert.match(r.error, /tidak ditemukan/);
});

test("jsmining: sourcemapper palsu -> file sumber diekstrak + dilaporkan", () => {
  const dir = fakeToolDir();
  const env = { PATH: `${dir}:${process.env.PATH}` };
  const outDir = join(dir, "src-out");
  const r = runSourcemapper(JS_URL, { program: JS_PROGRAM, env, outputDir: outDir });
  assert.equal(r.skipped, false);
  assert.equal(r.tool, "sourcemapper");
  assert.equal(r.files.length, 2);
  assert.ok(r.files.every((f) => f.startsWith(outDir)));
  assert.ok(existsSync(join(outDir, "webpack", "app.js")));
  assert.match(r.note, /diekstrak/);
  // Mode -url langsung ke .map.
  const r2 = runSourcemapper("", { program: JS_PROGRAM, env, mapUrl: "https://example.com/static/app.js.map", outputDir: join(dir, "src-out-2") });
  assert.equal(r2.skipped, false);
  assert.equal(r2.files.length, 2);
});

test("jsmining: sourcemapper tanpa input -> error", () => {
  const r = runSourcemapper("", { program: JS_PROGRAM });
  assert.equal(r.skipped, false);
  assert.match(r.error, /tidak diberikan/);
});

export { ROOT };
