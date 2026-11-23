// tests/cloud.test.js — enumerasi cloud + takeover P1-2 (tanpa kredensial).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { loadProgramFile } from "../bounty/lib/scope.js";
import {
  checkTakeover, matchTakeoverService, runCloudEnum, runS3Scanner,
  runAwsS3Ls, runNucleiTakeovers, parseCloudEnumOutput,
  parseS3ScannerOutput, parseAwsS3LsOutput, TAKEOVER_SIGNATURES,
} from "../bounty/lib/cloud.js";

const ROOT = resolve(import.meta.dirname, "..");
const PROGRAM = loadProgramFile(join(ROOT, "programs", "example.md"));
const NO_BIN_PATH = "/nonexistent-bin-dir";

test("takeover: S3 NoSuchBucket -> vulnerable; body normal -> tidak; CNAME asing -> null", async () => {
  const vuln = await checkTakeover({ host: "x.example.com", cname: "x.s3.amazonaws.com", body: "<Error><Code>NoSuchBucket</Code></Error>" });
  assert.equal(vuln.service, "AWS S3");
  assert.equal(vuln.vulnerable, true);
  assert.match(vuln.evidence, /NoSuchBucket/);
  const live = await checkTakeover({ host: "x.example.com", cname: "x.s3.amazonaws.com", body: "<html>live site</html>" });
  assert.equal(live.vulnerable, false);
  const unknown = await checkTakeover("app.unknownservice.example");
  assert.equal(unknown.service, null);
  assert.equal(unknown.vulnerable, false);
});

test("takeover: Heroku + GitHub Pages fingerprint; layanan diperbaiki ditandai claimable=no", async () => {
  const heroku = await checkTakeover({ host: "a.example.com", cname: "a.herokuapp.com", body: "No such app" });
  assert.equal(heroku.service, "Heroku");
  assert.equal(heroku.vulnerable, true);
  assert.equal(heroku.claimable, "yes");
  const gh = await checkTakeover({ host: "b.example.com", cname: "b.github.io", body: "There isn't a GitHub Pages site here." });
  assert.equal(gh.service, "GitHub Pages");
  assert.equal(gh.vulnerable, true);
  const shopify = await checkTakeover({ host: "c.example.com", cname: "c.myshopify.com", body: "Sorry, this shop is currently unavailable." });
  assert.equal(shopify.service, "Shopify");
  assert.equal(shopify.vulnerable, true);
  assert.equal(shopify.claimable, "no");
  assert.match(shopify.evidence, /sudah diperbaiki/);
});

test("takeover: tanpa body hanya kenali layanan; fetchFn dipakai bila ada", async () => {
  const only = await checkTakeover("x.azurewebsites.net");
  assert.equal(only.service, "Azure Web Apps");
  assert.equal(only.vulnerable, false);
  const fetchFn = async () => ({ ok: true, text: async () => "404 Web Site not found" });
  const viaFetch = await checkTakeover({ host: "y.example.com", cname: "y.azurewebsites.net" }, { fetchFn });
  assert.equal(viaFetch.vulnerable, true);
  const failedFetch = await checkTakeover({ host: "z.example.com", cname: "z.azurewebsites.net" }, { fetchFn: async () => { throw new Error("timeout"); } });
  assert.equal(failedFetch.vulnerable, false);
  assert.match(failedFetch.evidence, /tidak bisa ambil body/);
});

test("takeover: tabel signature lengkap + unik, host di luar scope diblokir", async () => {
  assert.ok(TAKEOVER_SIGNATURES.length >= 15);
  const services = new Set(TAKEOVER_SIGNATURES.map((s) => s.service));
  assert.equal(services.size, TAKEOVER_SIGNATURES.length);
  for (const s of TAKEOVER_SIGNATURES) {
    assert.ok(s.fingerprints.length > 0, s.service);
    assert.ok(["yes", "no", "unknown"].includes(s.claimable), s.service);
  }
  assert.equal(matchTakeoverService("APP.HEROKUAPP.COM").service, "Heroku");
  const blocked = await checkTakeover(
    { host: "x.evil.com", cname: "x.s3.amazonaws.com", body: "NoSuchBucket" },
    { program: PROGRAM }
  );
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.vulnerable, false);
});

test("parser cloud_enum: baris FOUND berisi bucket; baris lain dilewati", () => {
  const out = parseCloudEnumOutput([
    "FOUND: https://example-assets.s3.amazonaws.com/",
    "checking example...",
    "FOUND: example.blob.core.windows.net",
    "nothing here",
  ].join("\n"));
  assert.equal(out.length, 2);
  assert.match(out[0].bucket, /s3\.amazonaws\.com/);
  assert.match(out[1].bucket, /blob\.core\.windows\.net/);
  assert.deepEqual(parseCloudEnumOutput(""), []);
});

test("parser s3scanner: JSON publik + teks 'is public'; non-publik tidak jadi kandidat", () => {
  const out = parseS3ScannerOutput([
    '{"bucket":"example-public","public":true,"exists":true}',
    '{"bucket":"example-private","public":false,"exists":true}',
    'bucket "example-text" is public',
    "garbage line",
  ].join("\n"));
  assert.equal(out.length, 3);
  assert.equal(out[0].isPublic, true);
  assert.equal(out[1].isPublic, false);
  assert.equal(out[2].bucket, "example-text");
});

test("parser aws s3 ls: listing = publik; AccessDenied = tidak publik; NoSuchBucket = tidak ada", () => {
  const pub = parseAwsS3LsOutput("2024-01-01 00:00 123 index.html\n", "", 0);
  assert.equal(pub.isPublic, true);
  assert.equal(pub.exists, true);
  const denied = parseAwsS3LsOutput("", "An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied", 254);
  assert.equal(denied.isPublic, false);
  assert.equal(denied.exists, true);
  const missing = parseAwsS3LsOutput("", "An error occurred (NoSuchBucket) when calling the ListObjectsV2 operation: The specified bucket does not exist", 254);
  assert.equal(missing.exists, false);
  assert.equal(missing.isPublic, false);
});

test("runner: binary hilang -> skipped untuk cloud_enum, s3scanner, aws, nuclei", () => {
  const env = { PATH: NO_BIN_PATH };
  assert.equal(runCloudEnum("example.com", { program: PROGRAM, env }).skipped, true);
  assert.equal(runS3Scanner("example-assets", { program: PROGRAM, env }).skipped, true);
  assert.equal(runAwsS3Ls("example-assets", { program: PROGRAM, env }).skipped, true);
  assert.equal(runNucleiTakeovers("https://example.com/api/", { program: PROGRAM, env }).skipped, true);
});

test("runner: target/bucket di luar scope diblokir", () => {
  const env = { PATH: NO_BIN_PATH };
  const r1 = runCloudEnum("evil.com", { program: PROGRAM, env });
  assert.equal(r1.blocked, true);
  const r2 = runS3Scanner("unrelated-bucket", { program: PROGRAM, env });
  assert.equal(r2.blocked, true);
  const r3 = runAwsS3Ls("unrelated-bucket", { program: PROGRAM, env });
  assert.equal(r3.blocked, true);
  const r4 = runNucleiTakeovers("https://evil.com/api/", { program: PROGRAM, env });
  assert.equal(r4.blocked, true);
});

test("runner e2e: fake aws AccessDenied -> tidak publik, bukan error", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-cloud-"));
  try {
    writeFileSync(join(dir, "aws"), "#!/bin/sh\necho 'An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied' >&2\nexit 254\n", { mode: 0o755 });
    const env = { PATH: `${dir}:${process.env.PATH}` };
    const r = runAwsS3Ls("example-assets", { program: PROGRAM, env });
    assert.equal(r.skipped, false);
    assert.equal(r.error, undefined);
    assert.equal(r.findings.length, 0);
    assert.equal(r.results[0].isPublic, false);
    assert.equal(r.results[0].exists, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runner e2e: fake aws listing publik -> kandidat Public Cloud Storage", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-cloud-"));
  try {
    writeFileSync(join(dir, "aws"), "#!/bin/sh\necho '2024-01-01 00:00  123 index.html'\nexit 0\n", { mode: 0o755 });
    const env = { PATH: `${dir}:${process.env.PATH}` };
    const r = runAwsS3Ls("example-assets", { program: PROGRAM, env });
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].vulnClass, "Public Cloud Storage");
    assert.equal(r.findings[0].severity, "high");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runner e2e: fake nuclei takeover -> kandidat Subdomain Takeover", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-cloud-"));
  try {
    writeFileSync(join(dir, "nuclei"), "#!/bin/sh\ncat <<'EOF'\n{\"template-id\":\"http-takeover-detect\",\"info\":{\"name\":\"Subdomain Takeover\",\"severity\":\"high\",\"classification\":{\"cwe-id\":[\"CWE-284\"]}},\"matched-at\":\"https://sub.example.com/\",\"host\":\"https://sub.example.com\"}\nEOF\n", { mode: 0o755 });
    const env = { PATH: `${dir}:${process.env.PATH}` };
    const r = runNucleiTakeovers("https://example.com/api/", { program: PROGRAM, env });
    assert.equal(r.skipped, false);
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].vulnClass, "Subdomain Takeover");
    assert.equal(r.findings[0].cwe, "CWE-284");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
