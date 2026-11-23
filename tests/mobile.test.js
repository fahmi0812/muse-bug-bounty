// tests/mobile.test.js — bounty/lib/mobile.js (P1-4).
// MobSF diuji dengan fetch stub (tanpa server/Docker asli); jadx dengan
// binary palsu. Tidak ada secret/API key asli di file ini — semua
// fixture memakai TOKEN_CONTOH / nilai palsu yang dirakit saat runtime.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseMobSFReport, parseAndroidManifest, buildDockerCommand,
  runMobsf, runJadx, MOBSF_IMAGE, MOBSF_DEFAULT_URL,
} from "../bounty/lib/mobile.js";

const PROGRAM = { name: "example" };
const EMPTY_PATH = { PATH: "/nonexistent-dir-xyz" };

// Laporan MobSF contoh (bentuk v4: manifest array, code object, secrets).
// Nilai secret palsu — TIDAK BOLEH muncul di temuan mana pun.
const FAKE_SECRET_VALUE = "SECRET_CONTOH_XYZ123";
const SAMPLE_REPORT = {
  package_name: "com.example.app",
  file_name: "app-target.apk",
  manifest_analysis: [
    { title: "Activity (.MainActivity) is exported", severity: "high", description: "exported activity" },
    { title: "App can use cleartext traffic", severity: "warning", description: "cleartext" },
    { title: "App is signed with debug certificate", severity: "good", description: "ok" },
  ],
  code_analysis: {
    android_hardcoded_secret: {
      level: "high", cvss: 7.5, cwe: "CWE-798", title: "Hardcoded secret",
      files: { "com/example/App.java": [42] },
    },
    android_weak_crypto: {
      level: "warning", cvss: 5.9, cwe: 327, title: "Weak crypto: DES",
      files: { "com/example/Crypto.java": [10] },
    },
  },
  binary_analysis: [
    { title: "Binary is not signed with v2 scheme", severity: "info" },
  ],
  secrets: [{ type: "aws-key", value: FAKE_SECRET_VALUE }],
  permissions: {
    "android.permission.INTERNET": { status: "normal" },
    "android.permission.READ_EXTERNAL_STORAGE": { status: "dangerous" },
  },
  domains: ["api.example.com"],
};

test("parseMobSFReport: mapping kelas + severity, secret tidak disalin", () => {
  const { findings, duplicates } = parseMobSFReport(SAMPLE_REPORT, { fileName: "app-target.apk" });
  const classes = findings.map((f) => f.vulnClass);
  assert.ok(classes.includes("Exported Component"));
  assert.ok(classes.includes("Hardcoded Secret in App"));
  assert.ok(classes.includes("Weak Crypto"));
  assert.ok(classes.includes("Dangerous Permission"));
  assert.ok(classes.includes("Insecure Transport"));
  // "good" dilewati, bukan temuan.
  assert.ok(!findings.some((f) => /debug certificate/i.test(f.endpoint)));
  // Nilai secret tidak ada di temuan mana pun (hanya jenis + lokasi).
  assert.equal(JSON.stringify(findings).includes(FAKE_SECRET_VALUE), false);
  // Severity MobSF: high -> high, warning -> medium, info -> low.
  const exported = findings.find((f) => f.vulnClass === "Exported Component");
  assert.equal(exported.severity, "high");
  assert.equal(exported.cwe, "CWE-926");
  const secret = findings.find((f) => f.vulnClass === "Hardcoded Secret in App");
  assert.equal(secret.cwe, "CWE-798");
  const crypto = findings.find((f) => f.vulnClass === "Weak Crypto");
  assert.equal(crypto.cwe, "CWE-327"); // "327" dinormalisasi ke CWE-327
  assert.equal(crypto.severity, "medium");
  assert.ok(findings.every((f) => f.status === "candidate"));
  assert.ok(Array.isArray(duplicates));
});

test("parseMobSFReport: duplikat di-dedup", () => {
  const dup = { ...SAMPLE_REPORT, secrets: [{ type: "aws-key" }, { type: "aws-key" }] };
  const { findings, duplicates } = parseMobSFReport(dup, { fileName: "app-target.apk" });
  assert.equal(duplicates.length, 1);
  assert.ok(findings.length > 0);
});

test("parseAndroidManifest: exported component + cleartext", () => {
  const xml = `<manifest package="com.example.app">
  <application android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true"><intent-filter/></activity>
    <activity android:name=".HiddenActivity" android:exported="false" />
    <service android:name=".SyncService" android:exported="true" />
  </application></manifest>`;
  const found = parseAndroidManifest(xml, { packageName: "com.example.app" });
  assert.equal(found.length, 3); // 2 exported + cleartext
  assert.ok(found.some((f) => f.endpoint.includes(".MainActivity") && f.cwe === "CWE-926"));
  assert.ok(found.some((f) => f.vulnClass === "Insecure Transport" && f.cwe === "CWE-319"));
  assert.ok(!found.some((f) => f.endpoint.includes("HiddenActivity")));
});

test("buildDockerCommand: pin image + port + nama container", () => {
  const cmd = buildDockerCommand();
  assert.equal(cmd[0], "docker");
  assert.ok(cmd.includes(MOBSF_IMAGE));
  assert.ok(cmd.includes("8000:8000"));
  assert.ok(cmd.includes("mobsf"));
  assert.equal(MOBSF_IMAGE, "opensecurity/mobile-security-framework-mobsf:4.5.3");
  assert.equal(MOBSF_DEFAULT_URL, "http://127.0.0.1:8000");
});

function stubFetch(calls) {
  return async (url, opts = {}) => {
    calls.push({ url, headers: opts.headers ?? {}, body: opts.body });
    const path = String(url).split("?")[0];
    if (path.endsWith("/api/v1/upload")) {
      return { ok: true, text: async () => JSON.stringify({ hash: "abc123hash", scan_type: "apk", file_name: "app-target.apk" }) };
    }
    if (path.endsWith("/api/v1/scan") || path.endsWith("/api/v1/report_json")) {
      return { ok: true, text: async () => JSON.stringify(SAMPLE_REPORT) };
    }
    return { ok: false, status: 404, text: async () => "not found" };
  };
}

test("runMobsf: upload -> scan -> temuan, header Authorization kunci mentah", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-mobile-"));
  try {
    const apk = join(dir, "app-target.apk");
    writeFileSync(apk, Buffer.from("PK\x03\x04palsu"));
    const calls = [];
    const res = await runMobsf(apk, {
      program: PROGRAM,
      apiKey: "TOKEN_CONTOH",
      fetchFn: stubFetch(calls),
      sleepFn: async () => {},
    });
    assert.equal(res.error, undefined, JSON.stringify(res));
    assert.equal(res.programName, "example");
    assert.equal(res.packageName, "com.example.app");
    assert.ok(res.findings.length >= 5, `temuan: ${res.findings.length}`);
    assert.ok(res.findings.some((f) => f.vulnClass === "Exported Component"));
    assert.equal(JSON.stringify(res.findings).includes(FAKE_SECRET_VALUE), false);
    // Header auth = kunci mentah, BUKAN "Bearer ...".
    assert.ok(calls.length >= 2);
    assert.equal(calls[0].headers.Authorization, "TOKEN_CONTOH");
    assert.ok(!String(calls[0].headers.Authorization).startsWith("Bearer"));
    // Upload multipart berisi nama file.
    assert.ok(String(calls[0].headers["Content-Type"]).startsWith("multipart/form-data"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runMobsf: tanpa API key -> error; tanpa program -> error; file hilang -> error", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-mobile-"));
  try {
    const apk = join(dir, "app-target.apk");
    writeFileSync(apk, Buffer.from("PK\x03\x04palsu"));
    const noKey = await runMobsf(apk, { program: PROGRAM, fetchFn: stubFetch([]), env: { MOBSF_API_KEY: "", PATH: "" } });
    assert.match(noKey.error, /MOBSF_API_KEY/);
    const noProgram = await runMobsf(apk, { program: "", apiKey: "TOKEN_CONTOH", fetchFn: stubFetch([]) });
    assert.equal(noProgram.blocked, true);
    assert.match(noProgram.reason, /program tidak diberikan/);
    const missing = await runMobsf(join(dir, "tidak-ada.apk"), { program: PROGRAM, apiKey: "TOKEN_CONTOH", fetchFn: stubFetch([]) });
    assert.match(missing.error, /tidak ditemukan/);
    const badExt = await runMobsf(join(dir, "app-target.zip"), { program: PROGRAM, apiKey: "TOKEN_CONTOH", fetchFn: stubFetch([]) });
    assert.match(badExt.error, /tidak ditemukan/); // file belum ada -> dicek dulu
    writeFileSync(join(dir, "app-target.zip"), "x");
    const badExt2 = await runMobsf(join(dir, "app-target.zip"), { program: PROGRAM, apiKey: "TOKEN_CONTOH", fetchFn: stubFetch([]) });
    assert.match(badExt2.error, /ekstensi tidak didukung/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runMobsf: server tidak terjangkau -> error (bukan sukses diam-diam)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-mobile-"));
  try {
    const apk = join(dir, "app-target.apk");
    writeFileSync(apk, Buffer.from("PK\x03\x04palsu"));
    const res = await runMobsf(apk, {
      program: PROGRAM,
      apiKey: "TOKEN_CONTOH",
      fetchFn: async () => { throw new Error("connect ECONNREFUSED 127.0.0.1:8000"); },
    });
    assert.match(res.error, /tidak terjangkau/);
    assert.match(res.error, /docker run/); // panduan menyalakan MobSF
    assert.equal(res.findings.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runMobsf: useDocker tanpa binary docker -> skipped", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-mobile-"));
  try {
    const apk = join(dir, "app-target.apk");
    writeFileSync(apk, Buffer.from("PK\x03\x04palsu"));
    const res = await runMobsf(apk, { program: PROGRAM, apiKey: "TOKEN_CONTOH", useDocker: true, env: EMPTY_PATH, fetchFn: stubFetch([]) });
    assert.equal(res.skipped, true);
    assert.match(res.reason, /docker tidak ditemukan/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runJadx: binary hilang -> skipped; file hilang -> error", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-mobile-"));
  try {
    const apk = join(dir, "app-target.apk");
    writeFileSync(apk, Buffer.from("PK\x03\x04palsu"));
    const skipped = runJadx(apk, { program: PROGRAM, env: EMPTY_PATH });
    assert.equal(skipped.skipped, true);
    assert.match(skipped.reason, /jadx tidak ditemukan/);
    const missing = runJadx(join(dir, "tidak-ada.apk"), { program: PROGRAM, env: EMPTY_PATH });
    assert.match(missing.error, /tidak ditemukan/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runJadx: binary palsu -> manifest + secret dari sumber", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-mobile-"));
  const binDir = mkdtempSync(join(tmpdir(), "bounty-mobile-bin-"));
  try {
    const apk = join(dir, "app-target.apk");
    writeFileSync(apk, Buffer.from("PK\x03\x04palsu"));
    // Secret palsu dirakit saat runtime (bukan literal di file ini),
    // supaya pemindai secret tidak menandai fixture test.
    const secretLine = "api_" + 'key = "Zx9qW8eR7tY6uI5oP4aS3dF2gH1jK0lM9n8b7v6";';
    const jadx = join(binDir, "jadx");
    writeFileSync(jadx, `#!/bin/sh
# jadx palsu: $1=-d $2=outdir $3=apk
OUT="$2"
mkdir -p "$OUT/resources" "$OUT/sources/com/example"
cat > "$OUT/resources/AndroidManifest.xml" <<'XML'
<manifest package="com.example.app"><application>
<activity android:name=".MainActivity" android:exported="true" />
</application></manifest>
XML
cat > "$OUT/sources/com/example/MainActivity.java" <<'JAVA'
package com.example;
public class MainActivity {
  String ${secretLine}
}
JAVA
`);
    chmodSync(jadx, 0o755);
    const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
    const res = runJadx(apk, { program: PROGRAM, env });
    assert.equal(res.error, undefined, JSON.stringify(res));
    assert.ok(res.findings.some((f) => f.vulnClass === "Exported Component" && f.endpoint.includes(".MainActivity")));
    const secret = res.findings.find((f) => f.vulnClass === "Hardcoded Secret in App");
    assert.ok(secret, "secret dari sumber harus ketemu");
    assert.equal(secret.cwe, "CWE-798");
    // Nilai secret tidak ada di temuan.
    assert.equal(JSON.stringify(res.findings).includes("Zx9qW8eR7tY6uI5oP4aS3dF2gH1jK0lM9n8b7v6"), false);
    assert.ok(res.outDir && res.outDir.length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(binDir, { recursive: true, force: true });
  }
});
