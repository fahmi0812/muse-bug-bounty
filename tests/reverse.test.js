// tests/reverse.test.js — bounty/lib/reverse.js (P1-3, gated RE).
// Runner palsu (script di PATH) menggantikan ghidra-mcp / rea / jadx.
// Nilai secret dalam fixture dirakit saat runtime dari potongan string
// (seperti tests/secrets.test.js) supaya tidak ada literal token
// format-asli di file ini.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  parseGhidraStrings, parseReaOutput, parseJadxSources, stringsToFindings,
  runGhidraMcp, runRea, runJadxApk,
} from "../bounty/lib/reverse.js";

const ROOT = resolve(import.meta.dirname, "..");

// Stripe docs example key, dirakit saat runtime (bukan literal).
const SK_LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc";
const FAKE_BIN = join(tmpdir(), "bounty-re-fake.bin");

function fakeToolDir() {
  const dir = mkdtempSync(join(tmpdir(), "bounty-fake-re-"));
  writeFileSync(join(dir, "target.bin"), "ELF palsu\n");
  // ghidra-mcp palsu: server MCP stdio — jawab initialize + tools/call.
  writeFileSync(join(dir, "ghidra-mcp"), `#!/usr/bin/env node
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
const SK = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc";
rl.on("line", (line) => {
  let msg; try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === "initialize") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "ghidra-mcp", version: "2.0.0" } } }) + "\\n");
  } else if (msg.method === "tools/call" && msg.params?.name === "list_strings") {
    const text = JSON.stringify([
      { address: "0x1000", value: "https://api.example.com/v1" },
      { address: "0x1010", value: SK },
      { address: "0x1020", value: "DES_encrypt" },
      { address: "0x1030", value: "hello world" },
    ]);
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }] } }) + "\\n");
  } else if (msg.method === "tools/call" && msg.params?.name === "list_imports") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: JSON.stringify([{ name: "strcpy" }, { name: "printf" }]) }] } }) + "\\n");
  }
});
`, { mode: 0o755 });
  // rea palsu: cetak JSON envelope berisi string.
  writeFileSync(join(dir, "rea"), `#!/bin/sh
echo '{"evidence": {"strings": ["https://api.example.com/v1", "DES_encrypt", "hello world"], "functions": ["main"]}}'
`, { mode: 0o755 });
  // jadx palsu: tulis file .java + AndroidManifest.xml ke -d <dir>.
  // Kunci di dalam file .java palsu dirakit dari SK_LIVE (bukan literal).
  writeFileSync(join(dir, "jadx"), `#!/bin/sh
out=""
prev=""
for a in "$@"; do if [ "$prev" = "-d" ]; then out="$a"; fi; prev="$a"; done
mkdir -p "$out/com/example"
cat > "$out/com/example/MainActivity.java" <<'JAVA'
package com.example;
public class MainActivity {
  private static final String KEY = "${SK_LIVE}";
  void f() { javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding"); }
}
JAVA
cat > "$out/AndroidManifest.xml" <<'XML'
<manifest><application><activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter></activity></application></manifest>
XML
`, { mode: 0o755 });
  return dir;
}

function envWith(dir) {
  return { ...process.env, PATH: `${dir}:${process.env.PATH}` };
}

// --- Parser unit ---

test("reverse: parseGhidraStrings JSON array + baris biasa", () => {
  const fromJson = parseGhidraStrings(JSON.stringify([
    { address: "0x1", value: "hello world" },
    { address: "0x2", string: "another string" },
    "plain string here",
    "abc",
  ]));
  assert.deepEqual(fromJson, ["hello world", "another string", "plain string here"]);
  assert.deepEqual(parseGhidraStrings("foo bar\nbaz qux\n"), ["foo bar", "baz qux"]);
  assert.deepEqual(parseGhidraStrings(""), []);
});

test("reverse: parseReaOutput JSON rekursif + teks mentah", () => {
  const fromJson = parseReaOutput(JSON.stringify({ a: { b: ["alpha beta", "gamma delta"] }, c: 42 }));
  assert.ok(fromJson.includes("alpha beta"));
  assert.ok(fromJson.includes("gamma delta"));
  assert.deepEqual(parseReaOutput("plain line one\nplain line two\n"), ["plain line one", "plain line two"]);
});

test("reverse: stringsToFindings — secret high tanpa nilai di evidence, kripto CWE-327, http CWE-319", () => {
  const { findings, duplicates } = stringsToFindings([
    "https://api.example.com/v1",
    SK_LIVE,
    "DES_encrypt",
    "http://insecure.example.com/api",
    "hello world",
    SK_LIVE, // duplikat string yang sama -> dedup
  ], "/tmp/target.bin");
  const secret = findings.find((f) => f.vulnClass === "Hardcoded Secret in Binary");
  assert.ok(secret, "secret harus ketemu");
  assert.equal(secret.cwe, "CWE-798");
  assert.equal(secret.severity, "high");
  assert.equal(secret.endpoint, "target.bin");
  assert.ok(!secret.evidence.includes("4eC39"), "nilai secret TIDAK BOLEH ada di evidence");
  const crypto = findings.find((f) => f.vulnClass === "Weak Crypto in Binary");
  assert.ok(crypto);
  assert.equal(crypto.cwe, "CWE-327");
  const clear = findings.find((f) => f.vulnClass === "Cleartext HTTP in Binary");
  assert.ok(clear);
  assert.equal(clear.cwe, "CWE-319");
  assert.ok(findings.every((f) => f.status === "candidate"));
  assert.ok(duplicates.length >= 1, "duplikat secret harus tercatat");
});

test("reverse: parseJadxSources — secret + exported component, nilai tidak bocor", () => {
  const { findings } = parseJadxSources([
    { path: "/tmp/out/MainActivity.java", content: `class A { String k = "${SK_LIVE}"; }` },
    { path: "/tmp/out/AndroidManifest.xml", content: `<activity android:exported="true"><intent-filter><action android:name="x"/></intent-filter></activity>` },
  ]);
  const secret = findings.find((f) => f.vulnClass === "Hardcoded Secret in Binary");
  assert.ok(secret);
  assert.ok(!secret.evidence.includes("4eC39"), "nilai secret TIDAK BOLEH ada di evidence");
  const exported = findings.find((f) => f.vulnClass === "Exported Component");
  assert.ok(exported);
  assert.equal(exported.cwe, "CWE-926");
});

// --- Gate + file hilang + binary hilang ---

test("reverse: tanpa confirmed:true semua runner menolak (gated)", async () => {
  const g = await runGhidraMcp(FAKE_BIN, {});
  assert.match(g.error, /gated/);
  const r = runRea(FAKE_BIN, {});
  assert.match(r.error, /gated/);
  const j = runJadxApk(FAKE_BIN, {});
  assert.match(j.error, /gated/);
});

test("reverse: file tidak ada -> error; URL jarak jauh -> ditolak", async () => {
  const missing = join(tmpdir(), "bounty-re-tidak-ada.bin");
  const g = await runGhidraMcp(missing, { confirmed: true });
  assert.match(g.error, /tidak ditemukan/);
  const r = runRea("https://example.com/app.apk", { confirmed: true });
  assert.match(r.error, /hanya file lokal/);
  const j = runJadxApk(missing, { confirmed: true });
  assert.match(j.error, /tidak ditemukan/);
});

test("reverse: binary tidak ada -> skipped (bukan error)", async () => {
  const emptyPath = mkdtempSync(join(tmpdir(), "bounty-re-empty-"));
  try {
    const env = { ...process.env, PATH: emptyPath };
    const bin = join(emptyPath, "t.bin");
    writeFileSync(bin, "x");
    const g = await runGhidraMcp(bin, { confirmed: true, env });
    assert.equal(g.skipped, true);
    const r = runRea(bin, { confirmed: true, env });
    assert.equal(r.skipped, true);
    const j = runJadxApk(bin, { confirmed: true, env });
    assert.equal(j.skipped, true);
  } finally {
    rmSync(emptyPath, { recursive: true, force: true });
  }
});

// --- Runner dengan binary palsu ---

test("reverse: runGhidraMcp palsu -> secret + kripto, nilai tidak bocor", async () => {
  const dir = fakeToolDir();
  try {
    const bin = join(dir, "target.bin");
    const r = await runGhidraMcp(bin, { confirmed: true, env: envWith(dir) });
    assert.equal(r.error, undefined, JSON.stringify(r));
    assert.equal(r.skipped, false);
    const secret = r.findings.find((f) => f.vulnClass === "Hardcoded Secret in Binary");
    assert.ok(secret, JSON.stringify(r.findings));
    assert.ok(!JSON.stringify(r.findings).includes("4eC39"), "nilai secret tidak boleh ada di findings");
    assert.ok(r.findings.find((f) => f.vulnClass === "Weak Crypto in Binary"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reverse: runRea palsu -> kripto dari envelope JSON", () => {
  const dir = fakeToolDir();
  try {
    const bin = join(dir, "target.bin");
    const r = runRea(bin, { confirmed: true, env: envWith(dir) });
    assert.equal(r.error, undefined, JSON.stringify(r));
    assert.ok(r.findings.find((f) => f.vulnClass === "Weak Crypto in Binary"), JSON.stringify(r.findings));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reverse: runJadxApk palsu -> secret + exported, nilai tidak bocor", () => {
  const dir = fakeToolDir();
  try {
    const apk = join(dir, "app.apk");
    writeFileSync(apk, "APK palsu");
    const r = runJadxApk(apk, { confirmed: true, env: envWith(dir) });
    assert.equal(r.error, undefined, JSON.stringify(r));
    const secret = r.findings.find((f) => f.vulnClass === "Hardcoded Secret in Binary");
    assert.ok(secret, JSON.stringify(r.findings));
    assert.ok(!JSON.stringify(r.findings).includes("4eC39"), "nilai secret tidak boleh ada di findings");
    assert.ok(r.findings.find((f) => f.vulnClass === "Exported Component"), JSON.stringify(r.findings));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
