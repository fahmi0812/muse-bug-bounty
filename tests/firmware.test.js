// tests/firmware.test.js — bounty/lib/firmware.js (P2-1).
// Tool palsu (shell script di PATH) mencetak output palsu / menulis
// laporan palsu, jadi tidak butuh binwalk/unblob/cve-bin-tool asli.
// Semua hasil firmware = kandidat (status candidate, UNVERIFIED);
// CVE di komponen BUKAN bukti reachable/exploitable.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import {
  parseBinwalkText, parseBinwalkJson, parseUnblobReport, parseCveBinToolJson,
  runBinwalkNg, runUnblob, runCveBinTool,
} from "../bounty/lib/firmware.js";

const EMPTY_PATH = { PATH: "/nonexistent-dir-xyz" };

function fakeBinDir({ binwalkMode = "json", unblobMode = "report" } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bounty-firmware-"));
  const mk = (name, body) => {
    const p = join(dir, name);
    writeFileSync(p, `#!/bin/sh\n${body}\n`);
    chmodSync(p, 0o755);
  };
  // binwalk palsu: tulis JSON --log bila mode json, kalau tidak hanya
  // cetak tabel teks (lib fallback ke stdout).
  const binwalkBody = binwalkMode === "json"
    ? [
        `prev=""`,
        `for a in "$@"; do`,
        `  if [ "$prev" = "--log" ]; then printf '%s' '[{"offset":0,"description":"U-Boot version string, version: 2023.01"},{"offset":131136,"description":"SquashFS filesystem, little endian, version 4.0"}]' > "$a"; fi`,
        `  prev="$a"`,
        `done`,
        `printf '%s\\n' 'DECIMAL       HEXADECIMAL     DESCRIPTION' '0             0x0             U-Boot version string, version: 2023.01'`,
      ].join("\n")
    : `printf '%s\\n' 'DECIMAL       HEXADECIMAL     DESCRIPTION' '--------------------------------------------------------------------------------' '0             0x0             U-Boot version string, version: 2023.01' '131136        0x20040         SquashFS filesystem, little endian, version 4.0'`;
  mk("binwalk", binwalkBody);
  // unblob palsu: tulis --report JSON + buat file hasil ekstraksi.
  const unblobBody = unblobMode === "report"
    ? [
        `prev=""; outdir=""`,
        `for a in "$@"; do`,
        `  if [ "$prev" = "--report" ]; then printf '%s' '{"chunks":[{"path":"squashfs-root/bin/busybox","size":1234,"chunk_type":"SquashFS"},{"path":"squashfs-root/etc/passwd","size":100,"chunk_type":"file"}]}' > "$a"; fi`,
        `  if [ "$prev" = "-e" ]; then outdir="$a"; fi`,
        `  prev="$a"`,
        `done`,
        `mkdir -p "$outdir/squashfs-root/bin" "$outdir/squashfs-root/etc"`,
        `printf 'x' > "$outdir/squashfs-root/bin/busybox"`,
        `printf 'root:x:0:0' > "$outdir/squashfs-root/etc/passwd"`,
      ].join("\n")
    : [
        `prev=""; outdir=""`,
        `for a in "$@"; do`,
        `  if [ "$prev" = "-e" ]; then outdir="$a"; fi`,
        `  prev="$a"`,
        `done`,
        `mkdir -p "$outdir/rootfs/bin"`,
        `printf 'x' > "$outdir/rootfs/bin/busybox"`,
      ].join("\n");
  mk("unblob", unblobBody);
  // cve-bin-tool palsu: tulis JSON -o (bentuk objek ber-kunci produk),
  // dengan satu CVE duplikat (harus ter-dedup jadi 1 temuan).
  mk("cve-bin-tool", [
    `prev=""`,
    `for a in "$@"; do`,
    `  if [ "$prev" = "-o" ]; then printf '%s' '{"openssl":{"1.1.1":{"cves":[{"cve_number":"CVE-2023-12345","severity":"HIGH","score":7.5,"description":"test vuln"},{"cve_number":"CVE-2023-12345","severity":"HIGH","score":7.5,"description":"test vuln"}]}},"busybox":{"1.36.0":{"cves":[{"cve_number":"CVE-2024-99999","severity":"CRITICAL","score":9.8,"description":"test kritis"}]}}}' > "$a"; fi`,
    `  prev="$a"`,
    `done`,
    `echo "scan selesai"`,
  ].join("\n"));
  return dir;
}

function envWith(dir) {
  return { PATH: `${dir}${delimiter}${process.env.PATH}` };
}

function fakeImage() {
  const dir = mkdtempSync(join(tmpdir(), "bounty-fw-img-"));
  const p = join(dir, "firmware.bin");
  writeFileSync(p, Buffer.from("UBOOTFAKEFIRMWARE".repeat(64)));
  return { dir, file: p };
}

// --- Parser unit ---

test("firmware: parseBinwalkText tabel klasik (header + garis dipisah dilewati)", () => {
  const text = [
    "DECIMAL       HEXADECIMAL     DESCRIPTION",
    "--------------------------------------------------------------------------------",
    "0             0x0             U-Boot version string, version: 2023.01",
    "131136        0x20040         SquashFS filesystem, little endian, version 4.0",
    "",
  ].join("\n");
  const r = parseBinwalkText(text);
  assert.equal(r.length, 2);
  assert.equal(r[0].offset, 0);
  assert.equal(r[0].offsetHex, "0x0");
  assert.equal(r[1].offset, 131136);
  assert.equal(r[1].offsetHex, "0x20040");
  assert.match(r[1].description, /SquashFS/);
  assert.deepEqual(parseBinwalkText(""), []);
});

test("firmware: parseBinwalkJson array + objek results + string mentah", () => {
  const arr = parseBinwalkJson([{ offset: 0, description: "U-Boot" }, { offset: 512, description: "gzip" }]);
  assert.equal(arr.length, 2);
  assert.equal(arr[1].offsetHex, "0x200");
  const obj = parseBinwalkJson({ results: [{ offset: 64, description: "LZMA" }] });
  assert.equal(obj.length, 1);
  assert.equal(obj[0].description, "LZMA");
  assert.deepEqual(parseBinwalkJson({ bukan: "apa-apa" }), []);
  assert.deepEqual(parseBinwalkJson(null), []);
});

test("firmware: parseUnblobReport kumpulkan path dari chunks/files rekursif", () => {
  const report = {
    chunks: [
      { path: "root/bin/busybox", size: 1234, chunk_type: "SquashFS" },
      { path: "root/etc/passwd", size: 100, chunk_type: "file" },
      { path: "root/bin/busybox", size: 1234, chunk_type: "SquashFS" },
    ],
    nested: { files: [{ path: "root/lib/libc.so", size: 99 }] },
  };
  const r = parseUnblobReport(report);
  assert.equal(r.length, 3, "path duplikat dihitung sekali");
  assert.equal(r[0].type, "SquashFS");
  assert.deepEqual(parseUnblobReport([]), []);
  assert.deepEqual(parseUnblobReport(null), []);
});

test("firmware: parseCveBinToolJson bentuk objek + array, severity dipetakan", () => {
  const obj = parseCveBinToolJson({
    openssl: { "1.1.1": { cves: [{ cve_number: "CVE-2023-12345", severity: "HIGH", score: 7.5, description: "x" }] } },
    zlib: { "1.2.13": { cves: [{ cve_number: "CVE-2023-6992", severity: "UNKNOWN", score: 5.0 }] } },
    bukan: { "0": { cves: [{ cve_number: "BUKAN-CVE", severity: "HIGH" }] } },
  });
  assert.equal(obj.length, 2);
  assert.equal(obj[0].cve, "CVE-2023-12345");
  assert.equal(obj[0].severity, "high");
  assert.equal(obj[0].score, 7.5);
  assert.equal(obj[1].severity, "low", "UNKNOWN -> low, jangan dibesarkan");
  const arr = parseCveBinToolJson([
    { product: "curl", version: "8.0.0", cve_number: "CVE-2024-11111", severity: "CRITICAL", score: 9.8, cwe: "CWE-787" },
  ]);
  assert.equal(arr.length, 1);
  assert.equal(arr[0].cwe, "CWE-787");
  assert.deepEqual(parseCveBinToolJson({}), []);
});

// --- Runner e2e (binary palsu) ---

test("firmware: binwalk palsu -> signature dari JSON log + fallback teks", () => {
  const { dir, file } = fakeImage();
  try {
    const binDir = fakeBinDir({ binwalkMode: "json" });
    try {
      const r = runBinwalkNg(file, { env: envWith(binDir) });
      assert.equal(r.skipped, false);
      assert.equal(r.findings.length, 2);
      assert.equal(r.findings[1].vulnClass, "Firmware Component");
      assert.equal(r.findings[1].severity, "low", "info permukaan, bukan klaim vuln");
      assert.ok(existsSync(r.outDir));
    } finally { rmSync(binDir, { recursive: true, force: true }); }
    const binDir2 = fakeBinDir({ binwalkMode: "text" });
    try {
      const r2 = runBinwalkNg(file, { env: envWith(binDir2) });
      assert.equal(r2.findings.length, 2, "fallback ke tabel teks stdout");
      assert.equal(r2.findings[1].param, "0x20040");
    } finally { rmSync(binDir2, { recursive: true, force: true }); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("firmware: unblob palsu -> file dari report + fallback daftar direktori", () => {
  const { dir, file } = fakeImage();
  try {
    const binDir = fakeBinDir({ unblobMode: "report" });
    try {
      const r = runUnblob(file, { env: envWith(binDir) });
      assert.equal(r.skipped, false);
      assert.equal(r.findings.length, 2);
      assert.equal(r.findings[0].vulnClass, "Extracted Firmware File");
      assert.match(r.findings[0].evidence, /busybox/);
    } finally { rmSync(binDir, { recursive: true, force: true }); }
    const binDir2 = fakeBinDir({ unblobMode: "noreport" });
    try {
      const r2 = runUnblob(file, { env: envWith(binDir2) });
      assert.equal(r2.findings.length, 1, "fallback: daftar file di outDir");
      assert.match(r2.findings[0].param, /busybox/);
    } finally { rmSync(binDir2, { recursive: true, force: true }); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("firmware: cve-bin-tool palsu -> CVE findings, duplikat ter-dedup", () => {
  const { dir, file } = fakeImage();
  try {
    const binDir = fakeBinDir();
    try {
      const r = runCveBinTool(file, { env: envWith(binDir) });
      assert.equal(r.skipped, false);
      assert.equal(r.findings.length, 2, "CVE duplikat (openssl) ter-dedup jadi 1");
      assert.equal(r.duplicates.length, 1);
      const openssl = r.findings.find((f) => f.param.startsWith("openssl@"));
      assert.equal(openssl.vulnClass, "Known CVE in Firmware Component");
      assert.equal(openssl.severity, "high");
      assert.match(openssl.evidence, /CVE-2023-12345 di openssl 1\.1\.1 \(CVSS 7\.5\)/);
      const busybox = r.findings.find((f) => f.param.startsWith("busybox@"));
      assert.equal(busybox.severity, "critical");
      assert.match(busybox.evidence, /verifikasi reachability manual/);
    } finally { rmSync(binDir, { recursive: true, force: true }); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- Kontrak: skipped / error ---

test("firmware: binary hilang -> skipped; file hilang / URL -> error", () => {
  const { dir, file } = fakeImage();
  try {
    assert.equal(runBinwalkNg(file, { env: EMPTY_PATH }).skipped, true);
    assert.equal(runUnblob(file, { env: EMPTY_PATH }).skipped, true);
    assert.equal(runCveBinTool(file, { env: EMPTY_PATH }).skipped, true);
    assert.ok(runBinwalkNg(join(dir, "tidak-ada.bin")).error);
    assert.ok(runUnblob(join(dir, "tidak-ada.bin")).error);
    assert.ok(runCveBinTool(join(dir, "tidak-ada.bin")).error);
    assert.ok(runBinwalkNg("https://example.com/firmware.bin").error);
    assert.ok(runUnblob("https://example.com/firmware.bin").error);
    assert.ok(runCveBinTool("https://example.com/firmware.bin").error);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
