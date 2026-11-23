// tests/ethibench-export.test.js — eksportir temuan -> findings.jsonl EthiBench.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toFindingLine, exportFindings } from "../eval/ethibench-export.mjs";

test("toFindingLine: field lengkap dipertahankan, severity tidak dikenal -> medium", () => {
  const line = toFindingLine({
    title: "SQL Injection in Login",
    description: "Input login masuk query tanpa parameter.",
    steps: "1. POST /login dengan ' OR 1=1--",
    cwe: "CWE-89",
    severity: "CRITICAL",
    url: "http://localhost:3000/login",
  });
  assert.equal(line.title, "SQL Injection in Login");
  assert.equal(line.cwe, "CWE-89");
  assert.equal(line.severity, "critical");
  assert.equal(line.url, "http://localhost:3000/login");
  assert.equal(toFindingLine({ vulnClass: "SSRF", severity: "aneh" }).severity, "medium");
});

test("toFindingLine: field kosong dibuat dari judul + endpoint (matcher butuh teks)", () => {
  const line = toFindingLine({ vulnClass: "IDOR", endpoint: "/api/users/2", cwe: "CWE-639" });
  assert.equal(line.title, "IDOR");
  assert.match(line.description, /\/api\/users\/2/);
  assert.match(line.steps, /\/api\/users\/2/);
  assert.equal(line.cwe, "CWE-639");
});

test("exportFindings: layout run_<n>/<target>/findings.jsonl + jumlah baris benar", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-ethibench-"));
  try {
    const res = exportFindings(
      [
        { vulnClass: "SQL Injection", endpoint: "/login", cwe: "CWE-89", severity: "high" },
        { vulnClass: "XSS", endpoint: "/search?q=x", cwe: "CWE-79" },
      ],
      { target: "vuln-bank", run: 1, outDir: dir }
    );
    assert.equal(res.count, 2);
    assert.equal(res.file, join(dir, "run_1", "vuln-bank", "findings.jsonl"));
    const lines = readFileSync(res.file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(lines[0].title, "SQL Injection");
    assert.equal(lines[1].severity, "medium");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("exportFindings: target/out wajib, input kosong -> file kosong", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-ethibench-"));
  try {
    assert.throws(() => exportFindings([], { target: "", outDir: dir }), /--target wajib/);
    assert.throws(() => exportFindings([], { target: "vuln-bank" }), /--out wajib/);
    const res = exportFindings([], { target: "paygoat", run: 2, outDir: dir });
    assert.equal(res.count, 0);
    assert.equal(readFileSync(res.file, "utf8"), "");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
