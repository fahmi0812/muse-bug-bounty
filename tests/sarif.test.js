// tests/sarif.test.js — v1.3 (3.6): baca findings.sarif Strix (SARIF 2.1.0).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readSarif } from "../bounty/lib/sarif.js";

const SARIF = {
  version: "2.1.0",
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  runs: [
    {
      tool: { driver: { name: "strix", version: "1.7.0" } },
      results: [
        {
          ruleId: "SQL Injection",
          level: "error",
          message: { text: "SQL injection in /api/users?id=1" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "https://example.com/api/users?id=1" }, region: { startLine: 42 } } }],
        },
        {
          ruleId: "Cross-Site Scripting (XSS)",
          level: "warning",
          message: { text: "Reflected XSS in /search" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "https://example.com/search?q=x" } } }],
        },
      ],
    },
    { tool: { driver: { name: "strix" } }, results: [] },
  ],
};

test("readSarif: objek SARIF -> temuan dengan kelas + CWE + severity + endpoint", () => {
  const out = readSarif(SARIF);
  assert.equal(out.length, 2);
  assert.equal(out[0].endpoint, "https://example.com/api/users?id=1");
  assert.equal(out[0].vulnClass, "SQL Injection");
  assert.equal(out[0].cwe, "CWE-89");
  assert.equal(out[0].severity, "high"); // level error
  assert.match(out[0].evidence, /line 42/);
  assert.equal(out[1].vulnClass, "Cross-Site Scripting (XSS)");
  assert.equal(out[1].cwe, "CWE-79");
  assert.equal(out[1].severity, "medium"); // level warning
});

test("readSarif: baca dari file .sarif; input rusak -> []", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-sarif-"));
  const file = join(dir, "findings.sarif");
  writeFileSync(file, JSON.stringify(SARIF));
  const out = readSarif(file);
  assert.equal(out.length, 2);
  assert.equal(out[0].endpoint, "https://example.com/api/users?id=1");
  assert.deepEqual(readSarif(null), []);
  assert.deepEqual(readSarif({}), []);
  assert.deepEqual(readSarif({ version: "2.1.0", runs: [{ results: null }] }), []);
});

test("readSarif: ruleId tidak dikenal tetap dikembalikan (bukan dibuang)", () => {
  const out = readSarif({
    version: "2.1.0",
    runs: [{ results: [{ ruleId: "SOMETHING-WEIRD-123", level: "note", message: { text: "x" }, locations: [] }] }],
  });
  assert.equal(out.length, 1);
  assert.equal(out[0].vulnClass, "SOMETHING-WEIRD-123");
  assert.equal(out[0].severity, "low");
  assert.equal(out[0].endpoint, "");
});
