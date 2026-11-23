// tests/dvlaa-export.test.js — P2-2: eksportir temuan -> findings.jsonl DVLAA.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { toFindingLine, exportFindings, challengeFor } from "../eval/dvlaa-export.mjs";

const ROOT = resolve(import.meta.dirname, "..");

test("dvlaa-export: vulnClass -> challenge (LLM/ASI/AWDP)", () => {
  assert.equal(challengeFor({ vulnClass: "Prompt Injection" }), "LLM01");
  assert.equal(challengeFor({ vulnClass: "Sensitive Information Disclosure" }), "LLM02");
  assert.equal(challengeFor({ vulnClass: "RAG Poisoning" }), "LLM05");
  assert.equal(challengeFor({ vulnClass: "Tool Misuse and Exploitation" }), "ASI02");
  assert.equal(challengeFor({ vulnClass: "Memory Poisoning" }), "ASI06");
  assert.equal(challengeFor({ vulnClass: "Server-Side Request Forgery (SSRF)" }), "AWDP07");
  assert.equal(challengeFor({ vulnClass: "Broken Object Level Authorization" }), "AWDP09");
  assert.equal(challengeFor({ vulnClass: "Authentication Bypass" }), "AWDP05");
  assert.equal(challengeFor({ vulnClass: "Kelas Tidak Dikenal" }), undefined);
});

test("dvlaa-export: severity dinormalisasi, challenge eksplisit menang", () => {
  const line = toFindingLine({ vulnClass: "Prompt Injection", endpoint: "http://127.0.0.1:5080/challenge/1", severity: "CRITICAL", cwe: "CWE-74" });
  assert.equal(line.severity, "critical");
  assert.equal(line.challenge, "LLM01");
  assert.equal(line.cwe, "CWE-74");
  const weird = toFindingLine({ vulnClass: "X", severity: "parah" });
  assert.equal(weird.severity, "medium");
  const explicit = toFindingLine({ vulnClass: "Prompt Injection", challenge: "AWDP02" });
  assert.equal(explicit.challenge, "AWDP02");
});

test("dvlaa-export: input kosong -> file kosong; export menulis layout run_<n>/<target>/findings.jsonl", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-dvlaa-"));
  try {
    const empty = exportFindings([], { target: "dvlaa", run: 1, outDir: dir });
    assert.equal(readFileSync(empty.file, "utf8"), "");
    assert.equal(empty.count, 0);
    const res = exportFindings(
      [{ vulnClass: "Prompt Injection", endpoint: "http://127.0.0.1:5080/challenge/1", severity: "high", cwe: "CWE-74" }],
      { target: "dvlaa", run: 2, outDir: dir }
    );
    assert.equal(res.file, join(dir, "run_2", "dvlaa", "findings.jsonl"));
    const parsed = JSON.parse(readFileSync(res.file, "utf8").trim());
    assert.equal(parsed.title, "Prompt Injection");
    assert.equal(parsed.challenge, "LLM01");
    assert.ok(parsed.description.length > 0 && parsed.steps.length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dvlaa-export: tanpa target/out -> throw", () => {
  assert.throws(() => exportFindings([], { run: 1, outDir: "/tmp/x" }), /--target wajib/);
  assert.throws(() => exportFindings([], { target: "dvlaa", run: 1 }), /--out wajib/);
});

test("dvlaa-export: CLI smoke (node eval/dvlaa-export.mjs)", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-dvlaa-cli-"));
  try {
    const inFile = join(dir, "findings.json");
    writeFileSync(inFile, JSON.stringify([
      { vulnClass: "Tool Misuse and Exploitation", endpoint: "http://127.0.0.1:5080/agent/2", severity: "high" },
      { vulnClass: "Server-Side Request Forgery (SSRF)", endpoint: "http://127.0.0.1:5080/awdp/7", severity: "critical", cwe: "CWE-918" },
    ]));
    const outDir = join(dir, "out");
    const r = spawnSync(process.execPath, [join(ROOT, "eval/dvlaa-export.mjs"), `--in=${inFile}`, "--target=dvlaa", "--run=1", `--out=${outDir}`], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const file = join(outDir, "run_1", "dvlaa", "findings.jsonl");
    assert.ok(existsSync(file));
    const lines = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(lines[0].challenge, "ASI02");
    assert.equal(lines[1].challenge, "AWDP07");
    const bad = spawnSync(process.execPath, [join(ROOT, "eval/dvlaa-export.mjs")], { encoding: "utf8" });
    assert.equal(bad.status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
