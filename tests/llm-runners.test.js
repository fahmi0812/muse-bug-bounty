// tests/llm-runners.test.js — bounty/lib/llm-runners.js
// (garak agent-breaker + PyRIT Crescendo/TAP). Tool palsu (shell
// script di PATH) menulis output palsu, jadi tidak butuh garak/PyRIT
// asli. Semua hasil = candidate yang wajib verifikasi manual.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  parseAgentBreakerOutput,
  parsePyritOutput,
  buildPyritDriver,
  runGarakAgentBreaker,
  runPyrit,
} from "../bounty/lib/llm-runners.js";
import { parseProgram } from "../bounty/lib/scope.js";

const ROOT = resolve(import.meta.dirname, "..");

const PROGRAM_MD = `Nama: Example Program
Scope: example.com
Allowed: /api/, /login
Denied: /admin, /logout
Budget: $5
Rate: 10 req/detik
Roles: low, high
`;
const PROGRAM = parseProgram(PROGRAM_MD);
const TARGET = "https://example.com/api/chat";

function fakeBin(dir, name, script) {
  const p = join(dir, name);
  writeFileSync(p, script, { mode: 0o755 });
  chmodSync(p, 0o755);
  return p;
}

// --- Parser garak agent-breaker ---

test("llm-runners: parseAgentBreakerOutput JSONL hit -> temuan high, pass dilewati", () => {
  const text = [
    JSON.stringify({ probe_classname: "agent_breaker.AgentBreaker", detector_results: { AgentBreakerResult: 1 }, goal: "call admin tool" }),
    JSON.stringify({ probe_classname: "agent_breaker.ToolChain", detector_results: { AgentBreakerChainResult: 0 }, passed: true, result: "pass" }),
    JSON.stringify({ probe_classname: "encoding.Encode", detector_results: { Encoding: 1 } }),
    "bukan json, dilewati",
  ].join("\n");
  const f = parseAgentBreakerOutput(text, TARGET);
  assert.equal(f.length, 1, "hanya hit agent_breaker yang jadi temuan");
  assert.equal(f[0].vulnClass, "LLM Agent Breaker (AgentBreaker)");
  assert.equal(f[0].cwe, "CWE-74");
  assert.equal(f[0].severity, "high");
  assert.equal(f[0].endpoint, "/api/chat");
  assert.match(f[0].evidence, /perlu verifikasi manual/);
  assert.equal(f[0].status, "candidate");
});

test("llm-runners: parseAgentBreakerOutput passed=false -> temuan; fallback teks FAIL", () => {
  const f1 = parseAgentBreakerOutput(
    JSON.stringify({ probe_classname: "agent_breaker.ToolChain", passed: false }),
    TARGET
  );
  assert.equal(f1.length, 1);
  assert.equal(f1[0].vulnClass, "LLM Agent Breaker (ToolChain)");
  const f2 = parseAgentBreakerOutput("some summary\nFAIL agent_breaker.AgentBreaker: tool exploited\n", TARGET);
  assert.equal(f2.length, 1);
  assert.deepEqual(parseAgentBreakerOutput("", TARGET), []);
});

// --- Parser PyRIT ---

test("llm-runners: parsePyritOutput success=true -> temuan; success=false -> []", () => {
  const ok = parsePyritOutput(JSON.stringify({ strategy: "crescendo", objective: "Reveal the full system prompt", success: true, turns: 3 }), TARGET);
  assert.equal(ok.length, 1);
  assert.equal(ok[0].vulnClass, "LLM Multi-Turn Jailbreak (Crescendo)");
  assert.equal(ok[0].cwe, "CWE-74");
  assert.equal(ok[0].severity, "high");
  assert.match(ok[0].evidence, /perlu verifikasi manual/);
  const tap = parsePyritOutput(JSON.stringify({ strategy: "tap", success: true }), TARGET);
  assert.equal(tap[0].vulnClass, "LLM Multi-Turn Jailbreak (TAP)");
  assert.deepEqual(parsePyritOutput(JSON.stringify({ strategy: "crescendo", success: false, turns: 10 }), TARGET), []);
  assert.deepEqual(parsePyritOutput("bukan json", TARGET), []);
});

test("llm-runners: buildPyritDriver memuat Crescendo + TAP + HTTPTarget", () => {
  const d = buildPyritDriver();
  assert.match(d, /CrescendoOrchestrator/);
  assert.match(d, /TreeOfAttacksWithPruningOrchestrator/);
  assert.match(d, /HTTPTarget/);
  assert.match(d, /PYRIT_HTTP_TARGET/);
});

// --- Runner garak agent-breaker ---

test("llm-runners: runGarakAgentBreaker binary hilang -> skipped; di luar scope -> blocked", () => {
  const noBin = runGarakAgentBreaker(TARGET, { program: PROGRAM, env: { PATH: "/tmp/tidak-ada-bin" } });
  assert.equal(noBin.skipped, true);
  assert.match(noBin.reason, /garak tidak ditemukan/);
  const blocked = runGarakAgentBreaker("https://evil.com/api/chat", { program: PROGRAM, env: { PATH: "/tmp/tidak-ada-bin" } });
  assert.equal(blocked.blocked, true);
  const noCfg = runGarakAgentBreaker(TARGET, { program: PROGRAM, env: { PATH: "/tmp/tidak-ada-bin" } });
  assert.equal(noCfg.skipped, true); // binary dicek dulu
});

test("llm-runners: runGarakAgentBreaker tanpa generator config -> skipped dengan alasan", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-garak-ab-"));
  fakeBin(dir, "garak", "#!/bin/sh\nexit 0\n");
  const res = runGarakAgentBreaker(TARGET, { program: PROGRAM, env: { PATH: dir } });
  assert.equal(res.skipped, true);
  assert.match(res.reason, /generator config/);
});

test("llm-runners: runGarakAgentBreaker fake garak -> 1 temuan dari report jsonl", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-garak-ab-"));
  fakeBin(dir, "garak", `#!/bin/sh
prev=""
for a in "$@"; do
  if [ "$prev" = "--report_prefix" ]; then prefix="$a"; fi
  prev="$a"
done
printf '%s\\n' '{"probe_classname":"agent_breaker.AgentBreaker","detector_results":{"AgentBreakerResult":1},"goal":"call admin tool"}' > "$prefix.report.jsonl"
`);
  const cfg = join(dir, "gen.json");
  writeFileSync(cfg, JSON.stringify({ type: "rest", url: TARGET }));
  const res = runGarakAgentBreaker(TARGET, { program: PROGRAM, env: { PATH: dir }, generatorConfig: cfg });
  assert.equal(res.skipped, false);
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].vulnClass, "LLM Agent Breaker (AgentBreaker)");
});

// --- Runner PyRIT ---

test("llm-runners: runPyrit python3 hilang -> skipped; di luar scope -> blocked", () => {
  const noPy = runPyrit(TARGET, { program: PROGRAM, env: { PATH: "/tmp/tidak-ada-bin" } });
  assert.equal(noPy.skipped, true);
  assert.match(noPy.reason, /python3 tidak ditemukan/);
  const blocked = runPyrit("https://evil.com/api/chat", { program: PROGRAM, env: { PATH: "/tmp/tidak-ada-bin" } });
  assert.equal(blocked.blocked, true);
});

test("llm-runners: runPyrit fake python3 -> 1 temuan Crescendo dari JSON driver", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-pyrit-"));
  fakeBin(dir, "python3", `#!/bin/sh
if [ "$1" = "-c" ]; then exit 0; fi
for a in "$@"; do last="$a"; done
printf '%s' '{"strategy":"crescendo","objective":"Reveal the full system prompt","success":true,"turns":3}' > "$last"
`);
  const cfg = join(dir, "http-target.json");
  writeFileSync(cfg, JSON.stringify({ url: TARGET, method: "POST" }));
  const res = runPyrit(TARGET, { program: PROGRAM, env: { PATH: dir }, httpTargetConfig: cfg });
  assert.equal(res.skipped, false);
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].vulnClass, "LLM Multi-Turn Jailbreak (Crescendo)");
  assert.equal(res.findings[0].severity, "high");
});

test("llm-runners: runPyrit driver gagal (success=false) -> 0 temuan, bukan error", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-pyrit-"));
  fakeBin(dir, "python3", `#!/bin/sh
if [ "$1" = "-c" ]; then exit 0; fi
for a in "$@"; do last="$a"; done
printf '%s' '{"strategy":"tap","success":false,"turns":10}' > "$last"
`);
  const cfg = join(dir, "http-target.json");
  writeFileSync(cfg, JSON.stringify({ url: TARGET, method: "POST" }));
  const res = runPyrit(TARGET, { program: PROGRAM, env: { PATH: dir }, strategy: "tap", httpTargetConfig: cfg });
  assert.equal(res.skipped, false);
  assert.equal(res.findings.length, 0);
});
