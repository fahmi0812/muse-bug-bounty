// Tes untuk wizard `bounty setup`: fungsi murni (setup.js) + jalur
// non-interaktif CLI. Output CLI di-pipe (bukan TTY) -> warna mati.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  slugify, normalizeHost, scopeTemplate, SCOPE_TEMPLATES,
  defaultProviderBase, filterModels, buildProgramMarkdown, exampleTargetFor,
} from "../bounty/lib/setup.js";
import { parseProgram, checkScope } from "../bounty/lib/scope.js";
import { heading, hint } from "../bounty/lib/ui.js";
import { NINE_ROUTER_BASE } from "../bounty/lib/provider.js";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");

test("slugify: aman untuk nama file", () => {
  assert.equal(slugify("Staging API"), "staging-api");
  assert.equal(slugify("https://A.B.Com/x"), "a.b.com-x");
  assert.equal(slugify("  --weird__name-- "), "weird-name");
  assert.equal(slugify(""), "program");
});

test("normalizeHost: buang skema & path, lowercase", () => {
  assert.equal(normalizeHost("https://Staging.Contoh.Com/api/x"), "staging.contoh.com");
  assert.equal(normalizeHost("contoh.com"), "contoh.com");
});

test("scopeTemplate: terima nomor/kata, tolak yang lain", () => {
  assert.equal(scopeTemplate("1").key, "all");
  assert.equal(scopeTemplate("api").key, "api");
  assert.equal(scopeTemplate("3").key, "custom");
  assert.deepEqual(scopeTemplate("api").allowed, ["/api/"]);
  assert.equal(scopeTemplate("zzz"), null);
});

test("filterModels: substring case-insensitive; kosong -> semua", () => {
  const m = ["gpt-4o", "gpt-4o-mini", "claude-3"];
  assert.deepEqual(filterModels(m, "mini"), ["gpt-4o-mini"]);
  assert.deepEqual(filterModels(m, ""), m);
  assert.deepEqual(filterModels(m, "GPT"), ["gpt-4o", "gpt-4o-mini"]);
});

test("defaultProviderBase: anthropic vs openai(9router)", () => {
  assert.equal(defaultProviderBase("anthropic"), "https://api.anthropic.com");
  assert.equal(defaultProviderBase("openai"), NINE_ROUTER_BASE);
  assert.equal(defaultProviderBase(""), NINE_ROUTER_BASE);
});

test("buildProgramMarkdown: round-trip lewat parseProgram", () => {
  const md = buildProgramMarkdown({ name: "Staging", host: "staging.contoh.com", allowed: ["/api/"], denied: ["/admin"], budget: 7, rate: 3, roles: ["low"] });
  const p = parseProgram(md);
  assert.equal(p.name, "Staging");
  assert.deepEqual(p.allowedHosts, ["staging.contoh.com"]);
  assert.deepEqual(p.allowedPaths, ["/api/"]);
  assert.deepEqual(p.deniedPaths, ["/admin"]);
  assert.equal(p.maxBudgetUsd, 7);
  assert.equal(p.rateLimit, 3);
  assert.deepEqual(p.roles, ["low"]);
});

test("exampleTargetFor + checkScope: target contoh selalu in-scope", () => {
  for (const key of ["all", "api"]) {
    const t = scopeTemplate(key);
    const md = buildProgramMarkdown({ name: "P", host: "contoh.com", allowed: t.allowed, denied: [] });
    const prog = parseProgram(md);
    const target = exampleTargetFor("contoh.com", t.allowed);
    const scope = checkScope(prog, target);
    assert.equal(scope.ok, true, `${key}: ${target} -> ${scope.reason}`);
  }
  // "API saja" -> path /api/, bukan /
  assert.equal(exampleTargetFor("contoh.com", SCOPE_TEMPLATES.api.allowed), "https://contoh.com/api/");
});

test("heading/hint: ANSI hanya saat warna dipaksa nyala", () => {
  assert.equal(heading("Judul", { color: false }), "Judul");
  assert.match(heading("Judul", { color: true }), /\x1b\[1m/);
  assert.equal(hint("x", { color: false }), "x");
  assert.match(hint("x", { color: true }), /\x1b\[2m/);
});

test("CLI setup non-TTY tanpa --yes: keluar dengan panduan (exit 2)", () => {
  const r = spawnSync(process.execPath, [CLI, "setup"], { cwd: ROOT, encoding: "utf8", input: "" });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /butuh terminal interaktif|--yes/);
});

test("CLI setup --yes --skip-provider: bikin program + verifikasi Scope OK", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-setup-"));
  const r = spawnSync(process.execPath, [
    CLI, "setup", "--yes", "--skip-provider",
    "--name", "Staging Contoh", "--host", "staging.contoh.com", "--template", "api",
  ], { cwd: dir, env: { ...process.env, BOUNTY_DB: join(dir, "bounty.db") }, encoding: "utf8", input: "" });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const progPath = join(dir, "programs", "staging-contoh.md");
  assert.ok(existsSync(progPath), "file program harus dibuat");
  const p = parseProgram(readFileSync(progPath, "utf8"));
  assert.deepEqual(p.allowedHosts, ["staging.contoh.com"]);
  assert.deepEqual(p.allowedPaths, ["/api/"]);
  assert.match(r.stdout, /Scope OK/);
  assert.match(r.stdout, /bounty run --program/);
  rmSync(dir, { recursive: true, force: true });
});

test("CLI run tanpa argumen di non-TTY: tidak menggantung (pakai default lama)", () => {
  const dir = mkdtempSync(join(tmpdir(), "bounty-run-noarg-"));
  const r = spawnSync(process.execPath, [CLI, "run", "--dry-run"], { cwd: dir, env: { ...process.env, BOUNTY_DB: join(dir, "bounty.db") }, encoding: "utf8", input: "", timeout: 15000 });
  // programs/example.md tidak ada di cwd temp -> error jelas, bukan hang.
  assert.notEqual(r.signal, "SIGTERM", "tidak boleh timeout/hang");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Program tidak ditemukan/);
  rmSync(dir, { recursive: true, force: true });
});
