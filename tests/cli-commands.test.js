import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = resolve(ROOT, "bounty/bin/bounty.mjs");
function run(...args) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, encoding: "utf8" });
}

test("bounty programs lists dvga + llm-app", () => {
  const r = run("programs");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /dvga/);
  assert.match(r.stdout, /llm-app/);
  assert.match(r.stdout, /juice-shop/);
});

test("bounty findings empty store exit 0", () => {
  const r = run("findings");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Tidak ada temuan/);
});

test("bounty findings --program dvga exit 0", () => {
  const r = run("findings", "--program", "dvga");
  assert.equal(r.status, 0, r.stderr);
});

test("programs dvga + llm-app files exist and parse", () => {
  for (const name of ["dvga", "llm-app"]) {
    assert.ok(existsSync(resolve(ROOT, `programs/${name}.md`)), name);
    const txt = readFileSync(resolve(ROOT, `programs/${name}.md`), "utf8");
    assert.match(txt, /Budget: \$5/);
    assert.match(txt, /Roles: low, high/);
  }
});

test("winget manifests exist and are honest about status", () => {
  assert.ok(existsSync(resolve(ROOT, "winget/fahmi0812.muse-bug-bounty.yaml")));
  assert.ok(existsSync(resolve(ROOT, "winget/fahmi0812.muse-bug-bounty.installer.yaml")));
  const txt = readFileSync(resolve(ROOT, "winget/README.md"), "utf8");
  assert.match(txt, /Belum live di winget/);
});

test("README quickstart matches real CLI", () => {
  const txt = readFileSync(resolve(ROOT, "README.md"), "utf8");
  assert.match(txt, /programs\/example\.md/);
  assert.doesNotMatch(txt, /programs\/<nama>\.json/);
  assert.match(txt, /Node\.js >= 24/);
  assert.match(txt, /winget install fahmi0812\.muse-bug-bounty/);
});
