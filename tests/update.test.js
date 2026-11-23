// bounty update — repo git temp: pull maju, dirty file di-stash + kembali.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { isBountyRepo, findRepoDir, trackedDirtyLines, runUpdate } from "../bounty/lib/update.js";

function git(dir, ...args) {
  return execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-C", dir, ...args], { encoding: "utf8" });
}

function makeRepo(dir, version) {
  mkdirSync(dir, { recursive: true });
  git(dir, "init", "-b", "main");
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "muse-bug-bounty", version }, null, 2));
  writeFileSync(join(dir, "README.md"), "awal\n");
  git(dir, "add", ".");
  git(dir, "commit", "-m", "awal");
  return dir;
}

function withTmp(fn) {
  const base = mkdtempSync(join(tmpdir(), "bounty-update-"));
  try {
    return fn(base);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

const fakeInstall = () => ({ ok: true, fake: true });

test("update: isBountyRepo + findRepoDir", () => withTmp((base) => {
  const repo = makeRepo(join(base, "repo"), "1.0.0");
  assert.equal(isBountyRepo(repo), true);
  assert.equal(isBountyRepo(base), false);
  assert.equal(findRepoDir({ cwd: repo }), repo);
  assert.equal(findRepoDir({ source: repo }), repo);
  assert.equal(findRepoDir({ source: base }), null);
  assert.equal(findRepoDir({ cwd: base }), null);
}));

test("update: trackedDirtyLines hanya perubahan tracked", () => {
  assert.deepEqual(trackedDirtyLines(" M a.js\n?? baru.md\n M b.js\n"), ["M a.js", "M b.js"]);
  assert.deepEqual(trackedDirtyLines("?? saja.md\n"), []);
  assert.deepEqual(trackedDirtyLines(""), []);
});

test("update: pull maju + versi naik (tanpa perubahan lokal)", () => withTmp((base) => {
  const origin = makeRepo(join(base, "origin"), "1.0.0");
  const clone = join(base, "clone");
  git(base, "clone", "-q", origin, clone);
  // Remote maju: bump versi + ubah README.
  writeFileSync(join(origin, "package.json"), JSON.stringify({ name: "muse-bug-bounty", version: "1.0.1" }, null, 2));
  writeFileSync(join(origin, "README.md"), "baru\n");
  git(origin, "add", ".");
  git(origin, "commit", "-m", "bump");
  const r = runUpdate({ dir: clone, install: fakeInstall });
  assert.equal(r.from, "1.0.0");
  assert.equal(r.to, "1.0.1");
  assert.equal(r.stashed, false);
  assert.equal(readFileSync(join(clone, "README.md"), "utf8"), "baru\n");
}));

test("update: file lokal kotor di-stash, pull jalan, lalu dikembalikan", () => withTmp((base) => {
  const origin = makeRepo(join(base, "origin"), "1.0.0");
  const clone = join(base, "clone");
  git(base, "clone", "-q", origin, clone);
  // Remote ubah README; lokal ubah package.json (bukan file yang sama).
  writeFileSync(join(origin, "README.md"), "remote\n");
  git(origin, "add", ".");
  git(origin, "commit", "-m", "remote");
  writeFileSync(join(clone, "package.json"), JSON.stringify({ name: "muse-bug-bounty", version: "1.0.0-lokal" }, null, 2));
  const r = runUpdate({ dir: clone, install: fakeInstall });
  assert.equal(r.stashed, true);
  assert.equal(r.stashRestored, true);
  assert.equal(r.from, "1.0.0-lokal");
  assert.equal(r.to, "1.0.0-lokal"); // versi lokal tetap (file lokal kembali)
  assert.equal(readFileSync(join(clone, "README.md"), "utf8"), "remote\n");
  assert.equal(JSON.parse(readFileSync(join(clone, "package.json"), "utf8")).version, "1.0.0-lokal");
  assert.equal(git(clone, "stash", "list").trim(), ""); // tidak ada stash tertinggal
}));

test("update: dry-run tidak mengubah apa pun", () => withTmp((base) => {
  const origin = makeRepo(join(base, "origin"), "1.0.0");
  const clone = join(base, "clone");
  git(base, "clone", "-q", origin, clone);
  writeFileSync(join(origin, "README.md"), "remote\n");
  git(origin, "add", ".");
  git(origin, "commit", "-m", "remote");
  writeFileSync(join(clone, "README.md"), "lokal-kotor\n");
  const r = runUpdate({ dir: clone, dryRun: true, install: () => { throw new Error("install tidak boleh jalan di dry-run"); } });
  assert.equal(r.dryRun, true);
  assert.equal(r.to, "1.0.0");
  assert.equal(readFileSync(join(clone, "README.md"), "utf8"), "lokal-kotor\n");
  assert.equal(existsSync(join(clone, ".git", "refs", "stash")), false);
}));
