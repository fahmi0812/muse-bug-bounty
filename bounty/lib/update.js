// bounty update — perbarui wrapper dari repo git + instal ulang global.
// Alur: cari clone repo -> stash perubahan tracked (bila ada) -> git pull
// --ff-only -> coba kembalikan stash -> npm install -g.
// File yang tidak pernah diedit pengguna (mis. mode bounty.mjs yang berubah
// sendiri setelah npm install -g) tidak lagi menggagalkan update: perubahan
// itu di-stash dulu, lalu dikembalikan bila memungkinkan.
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { homedir } from "node:os";

export function isBountyRepo(dir) {
  try {
    if (!existsSync(join(dir, ".git"))) return false;
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    return pkg && pkg.name === "muse-bug-bounty";
  } catch {
    return false;
  }
}

export function candidateDirs(cwd) {
  const home = homedir();
  return [
    cwd,
    join(home, "muse-bug-bounty"),
    join(home, "Downloads", "LAB GITHUB", "EXPERIMENTAL", "muse-bug-bounty"),
  ];
}

// Cari clone repo: --source eksplisit dulu, lalu cwd, lalu lokasi umum.
export function findRepoDir({ source, cwd = process.cwd() } = {}) {
  if (source) {
    const dir = resolve(source);
    return isBountyRepo(dir) ? dir : null;
  }
  for (const dir of candidateDirs(cwd)) {
    if (isBountyRepo(dir)) return dir;
  }
  return null;
}

export function readVersion(dir) {
  try {
    return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version ?? null;
  } catch {
    return null;
  }
}

function git(dir, args) {
  return execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

// Baris status yang BUKAN untracked (??) = perubahan tracked yang bisa
// menghalangi pull. File untracked (programs/*.md, .bounty/) dibiarkan.
export function trackedDirtyLines(porcelain) {
  return String(porcelain ?? "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("??"));
}

export function defaultInstall(dir) {
  const r = spawnSync("npm", ["install", "-g", "--ignore-scripts"], { cwd: dir, stdio: "inherit" });
  if (r.error) throw new Error(`npm tidak bisa dijalankan: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`npm install -g gagal (exit ${r.status})`);
  return { ok: true };
}

// Jalankan update. install bisa di-override (dipakai test).
// dryRun: hanya laporkan rencana, tanpa mengubah apa pun.
export function runUpdate({ dir, dryRun = false, install = defaultInstall } = {}) {
  if (!dir || !isBountyRepo(dir)) throw new Error("bukan clone muse-bug-bounty (tidak ada .git/package.json yang cocok)");
  const from = readVersion(dir);
  let porcelain = "";
  try {
    porcelain = git(dir, ["status", "--porcelain=v1"]);
  } catch (e) {
    throw new Error(`git status gagal: ${String(e.stderr || e.message || e).trim()}`);
  }
  const dirty = trackedDirtyLines(porcelain);
  const plan = { dir, from, dirty, wouldStash: dirty.length > 0, wouldPull: true, wouldInstall: true };
  if (dryRun) return { ...plan, dryRun: true, to: from };
  let stashed = false;
  let stashRestored = null;
  try {
    if (dirty.length > 0) {
      git(dir, ["stash", "push", "-m", `bounty-update ${new Date().toISOString()}`]);
      stashed = true;
    }
    try {
      git(dir, ["pull", "--ff-only"]);
    } catch (e) {
      throw new Error(`git pull --ff-only gagal: ${String(e.stderr || e.message || e).trim()} — selesaikan konflik/riwayat lokal dulu, lalu ulangi bounty update`);
    }
    if (stashed) {
      try {
        git(dir, ["stash", "pop"]);
        stashRestored = true;
      } catch {
        stashRestored = false; // stash tetap tersimpan; pengguna pulihkan manual
      }
    }
    install(dir);
  } catch (e) {
    // Bila pull gagal setelah stash, stash tetap ada — beri tahu pengguna.
    if (stashed && stashRestored === null) {
      throw new Error(`${e.message}\nPerubahan lokalmu aman di stash — pulihkan dengan: git -C ${dir} stash pop`);
    }
    throw e;
  }
  const to = readVersion(dir);
  return { ...plan, to, stashed, stashRestored };
}
