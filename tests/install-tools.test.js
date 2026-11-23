// tests/install-tools.test.js — P2-6: scripts/install-tools.sh (mode rencana).
// Skrip TIDAK PERNAH dijalankan dengan --yes di sini (tidak ada go/pipx di
// VM dan instalasi nyata bukan urusan test). Yang diuji: mode rencana
// (--dry-run / tanpa flag) hanya mencetak perintah, subset flag, dan
// penolakan prasyarat (exit 2) saat --yes tapi prereq hilang.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const SCRIPT = join(ROOT, "scripts/install-tools.sh");

// PATH kosong: go/pipx/pdtm tidak ditemukan -> rencana tetap tercetak,
// --yes harus menolak dengan exit 2 sebelum menjalankan apa pun.
const EMPTY_ENV = { ...process.env, PATH: mkdtempSync(join(tmpdir(), "bounty-empty-path-")) };

function runScript(args, env = EMPTY_ENV) {
  // /bin/sh absolut: PATH kosong di env membuat spawnSync("sh") gagal
  // menemukan shell (ENOENT), padahal skrip sendiri harus jalan di situ.
  return spawnSync("/bin/sh", [SCRIPT, ...args], { cwd: ROOT, env, encoding: "utf8" });
}

test("install-tools: sh -n lolos (sintaks POSIX sh)", () => {
  const r = spawnSync("sh", ["-n", SCRIPT], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});

test("install-tools: --dry-run cetak semua perintah instal, tanpa --yes", () => {
  const r = runScript(["--dry-run"]);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /Mode rencana/);
  assert.match(r.stdout, /Tidak menjalankan apa pun/);
  assert.match(r.stdout, /go install -v github\.com\/projectdiscovery\/pdtm\/cmd\/pdtm@latest/);
  assert.match(r.stdout, /pdtm -install subfinder,dnsx,httpx,katana,nuclei/);
  assert.match(r.stdout, /go install .*github\.com\/BishopFox\/jsluice\/cmd\/jsluice@latest/);
  assert.match(r.stdout, /go install .*github\.com\/projectdiscovery\/interactsh\/cmd\/interactsh-client@latest/);
  assert.match(r.stdout, /pipx install garak/);
  assert.match(r.stdout, /pipx install pyrit/);
  assert.match(r.stdout, /--yes/);
});

test("install-tools: tanpa flag = mode rencana (tidak menjalankan apa pun)", () => {
  const r = runScript([]);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /Mode rencana/);
  assert.match(r.stdout, /Tidak menjalankan apa pun/);
});

test("install-tools: subset --pd-only / --go-only / --python-only", () => {
  const pd = runScript(["--pd-only"]);
  assert.equal(pd.status, 0, pd.stderr + pd.stdout);
  assert.match(pd.stdout, /pdtm -install/);
  assert.doesNotMatch(pd.stdout, /pipx install/);
  assert.doesNotMatch(pd.stdout, /jsluice/);

  const go = runScript(["--go-only"]);
  assert.equal(go.status, 0, go.stderr + go.stdout);
  assert.match(go.stdout, /jsluice/);
  assert.match(go.stdout, /interactsh-client/);
  assert.doesNotMatch(go.stdout, /pipx install/);
  assert.doesNotMatch(go.stdout, /pdtm -install/);

  const py = runScript(["--python-only"]);
  assert.equal(py.status, 0, py.stderr + py.stdout);
  assert.match(py.stdout, /pipx install garak/);
  assert.match(py.stdout, /pipx install pyrit/);
  assert.doesNotMatch(py.stdout, /go install/);
});

test("install-tools: --yes tanpa go/pipx -> exit 2 sebelum menjalankan apa pun", () => {
  const rGo = runScript(["--yes", "--go-only"]);
  assert.equal(rGo.status, 2, rGo.stderr + rGo.stdout);
  assert.match(rGo.stderr + rGo.stdout, /go tidak ditemukan/);

  const rPy = runScript(["--yes", "--python-only"]);
  assert.equal(rPy.status, 2, rPy.stderr + rPy.stdout);
  assert.match(rPy.stderr + rPy.stdout, /pipx tidak ditemukan/);
});

test("install-tools: argumen tidak dikenal -> usage + exit 1", () => {
  const r = runScript(["--bogus"]);
  assert.equal(r.status, 1, r.stderr + r.stdout);
  assert.match(r.stdout + r.stderr, /Usage/);
});
