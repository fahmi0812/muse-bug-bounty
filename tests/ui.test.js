import test from "node:test";
import assert from "node:assert/strict";
import {
  colorsEnabled,
  color,
  severityColor,
  severityBadge,
  table,
  progressBar,
  summaryBox,
  phaseLine,
  formatUsd,
} from "../bounty/lib/ui.js";

// Helper: jalankan fn dengan env sementara, kembalikan nilai lama di finally.
function withEnv(patch, fn) {
  const saved = {};
  for (const k of Object.keys(patch)) {
    saved[k] = Object.prototype.hasOwnProperty.call(process.env, k) ? process.env[k] : undefined;
  }
  try {
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    return fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const TTY = { isTTY: true };
const NO_TTY = {};

test("NO_COLOR (string kosong) mematikan warna walau TTY", () => {
  withEnv({ NO_COLOR: "", BOUNTY_NO_COLOR: undefined }, () => {
    assert.equal(colorsEnabled({ stream: TTY }), false);
  });
});

test("BOUNTY_NO_COLOR=1 mematikan warna walau TTY", () => {
  withEnv({ NO_COLOR: undefined, BOUNTY_NO_COLOR: "1" }, () => {
    assert.equal(colorsEnabled({ stream: TTY }), false);
  });
});

test("opts.color true memaksa nyala walau NO_COLOR ada", () => {
  withEnv({ NO_COLOR: "1", BOUNTY_NO_COLOR: undefined }, () => {
    assert.equal(colorsEnabled({ color: true, stream: NO_TTY }), true);
  });
});

test("opts.color false mematikan warna walau TTY", () => {
  withEnv({ NO_COLOR: undefined, BOUNTY_NO_COLOR: undefined }, () => {
    assert.equal(colorsEnabled({ color: false, stream: TTY }), false);
  });
});

test("stream tanpa isTTY -> warna mati", () => {
  withEnv({ NO_COLOR: undefined, BOUNTY_NO_COLOR: undefined }, () => {
    assert.equal(colorsEnabled({ stream: NO_TTY }), false);
    assert.equal(colorsEnabled({ stream: TTY }), true);
  });
});

test("color() tanpa warna = teks polos", () => {
  assert.equal(color("halo", "red", { color: false }), "halo");
  assert.equal(color("halo", "tidak-ada", { color: true }), "halo");
});

test("color() dengan warna = berisi kode ANSI + reset", () => {
  assert.equal(color("halo", "red", { color: true }), "\x1b[31mhalo\x1b[0m");
  assert.equal(color("halo", "green", { color: true }), "\x1b[32mhalo\x1b[0m");
  assert.equal(color("halo", "yellow", { color: true }), "\x1b[33mhalo\x1b[0m");
  assert.equal(color("halo", "cyan", { color: true }), "\x1b[36mhalo\x1b[0m");
  assert.equal(color("halo", "dim", { color: true }), "\x1b[2mhalo\x1b[0m");
  assert.equal(color("halo", "bold", { color: true }), "\x1b[1mhalo\x1b[0m");
});

test("severityColor memetakan semua level + tak dikenal", () => {
  assert.equal(severityColor("critical"), "red");
  assert.equal(severityColor("high"), "red");
  assert.equal(severityColor("medium"), "yellow");
  assert.equal(severityColor("low"), "cyan");
  assert.equal(severityColor("info"), "dim");
  assert.equal(severityColor("aneh"), "dim");
  assert.equal(severityColor(undefined), "dim");
});

test("severityBadge label Indonesia, polos saat warna mati", () => {
  const off = { color: false };
  assert.equal(severityBadge("critical", off), "[KRITIS]");
  assert.equal(severityBadge("high", off), "[TINGGI]");
  assert.equal(severityBadge("medium", off), "[SEDANG]");
  assert.equal(severityBadge("low", off), "[RENDAH]");
  assert.equal(severityBadge("info", off), "[INFO]");
  assert.equal(severityBadge("aneh", off), "[?]");
  assert.equal(severityBadge("critical", { color: true }), "\x1b[31m[KRITIS]\x1b[0m");
});

test("table() meratakan kolom, skip baris kosong, rows kosong -> ''", () => {
  const out = table([["a", "bb"], [], ["ccc", "d"]], ["Kolom1", "K2"], { color: false });
  assert.equal(out, "Kolom1  K2\n" + "a       bb\n" + "ccc     d");
  assert.equal(table([], ["H"], { color: false }), "");
  assert.equal(table([], [], { color: false }), "");
});

test("progressBar 0/20, setengah, penuh", () => {
  assert.equal(progressBar(0, 20), "[░░░░░░░░░░░░░░░░░░░░] 0/20");
  assert.equal(progressBar(10, 20), "[██████████░░░░░░░░░░] 10/20");
  assert.equal(progressBar(20, 20), "[████████████████████] 20/20");
  assert.equal(progressBar(6, 20), "[██████░░░░░░░░░░░░░░] 6/20");
});

test("progressBar done>total dijepit, total 0 -> blok kosong", () => {
  assert.equal(progressBar(30, 20), "[████████████████████] 20/20");
  assert.equal(progressBar(0, 0), "[░░░░░░░░░░░░░░░░░░░░] 0/0");
  assert.equal(progressBar(5, -3), "[░░░░░░░░░░░░░░░░░░░░] 0/0");
});

test("summaryBox bentuk kotak + judul di dalam", () => {
  assert.equal(summaryBox(["a", "bb"]), "┌────┐\n│ a  │\n│ bb │\n└────┘");
  assert.equal(
    summaryBox(["a"], { title: "Hasil" }),
    "┌───────┐\n│ Hasil │\n│ a     │\n└───────┘",
  );
});

test("phaseLine dengan dan tanpa detail", () => {
  assert.equal(phaseLine("Scope", "OK"), "▸ Scope: OK");
  assert.equal(phaseLine("Scope"), "▸ Scope");
  assert.equal(phaseLine("Scope", ""), "▸ Scope");
  assert.equal(phaseLine("Scope", undefined), "▸ Scope");
});

test("formatUsd: 5, 0.42, NaN, bukan angka", () => {
  assert.equal(formatUsd(5), "$5.00");
  assert.equal(formatUsd(0.42), "$0.42");
  assert.equal(formatUsd(0), "$0.00");
  assert.equal(formatUsd(NaN), "$0.00");
  assert.equal(formatUsd("bukan-angka"), "$0.00");
  assert.equal(formatUsd(undefined), "$0.00");
});
