// bounty/lib/ui.js — helper tampilan CLI (warna, tabel, progress, ringkasan).
// Murni format teks, tanpa I/O dan tanpa process.exit. Warna mati bila
// env NO_COLOR ada (nilai apa pun) atau BOUNTY_NO_COLOR=1, kecuali opts.color memaksa.
const ANSI = { red: 31, green: 32, yellow: 33, cyan: 36, dim: 2, bold: 1 };
// Kode SGR ANSI (mis. \x1b[31m ... \x1b[0m) untuk menghitung lebar tampak.
const ANSI_SGR_RE = /\x1b\[[0-9;]*m/g;
/** Panjang teks yang benar-benar terlihat (tanpa kode warna ANSI). */
function visibleLength(text) {
  return String(text).replace(ANSI_SGR_RE, "").length;
}

/** Apakah warna ANSI boleh dipakai. opts.color true memaksa nyala, false memaksa mati. */
export function colorsEnabled(opts = {}) {
  try {
    if (opts.color === true) return true;
    if (opts.color === false) return false;
    const env = typeof process !== "undefined" ? process.env : {};
    if (env && "NO_COLOR" in env) return false;
    if (env && env.BOUNTY_NO_COLOR === "1") return false;
    const stream = opts.stream ?? (typeof process !== "undefined" ? process.stdout : undefined);
    return stream?.isTTY === true;
  } catch {
    return false;
  }
}

/** Bungkus teks dengan kode ANSI bila warna nyala; nama tak dikenal -> teks polos. */
export function color(text, name, opts = {}) {
  const code = ANSI[name];
  if (code === undefined || !colorsEnabled(opts)) return String(text);
  return `\x1b[${code}m${text}\x1b[0m`;
}

/** Petakan severity ke nama warna (hanya pemetaan, bukan mewarnai). */
export function severityColor(severity) {
  switch (String(severity ?? "").trim().toLowerCase()) {
    case "critical":
    case "high":
      return "red";
    case "medium":
      return "yellow";
    case "low":
      return "cyan";
    case "info":
      return "dim";
    default:
      return "dim";
  }
}

/** Badge severity berbahasa Indonesia, diwarnai bila warna nyala. */
export function severityBadge(severity, opts = {}) {
  const labels = { critical: "[KRITIS]", high: "[TINGGI]", medium: "[SEDANG]", low: "[RENDAH]", info: "[INFO]" };
  const key = String(severity ?? "").trim().toLowerCase();
  const label = labels[key] ?? "[?]";
  return color(label, severityColor(key), opts);
}

/** Tabel teks rata kiri; kolom selebar item terpanjang, pemisah 2 spasi. */
export function table(rows, headers, opts = {}) {
  const data = (Array.isArray(rows) ? rows : []).filter((r) => Array.isArray(r) && r.length > 0);
  const head = Array.isArray(headers) ? headers : [];
  if (data.length === 0) return "";
  const all = head.length > 0 ? [head, ...data] : data;
  const cols = Math.max(...all.map((r) => r.length));
  // Lebar kolom dihitung dari panjang TAMPAK (tanpa kode ANSI), supaya
  // sel berwarna (mis. badge severity) tidak menggeser kolom berikutnya.
  const widths = Array.from({ length: cols }, (_, i) =>
    Math.max(...all.map((r) => visibleLength(r[i] ?? ""))),
  );
  const paint = colorsEnabled(opts);
  const lines = all.map((row, idx) => {
    const cells = Array.from({ length: cols }, (_, i) => {
      const cell = String(row[i] ?? "");
      return cell + " ".repeat(Math.max(0, widths[i] - visibleLength(cell)));
    });
    const line = cells.join("  ").replace(/\s+$/, "");
    return idx === 0 && head.length > 0 && paint ? `\x1b[1m${line}\x1b[0m` : line;
  });
  return lines.join("\n");
}

/** Progress bar teks, mis. "[██████░░░░░░░░░░░░░░] 6/20". */
export function progressBar(done, total, width = 20) {
  const w = Math.max(0, Math.floor(Number(width) || 0));
  const t = Number(total);
  if (!Number.isFinite(t) || t <= 0) return `[${"░".repeat(w)}] 0/0`;
  const d = Math.min(Math.max(0, Math.floor(Number(done) || 0)), t);
  const filled = Math.round((d / t) * w);
  return `[${"█".repeat(filled)}${"░".repeat(w - filled)}] ${d}/${t}`;
}

/** Kotak teks dari garis ─ │ ┌┐└┘; judul (bila ada) jadi baris pertama di dalam kotak. */
export function summaryBox(lines, opts = {}) {
  const body = Array.isArray(lines) ? lines.map((l) => String(l)) : [];
  const all = opts.title !== undefined && opts.title !== null && opts.title !== ""
    ? [String(opts.title), ...body]
    : body;
  // Lebar dari panjang TAMPAK supaya isi berwarna (kode ANSI) tidak
  // menggeser garis tepi kanan kotak.
  const inner = Math.max(0, ...all.map((l) => visibleLength(l))) + 2;
  const top = `┌${"─".repeat(inner)}┐`;
  const bottom = `└${"─".repeat(inner)}┘`;
  const middle = all.map((l) => `│ ${l + " ".repeat(Math.max(0, inner - 2 - visibleLength(l)))} │`);
  return [top, ...middle, bottom].join("\n");
}

/** Satu baris fase, mis. "▸ Scope: OK" (tanpa detail -> "▸ Scope"). */
export function phaseLine(phase, detail, opts = {}) {
  const p = String(phase ?? "");
  if (detail === undefined || detail === null || String(detail) === "") return `▸ ${p}`;
  return `▸ ${p}: ${detail}`;
}

/** Judul seksi (tebal) untuk wizard/ringkasan; warna mengikuti colorsEnabled. */
export function heading(text, opts = {}) {
  return color(String(text ?? ""), "bold", opts);
}

/** Teks petunjuk redup (mis. nilai default pada prompt). */
export function hint(text, opts = {}) {
  return color(String(text ?? ""), "dim", opts);
}

/** Format dolar 2 desimal, mis. 5 -> "$5.00"; bukan angka/NaN -> "$0.00". */
export function formatUsd(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return "$0.00";
  return `$${v.toFixed(2)}`;
}
