// bounty/lib/codesearch.js — pencarian kode gaya opengrep (P1-5 parity).
// ripgrep (`rg --json`) bila ada, fallback jalan kaki file Node + regex.
// Hanya baca file teks (maks 1 MB/file, maks 2000 file), tidak menulis.
// Pola regex tidak valid -> {error} (bukan throw).
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";
import { spawnSync } from "node:child_process";

const SKIP_DIRS = new Set([".git", "node_modules", ".bounty", "dist", "build", "coverage"]);
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 2000;

function findBinary(name) {
  const parts = String(process.env.PATH ?? "").split(":");
  for (const dir of parts) {
    const p = join(dir, name);
    try { if (existsSync(p) && statSync(p).isFile()) return p; } catch {}
  }
  return null;
}

function walkFiles(dir, out = []) {
  if (out.length >= MAX_FILES) return out;
  let entries = [];
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (out.length >= MAX_FILES) break;
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) walkFiles(p, out);
    } else if (e.isFile() && !e.name.startsWith(".")) {
      out.push(p);
    }
  }
  return out;
}

export function searchCode(dir, pattern, { maxResults = 50, useRipgrep = true } = {}) {
  const started = Date.now();
  if (!dir || !existsSync(dir)) return { error: `direktori tidak ditemukan: ${dir}`, results: [], time_ms: 0 };
  let re;
  try { re = new RegExp(pattern, "i"); } catch (e) { return { error: `regex tidak valid: ${e.message}`, results: [], time_ms: 0 }; }
  const rg = useRipgrep ? findBinary("rg") : null;
  if (rg) {
    const res = spawnSync(rg, ["--json", "--no-heading", "-m", String(maxResults), "-e", pattern, dir], { encoding: "utf8", timeout: 60000 });
    if (!res.error && res.status === 0) {
      const results = [];
      for (const line of String(res.stdout ?? "").split("\n")) {
        if (!line.trim()) continue;
        try {
          const j = JSON.parse(line);
          if (j.type === "match") {
            results.push({ file: j.data.path.text, line: j.data.line_number, text: (j.data.lines.text ?? "").trim().slice(0, 300) });
          }
        } catch {}
        if (results.length >= maxResults) break;
      }
      return { tool: "ripgrep", results, time_ms: Date.now() - started };
    }
    // rg gagal (mis. tidak ada hasil = exit 1) -> fallback jalan kaki.
  }
  const results = [];
  for (const file of walkFiles(dir)) {
    if (results.length >= maxResults) break;
    let st;
    try { st = statSync(file); } catch { continue; }
    if (!st.isFile() || st.size > MAX_FILE_BYTES) continue;
    if ([".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".ico", ".woff", ".woff2"].includes(extname(file).toLowerCase())) continue;
    let text;
    try { text = readFileSync(file, "utf8"); } catch { continue; }
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) {
        results.push({ file, line: i + 1, text: lines[i].trim().slice(0, 300) });
        if (results.length >= maxResults) break;
      }
    }
  }
  return { tool: rg ? "node-walk (rg fallback)" : "node-walk", results, time_ms: Date.now() - started };
}

export default { searchCode };
