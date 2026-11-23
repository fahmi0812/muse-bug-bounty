// bounty/lib/secrets.js — secret-leak scan + redaksi untuk output/log/laporan (P1-1).
// Dipakai sebelum laporan ditulis ke file/stdout (lihat bin/bounty.mjs cmdReport).
// Beda dengan guard.js: API di sini mengembalikan lokasi baris per temuan
// (scanText -> { found, matches: [{ type, line }] }) dan dipakai untuk
// memblokir/membersihkan laporan, bukan untuk guard perintah.
//
// Aturan panjang minimum: secret asli panjang (>= 20 karakter badan token).
// Fixture palsu seperti 'sk-abcdef' (6 karakter) TIDAK ditandai — itu bukan
// secret, itu contoh di test/docs.
export const SECRET_PATTERNS = [
  { type: "openai-key", re: /sk-[A-Za-z0-9_-]{20,}/ },
  { type: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  { type: "github-token", re: /ghp_[A-Za-z0-9]{20,}/ },
  { type: "github-pat", re: /github_pat_[A-Za-z0-9_]{20,}/ },
  { type: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { type: "bearer-token", re: /Bearer\s+[A-Za-z0-9._-]{20,}/ },
  { type: "jwt", re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  // Assignment: password=... / api_key=... / secret=... — nilai min 4 karakter
  // supaya 'password=' kosong atau placeholder 1-3 huruf tidak ikut ditandai.
  { type: "password-assign", re: /(?:password|passwd|pwd)\s*=\s*[^\s'";]{4,}/i },
  { type: "api-key-assign", re: /(?:api[_-]?key|apikey|secret)\s*=\s*[^\s'";]{4,}/i },
];

/**
 * scanText(text) -> { found: boolean, matches: [{ type, line }] }.
 * line = nomor baris (1-based) tempat match ditemukan.
 */
export function scanText(text) {
  const input = String(text ?? "");
  const matches = [];
  for (const { type, re } of SECRET_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    let m;
    while ((m = g.exec(input)) !== null) {
      const line = input.slice(0, m.index).split("\n").length;
      matches.push({ type, line });
      if (m[0].length === 0) g.lastIndex += 1; // jaga-jaga match kosong
    }
  }
  return { found: matches.length > 0, matches };
}

/**
 * redact(text) — ganti setiap secret dengan [REDACTED].
 * Untuk assignment (password=...), nama kuncinya dipertahankan
 * ('password=[REDACTED]') supaya laporan tetap bisa dibaca; untuk token
 * mentah, seluruh token diganti.
 */
export function redact(text) {
  let out = String(text ?? "");
  for (const { type, re } of SECRET_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    if (type === "password-assign" || type === "api-key-assign") {
      out = out.replace(g, (m) => m.replace(/\s*=\s*[^\s'";]+$/, "=[REDACTED]"));
    } else {
      out = out.replace(g, "[REDACTED]");
    }
  }
  return out;
}

export default { scanText, redact, SECRET_PATTERNS };
