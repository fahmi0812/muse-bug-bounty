// bounty/lib/secrets.js — secret-leak scan + redaksi untuk output/log/laporan (P1-1).
// Dipakai sebelum laporan ditulis ke file/stdout (lihat bin/bounty.mjs cmdReport).
// Beda dengan guard.js: API di sini mengembalikan lokasi baris per temuan
// (scanText -> { found, matches: [{ type, line }] }) dan dipakai untuk
// memblokir/membersihkan laporan, bukan untuk guard perintah.
//
// Aturan:
// - Pola format-spesifik diurutkan dari yang paling spesifik ke generik.
// - Placeholder (EXAMPLE, xxxx, fake, dummy, changeme, <...>) TIDAK ditandai
//   pada pola assignment/entropi — tapi TIDAK berlaku untuk token format
//   spesifik (mis. AKIA...EXAMPLE tetap ditandai: itu format AWS yang sah,
//   dan test lama mengandalkannya).
// - Dedup antar-rule: satu rentang teks yang sudah kena rule spesifik tidak
//   dilaporkan lagi oleh rule generik (mis. sk-... di dalam `key=sk-...`
//   hanya dilaporkan sekali sebagai openai-key).
// - JWT divalidasi: segmen header harus decode base64url menjadi JSON yang
//   berisi field "alg" — token eyJ... acak tanpa alg bukan JWT.
// - Entropi Shannon sebagai fallback generik: nilai >= 20 karakter dalam
//   assignment ke variabel bernama kredensial, entropi >= 4,5 bit/karakter
//   (base64) atau >= 3,7 (hex). Menangkap secret custom tanpa prefix.
// - Fixture palsu seperti 'sk-abcdef' (6 karakter) TIDAK ditandai.
export const PLACEHOLDER_RE = /(?:example|xxxx|fake|dummy|changeme|placeholder|your[_-]?|replace[_-]?me|test123|123456|<[^>]*>)/i;

export function isPlaceholder(value) {
  return PLACEHOLDER_RE.test(String(value ?? ""));
}

export function shannonEntropy(s) {
  const str = String(s ?? "");
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isHex(s) {
  return /^[0-9a-fA-F]+$/.test(s);
}

export function isHighEntropy(value) {
  const v = String(value ?? "");
  if (v.length < 20) return false;
  if (isPlaceholder(v)) return false;
  const h = shannonEntropy(v);
  return isHex(v) ? h >= 3.7 : h >= 4.5;
}

export function isValidJwt(token) {
  try {
    const [header] = String(token).split(".");
    const b64 = header.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    return json && typeof json === "object" && typeof json.alg === "string" && json.alg.length > 0;
  } catch {
    return false;
  }
}

// Urutan penting: spesifik dulu, generik belakangan (dedup mengandalkan ini).
export const SECRET_PATTERNS = [
  { type: "openai-key", re: /sk-[A-Za-z0-9_-]{20,}/ },
  { type: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  // AWS secret access key: 40 karakter base64, dekat kata aws_secret.
  { type: "aws-secret-key", re: /(?:aws[_-]?secret(?:[_-]?access)?[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i },
  { type: "stripe-key", re: /(?:sk|rk)_live_[A-Za-z0-9]{16,}/ },
  { type: "slack-token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { type: "slack-webhook", re: /hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]+/ },
  { type: "github-token", re: /gh[pousr]_[A-Za-z0-9]{20,}/ },
  { type: "github-pat", re: /github_pat_[A-Za-z0-9_]{20,}/ },
  { type: "gitlab-token", re: /glpat-[A-Za-z0-9_-]{15,}/ },
  { type: "google-api-key", re: /AIza[0-9A-Za-z_-]{20,}/ },
  { type: "npm-token", re: /npm_[A-Za-z0-9]{20,}/ },
  { type: "pypi-token", re: /pypi-[A-Za-z0-9_-]{20,}/ },
  { type: "huggingface-token", re: /hf_[A-Za-z0-9]{20,}/ },
  { type: "discord-webhook", re: /discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/ },
  { type: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { type: "bearer-token", re: /Bearer\s+[A-Za-z0-9._-]{20,}/ },
  { type: "jwt", re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  // Kredensial di URL / connection string DB: scheme://user:pass@host
  { type: "url-credentials", re: /(?:https?|ftp|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s/'":]+:[^\s/'"@]+@[^\s'"]+/i },
  { type: "db-connection-string", re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s/'":]+:[^\s/'"@]+@[^\s'"]+/i },
  // Assignment: password=... / api_key=... / secret=... — nilai min 4 karakter
  // supaya 'password=' kosong atau placeholder 1-3 huruf tidak ikut ditandai.
  { type: "password-assign", re: /(?:password|passwd|pwd)\s*=\s*[^\s'";]{4,}/i },
  { type: "api-key-assign", re: /(?:api[_-]?key|apikey|secret)\s*=\s*[^\s'";]{4,}/i },
];

// Pola assignment yang dibolehkan masuk fallback entropi (nama variabel kredensial).
const ENTROPY_ASSIGN_RE = /(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|auth|credential|private[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9\-_+/=]{20,})['"]?/gi;

// Tipe yang nilai assignment-nya dicek placeholder (bukan token format spesifik).
// aws-secret-key sengaja TIDAK di sini: 40 karakter base64 adalah bukti format
// yang kuat (konsisten dengan AKIA...EXAMPLE yang tetap ditandai).
const ASSIGNMENT_TYPES = new Set(["password-assign", "api-key-assign"]);

function overlaps(a, b) {
  return a.start < b.end && b.start < a.end;
}

/**
 * scanText(text) -> { found: boolean, matches: [{ type, line }] }.
 * line = nomor baris (1-based) tempat match ditemukan.
 */
export function scanText(text) {
  const input = String(text ?? "");
  const matches = [];
  const ranges = [];
  const add = (type, index, length, upgradeFrom = null) => {
    const range = { start: index, end: index + length };
    const hit = ranges.findIndex((r) => overlaps(r, range));
    if (hit >= 0) {
      // Upgrade: match entropi menggantikan match assignment generik yang
      // tumpang tindih (lebih informatif), bukan menambah laporan ganda.
      if (upgradeFrom && upgradeFrom.has(ranges[hit].type)) {
        matches.splice(hit, 1);
        ranges.splice(hit, 1);
      } else {
        return false; // dedup antar-rule
      }
    }
    ranges.push({ ...range, type });
    matches.push({ type, line: input.slice(0, index).split("\n").length });
    return true;
  };

  for (const { type, re } of SECRET_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    let m;
    while ((m = g.exec(input)) !== null) {
      if (m[0].length === 0) { g.lastIndex += 1; continue; }
      // JWT: hanya yang header-nya JSON berisi "alg".
      if (type === "jwt" && !isValidJwt(m[0])) continue;
      // Placeholder: hanya untuk tipe assignment.
      if (ASSIGNMENT_TYPES.has(type)) {
        const value = m[1] ?? m[0].split(/[:=]/).pop() ?? "";
        if (isPlaceholder(value)) continue;
      }
      add(type, m.index, m[0].length);
    }
  }

  // Fallback entropi: assignment ke variabel kredensial dengan nilai acak panjang.
  const eg = new RegExp(ENTROPY_ASSIGN_RE.source, ENTROPY_ASSIGN_RE.flags);
  let em;
  while ((em = eg.exec(input)) !== null) {
    const value = em[1] ?? "";
    if (!isHighEntropy(value)) continue;
    add("high-entropy-secret", em.index, em[0].length, new Set(["password-assign", "api-key-assign"]));
  }

  return { found: matches.length > 0, matches };
}

/**
 * redact(text) — ganti setiap secret dengan [REDACTED].
 * Untuk assignment (password=...), nama kuncinya dipertahankan
 * ('password=[REDACTED]') supaya laporan tetap bisa dibaca; untuk token
 * mentah, seluruh token diganti; untuk URL, password di antara ':' dan '@'
 * diganti ('https://user:[REDACTED]@host').
 */
export function redact(text) {
  let out = String(text ?? "");
  for (const { type, re } of SECRET_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    if (type === "password-assign" || type === "api-key-assign") {
      out = out.replace(g, (m) => {
        const value = m.split(/[:=]/).pop() ?? "";
        return isPlaceholder(value) ? m : m.replace(/\s*=\s*[^\s'";]+$/, "=[REDACTED]");
      });
    } else if (type === "url-credentials" || type === "db-connection-string") {
      out = out.replace(g, (m) => m.replace(/:([^:@/]+)@/, ":[REDACTED]@"));
    } else if (type === "jwt") {
      out = out.replace(g, (m) => (isValidJwt(m) ? "[REDACTED]" : m));
    } else {
      out = out.replace(g, "[REDACTED]");
    }
  }
  // Redaksi fallback entropi (jaga nama kunci, sembunyikan nilai).
  out = out.replace(new RegExp(ENTROPY_ASSIGN_RE.source, ENTROPY_ASSIGN_RE.flags), (m, value) => {
    if (!isHighEntropy(value)) return m;
    return m.replace(value, "[REDACTED]");
  });
  return out;
}

export default { scanText, redact, SECRET_PATTERNS, shannonEntropy, isHighEntropy, isValidJwt, isPlaceholder };
