// bounty/lib/guard.js — pre-execution guard + secret scanner.
import { resolve, isAbsolute, relative, sep } from "node:path";

const BLOCKED_PATTERNS = [
  { re: /\brm\s+(?:-[a-z]*r[a-z]*\s+|--recursive\b)/i, reason: "rm recursive diblokir" },
  { re: /\brm\s+.*\s\/\s*($|;|&&|\|\|)/, reason: "rm terhadap root diblokir" },
  { re: /\bgit\s+push\b/i, reason: "git push diblokir (tulis repo hanya lewat jalur resmi)" },
  { re: /\bgit\s+reset\s+--hard\b/i, reason: "git reset --hard diblokir" },
  { re: /\bgit\s+clean\s+-[a-z]*f/i, reason: "git clean -f diblokir" },
  { re: /\|\s*(?:sh|bash|zsh|fish)\b/, reason: "pipe-to-shell diblokir" },
  { re: /\bchmod\s+777\b/, reason: "chmod 777 diblokir" },
  { re: /\bdd\s+if=/i, reason: "dd if= diblokir" },
  { re: /\bmkfs\b|\bformat\s+[a-z]:/i, reason: "format filesystem diblokir" },
  { re: /:\s*\(\s*\)\s*\{/, reason: "fork bomb diblokir" },
];

// Denylist tool kategori K/L (abuse / bypass-aktivasi) — dilarang untuk bounty.
// Nama repo/tool dari PDF kategori K/L; diblokir di kode, bukan cuma di docs.
export const KL_DENYLIST = [
  { name: "sms-bomber", re: /sms[-_ ]?bomber/i, reason: "tool SMS bomber (kategori K) diblokir" },
  { name: "otp-bomber", re: /otp[-_ ]?bomber/i, reason: "tool OTP bomber (kategori K) diblokir" },
  { name: "bomber", re: /\bbomber\b/i, reason: "tool bomber (kategori K) diblokir" },
  { name: "sms-spam", re: /sms[-_ ]?spam/i, reason: "tool SMS spam (kategori K) diblokir" },
  { name: "otp-spam", re: /otp[-_ ]?spam/i, reason: "tool OTP spam (kategori K) diblokir" },
  { name: "jailbreak", re: /jailbreak/i, reason: "tool jailbreak (kategori K) diblokir" },
  { name: "hackingtool", re: /hackingtool/i, reason: "tool hackingtool (kategori K) diblokir" },
  { name: "aktivator", re: /\b(aktivator|activator)\b/i, reason: "tool aktivator/bypass lisensi (kategori L) diblokir" },
  { name: "captcha-solver", re: /captcha[-_ ]?(solver|solving|bypass)/i, reason: "captcha solver/bypass (kategori L) diblokir" },
];

// Pola bypass red-team: perintah destruktif yang disembunyikan lewat
// encoding, substitusi, atau chaining. Guard harus gagalkan semuanya.
const BYPASS_PATTERNS = [
  { re: /\bbase64\s+(?:-d|--decode)\b/i, reason: "decode base64 diblokir (jalur bypass)" },
  { re: /\beval\s+\S/i, reason: "eval diblokir (jalur bypass)" },
  { re: /\$\(\s*(?:rm|curl|wget|chmod|dd)\b/i, reason: "substitusi perintah destruktif diblokir" },
  { re: /`[^`]*\b(?:rm|chmod|dd)\b[^`]*`/i, reason: "backtick perintah destruktif diblokir" },
  { re: /\brm\$\{IFS\}/i, reason: "rm dengan IFS trick diblokir" },
  { re: /\bfind\s+\S+\s+.*-exec\s+rm\b/i, reason: "find -exec rm diblokir" },
  { re: /\bxargs\s+rm\b/i, reason: "xargs rm diblokir" },
  { re: /\bsh\s+-c\b/i, reason: "sh -c diblokir (jalur bypass)" },
  { re: /\|\s*(?:python3?|perl|ruby|node)\b/i, reason: "pipe ke interpreter diblokir" },
  { re: /\bpython3?\s+-c\b[^&;]*\b(?:rm|os\.system|subprocess)\b/i, reason: "python -c destruktif diblokir" },
  { re: /\bcurl\b[^|]*\|\s*base64/i, reason: "curl | base64 diblokir (jalur bypass)" },
  { re: /;\s*(?:rm|chmod|dd|git\s+push)\b/i, reason: "chaining ke perintah terlarang diblokir" },
  { re: /&&\s*(?:rm|chmod|dd|git\s+push)\b/i, reason: "chaining ke perintah terlarang diblokir" },
  { re: /\|\|\s*(?:rm|chmod|dd|git\s+push)\b/i, reason: "chaining ke perintah terlarang diblokir" },
];

const SECRET_FILE_PATTERNS = [
  /\.env(\.|$|\s|["'])/i,
  /\.pem\b/i,
  /\.key\b/i,
  /\bid_rsa\b/i,
  /credentials/i,
  /\.aws\b/i,
  /\.ssh\b/i,
  /\.gnupg\b/i,
];

const SECRET_PATTERNS = [
  { name: "openai-key", re: /sk-[A-Za-z0-9_-]{16,}/ },
  { name: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "bearer-token", re: /Bearer\s+[A-Za-z0-9._-]{20,}/ },
  { name: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: "password-assign", re: /(?:password|passwd|pwd)\s*=\s*\S+/i },
  { name: "api-key-assign", re: /(?:api[_-]?key|apikey|secret)\s*=\s*['"][^'"]{8,}['"]/i },
  { name: "github-token", re: /ghp_[A-Za-z0-9]{20,}/ },
  { name: "jwt", re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
];

function escapesWorkspace(cmd, workspace) {
  if (!workspace) return false;
  const ws = resolve(workspace);
  // ".." segments that walk out of the workspace.
  const tokens = cmd.split(/[\s;"'&|<>]+/).filter(Boolean);
  for (const tok of tokens) {
    if (tok.includes("..")) {
      // A ".." that resolves outside the workspace is blocked.
      const cleaned = tok.replace(/^['"]|['"]$/g, "");
      if (isAbsolute(cleaned)) {
        if (relative(ws, resolve(cleaned)).startsWith("..")) return true;
      } else if (cleaned.startsWith("..")) {
        return true;
      }
    }
    // Absolute path outside the workspace (write targets / reads of secrets).
    if (isAbsolute(tok.replace(/^['"]|['"]$/g, ""))) {
      const p = resolve(tok.replace(/^['"]|['"]$/g, ""));
      const rel = relative(ws, p);
      if (rel.startsWith("..") || rel.startsWith(`..${sep}`)) {
        // Allowlist: reading well-known system binaries/configs is not a write;
        // but any absolute path outside workspace is treated as escape here
        // unless it is a plain command name under /usr/bin, /bin, /usr/local/bin.
        if (!/^\/(usr\/bin|usr\/local\/bin|bin)\/[^/]+$/.test(p)) return true;
      }
    }
  }
  return false;
}

export function checkCommand(cmd, workspace = process.cwd()) {
  const command = String(cmd ?? "").trim();
  if (!command) return { allowed: false, reason: "perintah kosong" };

  for (const { re, reason } of BLOCKED_PATTERNS) {
    if (re.test(command)) return { allowed: false, reason };
  }
  for (const { re, reason } of BYPASS_PATTERNS) {
    if (re.test(command)) return { allowed: false, reason };
  }
  for (const { re, reason } of KL_DENYLIST) {
    if (re.test(command)) return { allowed: false, reason };
  }
  for (const re of SECRET_FILE_PATTERNS) {
    if (re.test(command)) return { allowed: false, reason: "akses file rahasia diblokir (.env/.pem/.key/id_rsa/credentials/.aws/.ssh)" };
  }
  if (escapesWorkspace(command, workspace)) {
    return { allowed: false, reason: "perintah keluar dari workspace diblokir" };
  }
  return { allowed: true, reason: "OK" };
}

export function scanSecrets(text) {
  const input = String(text ?? "");
  const findings = [];
  for (const { name, re } of SECRET_PATTERNS) {
    const m = input.match(new RegExp(re, "g"));
    if (m) findings.push({ type: name, count: m.length, sample: redact(m[0]) });
  }
  return findings;
}

export function redact(text) {
  let out = String(text ?? "");
  for (const { re } of SECRET_PATTERNS) {
    out = out.replace(new RegExp(re, "g"), "[REDACTED]");
  }
  return out;
}

export default { checkCommand, scanSecrets, redact, KL_DENYLIST };
