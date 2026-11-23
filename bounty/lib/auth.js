// bounty/lib/auth.js — auth-minimal: cookie/token placeholders + 2 roles.
// NEVER put real credentials here. Replace REPLACE-ME via env / provider config.
export const PLACEHOLDER = "REPLACE-ME";

export function getRoleProfile(program, role = "low") {
  const r = String(role).toLowerCase() === "high" ? "high" : "low";
  const cookie = process.env[`BOUNTY_COOKIE_${r.toUpperCase()}`] || PLACEHOLDER;
  const token = process.env[`BOUNTY_TOKEN_${r.toUpperCase()}`] || PLACEHOLDER;
  return {
    role: r,
    cookie,
    token,
    header: `Cookie: ${cookie}`,
    program: program?.name ?? "",
  };
}

export function buildInstruction(program, role = "low") {
  const profile = getRoleProfile(program, role);
  const hosts = (program?.allowedHosts ?? []).join(", ") || "(scope belum diisi)";
  const denied = (program?.deniedPaths ?? []).join(", ") || "(tidak ada)";
  const budget = program?.maxBudgetUsd ?? 5;
  return [
    `Grey-box instruction — program: ${profile.program || "(tanpa nama)"}`,
    `Role: ${profile.role} (cookie/token placeholder, JANGAN pakai kredensial asli).`,
    `Scope: hanya host ${hosts}. Dilarang menyentuh path: ${denied}.`,
    `Budget: maks $${budget}. Jangan submit, jangan bayar, jangan deposit.`,
    `Hanya uji kerentanan di dalam scope; laporkan kandidat, jangan eksploitasi destruktif.`,
    `Cookie: ${profile.cookie}`,
    `Token: ${profile.token}`,
  ].join("\n");
}

export default { getRoleProfile, buildInstruction, PLACEHOLDER };
