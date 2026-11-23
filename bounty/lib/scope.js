// bounty/lib/scope.js — parse programs/*.md + scope gate.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Expected markdown lines (case-insensitive keys):
//   Scope: example.com, api.example.com
//   Allowed: /api/, /login
//   Denied: /admin, /logout
//   Budget: 5
//   Rate: 10
//   Roles: low, high
export function parseProgram(mdText) {
  const text = String(mdText ?? "");
  const lines = text.split(/\r?\n/);
  const program = {
    name: "",
    allowedHosts: [],
    allowedPaths: [],
    deniedPaths: [],
    maxBudgetUsd: 5,
    rateLimit: 10,
    roles: ["low", "high"],
  };

  const firstHeading = lines.find((l) => /^#\s+/.test(l));
  if (firstHeading) program.name = firstHeading.replace(/^#\s+/, "").trim();

  const getList = (key) => {
    const line = lines.find((l) => new RegExp(`^\\s*${key}\\s*:`, "i").test(l));
    if (!line) return [];
    return line.split(":").slice(1).join(":").split(",").map((s) => s.trim()).filter(Boolean);
  };
  const getNum = (key, fallback) => {
    const line = lines.find((l) => new RegExp(`^\\s*${key}\\s*:`, "i").test(l));
    if (!line) return fallback;
    const n = Number(line.split(":").slice(1).join(":").trim().replace(/[^0-9.]/g, ""));
    return Number.isFinite(n) && n > 0 ? n : fallback;
  };

  program.allowedHosts = getList("Scope").map((h) => h.replace(/^https?:\/\//, "").split("/")[0].toLowerCase());
  program.allowedPaths = getList("Allowed");
  program.deniedPaths = getList("Denied");
  program.maxBudgetUsd = getNum("Budget", 5);
  program.rateLimit = getNum("Rate", 10);
  const roles = getList("Roles");
  if (roles.length) program.roles = roles.map((r) => r.toLowerCase());
  if (!program.name) {
    const nameLine = lines.find((l) => /^\s*Name\s*:/i.test(l));
    if (nameLine) program.name = nameLine.split(":").slice(1).join(":").trim();
  }
  return program;
}

export function loadProgramFile(path) {
  const abs = resolve(path);
  const text = readFileSync(abs, "utf8");
  return parseProgram(text);
}

function hostMatches(host, allowedHosts) {
  const h = String(host).toLowerCase();
  return allowedHosts.some((allowed) => {
    const a = String(allowed).toLowerCase();
    return h === a || h.endsWith(`.${a}`);
  });
}

export function checkScope(program, targetUrl) {
  if (!program || !Array.isArray(program.allowedHosts) || program.allowedHosts.length === 0) {
    return { ok: false, reason: "program tanpa scope (allowedHosts kosong) — tolak" };
  }
  let url;
  try {
    url = new URL(targetUrl);
  } catch {
    return { ok: false, reason: `target bukan URL valid: ${targetUrl}` };
  }
  if (!hostMatches(url.hostname, program.allowedHosts)) {
    return { ok: false, reason: `host ${url.hostname} di luar scope (${program.allowedHosts.join(", ")})` };
  }
  const path = url.pathname;
  if ((program.deniedPaths ?? []).some((d) => path === d || path.startsWith(d.endsWith("/") ? d : d + "/") || path.startsWith(d))) {
    return { ok: false, reason: `path ${path} ada di Denied` };
  }
  if ((program.allowedPaths ?? []).length > 0) {
    const ok = program.allowedPaths.some((a) => path === a || path.startsWith(a));
    if (!ok) return { ok: false, reason: `path ${path} tidak ada di Allowed (${program.allowedPaths.join(", ")})` };
  }
  return { ok: true, reason: "Scope OK" };
}

export default { parseProgram, loadProgramFile, checkScope };
