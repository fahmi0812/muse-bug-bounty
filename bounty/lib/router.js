// bounty/lib/router.js — skill router (top 5 by keyword match).
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export function loadSkillsIndex() {
  const candidates = [
    resolve(__dirname, "../skills/bounty/skills-index.json"),
    resolve(process.cwd(), "skills/bounty/skills-index.json"),
    resolve(process.cwd(), "skills-index.json"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      try {
        const data = JSON.parse(readFileSync(p, "utf8"));
        return Array.isArray(data) ? data : data.skills ?? [];
      } catch {
        return [];
      }
    }
  }
  return [];
}

function tokens(text) {
  return String(text ?? "").toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 1);
}

function scoreSkill(contextText, skill) {
  const ctx = new Set(tokens(contextText));
  const keywords = new Set([
    ...(skill.keywords ?? []).flatMap((k) => tokens(k)),
    ...tokens(skill.vuln_class ?? ""),
    ...tokens(skill.when ?? ""),
    ...tokens(skill.name ?? ""),
  ]);
  let score = 0;
  const matched = [];
  for (const kw of keywords) {
    if (ctx.has(kw)) {
      score += 1;
      matched.push(kw);
    }
  }
  return { score, matched };
}

function scoreAll(contextText, skills) {
  const ctx = String(contextText ?? "").trim();
  return (skills ?? loadSkillsIndex()).map((skill) => {
    const { score, matched } = scoreSkill(ctx, skill);
    return {
      name: skill.name,
      vuln_class: skill.vuln_class ?? "",
      score,
      reason: matched.length ? `match: ${matched.join(", ")}` : "no keyword match",
    };
  });
}

function topWithFallback(scored, ctx) {
  const sorted = [...scored].sort((a, b) => b.score - a.score);
  const top = sorted.slice(0, 5);
  const best = top[0]?.score ?? 0;
  if (!ctx || best < 2) {
    const fallback = { name: "triage-generic", score: 0, reason: "fallback: skor tertinggi < 2 atau konteks kosong" };
    const rest = top.filter((s) => s.name !== "triage-generic");
    return [fallback, ...rest].slice(0, 5);
  }
  return top;
}

export function routeSkills(contextText, skills = null) {
  const ctx = String(contextText ?? "").trim();
  return topWithFallback(scoreAll(ctx, skills), ctx);
}

// ---- Router belajar (v1.2 M2) ----
// Lesson = { skill, vuln_class, outcome } dari memory_lesson (hanya
// verdict manusia; outcome 'confirmed' | 'false_positive').
// Skor akhir = skor keyword + bonus track record:
//   +0.15 per lesson 'confirmed' untuk skill itu di vuln_class yang sama
//   (maks +0.45), -0.15 per 'false_positive' (maks -0.45).
// Lesson tanpa vuln_class berlaku untuk skill itu di kelas apa pun;
// lesson dengan vuln_class berbeda dari skill tidak dihitung.
// Tanpa lessons (dan tanpa patterns), hasil IDENTIK dengan routeSkills().
const LESSON_STEP = 0.15;
const LESSON_CAP = 0.45;

function normClass(v) {
  return String(v ?? "").trim().toLowerCase();
}

function lessonOutcome(lesson) {
  const o = String(lesson?.outcome ?? lesson?.verdict ?? "").trim().toLowerCase();
  if (o === "confirmed") return "confirmed";
  if (o === "false_positive" || o === "false-positive" || o === "fp") return "false_positive";
  return null;
}

export function lessonStats(lessons) {
  const stats = {};
  for (const lesson of lessons ?? []) {
    const skill = String(lesson?.skill ?? "").trim();
    const outcome = lessonOutcome(lesson);
    if (!skill || !outcome) continue;
    stats[skill] ??= { confirmed: 0, falsePositive: 0 };
    if (outcome === "confirmed") stats[skill].confirmed += 1;
    else stats[skill].falsePositive += 1;
  }
  return stats;
}

function lessonBonus(skill, lessons) {
  let confirmed = 0;
  let falsePositive = 0;
  for (const lesson of lessons ?? []) {
    if (String(lesson?.skill ?? "").trim() !== skill.name) continue;
    const lessonClass = normClass(lesson?.vuln_class);
    // Lesson ber-vuln_class hanya berlaku di kelas yang sama.
    if (lessonClass && normClass(skill.vuln_class) && lessonClass !== normClass(skill.vuln_class)) continue;
    const outcome = lessonOutcome(lesson);
    if (outcome === "confirmed") confirmed += 1;
    else if (outcome === "false_positive") falsePositive += 1;
  }
  const bonus = Math.min(confirmed, 3) * LESSON_STEP - Math.min(falsePositive, 3) * LESSON_STEP;
  return Math.max(-LESSON_CAP, Math.min(LESSON_CAP, bonus));
}

export function routeWithLessons(contextText, lessons = [], patterns = null, skills = null) {
  const ctx = String(contextText ?? "").trim();
  const list = skills ?? loadSkillsIndex();
  const scored = scoreAll(ctx, list).map((entry) => {
    const skill = list.find((s) => s.name === entry.name) ?? entry;
    let bonus = lessonBonus(skill, lessons);
    let reason = entry.reason;
    // Bukti pola laporan (opsional): +0.05 per pola BERSITASI untuk skill
    // itu (maks +0.15). Pola uncited tidak menambah skor — hanya pola
    // dengan h1_report_id/link nyata yang dihitung sebagai bukti.
    if (Array.isArray(patterns) && patterns.length > 0) {
      const cited = patterns.filter(
        (p) => p?.skill === entry.name && p?.uncited === false && (p?.h1_report_id || p?.link),
      ).length;
      const evidenceBonus = Math.min(cited, 3) * 0.05;
      if (evidenceBonus > 0) {
        bonus += evidenceBonus;
        reason += ` +bukti pola bersitasi ${cited}`;
      }
    }
    if (bonus !== 0) {
      const rounded = Math.round((entry.score + bonus) * 100) / 100;
      return { ...entry, score: rounded, reason: `${reason} +lesson ${bonus > 0 ? "+" : ""}${bonus}` };
    }
    return entry;
  });
  return topWithFallback(scored, ctx);
}

export function routerAccuracy(selected, expectedClasses = []) {
  const sel = new Set((selected ?? []).map((s) => String(s.name ?? s).toLowerCase()));
  const expected = (expectedClasses ?? []).map((c) => String(c).toLowerCase());
  const total = expected.length;
  if (total === 0) return { hit: 0, total: 0, accuracy: 0 };
  let hit = 0;
  for (const e of expected) {
    if ([...sel].some((s) => s.includes(e) || e.includes(s))) hit += 1;
  }
  return { hit, total, accuracy: hit / total };
}

export default { routeSkills, routeWithLessons, lessonStats, routerAccuracy, loadSkillsIndex };
