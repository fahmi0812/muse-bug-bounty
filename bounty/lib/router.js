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

export function routeSkills(contextText, skills = null) {
  const list = skills ?? loadSkillsIndex();
  const ctx = String(contextText ?? "").trim();
  const scored = list.map((skill) => {
    const { score, matched } = scoreSkill(ctx, skill);
    return { name: skill.name, score, reason: matched.length ? `match: ${matched.join(", ")}` : "no keyword match" };
  });
  scored.sort((a, b) => b.score - a.score);
  const top = scored.slice(0, 5);
  const best = top[0]?.score ?? 0;
  if (!ctx || best < 2) {
    const fallback = { name: "triage-generic", score: 0, reason: "fallback: skor tertinggi < 2 atau konteks kosong" };
    const rest = top.filter((s) => s.name !== "triage-generic");
    return [fallback, ...rest].slice(0, 5);
  }
  return top;
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

export default { routeSkills, routerAccuracy, loadSkillsIndex };
