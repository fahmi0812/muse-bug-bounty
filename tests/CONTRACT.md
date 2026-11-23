# Kontrak API lib — dicocokkan ke implementasi nyata di `bounty/lib/`
# (ditulis agen lib). Bila lib berubah, update file ini + test bersamaan.

## router.js
- `routeSkills(contextText, skills)` → `[{ name, score, reason }]` maks 5,
  skor desc. `contextText`: string. `skills`: `[{ name, keywords: [],
  vuln_class?, when? }]`. Konteks kosong atau skor terbaik < 2 →
  entri pertama `'triage-generic'`.
- `routerAccuracy(selected, expectedClasses)` → `{ hit, total, accuracy }`.
- `loadSkillsIndex()` → baca `skills/bounty/skills-index.json` bila ada.

## dedup.js
- `canonicalKey({ endpoint, method, param, vulnClass, cwe })` → string:
  endpoint lowercase tanpa trailing slash, method uppercase, kelas
  lowercase dengan spasi→`-`, cwe uppercase. (Tidak menormalisasi
  `:id` → nilai konkret; itu urusan `param`.)
- `dedupCandidates(list)` → `{ unique, duplicates }`.

## rate.js
- `class TokenBucket(ratePerSec = 10, burst = 10)` — `tryAcquire()` bool
  (refill pakai `Date.now()`), `acquire()` async tunggu token.
- `backoffDelay(attempt)` → `min(1000 * 2^attempt, 30000)`.

## scope.js
- `parseProgram(mdText)` → `{ name, allowedHosts, allowedPaths,
  deniedPaths, maxBudgetUsd, rateLimit, roles }` dari baris
  `Scope: / Allowed: / Denied: / Budget: / Rate: / Roles:`.
- `checkScope(program, targetUrl)` → `{ ok, reason }`. Subdomain parent
  host ikut lolos. Fail-closed: hosts kosong / URL tak valid → tolak.

## guard.js
- `checkCommand(cmd, workspace = process.cwd())` → `{ allowed, reason }`.
  Blokir: `rm -rf`, `git push`, `git reset --hard`, `git clean -f`,
  pipe-to-shell, `chmod 777`, `dd if=`, akses file rahasia
  (`.env`/`.pem`/`.key`/`id_rsa`/`credentials`/`.aws`/`.ssh`), keluar workspace.
- `scanSecrets(text)` → `[{ type, count, sample }]`; `redact(text)` →
  teks dengan rahasia diganti `[REDACTED]`.

## provider.js
- `detectModels({ type, baseUrl, apiKey, fetchImpl, timeoutMs })` →
  `{ models }` atau `{ models: [], warning: '0 model' }`.
  Paginasi via `after_id` + `has_more`/`last_id`. Error: 401/403 →
  `key ditolak (401/403)`, 404 → `endpoint /models tidak ditemukan (404)`,
  lain → `provider error HTTP {status}`, timeout/abort → pesan timeout.
- `saveProvider({ name, type, baseUrl, apiKey, model, dir })` → tulis
  `providers.json` (meta, tanpa key) + `credentials.json`, keduanya 0600.
- `loadProviders(dir)` → meta JSON atau `null`.
- `writeStrixConfig(model, baseUrl, apiKey, type)` → path `~/.strix/cli-config.json`.

## store.js
- `class Store(path)` — SQLite `node:sqlite`; dir 0700, file 0600.
  `upsertProgram(name, scope, policy)` / `getProgram(name)` (null bila tak ada).
  `addCandidate({ program, endpoint, method, param, vulnClass, cwe })` →
  id; `listCandidates(program, status='candidate')`;
  `approveCandidate(id)` / `rejectCandidate(id)` → row.
  `addFinding({ program, endpoint, method, param, vulnClass, cwe,
  severity, verdict, evidence, chainId })` → id.
  `addEvidence(findingId, kind, content)` / `addChain(program, steps)`.
  `addRun({ version, target, lab, tp, fp, fn, timeMs, usd })` → id;
  `listRuns(limit=50)` desc. `close()`.

## auth.js
- `getRoleProfile(program, role='low')` → `{ role, cookie, token, header,
  program }`; cookie/token dari env `BOUNTY_COOKIE_{LOW|HIGH}` /
  `BOUNTY_TOKEN_{LOW|HIGH}`, default `'REPLACE-ME'`. Role tak dikenal → low.
- `buildInstruction(program, role='low')` → string; menyebut `Role:`,
  scope host, denied path, `Budget: maks $N`, larangan submit/bayar/deposit.

## bench.js
- `scoreFindings(findings, oracleArray)` → `{ tp, fp, fn, precision,
  recall, fpRate }`; kunci = endpoint+method+vuln_class+cwe
  (case-insensitive); duplikat temuan yang sama dihitung FP.
- `median(values)` → median (0 bila kosong).
- `runBench({ labs, runs, runFn })` → per lab `{ lab, runs, median: { tp,
  fp, fn, time_ms, usd, precision, recall }, variance, perRun }`;
  `lab.oracle` / `lab.expected` dipakai sebagai oracle.
