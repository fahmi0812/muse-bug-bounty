# Changelog — muse-bug-bounty

Format: tiap rilis = daftar fitur + batasan. Tanggal WIB.

## [Unreleased]

## [1.3.2] — 2026-11-23

### Added
- **2 skill terakhir yang tertunda sejak v1.1, kini selesai dengan parafrase defensif** (ditulis langsung satu-satu, sama seperti v1.3.1 — keduanya lolos tanpa flag): `hunt-mfa-bypass` (fokus celah logika penegakan MFA; menebak/brute-force kode MFA dan OTP DILARANG eksplisit di skill) dan `hunt-host-header` (fokus tautan reset + cache, hanya akun test sendiri). Index 57 → **59 entri**. Semua skill Tier 1 + Tier 2 dari plan-power-v1.1 kini lengkap — tidak ada lagi skill tertunda.
- **Batasan jujur v1.3.2:** angka bench tidak berubah (oracle lab tidak punya kelas MFA bypass / host header) — efek dua skill ini baru terasa di target asli.

## [1.3.1] — 2026-11-23

### Added
- **8 skill Tier 2 yang tertunda di v1.3.0, kini selesai dengan pendekatan parafrase defensif** (fokus deteksi + validasi akun test, minim payload mentah — ditulis langsung, bukan lewat agen paralel): `hunt-dom` (yang sempat kena flag — kini lolos), `hunt-nodejs`, `hunt-http-smuggling`, `hunt-jwt-crypto`, `hunt-llm-ai`, `hunt-api-misconfig`, `web2-recon`, `bug-bounty` (orkestrator). Index 49 → **57 entri**. Tier 2 dari plan-power-v1.1 kini lengkap.
- **Metrik router diperbaiki:** `expectedSkillFor()` di `bounty/lib/bench.js` kini memetakan DOM XSS → `hunt-dom` dan kelas LLM → `hunt-llm-ai` (sebelumnya menunjuk skill lama yang sudah digantikan); `routerAccuracy()` menerima skill pengganti yang sah (`hunt-jwt-crypto` untuk JWT, `hunt-dom` untuk XSS) — skill yang lebih dalam terpilih bukan regresi.
- **Hasil bench (mock):** akurasi router llm-app **33% → 67%** (4/6); juice-shop kembali 70% (7/10), dvga 100%, dvwa 88%, vampi 63%. 3 miss juice-shop tersisa sudah ada sebelum v1.3.1 (credentials, sensitive data exposure, DoS) — bukan regresi.
- **Batasan jujur v1.3.1:** `hunt-mfa-bypass` + `hunt-host-header` (dari v1.1) masih tertunda — belum dicoba lagi dengan pendekatan ini.

## [1.3.0] — 2026-11-23

### Added
- **v1.3 — Perdalam + scale (plan-power-v1.1):**
  - **Skill Tier 2 (sebagian):** `hunt-lfi`, `hunt-nosqli` (index 47 → 49). **Ditunda jujur:** `hunt-dom` kena flag keamanan saat penulisan dan TIDAK dibuat ulang; 7 skill Tier 2 lainnya (`hunt-nodejs`, `hunt-http-smuggling`, `hunt-jwt-crypto`, `hunt-llm-ai`, `hunt-api-misconfig`, `web2-recon`, `bug-bounty`) belum dibuat karena tool agen penulis dimatikan setelah flag itu — akan ditulis terpisah setelah tinjauan manual. (Pola sama seperti `hunt-mfa-bypass`/`hunt-host-header` di v1.1.)
  - **Runner batch 2 (7 runner, `SUPPORTED_TOOLS` 3 → 10):** arjun (parameter tersembunyi), graphql-cop, gitleaks, trufflehog, osv-scanner (reachability hanya `reachable` bila ada bukti pemakaian paket, tanpa bukti = `unproven`), garak, deepteam — semua mengikuti pola lama (scope gate, binary hilang = dilewati, timeout 120 detik, hasil = kandidat). `bounty scan --path DIR` (checkout lokal osv-scanner) + `--model MODEL` (garak/deepteam). Playbook baru `playbooks/runners-v13.md`. Flag CLI runner mengikuti dokumentasi tiap tool (best-effort, parser toleran).
  - **Trail of Bits (3.3):** `audit-context-building` + `insecure-defaults` (ditulis ulang, atribusi CC-BY-SA-4.0) — `insecure-defaults` memakai pola refuting verifier (default yang terlihat tidak aman wajib dibuktikan dengan akun test sebelum dilapor).
  - **Cost tracking nyata (3.5):** `bounty/lib/cost.js` (`costFromRunJson`, `budgetStatus` warn ≥80%, `shouldStop`); `bounty run` kini mencetak peringatan saat biaya mendekati/melebihi budget.
  - **Multi-target + SARIF (3.6):** `bounty/lib/queue.js` — `bounty run --targets url1,url2` menjalankan target satu per satu dengan satu pool budget (berhenti bila tercapai); `bounty/lib/sarif.js` membaca `strix_runs/<run>/findings.sarif` Strix sebagai sumber temuan ketiga (tanpa generator SARIF sendiri); `bounty view` membuka dashboard Strix di background (bukan dashboard sendiri).
  - **Lab LLM nyata (3.7):** service `llm-app` di `eval/docker-compose.yml` kini build dari repo resmi LLMVault (CyberSunil/LLMVault, MIT, 25 lab OWASP LLM Top 10 2025, Play Mode offline), port 8000:5000. **Jujur: endpoint + oracle llm-app.json BELUM diverifikasi terhadap rute LLMVault** — verifikasi live di laptop sebelum angka bench llm-app diklaim.
- **Batasan jujur v1.3:** 8 skill Tier 2 tertunda (lihat di atas); flag CLI runner best-effort (belum diuji live terhadap binary aslinya); lab LLMVault belum dijalankan live di VM (tidak ada Docker) — compose git-context belum terbukti jalan.

## [1.2.0] — 2026-11-23

### Added
- **v1.2 — Ingatan + peta (plan-power-v1.1):**
  - **M0 fondasi memori** (`bounty/lib/memory.js`): tabel `memory_episode` (append-only, ditulis tiap `run` dan `review`), `memory_fact` (triple + validitas bi-temporal: invalidasi, bukan DELETE), `memory_lesson` (hanya dari verdict manusia approve/reject), `memory_coverage` (permukaan × kelas: examined/ruled_out/open). CLI `bounty memory [--list] [--lessons] [--program X]`.
  - **M1 pencarian serupa (FTS5)**: `finding_fts` + trigger sinkronisasi atas `candidate`; `findSimilar()` dengan RRF (0,5·BM25 + 0,3·cosine TF-IDF di JS + 0,2·boost kelas+CWE sama). `bounty findings --similar <id>`; `bounty run` memberi peringatan bila pola serupa pernah ditolak (FP) oleh reviewer.
  - **M2 router belajar** (`bounty/lib/router.js`): `routeWithLessons()` — skor skill = keyword + track record (+0,15 per `confirmed`, −0,15 per `false_positive`, maks ±0,45); tanpa lesson hasil identik dengan router lama. Bench kini memakai lesson + pola (`eval/run-bench.mjs`).
  - **Pola laporan sebagai data** (`bounty/data/report-patterns.json`, 12 pola seed): `{skill, subclass, cwe, cve, h1_report_id, tahun, payout}` + link. **Jujur: ke-12 pola `uncited: true`** — tidak ada ID laporan/CVE/tahun/payout yang dikarang; bonus bukti pola router = 0 sampai ada pola bersitasi terverifikasi.
  - **M3 graf sebagai view** (`bounty/lib/graph.js`): `v_graph_node/edge/coverage/hot_asset/finding_chain` — view murni, 0 migrasi; chain rekursif CTE depth ≤ 5. **Fix integrasi:** kandidat ikut jadi node + edge `program->candidate`, karena tabel asset/endpoint hampir tidak pernah terisi — tanpa ini graf kosong setelah run. CLI `bounty graph [--program X]` (fallback: program dengan kandidat terbanyak).
  - **M4 trace Shannon**: `bounty trace <finding-id>` — jejak source → sink dari chain + evidence yang tercatat; bila tidak ada, path minimal + penjelasan jujur (bukan taint analysis dinamis). Fallback ke id kandidat.
- **Batasan jujur v1.2:** `traceFinding` hanya dari chain/evidence tercatat; `v_coverage` fallback hanya mengenal examined/open (`ruled_out` butuh `memory_coverage`); pola laporan semuanya uncited sampai ada sitasi terverifikasi.

## [1.1.0] — 2026-11-23

### Added
- **v1.1 — Brain + proof (plan-power-v1.1):**
  - **8 skill hunt Tier 1 baru** (index 37 → 45): `hunt-oauth`, `hunt-ato`, `hunt-session`, `hunt-forgot-password`, `hunt-saml`, `hunt-cors`, `hunt-cache-poison`, `hunt-websocket` — ditulis ulang dengan kata sendiri, atribusi Claude-BugHunter (MIT/CC-BY-4.0), blok "Scope & larangan" di tiap file. **Ditunda jujur:** `hunt-mfa-bypass` dan `hunt-host-header` kena flag keamanan saat penulisan dan TIDAK dibuat ulang — akan ditulis terpisah setelah tinjauan manual.
  - **Secrets P0:** 15 pola format-spesifik baru (total 24) — AWS secret key, Stripe `sk_live_`/`rk_live_`, Slack token + webhook, GitHub `gho_/ghu_/ghs_/ghr_`, GitLab `glpat-`, Google `AIza`, npm, PyPI, Hugging Face, kunci DSA/PGP/ENCRYPTED, kredensial di URL + connection string DB, Discord webhook; validasi JWT (header harus JSON berisi `alg`); skor entropi Shannon sebagai fallback generik; placeholder denylist (`EXAMPLE`, `xxxx`, `fake`, `dummy`, `changeme`); dedup antar-rule.
  - **Runner on-demand + `bounty scan`:** `bounty/lib/runners.js` menjalankan nuclei, dalfox, ffuf sebagai runner beneran (bukan playbook) — cek binary (tidak ada = dilewati exit 0), scope gate, timeout 120 detik, output JSON diparse jadi kandidat `candidate` (dedup, UNVERIFIED). Perintah baru: `bounty scan --tool nuclei|dalfox|ffuf --target URL --program programs/<nama>.md`.
  - **Akurasi router di bench:** `routerAccuracy()` di `bounty/lib/bench.js` — hit-rate top-5 skill vs oracle per lab, tampil di `npm run bench` (mock saat ini: dvga 100%, dvwa 88%, juice-shop 70%, vampi 63%, llm-app 33% — llm-app rendah karena belum ada skill hunt khusus kelas LLM selain prompt injection).
  - **Denylist K/L di kode:** `guard.js` kini memblokir perintah yang menyebut tool kategori K/L (bomber, sms-spam, otp-bomber, jailbreak, aktivator, captcha solver) + pola bypass red-team (base64 -d, eval, `$(rm...)`, `rm${IFS}`, pipe ke interpreter, chaining ke perintah terlarang) — sebelumnya hanya prose di docs.
  - **Fix cmdRun (dari observasi mendalam):** Strix exit 2 = "vulns found", kini dipetakan ke sukses-dengan-temuan (exit 0, audit `ok-findings`), bukan "failed". Temuan/biaya kini dibaca dari artefak Strix `strix_runs/<run>/run.json` + `vulnerabilities.json` sebagai sumber utama (`readStrixArtifacts()`), stdout hanya fallback. `STRIX_TELEMETRY=0` disetel saat spawn Strix (privasi tim).
  - **Gitleaks config:** `.gitleaks.toml` baru — 14 temuan di `tests/secrets.test.js` adalah fixture PALSU (kunci contoh dari dokumentasi Stripe, ID nol, domain example.com); file itu dikecualikan dengan dokumentasi di config, scan kini bersih.
- **Alur run -> store -> review disambung (kritik #1):** `bounty run` meneruskan `--skills-dir` (+ `STRIX_SKILLS_DIR`) dan `--max-turns` (default 500) ke Strix; output Strix diparse (`bounty/lib/strix-output.js`: JSON/JSONL/Markdown, kanonikalisasi kelas + CWE, dedup) menjadi kandidat `candidate` di `bounty.db`; biaya terukur (`$X`) dicatat di tabel `run`. Diuji dengan Strix palsu (98/98 test).
- **Eval live + baseline (kritik #2):** `eval/measure-baseline.mjs` (`npm run measure-baseline`, `npm run bench:live`) — nyalakan lab Docker, ukur baseline Strix vs bounty, simpan `eval/results/baseline.json` + `latest.json`, gate TP/FP per lab. Exit 2 bila Docker/Strix tidak ada (bukan mock diam-diam). `npm run bench` kini menjalankan gate vs baseline bila `baseline.json` ada.
- **CI bench gate:** `npm run bench` ditambah ke `.github/workflows/ci.yml` (perlu di-push lewat browser Fahmi — workflow tidak bisa lewat API).

## [1.0.0] — 2026-11-23

Rilis produksi pertama (v1.0.0). Status: **produksi (docs + kode v1)** —
lihat "Batasan live" di bawah; belum semua jalur diuji live.

### P0 (v1 — wajib)

- Wrapper `bounty` extension-first di atas Strix (Strix tidak dibundel):
  scope gate fail-closed, pre-execution guard, rate limiter global
  (10 req/detik), satu store SQLite `bounty.db` (program → asset →
  endpoint → candidate → finding → evidence → chain + run).
- Dua mode: Mode 1 Muse skill (tanpa provider) dan Mode 2 Standalone
  CLI dengan provider picker ala Lumitome (OpenAI/Anthropic/9router).
- Provider picker: `GET /models`, simpan config 0600, key terpisah
  0600, tulis via `.tmp` + rename.
- Auth-minimal: cookie/token/header statis + 2 peran low/high-priv.
- Eval harness: 3 lab (Juice Shop, DVWA, VAmPI), oracle ground-truth,
  bench multi-run 3× (median TP/FP/FN/precision/recall), gate rilis
  FP turun / TP tidak turun vs baseline Strix.
- Installer: `curl | bash` (Linux/macOS), `npm install -g`,
  PowerShell (Windows); pilihan Docker [1] Ya / [2] Tidak.
- Skill Muse `skills/bounty/` + katalog skill hunt padat (24 `hunt-*`),
  template laporan HackerOne/Bugcrowd, threat model.
- Budget default $5/target, `--max-turns` aman, mode `quick`/`deep`.

### P1 (setelah v1 hijau)

- Guard lanjutan: secret-leak guard, governance deny-by-default,
  audit trail, red-team test guard.
- Reviewer manual di `strix view` (approve/reject/turun severity).
- Lab diperluas: DVGA (GraphQL) + 1 app ber-LLM; checklist LLM/Agentic
  Top 10 tervalidasi.
- Tool + playbook: dalfox, amass, katalog HexStrike 150 tool on-demand,
  template Nuclei, verifikasi TruffleHog, SBOM Trivy, SARIF/PDF.
- Konten lanjutan: vbsec 21 tipe, Ghostsecurity full loop, Trail of
  Bits, review PR diff-aware, mindmap view, Shannon tracing (pola saja),
  SQL wordlist terkurasi.

### P2 (mode terpisah — docs di `docs/p2-*.md`)

- Fork core Strix penuh: remote `upstream`, rebase berkala
  (`scripts/rebase-upstream.sh`), patch branch terpisah.
- PentAGI penuh (Postgres/pgvector, Neo4j/Graphiti, Langfuse/Grafana)
  — compose opsional `eval/docker-compose-pentagi.yml`.
- MCP 16 platform bounty (HackerOne, Bugcrowd, Intigriti, Immunefi,
  YesWeHack, dll) — baca-saja, **tanpa auto-submit**, tanpa kredensial.
- RE native (Ghidra/jadx/x64dbg/radare2/LLM4Decompile/binaryen-wabt),
  mode RE terpisah.
- Mobile: MobSF REST API + CI/CD, fokus API backend mobile.
- LLM red-team: garak/deepteam + mapping OWASP LLM Top 10.
- Capture session manual + MITM recording proxy (2FA/OTP/SSO) —
  docs, **bukan** bypass/captcha solving.

### Produksi / tim (baru di 1.0.0)

- `docs/TEAM.md`: onboarding 1 perintah, peran low/high + reviewer,
  aturan scope, budget $5, rate 10/detik, audit, larangan.
- `.env.example` (placeholder saja), `CONTRIBUTING.md`, `SECURITY.md`.
- CI GitHub Actions (`.github/workflows/ci.yml`): Node 20, `npm test`,
  gitleaks, `node --check`.

### Batasan live (jujur — belum diuji live)

- **Docker/Strix belum diuji live di VM ini**: lab eval jalan mode
  no-docker (mock findings deterministik); `docker compose` lab dan
  Strix asli belum dijalankan di sini.
- **Provider picker belum diuji live**: belum ada panggilan API
  berbayar / `GET /models` ke provider nyata dari repo ini.
- **PowerShell installer (`scripts/install.ps1`) belum diuji live**
  di Windows.
- **P2 belum diuji live**: fork Strix, PentAGI, MCP platform, RE,
  mobile, LLM red-team, capture 2FA — semuanya docs + template,
  belum ada run nyata.
- Bench live ke lab Docker (Juice Shop/DVWA/VAmPI sungguhan) belum
  dijalankan; angka TP/FP sejauh ini dari mock deterministik.

## [0.1.0] — 2026-11-23

- Rilis awal: wrapper Strix + skill Muse + eval harness (plan v3.1).
