# muse-bug-bounty

> **Status: produksi v1.12.0 (2026-11-23).** Wrapper, skill, eval harness,
> docs P2, dan dokumen tim sudah lengkap (`docs/TEAM.md`,
> `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`). Lihat
> [Batasan live](#batasan-live) — beberapa jalur belum diuji live
> (Docker/Strix/provider/PowerShell) dan ditulis jujur di sana.

> **Setup terpandu (baru di main, 2026-11-23):** satu perintah `bounty setup`
> menuntun prasyarat → provider → target & scope → verifikasi (Scope OK),
> lalu `bounty run` tanpa argumen tinggal pilih program. Detail di
> [Quickstart](#quickstart).

> **v1.11.0 — ingatan belajar (2026-11-23):** `bounty/lib/learning.js` —
> track record presisi per skill dari verdict reviewer (router naik/turun
> max ±0.3) + similarity vektor-hash di `findings --similar` +
> `bounty memory --track-record`. Menutup rangkaian v1.9 → v1.10 → v1.11.

> **v1.10.0 — planner coverage (2026-11-23):** `bounty/lib/planner.js` +
> perintah baru `bounty plan` — peta surface × kelas vuln, rencana hunt
> ke pasangan yang masih terbuka, surface terpanas dulu, max 3 kelas
> per surface.

> **v1.9.0 — otak BugHunter (2026-11-23):** 22 skill baru (index 67 → **89**),
> pola bersitasi 85 → **124** (bersitasi 73 → **112**, 21 skill), 8 skill
> Tier-1 diperdalam, perintah baru `bounty skills`. Termasuk perbaikan
> UI/UX dari PR #1 (sudah merge ke main): warning SQLite disaring, help
> dikelompokkan, Scope DITOLAK ke stderr, did-you-mean.

Tool `bounty` — pembungkus aman dan ringan di atas
[Strix](https://github.com/usestrix/strix) (`usestrix/strix`, Apache-2.0)
untuk bug bounty web-first: scope gate, guard pra-eksekusi, rate limiter
global, dan satu store `bounty.db`. Nol dependensi, $0, tanpa auto-submit,
tanpa pembayaran, tanpa deposit.

> **Strix TIDAK dibundel di repo ini.** Strix diinstal oleh user
> (lihat [Install](#install)). Repo ini hanya berisi wrapper `bounty`,
> skill Muse, eval harness, dan installer.

## Dua mode

| Mode | Cara pakai | Provider |
| --- | --- | --- |
| **1 — Muse skill** | Instal skill `skills/bounty/` ke Muse; agen memakai Strix lewat env `STRIX_SKILLS_DIR` | Tanpa provider — pakai model Muse yang sedang berjalan |
| **2 — Standalone CLI** | `bounty setup` sekali, lalu `bounty run` | Provider picker ala Lumitome (OpenAI / Anthropic / 9router lokal, pilih saat setup pertama) |

Mode 1 tidak butuh API key apa pun. Mode 2 butuh key provider yang user
pasang sendiri sekali di awal (`bounty setup` → langkah provider);
key disimpan lokal dengan mode file `0600`, tidak pernah di-commit.

## Install

Butuh Node.js >= 24. Pilih salah satu:

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/fahmi0812/muse-bug-bounty/main/scripts/install.sh | bash
# atau dari clone:
git clone https://github.com/fahmi0812/muse-bug-bounty.git
cd muse-bug-bounty
bash scripts/install.sh
```

```powershell
# Windows (PowerShell)
.\scripts\install.ps1
```

```powershell
# Windows (winget) — setelah manifest di winget/ di-merge ke winget-pkgs
winget install fahmi0812.muse-bug-bounty
# Status winget: lihat winget/README.md (belum live, butuh release + PR winget-pkgs)
```

Installer menanyakan **Docker [1] Ya / [2] Tidak** (default 1).
Docker hanya dipakai untuk lab eval lokal (Juice Shop, DVWA, VAmPI);
tanpa Docker, bench tetap jalan dalam mode no-docker (lihat
[eval/README.md](eval/README.md)).

```bash
# Non-interaktif:
BOUNTY_DOCKER=1 bash scripts/install.sh   # dengan Docker
BOUNTY_DOCKER=0 bash scripts/install.sh   # tanpa Docker
bash scripts/install.sh --no-docker       # flag juga bisa
```

## Install tim (kontributor)

Cukup 1 perintah — tanpa Strix, Docker, atau provider:

```bash
git clone https://github.com/fahmi0812/muse-bug-bounty.git && cd muse-bug-bounty && npm test
```

Lalu baca [docs/TEAM.md](docs/TEAM.md) (peran, aturan scope, budget,
audit, larangan) dan [CONTRIBUTING.md](CONTRIBUTING.md). Salin
`.env.example` ke `.env` bila butuh variabel lokal — isinya hanya
placeholder `REPLACE-ME`, jangan commit `.env`.

Lalu instal Strix (bukan bagian repo ini):

```bash
curl -sSL https://strix.ai/install | bash
```

Dan, hanya untuk Mode 2, jalankan setup terpandu sekali (provider +
target + scope + verifikasi, tinggal pilih-pilih):

```bash
bounty setup
```

`bounty setup` menuntun 4 langkah: (1) cek prasyarat (Node/Strix),
(2) provider — tipe, base URL (default 9router lokal
`http://127.0.0.1:20128/v1`), API key (tidak di-echo), deteksi + filter +
pilih model, (3) target — host + template scope (seluruh situs / API
saja / custom) + Budget/Rate/Roles (semua ada default), disimpan ke
`programs/<nama>.md` (program yang sudah ada bisa dipilih, tidak perlu
dibuat ulang), (4) verifikasi scope in-process (harus Scope OK).
Non-interaktif: `bounty setup --yes --api-key KEY --model ID --host
staging.contoh.com [--template all|api|custom]`; `--skip-provider`
memakai provider tersimpan. Wizard lama `bounty provider` tetap ada
untuk mengubah provider saja.

Update ke versi terbaru nanti tinggal satu perintah dari mana saja:
`bounty update` (cari clone otomatis, `git pull` + instal ulang global;
perubahan lokal di-stash dulu lalu dikembalikan).

## Quickstart

```bash
# Setup terpandu sekali — provider + target + scope + verifikasi
bounty setup

# Lalu jalan, tinggal pilih program (tanpa argumen, di terminal)
bounty run

# Atau eksplisit seperti dulu:
# Kering dulu — tidak ada request keluar, tidak ada temuan dikirim
bounty run --target https://example.com/api/users --program programs/example.md --dry-run

# Jalan sungguhan (butuh Strix terinstal + scope program terdaftar)
bounty run --target https://example.com/api/users --program programs/example.md

# Lihat program & temuan yang tersimpan
bounty programs
bounty findings --program example
```

Sebelum jalan, daftarkan scope program di `programs/<nama>.md`
(contoh ada di `programs/` — termasuk `dvga.md` dan `llm-app.md`). Target di luar scope **ditolak** oleh
scope gate sebelum request apa pun dikirim.

## Struktur repo

```text
muse-bug-bounty/
├── bounty/
│   ├── bin/bounty.mjs      # CLI entrypoint
│   └── lib/                # router, dedup, rate, scope, guard,
│                           # provider, setup wizard, store (SQLite bounty.db), auth, bench
├── skills/bounty/          # Muse skill (Mode 1)
├── programs/               # definisi scope program (.md: example, juice-shop, dvwa, vampi, dvga, llm-app)
├── eval/
│   ├── oracle/labels/      # ground truth Juice Shop / DVWA / VAmPI
│   ├── run-bench.mjs       # bench TP/FP/FN vs baseline Strix
│   ├── docker-compose.yml  # lab lokal (opsional, butuh Docker)
│   └── results/            # hasil bench (latest.json)
├── scripts/                # install.sh / install.ps1 / install.js / bounty.cmd
├── winget/                 # manifest winget (lihat winget/README.md — belum live)
├── tests/                  # node:test, tanpa network/Docker/Strix
├── README.md
└── LICENSE                 # Apache-2.0
```

## Test & bench

```bash
npm test                  # node --test tests/ — deterministik, tanpa network
npm run bench             # eval/run-bench.mjs — mock (deterministik) + gate baseline bila baseline.json ada
npm run measure-baseline  # LIVE: ukur baseline Strix vs bounty di lab Docker (butuh Docker + Strix, di laptop)
```

`bounty run` sekarang meneruskan skill ke Strix lewat env `STRIX_SKILLS_DIR` (flag `--skills-dir` tidak ada di Strix versi terinstal di laptop — diverifikasi dari usage Strix 24 Nov 2026), lalu mem-parse output Strix (JSON / JSONL / Markdown) menjadi kandidat di `bounty.db` — semua berstatus `candidate` (UNVERIFIED) sampai disetujui di `bounty review`. Biaya terukur dari output (`Total cost: $X`) dicatat di tabel `run`. **v1.1:** sumber utama temuan/biaya adalah artefak Strix `strix_runs/<run>/run.json` + `vulnerabilities.json` (stdout hanya fallback); Strix exit 2 = "vulns found" dipetakan ke sukses-dengan-temuan (bukan error); `STRIX_TELEMETRY=0` disetel saat spawn. Sebelum jalan, wrapper memeriksa `~/.strix/cli-config.json` + env `STRIX_WEB_SEARCH_PROVIDER`, lalu meneruskan provider tersimpan (`.bounty/providers/`) ke Strix lewat env (`STRIX_LLM`/`LLM_API_BASE`/`LLM_API_KEY`) dan memperbaiki file config bila bentuknya masih flat (loader Strix hanya membaca blok `{"env": ...}`) — nilai yang tidak dikenal Strix (mis. `custom`) dihapus dari file (fallback `auto`) supaya Strix tidak crash saat start; bila nilainya dari env shell, run dibatalkan dengan petunjuk `unset`. Strix yang crash (traceback / exit non-zero selain 2) dilaporkan sebagai error, tanpa ringkasan sukses. Selagi Strix jalan, CLI menampilkan status satu baris (animasi berputar + waktu berjalan + baris terakhir output Strix, hanya bila terminal interaktif) — run pertama yang pull image Docker tidak lagi terlihat diam.

**v1.1 — runner on-demand:** `bounty scan --tool nuclei|dalfox|ffuf --target URL --program programs/<nama>.md` menjalankan tool itu (bila terinstal; bila tidak ada, dilewati tanpa error) dan menyimpan temuannya sebagai kandidat. Bench kini juga mengukur **akurasi router** (top-5 skill vs oracle per lab; mock saat ini: dvga 100%, dvwa 88%, juice-shop 70%, vampi 63%, llm-app 33%).

**v1.2 — ingatan + peta:** tiap run/review menulis episode memori; verdict reviewer (approve/reject) jadi lesson yang mengubah skor router di run berikutnya; `bounty findings --similar <id>` mencari temuan serupa (FTS5 + RRF) dan run memberi peringatan bila polanya pernah ditolak; `bounty memory` / `bounty graph` / `bounty trace <id>` menampilkan ingatan, peta aset, dan jejak source → sink. Semua di `bounty.db` yang sama, tanpa server baru.

**v1.3 — perdalam + scale:** 7 runner baru (arjun, graphql-cop, gitleaks, trufflehog, osv-scanner, garak, deepteam) — `bounty scan` kini 10 tool; `bounty run --targets url1,url2` antrean multi-target dengan satu pool budget + peringatan biaya; `bounty view` membuka dashboard Strix; lab LLM nyata dipilih: LLMVault (MIT, 25 lab OWASP LLM Top 10 — endpoint/oracle belum diverifikasi live). 2 skill Tier 2 baru (lfi, nosqli) + 2 skill Trail of Bits.

**v1.3.1 — 8 skill Tier 2 tertunda selesai** dengan parafrase defensif (fokus deteksi + validasi, minim payload mentah): `hunt-dom` (yang sempat kena flag — kini lolos), `hunt-nodejs`, `hunt-http-smuggling`, `hunt-jwt-crypto`, `hunt-llm-ai`, `hunt-api-misconfig`, `web2-recon`, `bug-bounty`. Index 57 entri; akurasi router llm-app naik 33% → 67% (mock).

**v1.5 — semua P0 (P0-2 s.d. P0-7):** pola bersitasi 12 → 85 (73 berlink HackerOne asli), recon pipeline (subfinder/dnsx/httpx/katana/nuclei KEV/crt.sh), jsluice + sourcemapper, interactsh OAST, LLM 2026 (OWASP LLM01–10 + ASI01–10, garak agent-breaker, PyRIT), platform read-only (scope sync, cek duplikat, draft — tanpa auto-submit). Index skill kini 61. Runner baru belum pernah jalan live (binary tidak ada di VM).

**v1.8 — CLI dibagusin + lebih mudah dipahami:** `bounty/lib/ui.js` (zero-dep) — warna otomatis (mati bila di-pipe atau `NO_COLOR`/`BOUNTY_NO_COLOR=1`), badge severity Bahasa Indonesia (`[KRITIS]`/`[TINGGI]`/`[SEDANG]`/`[RENDAH]`/`[INFO]`), tabel sejajar untuk `programs`/`findings`/`review`, progress bar antrean multi-target, dan kotak "Ringkasan run" di akhir tiap run (temuan, kandidat baru, duplikat, biaya vs budget). Tidak ada perubahan perilaku hunt/scope/budget/store — hanya tampilan.

**v1.7 — semua P2 (P2-1 s.d. P2-6):** firmware ringan (`bounty firmware`: binwalk-ng, unblob, cve-bin-tool; EMBA opt-in semalam), DVLAA (81 tantangan, eksportir `npm run dvlaa-export` — best-effort, lisensi Unknown, lab saja), Promptfoo CI gate (`bounty promptfoo-gate`, fail-closed), graph gate (`bounty graph-gate` — upgrade hanya bila baseline membuktikan), WiFi/C2 sengaja tidak dibangun (dikunci di guard), installer pdtm/go/pipx (`scripts/install-tools.sh`, winget masih belum live). Tidak ada runner P2 yang pernah jalan live (binary tidak ada di VM).

**v1.6 — semua P1 (P1-1 s.d. P1-7):** GraphQL recovery (`bounty graphql`), cloud enum + takeover (`bounty cloud`), RE headless gated (`bounty reverse`), mobile statis MobSF + jadx (`bounty scan --tool mobsf|jadx`), parity Strix (`--fail-on`, `--pause`/`--resume`, evidence ID, timings, `bounty dedup`, `bounty codesearch`), 6 skill enterprise identity, Caido MCP live (`bounty caido`). Index skill kini 67. Tidak ada runner P1 yang pernah jalan live (binary tidak ada di VM); `@caido/mcp-server` 404 di npm — pakai clone `caido/mcp-caido`.

**v1.4 — baseline pack P0-1:** panduan XBEN (104 tantangan, subset 10 untuk sinyal awal) + EthiBench (108 GT, versi dipatok) di `eval/benchmarks/`, eksportir temuan → `findings.jsonl`, dan `scripts/baseline-laptop.sh` satu perintah di laptop. Baseline live-nya sendiri masih menunggu laptop — pack ini membuatnya siap jalan, bukan menjalankannya.

**v1.3.2 — 2 skill terakhir selesai:** `hunt-mfa-bypass` (celah logika penegakan MFA; tebak/brute-force kode DILARANG) dan `hunt-host-header`. Index kini 59 entri — semua skill Tier 1 + Tier 2 lengkap, tidak ada lagi yang tertunda.

Bench menjalankan tiap lab 3× (mock findings deterministik, seed tetap),
menghitung TP/FP/FN/precision/recall per run dan median lintas run,
lalu menyimpan `eval/results/latest.json`. Gate: FP harus turun dan TP
tidak turun dibanding baseline Strix. Detail di
[eval/README.md](eval/README.md).

## Keamanan

- **Scope gate** — host/path di luar scope program ditolak sebelum
  request keluar. Tidak ada scanning liar.
- **Guard pra-eksekusi** — perintah destruktif diblokir (`rm -rf`,
  `git push`, `git reset --hard`, baca `.env`, pipe-to-shell, ...).
  Hanya perintah yang diizinkan (mis. `strix --target ...`) yang jalan.
- **Budget** — default **$5/target**; run berhenti saat budget habis.
- **Rate limit** — default **10 req/detik** global, dengan backoff. Jujur: bucket menegakkan rate request wrapper; request internal Strix dibatasi lewat `--max-budget` / `--max-turns` + instruksi, bukan lewat bucket wrapper.
- **Kredensial** — `providers.json` / `credentials.json` disimpan
  mode `0600`, masuk `.gitignore`, tidak pernah dikirim ke mana pun
  selain provider yang user pilih.
- **Tanpa auto-submit / pembayaran** — temuan hanya disimpan lokal
  (`bounty.db` + `evidence/`); submit ke program selalu manual oleh user.

## Batasan live (jujur — belum diuji live)

- **Docker/Strix belum diuji live di VM ini**: lab eval jalan mode
  no-docker (mock findings deterministik); `docker compose` lab dan
  Strix asli belum dijalankan di sini.
- **Provider picker sudah diuji live ke 9router lokal** (23 Nov 2026):
  `bounty provider` mendeteksi **212 model** via `GET /models` di
  `http://127.0.0.1:20128/v1` dan menyimpan provider + Strix config.
  Provider berbayar (OpenAI/Anthropic) belum diuji live dari repo ini.
- **PowerShell installer (`scripts/install.ps1`) belum diuji live**
  di Windows.
- **Baseline belum pernah diukur live**: `eval/results/baseline.json` belum ada — ukur di laptop: `npm run measure-baseline` (butuh Docker + Strix). Sampai itu jalan, klaim TP/FP vs baseline belum terbukti.
- **P2 belum diuji live**: fork Strix, PentAGI, MCP platform, RE,
  mobile, LLM red-team, capture 2FA — semuanya docs + template di
  `docs/p2-*.md`, belum ada run nyata.
- **v1.3 (baru):** 8 skill Tier 2 tertunda karena flag keamanan
  (`hunt-dom` dihentikan saat penulisan; 7 lainnya belum dibuat);
  flag CLI runner batch 2 (arjun, graphql-cop, gitleaks, trufflehog,
  osv-scanner, garak, deepteam) best-effort — belum diuji live terhadap
  binary aslinya; lab LLMVault (build git-context) belum dijalankan
  live dan endpoint/oracle llm-app belum diverifikasi terhadapnya.
- Bench live ke lab Docker (Juice Shop/DVWA/VAmPI sungguhan) belum
  dijalankan; angka TP/FP sejauh ini dari mock deterministik.

## Lisensi & atribusi

Repo ini berlisensi **Apache License 2.0** (lihat `LICENSE`).

- **Strix** (`usestrix/strix`) — Apache-2.0. Base tool; tidak dibundel.
- Pola & ide yang dipelajari (bukan salinan kode verbatim):
  - **Claude-BugHunter** — MIT (katalog skill bounty).
  - **Cloudflare**-related bounty tooling — MIT.
  - **OWASP** (Juice Shop, testing guide) — MIT.
  - **Shannon, ARTEX, VulnHunter** — AGPL (pola deteksi saja;
    tidak ada kodenya di repo ini).
- Lab eval: **OWASP Juice Shop**, **DVWA**, **VAmPI** — masing-masing
  dengan lisensinya sendiri (lihat repo lab terkait).
