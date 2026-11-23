# Changelog — muse-bug-bounty

Format: tiap rilis = daftar fitur + batasan. Tanggal WIB.

## [1.13.4] — 2026-11-24

### Fixed
- **Pre-flight config Strix diperluas: nilai 'custom' yang lolos v1.13.3 kini ketangkap.** Run di laptop Fahmi tetap crash dengan ValidationError yang sama meski v1.13.3 sudah terinstal — artinya nilainya masuk lewat jalur yang belum diperiksa. Jebakan: pydantic-settings membaca env dengan `populate_by_name=True` + `case_sensitive=False`, jadi field `web_search_provider` bisa masuk lewat DUA nama env — `STRIX_WEB_SEARCH_PROVIDER` (alias) maupun `WEB_SEARCH_PROVIDER` (nama field, tanpa prefix) — dalam huruf apa pun; v1.13.3 hanya memeriksa nama alias. Kini pre-flight memindai semua kunci env (case-insensitive) untuk kedua nama itu, dan di file memeriksa bentuk flat, blok `{"env": ...}`, DAN bentuk nested `{"integrations": {...}}`. Bila sumbernya env, run dibatalkan dengan nama var yang persis (`unset WEB_SEARCH_PROVIDER`, dst.); bila sumbernya file, kunci dihapus otomatis seperti sebelumnya.

## [1.13.3] — 2026-11-24

### Fixed
- **`bounty run` — Strix crash saat start karena config tak valid kini diperbaiki otomatis sebelum run.** Run dari degre lolos guard dan flag sudah benar, tapi Strix crash di `pull_docker_image` → `load_settings`: `ValidationError: IntegrationSettings.web_search_provider — Input should be 'auto', 'perplexity' or 'exa'` karena nilainya `'custom'`. Nilai itu BUKAN dari wrapper (writeStrixConfig hanya menulis 3 kunci LLM) — asalnya dari `~/.strix/cli-config.json` (blok `{"env": ...}` warisan Strix lama) atau env shell; diverifikasi dari upstream `strix/config/settings.py` (Literal auto|perplexity|exa, default auto, alias `STRIX_WEB_SEARCH_PROVIDER`) + `strix/config/loader.py` (env menang, lalu file, lalu default). Kini `bounty run` memeriksa config sebelum spawn: nilai tak valid di FILE dihapus otomatis (fallback `auto`; `'custom'` tidak bisa jalan di Strix mana pun) dan dilaporkan; nilai tak valid dari ENV SHELL membatalkan run dengan petunjuk `unset` yang persis.
- **Strix crash tidak lagi dicetak sebagai ringkasan sukses 0 temuan.** Bila Strix keluar non-zero (selain exit 2 temuan) atau output mengandung traceback/`validation error for …Settings`/`Failed to execute script`, run dilaporkan sebagai error (exit 2, tanpa ringkasan sukses, tanpa mencatat run) dengan pesan "Strix gagal jalan (exit N)".

## [1.13.2] — 2026-11-24

### Fixed
- **`bounty run` — flag Strix diperbaiki dari usage asli (bukan dugaan).** Run pertama dari folder degre lolos guard tapi Strix menolak argumen: `--budget` TIDAK PERNAH ADA (dugaan kita), `--skills-dir` hanya ada di Strix upstream terbaru — tidak ada di build Strix terinstal di laptop (usage-nya tidak mencantumkan keduanya). Kini perintah Strix hanya `--target … --max-budget <budget> --max-turns <n>`; skill diteruskan lewat env `STRIX_SKILLS_DIR` (diverifikasi nyata di upstream `strix/skills/__init__.py`: `SKILLS_DIR_ENV`). `eval/measure-baseline.mjs`, `scripts/baseline-laptop.sh` (Langkah 0), README, dan docs/TEAM.md ikut diperbaiki.
- **Exit 2 Strix yang sebenarnya error argumen tidak lagi disangka "temuan ditemukan".** Sebelumnya wrapper mengira semua exit 2 = vulns found, lalu mencetak ringkasan sukses 0 temuan — menyesatkan. Kini bila output mengandung `unrecognized arguments` / `usage: strix` / `strix: error:`, run dilaporkan sebagai error (exit 2, tanpa ringkasan sukses, tanpa mencatat run) dengan pesan jelas bahwa ini bug wrapper.

## [1.13.1] — 2026-11-24

### Fixed
- **`bounty run` — guard tidak lagi memblokir run dari folder mana saja.** Penyebab "Perintah diblokir guard: perintah keluar dari workspace diblokir" saat Fahmi run dari `~/Downloads/UNF/cy1/degre`: guard memakai cwd sebagai workspace, sementara `--skills-dir` menunjuk ke folder instal bounty (di luar cwd) — jadi setiap run dari luar clone selalu diblokir. Kini `checkCommand` menerima `allowRoots`: folder instal tool sendiri (berisi `skills/`) diizinkan sebagai rujukan path absolut; aturan blokir lain (rm, pipe-to-shell, denylist K/L, file rahasia, path absolut di luar workspace+allowRoots) tetap berlaku penuh.
- **`bounty update` — pulihkan +x bin setelah instal (self-heal).** Akar masalah "Permission denied" akhirnya ketemu: instal global dari folder lokal itu symlink ke clone (bukan salinan), dan npm memberi +x pada file bin di clone saat instal — tapi `git restore`/`git stash`/`git pull` mengembalikan mode file ke 644 yang terlacak, sehingga binary global ikut kehilangan +x. Kini `bounty update` menjalankan `chmod 755` pada `bounty/bin/bounty.mjs` setelah instal (best-effort). Catatan: percobaan melacak mode 755 di git dibatalkan — push snapshot menyimpan mode 100644 apa pun isi index, dan eksperimen membuktikan npm selalu memaksa +x saat instal, jadi mode di repo bukan penyebabnya.

## [1.13.0] — 2026-11-24

### Added
- **`bounty update` — perbarui wrapper dengan satu perintah.** `git pull` berulang kali gagal di laptop Fahmi karena perubahan lokal di `bounty/bin/bounty.mjs` (bukan editan sengaja) menghalangi merge. Kini cukup `bounty update` dari mana saja: cari clone otomatis (folder saat ini / `~/muse-bug-bounty` / lokasi lama, atau `--source DIR`), stash perubahan tracked bila ada, `git pull --ff-only`, lalu `npm install -g --ignore-scripts`, dan coba kembalikan stash (bila bentrok, stash tetap aman + petunjuk pulihkan manual). `--dry-run` hanya menampilkan rencana. File untracked (program buatan sendiri, `.bounty/`) tidak disentuh.

## [1.12.1] — 2026-11-24

### Fixed
- **`bounty setup` — prompt API key dobel & "Mendeteksi model..." nempel.** Masking lama (hapus-baris per ketikan via keypress) berantakan di sebagian terminal: prompt tercetak dua kali dan pesan berikutnya menempel di baris yang sama. Diganti pendekatan bisukan-echo (`_writeToOutput`): prompt ditulis sekali, ketikan disembunyikan, diakhiri tepat satu newline. Nilai key tetap tidak tampil/dilog.
- **`bounty setup` — daftar model membanjiri layar (254 baris).** Kini bila model > 40: ada loop filter ("ketik kata kunci untuk mempersempit") dan tampilan dibatasi 40 teratas dengan catatan "… dan N lagi". Pemilihan tetap bisa via nomor / id / sebagian nama (termasuk yang tak tampil).
- **`bounty run` — pesan "Strix tidak ditemukan" lebih jelas.** Menyebut "di PATH" + petunjuk `source ~/.bashrc` / buka terminal baru bila Strix baru diinstal (installer menaruh PATH di `~/.bashrc`, shell berjalan belum memuatnya).

## [1.12.0] — 2026-11-23

### Added
- **v1.12 — perbaikan kecil (dari audit "apa yang masih kurang"):**
  - **Router accuracy 100% semua lab (mock):** dvga 100%, dvwa 88% → **100%**, juice-shop 70% → **100%**, llm-app 67% → **100%**, vampi 63% → **100%**. Caranya: (a) 8 pemetaan kelas baru di `CLASS_TO_SKILL` (weak credentials → hunt-auth-bypass, sensitive/excessive data exposure → hunt-secrets, DoS → hunt-dos baru, broken function level authorization → hunt-broken-access, local file inclusion/LFI → hunt-lfi); (b) skill baru `hunt-dos.md` (CWE-400, index 89 → **90**); (c) pengayaan keyword (hunt-auth-bypass +weak/credentials/hardcoded, hunt-secrets +sensitive/data/exposure/disclosure, hunt-llm-ai +sensitive/exfiltration/leakage/retrieval). **Jujur: ini akurasi routing mock (keyword vs label oracle), BUKAN TP/FP live — baseline live tetap menunggu laptop.**
  - **Promosi penuh track-record (v1.11 diperbaiki):** `scoreAll`/`topWithFallback`/`scoreWithBonuses` kini diekspor dari router.js; `routeWithTrackRecord` menerapkan bonus ke SEMUA skill sebelum top-5 dipotong — skill peringkat 6 kini bisa dipromosikan (test baru membuktikannya).
  - **Recon otomatis daftarkan surface:** `bounty recon` kini mendaftarkan hasil (hostname/URL/endpoint, max 20/run) sebagai surface ke planner via `recordSurface` — `bounty plan` langsung bisa merencanakan hunt ke temuan recon; idempotent (recon ulang tidak menambah).
  - **Pola bersitasi 6 kelas kosong: hasil 0 (terverifikasi).** Riset ulang ke clone upstream (skill + disclosed-reports + daftar "Further...") memastikan upstream memang tidak mencantumkan ID HackerOne eksplisit untuk hunt-xss, hunt-nosqli, hunt-host-header, hunt-session, hunt-cors, hunt-websocket — tidak ada ID yang bisa ditambahkan tanpa menebak. Tetap 124 pola / 112 bersitasi.
- **Batasan jujur v1.12.0:** 6 kelas kosong SUDAH terisi (batch 1A, lihat bawah); 157 dari 172 pola bersitasi masih tanpa payout terverifikasi; akurasi router 100% adalah mock — bukti live (baseline, `strix --help`, runner, oracle LLMVault) tetap menunggu laptop Fahmi; winget masih belum live.

  **Batch pola 2 — ambil dari repo Claude-BugHunter (23 Nov 2026, ~22:35 WIB):** +33 pola dari bagian "Cited Public Examples" clone upstream (CC-BY-4.0, adaptasi + atribusi; subclass ditulis ulang). Total kini 184 pola / 172 bersitasi dari 34 skill; 7 skill baru terisi (brute-force 5, captcha-bypass 3, clickjacking 3, cloud-misconfig 5, html-injection 5, source-leak 7, tls-network 5). Temuan penting: jalan pintas repo ternyata hampir jenuh — bagian Cited yang belum dipanen tinggal sedikit; sisa ~338 ID "baru" di clone sebagian besar ada di "Further disclosed reports" (link + payout saja, tanpa subclass — butuh verifikasi live per laporan, bukan ekstraksi repo). Semua pola batch 2 tahun/payout null (upstream tak menyebut keduanya bersamaan).

  **Batch pola 1A, pasca-push v1.12.0 (commit terpisah, tanpa bump versi):** +15 pola baru, semua diverifikasi live di hackerone.com — 6 kelas yang tadinya kosong kini terisi: xss 3, nosqli 1, host-header 3, session 2, cors 3, websocket 3. Total kini 151 pola / 139 bersitasi dari 27 skill, 15 dengan payout+tahun terverifikasi (baru: 1147433 $5.300/2021, 1444675 $300/2022, 423136 $5.000/2018) dan 30 dengan tahun. 2 slot gagal (nosqli ke-3 + session ke-3 — HackerOne rate-limit konsisten; kandidat terkuat 1547684 Shopify $1.600/2022 hanya terlihat di snippet pencarian, tidak dimasukkan). 2 verifikasi paling lemah dicatat: 137181 (tahun dari tanggal komentar/triage, bukan baris submitted) dan 263873 (judul tak muncul di fetch, tapi program/tanggal/weakness/bounty terlihat).

  **Batch pola 1B, pasca-push v1.12.0 (commit terpisah, tanpa bump versi):** +12 pola baru, semua diverifikasi live di hackerone.com (ssti 2, auth-bypass 2, sqli 3, rce 3, csrf 2) — total kini 136 pola / 124 bersitasi, 12 dengan payout+tahun terverifikasi (baru: 476150 $2.500/2019, 838855 $2.000/2020, 206872 $2.500/2017, 658013 $12.000/2019, 181879 $18.000/2016) dan 15 dengan tahun. 14 kandidat lain gagal diverifikasi (rate-limit/timeout/halaman kosong) — tidak dimasukkan. Batch 1A (6 kelas kosong) masih jalan.

  **Koreksi data pola, pasca-push v1.12.0 (commit terpisah, tanpa bump versi):** spot-check 10 laporan H1 live — 5 terverifikasi penuh (383127 SQLi $25.000/2018, 826361 SSRF $10.000/2020, 488147 smuggling $18.900/2019, 3800870 JWT $1.337/2026, 827052 LFI $20.000/2020) + 1 tahun saja (1213237 IDOR 2021, payout tidak tercantum); total kini 7 pola dengan payout+tahun terverifikasi dan 8 dengan tahun. Subclass 488147 diperbaiki: "$20.000" adalah milik 510152, bukan 488147. 4 lainnya tidak terverifikasi (2 timeout, 1 gagal fetch, 1 tanpa payout/tanggal di halaman) — tetap null, tidak ditebak.

## [1.11.0] — 2026-11-23

### Added
- **v1.11 — ingatan yang benar-benar belajar (PentAGI-style, ringan), tahap 3 dari "gas semuanya berurutan":**
  - **`bounty/lib/learning.js` (baru, zero-dep):** `hashVector` (feature-hashing 128-dim, FNV-1a, L2-normalize) + `vectorCosine`; `skillTrackRecord` (presisi per skill dari verdict reviewer: confirmed/(confirmed+fp); weight = (presisi − 0.5) × 2, clamp ±1, **weight 0 bila total < 3** — data minim tidak berpendapat); `routeWithTrackRecord` (skor keyword + nudge lesson ±0.15 cap ±0.45 + bonus pola + **bonus track-record ±0.3**; tanpa lesson/track/pola → deepEqual-identik dengan router lama); `findSimilarV2` (fusion 0.4·BM25 + 0.2·TF-IDF + 0.2·cosine vektor-hash + 0.2·boost kelas+CWE). 5 test.
  - **Penyambungan:** `bounty findings --similar` dan peringatan FP di `bounty run` kini pakai `findSimilarV2`; `bounty memory --track-record` tampilkan tabel presisi + bobot per skill (butuh ≥3 verdict); bench kini route lewat `routeWithTrackRecord` (tanpa lesson/track → hasil sama).
  - **Batasan jujur v1.11.0:** track-record hanya mengurutkan ulang skill yang sudah masuk top-5 keyword (skill peringkat 6 tidak bisa dipromosikan — `scoreAll` di router.js tidak diekspor; promosi penuh butuh satu baris ekspor di sana); similarity vektor = hash token, bukan embedding model (tidak menangkap sinonim); baseline live + oracle LLMVault tetap menunggu laptop Fahmi. Ini menutup rangkaian "gas semuanya berurutan" (v1.9 otak → v1.10 planner → v1.11 ingatan).

## [1.10.0] — 2026-11-23

### Added
- **v1.10 — planner berbasis coverage (ARTEX-style), tahap 2 dari "gas semuanya berurutan":**
  - **`bounty/lib/planner.js` (baru, zero-dep):** `buildCoverageMap` (surface × kelas vuln, status examined/open/ruled_out — surface = union endpoint candidate + surface terdaftar), `planNext` (pasangan (surface, kelas) yang masih open; surface terpanas dulu, lalu kelas paling sering terkonfirmasi, lalu abjad; **noise governor max 3 kelas per surface**), `recordSurface` (daftarkan surface baru — tulis baris `open` hanya untuk kelas yang belum punya baris, tanpa menimpa examined/ruled_out), `coverageSummary` (surface, examined/open/ruled_out, pct). Universe = 72 kelas vuln dari skills-index (86 unik minus 14 skill meta/metodologi yang bukan kelas vuln — daftar pengecualian diekspor sebagai `EXCLUDED_META_CLASSES`). Ide diambil dari ARTEX (AGPL — hanya idenya, bukan kodenya). 9 test.
  - **Perintah baru `bounty plan --program <nama> [--limit N] [--record <surface>]`: ** kotak ringkasan coverage + tabel rencana (Surface/Kelas/Alasan) + petunjuk lanjut hunt (`bounty scan ...`); program kosong → exit 0 + petunjuk daftar surface; tanpa --program → exit 2.
- **Batasan jujur v1.10.0:** planner hanya membaca candidate + memory_coverage yang sudah ada — surface dari recon (subfinder/httpx/katana) belum otomatis didaftarkan (pakai `--record` dulu); planner tidak memilih target run otomatis (rencana dibaca manusia, baru dijalankan manual); baseline live + oracle LLMVault tetap menunggu laptop Fahmi. Lanjut: v1.11 ingatan.

## [1.9.0] — 2026-11-23

### Added
- **v1.9 — otak BugHunter, tahap 1 dari "gas semuanya berurutan":**
  - **22 skill baru (index 67 → 89):** hunt-aspnet, hunt-cicd, hunt-clickjacking, hunt-cloud-misconfig, hunt-exceptional-conditions, hunt-fintech-graphql, hunt-grpc, hunt-html-injection, hunt-k8s, hunt-laravel, hunt-ldap, hunt-nextjs, hunt-ntlm-info, hunt-rag-vector, hunt-shadow-api, hunt-source-leak, hunt-spa-api, hunt-springboot, hunt-subdomain, hunt-tls-network, hunt-brute-force, hunt-captcha-bypass. Semua ditulis ulang dengan kata sendiri (adaptasi Claude-BugHunter MIT/CC-BY-4.0) + blok "Scope & larangan" + Gate-0. **hunt-brute-force dan hunt-captcha-bypass hanya dalam bentuk deteksi kontrol-hilang** (amati ada/tidaknya 429/lockout/CAPTCHA dengan akun test sendiri; menebak kredensial/OTP dan alat solver DILARANG di dalam skill).
  - **Pola bersitasi 85 → 124 (bersitasi 73 → 112, 21 skill):** 39 pola baru dari `docs/disclosed-reports/` upstream untuk 7 kelas yang tadinya kosong — hunt-idor 6, hunt-dom 6, hunt-jwt-crypto 5, hunt-mfa-bypass 5, hunt-cache-poison 5, hunt-http-smuggling 8, hunt-auth-bypass 4. Semua payout/tahun null (upstream tak menyebut tahun terverifikasi — tidak disalin). Satu ID (136169) tidak dihitung dua kali (sudah ada sebagai pola hunt-saml).
  - **Pendalaman 8 skill Tier-1:** hunt-oauth, hunt-ato, hunt-session, hunt-sqli, hunt-xss, hunt-ssrf, hunt-idor, hunt-graphql — masing-masing + seksi "## Pendalaman" (5 pola deteksi + 1 chain + 1 catatan Gate-0), isi lama tidak diubah.
  - **Perintah baru `bounty skills [--skill <nama>]`: ** daftar skill (tabel Skill/Kelas/CWE + total) atau tampilkan isi satu skill; tak dikenal → stderr + exit 2. Masuk COMMANDS (did-you-mean ikut mengenalinya).
  - **Perbaikan UI/UX dari PR #1 (sudah merge ke main, 2026-11-23 20:14 WIB):** warning SQLite disaring (hanya ExperimentalWarning sqlite), help dikelompokkan per seksi + deskripsi run/review diperbaiki, `bounty programs` tanpa label rangkap, Scope DITOLAK ke stderr via `printScope`, did-you-mean untuk perintah tak dikenal, petunjuk langkah berikutnya seragam di graphql/cloud/reverse/firmware, `phaseLine` dipakai, `progressBar` hormati `width`.
- **Batasan jujur v1.9.0:** 6 kelas tetap tanpa pola bersitasi (hunt-xss, hunt-nosqli, hunt-host-header, hunt-session, hunt-cors, hunt-websocket — upstream tidak menyebut ID H1 eksplisit untuk kelas-kelas itu); skill baru tetap ringkas (~40-70 baris, bukan 872 baris seperti upstream); pola baru hanya terverifikasi lewat sitasi upstream (bukan dibuka satu per satu di HackerOne, kecuali 3 spot-check lama); baseline live + oracle LLMVault tetap menunggu laptop Fahmi. Lanjut: v1.10 planner, v1.11 ingatan.

## [Unreleased]

### Added
- **`bounty setup` — wizard terpandu satu alur (berwarna di terminal).** Satu perintah menuntun: (1) cek prasyarat (Node/Strix), (2) provider → tipe/base-url/API key (input tidak di-echo) → deteksi + filter + pilih model, (3) target → host + template scope (seluruh situs / API saja / custom) + Budget/Rate/Roles (semua ada default), simpan ke `programs/<nama>.md`, (4) verifikasi scope in-process. Folder `programs/` dibuat otomatis; provider tersimpan tetap `0600` & tak pernah dilog. Warna nyala otomatis di TTY, mati saat di-pipe/`NO_COLOR`. Non-TTY tidak menggantung: minta `--yes` + flag atau keluar dengan panduan. Logika murni dipisah ke `bounty/lib/setup.js` (round-trip ke `parseProgram`, target verifikasi dijamin in-scope) — 11 test.
- **`bounty run` tanpa argumen (di terminal)** menampilkan daftar program tersimpan untuk dipilih nomor, lalu konfirmasi target (default = contoh in-scope). Non-TTY tetap memakai perilaku lama (tidak menggantung).
- **`ui.js`:** helper `heading` (tebal) + `hint` (redup) untuk wizard.

### Fixed
- **`summaryBox` tidak sejajar saat isi berwarna.** Sama seperti `table()`, lebar kotak dihitung dari panjang mentah termasuk kode ANSI sehingga garis tepi kanan bergeser bila isi diwarnai (dipakai kotak ringkasan `setup`/`run`). Lebar kini dari panjang tampak.
- **CLI UI/UX polish (hanya tampilan, perilaku hunt/scope/budget/store tidak berubah):**
  - **Warning SQLite tidak lagi bocor:** `ExperimentalWarning` dari `node:sqlite` disaring di `bounty/bin/bounty.mjs` sehingga perintah baca sederhana (`--version`, `findings`, `review`, `programs`) tidak lagi mengotori stderr/CI; warning lain tetap dicetak apa adanya.
  - **Teks `--help` dirapikan:** deskripsi yang salah tempat diperbaiki (penjelasan `run` tadinya muncul di bawah `view`; penjelasan `review` di bawah `trace`) dan perintah dikelompokkan per seksi (Setup, Alur inti, Recon & scan, dll.) agar mudah dipindai.
  - **`bounty programs`:** label "Program" tidak lagi bertumpuk tiga (judul manual dibuang, prefiks "Program:" pada nama di-strip agar tidak menduplikasi header kolom).
  - **Pesan gagal ke stderr:** "Scope DITOLAK" kini ditulis ke stderr (bukan stdout) di `run`/`scan`/`recon` dan diwarnai merah secara seragam lewat helper `printScope`.
  - **Perintah tak dikenal:** kini memberi saran "Maksud Anda ...?" (jarak edit) + daftar perintah singkat ke stderr, bukan membuang seluruh teks help.
  - **Petunjuk langkah berikutnya seragam:** `graphql`/`cloud`/`reverse`/`firmware` kini ikut menampilkan `Lihat antrean: bounty review | bounty findings` saat ada kandidat baru.
  - **`phaseLine` dipakai** di baris budget `bounty run` (sebelumnya helper ini tak terpakai di CLI); `progressBar` menghormati parameter `width` saat `total <= 0`.
  - **Bug: `bounty run` tunggal yang ditolak scope gate exit 0 (bukan 2).** `runSingleTarget` mengembalikan angka telanjang `2` di jalur scope-ditolak, sedangkan `cmdRun` membaca `r.code` → `undefined` → exit 0. Kini mengembalikan bentuk hasil `{code,...}` yang benar sehingga target di luar scope exit 2 (gate gagal = gagal, bukan sukses diam-diam).
  - **Bug: `bounty graph-gate` melempar `ReferenceError` tiap jalan (ditelan try/catch).** `listCoverage` dipakai tapi tidak di-import, jadi statistik `openCoverage`/`totalFindings`/`untracedFindings` tidak pernah terisi dan 3 dari 4 sinyal gate diabaikan diam-diam. Import diperbaiki.
  - **Bug: tabel `findings`/`review` tidak sejajar di terminal berwarna.** `table()` menghitung lebar kolom dari panjang string mentah termasuk kode ANSI, sehingga sel berwarna (badge severity) menggeser kolom berikutnya. Lebar kini dihitung dari panjang tampak (kode ANSI diabaikan); output pipe/non-warna tidak berubah.

## [1.8.0] — 2026-11-23

### Added
- **v1.8 — CLI dibagusin + lebih mudah dipahami:**
  - **`bounty/lib/ui.js` (baru, zero-dep):** `colorsEnabled` (mati bila `NO_COLOR` / `BOUNTY_NO_COLOR=1` / output di-pipe — log tetap bersih), `color` (red/green/yellow/cyan/dim/bold ANSI), `severityColor` + `severityBadge` (label Indonesia `[KRITIS]`/`[TINGGI]`/`[SEDANG]`/`[RENDAH]`/`[INFO]`), `table` (kolom rata kiri), `progressBar` (`[████░░] n/N`), `summaryBox` (kotak ringkasan `┌┐└┘│─`), `phaseLine` (`▸ Fase: detail`), `formatUsd` (`$5.00`). 15 test.
  - **Disambung ke CLI:** `bounty run` — Scope OK/DITOLAK berwarna + kotak "Ringkasan run" (temuan, kandidat baru masuk store, duplikat, biaya vs budget, status); `bounty run --targets` — progress bar per target + kotak "Ringkasan antrean"; `bounty programs` / `bounty findings` / `bounty review` — tabel sejajar + badge severity + baris total; approve hijau, reject kuning, tidak ditemukan merah. Semua teks lama dipertahankan sebagai substring (tes lama tetap hijau; warna mati total bila non-TTY).
- **Batasan jujur v1.8.0:** tampilan baru belum pernah dilihat di terminal sungguhan (hanya output pipe di VM — warna aktif hanya di TTY); tidak ada perubahan perilaku hunt/scope/budget/store — hanya tampilan.

## [1.7.0] — 2026-11-23

### Added
- **v1.7 — semua P2 deep research (P2-1 s.d. P2-6), berurutan:**
  - **P2-1 Firmware ringan:** `bounty/lib/firmware.js` — `bounty firmware --tool binwalk-ng|unblob|cve-bin-tool --file <image>` (binwalk-ng 4.0, unblob 26.6.4, cve-bin-tool 3.4; file lokal saja, timeout 600 dtk, CVE → temuan "Known CVE in Firmware Component" dengan severity dari CVSS, bukti reachability wajib manual). EMBA sengaja TIDAK di-wire (14–25 jam/image, ~20 GB Docker — opt-in semalam, lihat `docs/firmware.md`). 8 test.
  - **P2-2 DVLAA:** `eval/benchmarks/dvlaa.md` + `eval/dvlaa-export.mjs` (`npm run dvlaa-export`) — DVLAA (Damnn Vulnerable LLM and Agent Application, Tcotl/DVLAA, 81 tantangan: 24 OWASP LLM + 10 Agent + 11 gabungan + 30 AWDP + 6 model-poisoning; skor = Flag per tantangan via UI). Eksportir memakai format kompatibel EthiBench + petunjuk `challenge` (LLM01/ASI02/AWDP07) — **best-effort, bukan format resmi** (DVLAA tidak mendefinisikan format pengiriman temuan). Lisensi DVLAA **Unknown** — jalankan sebagai lab saja, jangan vendor kodenya. 5 test.
  - **P2-3 Promptfoo CI gate:** `bounty/lib/promptfoo-gate.js` — `bounty promptfoo-gate --results <hasil.json> [--min-pass-rate 0.8]` (fail-closed: tanpa hasil/kunci = gagal, bukan lolos) + `eval/promptfoo/promptfooconfig.yaml` (6 kasus harness llm-app + bagian redteam) + `docs/promptfoo-gate.md`. Langkah CI-nya dipasang lewat web UI (workflow tidak bisa lewat API). 6 test.
  - **P2-4 Graph gate:** `bounty/lib/graph-gate.js` — `bounty graph-gate [--baseline eval/results/baseline.json]` (keputusan upgrade graf/memori: "upgrade" hanya bila baseline membuktikan planning/state adalah bottleneck — sinyal tp-down ≥2 lab, FP berulang ≥3 kelas, open-coverage ≥5, temuan tanpa chain >50%; tanpa baseline jawabannya selalu "tetap SQL") + `eval/benchmarks/graph-gate.md`. 5 test.
  - **P2-5 WiFi/C2 do-not-build:** dikunci di kode — `KL_DENYLIST` di `bounty/lib/guard.js` kini menolak `wifite`, `aircrack`, `bettercap`, `sliver`, `covenant`, `mythic`, `cobalt-strike` + `docs/p2-wifi-c2.md` (alasan: di luar scope bounty, risiko hukum, merusak janji ringan). 8 test.
  - **P2-6 Installer pdtm/go/pipx:** `scripts/install-tools.sh` (mode rencana = default, `--yes` baru menjalankan; `--pd-only`/`--go-only`/`--python-only`; pdtm + 5 tool PD, `go install` jsluice + interactsh-client, `pipx install` garak + pyrit) + `docs/install-tools.md`. Winget resmi **masih belum live** — skrip ini jalur yang didukung. 6 test.
- **Batasan jujur v1.7.0:** tidak ada satu pun runner P2 yang pernah jalan live (binary tidak ada di VM — flag CLI + bentuk output best-effort, verifikasi `--help` masing-masing di laptop); DVLAA belum pernah jalan (butuh laptop, RAM 8 GB+ disarankan); promptfoo belum pernah jalan live (butuh provider key); graph gate belum pernah memutuskan "upgrade" (baseline belum ada); baseline live P0-1 + oracle LLMVault tetap menunggu laptop.

## [1.6.0] — 2026-11-23

### Added
- **v1.6 — semua P1 deep research (P1-1 s.d. P1-7), berurutan:**
  - **P1-1 GraphQL recovery:** `bounty/lib/graphql.js` — `bounty graphql --target URL [--field user]` (fingerprint, introspeksi, rebuild schema gaya clairvoyance bila introspeksi dimatikan, tes BOLA/alias/batching; schema hasil tebakan ditandai partial). 11 test.
  - **P1-2 Cloud enum + takeover:** `bounty/lib/cloud.js` — `bounty cloud --tool takeover|cloud-enum|s3scanner|aws-s3-ls|nuclei-takeovers` (17 fingerprint layanan, cloud_enum, s3scanner, `aws s3 ls --no-sign-request`, nuclei `http/takeovers/`). Tanpa kredensial, tanpa klaim — fingerprint wajib verifikasi manual. Prowler sengaja TIDAK di-wire (opt-in berkredensial). 12 test.
  - **P1-3 RE runner headless gated:** `bounty/lib/reverse.js` — `bounty reverse --tool ghidra-mcp|rea|jadx --file <binary/APK> --confirm true` (GhidraMCP 2.0 pin Ghidra 12.1.4, REA 6.8.0, jadx APK; file lokal + konfirmasi operator wajib; nilai secret tidak masuk temuan) + `eval/benchmarks/crackmebench.md`. 10 test.
  - **P1-4 Mobile statis:** `bounty/lib/mobile.js` — `bounty scan --tool mobsf|jadx` (MobSF REST upload/scan/report_json, image kanonik `opensecurity/mobile-security-framework-mobsf:4.5.3`, auth header = kunci mentah bukan Bearer; jadx + parse manifest). Frida/Objection dinamis TIDAK di-wire. 10 test.
  - **P1-5 Strix parity:** `bounty run --fail-on low|medium|high|critical` (exit 3 bila temuan ≥ ambang; severity heuristik dari kelas vuln, bukan CVSS), `--pause` (state jeda `.bounty/pause-<ts>.json`, exit 4) + `--resume <file>`, HTTP evidence ID (request-id Strix/Caido disimpan sebagai evidence kandidat), per-run timings (`BOUNTY_RECORD_TIMINGS=1` → `.bounty/timings.jsonl`), `bounty dedup` (validasi kunci kanonik), `bounty codesearch --dir --pattern` (ripgrep bila ada, fallback jalan kaki file). 5 test.
  - **P1-6 Enterprise identity skills:** 6 skill baru (Entra/M365, Okta, vCenter, SSL-VPN, SharePoint ToolShell, Cloud IAM) — hanya CVE publik terverifikasi (vCenter 2024-37079/37080/38812, 2025-22224/22225/22226; Fortinet 2024-21762/55591, 2023-27997; Palo Alto 2024-3400/5910; Citrix 2023-3519/4966; SharePoint ToolShell 2025-53770/53771/49704/49706). Index skill 61 → **67**.
  - **P1-7 Caido MCP live:** `bounty/lib/caido.js` + `docs/caido.md` — `bounty caido --list [--filter Q] | --replay <id>` (read/replay saja, nama tool diselesaikan adaptif dari `tools/list`). 9 test.
- **Batasan jujur v1.6.0:** tidak ada satu pun runner P1 yang pernah jalan live (binary tidak ada di VM — flag CLI + bentuk output best-effort, verifikasi di laptop); paket npm `@caido/mcp-server` mengembalikan 404 (23 Nov 2026) — jalur terverifikasi = clone `caido/mcp-caido` + `node dist/index.js` via `--mcp-path`; image MobSF `opensecurity/mobsf:v4.5.3` tidak ada di Docker Hub (pakai `opensecurity/mobile-security-framework-mobsf:4.5.3`); pin MobSF 4.5.3 mendahului publikasi CVE-2026-104585 — jangan asumsikan sudah ditambal; baseline live P0-1 + oracle LLMVault tetap menunggu laptop. Bug ketemu saat integrasi: `cmdPatterns` kehilangan baris `loadPatterns()` saat edit (diperbaiki, test 311/311). **Perbaikan pasca-push:** CI run #20 gagal karena gitleaks menemukan 2 literal palsu di `tests/mobile.test.js` (baris 20, 225) — fixture kini dibangkitkan runtime (SHA-256 deterministik, tanpa literal mirip kunci) + `.gitleaks.toml` mengecualikan file itu (hanya karena commit `3a9ec32` menyimpan literal lama di histori; CI memindai histori penuh).

## [1.5.0] — 2026-11-23

### Added
- **v1.5 — semua P0 deep research (P0-2 s.d. P0-7), berurutan:**
  - **P0-2 pola bersitasi:** `bounty/data/report-patterns.json` 12 → **85 pola (73 bersitasi)** dari `docs/disclosed-reports` Claude-BugHunter (CC-BY-4.0, atribusi di `patterns.js`); tiap pola pakai link `hackerone.com/reports/<id>` yang disalin dari contoh bernama upstream, 3 dicek live (2262382, 745324, 925585). 14 skill kini punya ≥4 pola bersitasi (bonus router +0,15 penuh). `bounty patterns [--skill X]` tampilkan hitungan + link. Jujur: 71 pola `payout`/`tahun` null (upstream tidak menyebut tahun terverifikasi — tidak disalin); pola untuk skill lain (xss, idor, jwt-crypto, mfa-bypass, dsb.) belum ada karena upstream tidak mencantumkan ID H1 bernama di contohnya.
  - **P0-3 recon pipeline:** `bounty/lib/recon.js` — `bounty recon --tool subfinder|dnsx|httpx|katana|nuclei-kev|crtsh` + `bounty recon --update-templates` (nuclei KEV subset, `-tags kev`). Scope gate host-only untuk enum domain. Flag CLI PD best-effort (binary tidak ada di VM).
  - **P0-4 JS mining:** `bounty/lib/jsmining.js` — `bounty scan --tool jsluice|sourcemapper`; nilai secret TIDAK PERNAH masuk kandidat/store (hanya jenis + catatan).
  - **P0-5 OAST:** `bounty/lib/oast.js` — `bounty oast start|poll|stop` (interactsh-client, server self-hosted via `INTERACTSH_SERVER`, token tidak pernah masuk objek sesi/log).
  - **P0-6 LLM 2026:** `skills/bounty/hunt/hunt-llm-2026.md` (OWASP LLM Top 10 2026: LLM01–LLM10) + `hunt-llm-agentic.md` (ASI01–ASI10), `bounty/lib/llm-runners.js` (`bounty scan --tool garak-agent-breaker|pyrit`, Crescendo/TAP), `eval/benchmarks/llmvault.md` (verifikasi oracle Play Mode 25 flag = langkah laptop). Index skill 59 → 61.
  - **P0-7 platform read-only:** `bounty/lib/platforms.js` — `bounty platform scope|hacktivity|draft|sync-scope` (HackerOne/Bugcrowd, token hanya dari env, tanpa satu pun jalur submit/pembayaran; `draft` = Markdown bertanda DRAFT, kirim manual). Hacktivity H1 via feed publik (best-effort, tanpa REST resmi); Bugcrowd tanpa pencarian laporan publik.
- **Batasan jujur v1.5.0:** semua runner baru belum pernah jalan live (binary tidak ada di VM — flag CLI best-effort, perlu `strix --help`/cek binary di laptop); baseline live P0-1 tetap menunggu laptop; oracle LLMVault tetap belum terverifikasi.

## [1.4.0] — 2026-11-23

### Added
- **v1.4 — Baseline pack P0-1 (dari deep research gap report):**
  - **`eval/benchmarks/xben.md`:** prosedur XBEN (usestrix/benchmarks, 104 tantangan) — setup Poetry, `run_infer.py`, subset 10 tantangan yang disarankan untuk sinyal awal, angka acuan Strix v0.4.0 (100/104, ~$3,37/tantangan — angka upstream, bukan angka kita), aturan jujur (model/budget/daftar tantangan sama, 3 run, median).
  - **`eval/benchmarks/ethibench.md`:** prosedur EthiBench (108 GT: vuln-bank 60, paygoat 28, xben-090 20) — versi yang dipatok (vuln-bank `b1962823` + patch de-hinting, paygoat `69589b4`), angka acuan paper (Claude Code recall +18,83% vs Strix), aturan jujur.
  - **`eval/ethibench-export.mjs`:** eksportir temuan → `findings.jsonl` EthiBench (`run_<n>/<target>/findings.jsonl`, field title/description/steps/cwe/severity/url) + 4 test baru.
  - **`scripts/baseline-laptop.sh` (+ `npm run baseline:laptop`):** satu perintah di laptop — cek prasyarat (Docker, Strix, Node ≥ 24, Python, Poetry, pipx), lab lokal 3 run, lalu panduan XBEN + EthiBench. Keluar 2 bila prasyarat hilang (terverifikasi di VM: exit 2, Docker/Strix/Poetry/pipx tidak ada — bukan mock diam-diam).
- **Batasan jujur v1.4.0:** baseline LIVE tetap belum pernah jalan — semua langkah live butuh laptop Fahmi (Docker + Strix + model). Pack ini hanya membuat baseline itu siap dijalankan, bukan menjalankannya.

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
