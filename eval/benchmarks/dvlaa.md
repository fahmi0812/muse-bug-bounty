# DVLAA — eval LLM agentic (P2-2, langkah LAPTOP)

DVLAA dipakai sebagai eval agentic **setelah** oracle LLMVault Play
Mode terverifikasi (`eval/benchmarks/llmvault.md` dulu, DVLAA
kemudian). Dokumen ini menjelaskan cara menjalankannya di laptop —
**bukan di VM, dan bukan dikerjakan di sini**.

## Yang sudah terverifikasi dari README upstream (23 Nov 2026)

Sumber utama: https://github.com/Tcotl/DVLAA (README, dibaca
23 Nov 2026; commit `81d1d60`, repo dibuat 2026-07-23, ★51,
14 commit). Ringkasan kedua:
https://trove.briskstack.com/r/a0d23cd9-b252-427a-aef6-60d3d84a99a0
(dibaca 23 Nov 2026).

- **DVLAA = Damn Vulnerable LLM and Agent Application** — lab
  keamanan LLM/agent lokal (Flask), "DVWA untuk LLM/agent".
  Meliputi OWASP LLM Top 10 + Agent Security Top 10.
- **81 tantangan:** 24 sub-tantangan OWASP LLM + 10 skenario Agent
  + 11 soal gabungan + 30 AWDP + 6 soal nyata model-poisoning
  (24+10+11+30+6 = 81).
- **Penilaian = Flag per tantangan.** Tiap tantangan diverifikasi
  state-machine: Flag hanya diterima bila respons JSON server yang
  rentan benar-benar mengembalikan Flag sesi saat itu. Tidak ada
  penilaian kata kunci atau status frontend.
- **AWDP (Attack With Defense Patch), 30 soal:** tiap soal punya
  fase serang DAN fase bertahan (kirim patch `.tar.gz` berisi
  `update.sh` + file yang diperbaiki; platform TIDAK menjalankan
  shell sembarangan — hanya operasi `cp`/`mv`/`rm` yang diizinkan;
  verifikasi dua tahap: cek kontrak statis, lalu regresi ganda —
  vuln harus terblokir DAN fungsi bisnis tetap jalan).
  - AWDP01–10 memetakan CVE publik (Dify, RAGFlow, Langflow,
    Flowise, Open WebUI, n8n) — CVE/NVD/GHSA hanya menjelaskan
    root cause; Flag dan rantai serang dibuat lokal, tidak pernah
    menyentuh upstream. Peta yang tercantum di README:
    AWDP02 Dify CVE-2024-10252, AWDP03 RAGFlow CVE-2024-53450,
    AWDP04 Langflow CVE-2024-48061, AWDP05 Flowise CVE-2024-8181,
    AWDP06 Dify CVE-2025-32790, AWDP07 Open WebUI CVE-2024-30256,
    AWDP08 Dify CVE-2025-0185, AWDP09 RAGFlow CVE-2025-25282,
    AWDP10 n8n CVE-2025-52554.
  - AWDP11–30 adaptasi dari 2026 China (Guangxi)–ASEAN AI
    Security Competition, track AI Agent (match_1443).
  - Dua track per soal: simulasi (default, tanpa dependensi) dan
    reproduksi nyata (opsional, tarik container resmi upstream).
- **6 soal nyata model-poisoning (REAL01–REAL06):** adapter
  forensik, pickle, output-layer, preprocess fingerprint, REAL05
  Web penuh (RAG poisoning + tool_call injection), LoRA merge gate.
- **Model:** lokal, Ollama, SiliconFlow, OpenAI-Compatible
  (dikonfigurasi di halaman Model Management; API key hanya
  ditampilkan bermasker).
- **Jalan:** `git clone https://github.com/Tcotl/DVLAA.git` lalu
  `./install.sh` (membuat network `dvlaa-net`, build image,
  start target simulasi AWDP + gateway nginx port 5080, tunggu
  `/health`). Atau manual Docker, atau lokal
  (`pip install -r requirements.txt && python -m dvlaa`).
- **Prasyarat (README):** Python 3.11+, Docker 24.0+, RAM
  minimum 4 GB, direkomendasikan 8 GB+; track reproduksi nyata
  Dify disarankan 16 GB. Lebih berat dari LLMVault — jangan
  jalankan bersamaan dengan lab lain di laptop yang sama.
- **Akses:** `http://127.0.0.1:5080/` (gateway tunggal).
  Login default yang tercantum di README: `admin` /
  `DVLAA2026+` — **ganti password ini saat deploy di laptop**
  (bisa lewat env `DVLAA_ADMIN_USERNAME` /
  `DVLAA_ADMIN_PASSWORD`); jangan biarkan default di mesin
  yang terhubung jaringan.
- **Jangan expose ke internet** — sengaja rentan, lab lokal saja.
- **Lisensi: TIDAK TERVERIFIKASI.** Daftar file root repo
  (23 Nov 2026) tidak menampilkan file LICENSE, dan daftar
  radar independen mencatat lisensi DVLAA sebagai "Unknown".
  Akibatnya: jalankan sebagai lab saja, **jangan vendor atau
  salin kode DVLAA** ke repo ini sampai lisensinya jelas.

## Yang TIDAK ada di DVLAA (jujur)

DVLAA adalah **training range, bukan benchmark harness** seperti
XBEN/EthiBench. Yang tidak ditemukan di README upstream
(23 Nov 2026):

- **Tidak ada format pengiriman temuan agen** (tidak ada
  `findings.jsonl`, tidak ada skema JSON temuan, tidak ada API
  submit hasil). Satu-satunya "hasil" yang diakui platform
  adalah Flag per tantangan yang disubmit lewat UI web.
- **Tidak ada runner eval otomatis / CLI scorer.** Tidak ada
  perintah "jalankan agen X terhadap semua tantangan dan cetak
  skor". Penilaian dilakukan manusia (atau agen) yang memainkan
  tiap tantangan dan mengumpulkan Flag.
- **Tidak ada angka acuan agen lain** di README (tidak ada skor
  Strix/Claude/dll. atas DVLAA).

Karena itu `eval/dvlaa-export.mjs` memakai format
**kompatibel EthiBench** (field `title`/`description`/`steps`/
`cwe`/`severity`/`url`) ditambah field `challenge` (petunjuk
tantangan DVLAA yang relevan, mis. `LLM01`, `ASI02`, `AWDP07`).
Format ini **best-effort, bukan format resmi DVLAA** — ia hanya
jembatan agar temuan bisa dinilai (manual atau LLM-judge)
terhadap tantangan DVLAA. Jangan klaim DVLAA "menerima" file
ini.

## Cara menjalankan eval (laptop)

1. Verifikasi dulu oracle LLMVault Play Mode
   (`eval/benchmarks/llmvault.md`). DVLAA hanya setelah itu.
2. Clone + jalankan DVLAA:
   ```text
   git clone https://github.com/Tcotl/DVLAA.git
   cd DVLAA
   ./install.sh
   ```
   Tunggu `/health` di `http://127.0.0.1:5080/health`.
   Ganti password admin default.
3. Pilih subset awal **10 tantangan** (sinyal pertama, bukan
   81 sekaligus — 81 tantangan multi-turn itu mahal):
   LLM01 (prompt injection), LLM02 (sensitive disclosure),
   LLM05 (data/model poisoning), LLM08 (hidden context),
   ASI02 (tool misuse), ASI05 (unexpected code execution),
   AWDP02 (Dify prompt injection), AWDP05 (Flowise auth
   bypass), AWDP07 (Open WebUI SSRF), REAL05 (RAG poisoning +
   tool_call injection). Jalankan subset yang SAMA untuk
   baseline dan bounty.
4. Jalankan agen (baseline Strix tanpa skill, lalu bounty
   dengan skill) terhadap tiap tantangan di subset; catat
   Flag yang berhasil diambil per tantangan.
5. Ekspor temuan agen ke JSONL DVLAA:
   ```text
   node eval/dvlaa-export.mjs --in findings.json --target dvlaa --run 1 --out eval/results/dvlaa
   ```
   File: `eval/results/dvlaa/run_<n>/dvlaa/findings.jsonl`.
6. Skor = **Flag didapat / tantangan di subset** (mis. 6/10),
   plus biaya dan waktu per tantangan. Bandingkan baseline vs
   bounty pada model, budget, dan daftar tantangan yang sama.

## Aturan jujur

- Model, budget, dan daftar tantangan **sama** di kedua sisi;
  3 run, ambil median.
- Satu Flag = satu tantangan lolos. Temuan tanpa Flag yang
  terverifikasi TIDAK dihitung sebagai lolos.
- Field `challenge` di JSONL adalah petunjuk pemetaan kelas
  vuln → tantangan; penilai (manusia/LLM-judge) yang
  memutuskan apakah temuan itu benar menjawab tantangannya.
- Track AWDP "reproduksi nyata" (container upstream) opsional
  dan berat — subset awal memakai track simulasi saja.
- Jangan laporkan skor DVLAA sebelum satu run live selesai di
  laptop. Tidak ada angka DVLAA untuk tool ini saat ini.
