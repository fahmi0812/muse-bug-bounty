# LLMVault — verifikasi oracle llm-app (P0-6, langkah LAPTOP)

Oracle `eval/oracle/labels/llm-app.json` (6 vuln, endpoint `/chat` +
`/tools/execute`) ditulis untuk placeholder lama dan **BELUM
terverifikasi** terhadap rute LLMVault yang sebenarnya. Dokumen ini
menjelaskan cara memverifikasinya di laptop — **bukan di VM, dan
bukan dikerjakan di sini**.

## Yang sudah terverifikasi dari README upstream (23 Nov 2026)

- LLMVault v2.0, CyberSunil/LLMVault, MIT, ★363.
- **Play Mode: 25 lab, 3 tier** — 10 Core (satu per kategori OWASP LLM
  Top 10 **2025**), 10 Advanced multi-turn, 5 Expert.
  Asistennya scripted, flag deterministik (reproduce setiap kali).
- **Live Mode:** model nyata lokal via Ollama (`qwen2.5:3b-instruct`,
  ~2 GB, CPU cukup); secret baru tiap sesi; 3 skenario (prompt
  injection, indirect injection via gambar, output handling).
- **Jalan:** `docker compose up --build` lalu buka
  `http://127.0.0.1:5000` (Flask/gunicorn). Atau
  `pip install -r requirements.txt && python app.py`.
- **Jangan expose ke internet** — sengaja rentan, lab lokal saja.
- **Tier Expert terenkripsi** (`challenges/expert.enc`, Fernet) —
  isinya tidak tercantum di README; kunci dipegang operator
  (CyberSunil) dan diberikan manual setelah kartu penyelesaian
  dibagikan. Jangan klaim isi Expert tanpa membuka tier itu.
- **Peta Core (penomoran 2025 — WAJIB ditranslasi ke 2026):**

  | Lab | Teknik | 2025 | 2026 |
  |---|---|---|---|
  | The Obedient Assistant | direct instruction override | LLM01 | LLM01 Prompt Injection |
  | Redaction Theater | output-filter bypass via encoding | LLM02 | LLM02 Sensitive Information Disclosure |
  | Trust the Manifest? | typosquatted / unsigned dependency | LLM03 | LLM04 Supply Chain |
  | The Sleeper Phrase | poisoned-data backdoor trigger | LLM04 | LLM05 Data and Model Poisoning |
  | Rendered Without Question | unsanitised output → injection | LLM05 | LLM10 Improper Output Handling |
  | Keys to the Kingdom | over-permissioned tool, no authz | LLM06 | LLM03 Excessive Agency |
  | Loose Lips | secret leaked from system prompt | LLM07 | LLM08 Hidden Context Exposure |
  | Retrieval Without Borders | RAG retrieval ignores ACLs | LLM08 | LLM09 Vector and Embedding Weaknesses |
  | The Yes-Man | sycophancy / false authority | LLM09 | LLM07 Misinformation |
  | Denial of Wallet | runaway generation + leaky error | LLM10 | LLM06 Unbounded Consumption |

  Lab Advanced (multi-turn: Roleplay Unchained, Death by a Thousand
  Hints, Confused Deputy, Crossed Wires, The Oracle, dll.) dan Expert
  TIDAK dipetakan di sini — petakan saat verifikasi live, jangan
  tebak dari nama labnya saja.

## Langkah verifikasi (laptop)

1. Clone + jalankan lab (profile `llm` di `eval/docker-compose.yml`
   sudah mem-build dari repo resmi; port `127.0.0.1:8000:5000`):
   ```text
   docker compose -f eval/docker-compose.yml --profile llm up -d --build llm-app
   ```
2. Buka `http://127.0.0.1:8000`, mainkan **tiap lab Play Mode**
   (Core 10 dulu, lalu Advanced 10), catat per lab:
   - URL/route sebenarnya yang dipakai lab (apakah `/chat` dan
     `/tools/execute` benar ada? catat route aslinya bila beda),
   - flag mana yang terpicu dan teknik apa yang memicunya,
   - kelas OWASP 2026-nya (pakai tabel di atas, bukan nomor 2025).
3. Update `eval/oracle/labels/llm-app.json`: ganti endpoint dengan
   route asli, tambah/ubah vuln sesuai flag yang terpicu, hapus
   vuln yang tidak bisa dipicu di Play Mode. Perbarui juga
   `programs/llm-app.md` (Allowed path + catatan).
4. Jalankan garak + deepteam (sudah ada di `bounty/lib/runners.js`)
   dan runner baru `bounty/lib/llm-runners.js` (garak agent-breaker,
   PyRIT Crescendo/TAP) ke lab, lalu hitung **pass rate**: berapa
   dari 25 flag Play Mode yang terdeteksi sebagai kandidat.
5. Bila route/oracle berubah, jalankan ulang `npm run bench` dan
   catat angka llm-app yang baru — angka lama (mock) tidak berlaku
   lagi setelah oracle berubah.

## Aturan jujur

- Jangan klaim angka bench llm-app sebelum langkah 2–3 selesai.
- Jangan tulis route LLMVault dari tebakan — hanya dari yang
  terlihat live di laptop.
- Tier Expert tidak bisa diverifikasi tanpa kunci operator; bila
  tidak dibuka, catat "Expert: belum diverifikasi" — bukan 0/5.
- Live Mode (model nyata) tidak punya flag deterministik — jangan
  pakai untuk oracle; Play Mode yang jadi oracle.
