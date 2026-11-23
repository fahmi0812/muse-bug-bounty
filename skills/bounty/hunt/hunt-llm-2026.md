# hunt-llm-2026 — OWASP LLM Top 10 2026 (remap dari 2025)

Kelas: LLM Security | CWE: CWE-74, CWE-200, CWE-20, CWE-400 | OWASP Top 10 for LLM Applications 2026 (LLM01–LLM10)

Dipetakan dari OWASP Top 10 for LLM Applications 2026, OWASP GenAI Security Project (CC BY-SA 4.0) — dirilis 3–4 Agu 2026. Skill lama `hunt-llm-ai.md` memakai penomoran 2025; skill ini menggantikannya sebagai peta terbaru.

## Pemetaan 2025 → 2026 (8 dari 10 pindah nomor, 1 diganti nama)
- LLM01:2026 Prompt Injection (tetap 1)
- LLM02:2026 Sensitive Information Disclosure (tetap 2)
- LLM03:2026 Excessive Agency (naik dari 6)
- LLM04:2026 Supply Chain (dari 3)
- LLM05:2026 Data and Model Poisoning (dari 4)
- LLM06:2026 Unbounded Consumption (naik dari 10)
- LLM07:2026 Misinformation (dari 9)
- LLM08:2026 Hidden Context Exposure (dari 7, dulu "System Prompt Leakage" — diperluas: bukan cuma system prompt, tapi semua konteks tersembunyi)
- LLM09:2026 Vector and Embedding Weaknesses (dari 8)
- LLM10:2026 Improper Output Handling (turun dari 5; kini termasuk ANSI escape ke terminal dan gambar Markdown yang mengekstrak data lewat URL)

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high), hanya aplikasi lab atau aplikasi yang kamu miliki / diizinkan menguji.
- Jangan paksa model membocorkan data pengguna lain; uji hanya dengan data akun test sendiri.
- Berhenti saat kena rate limit / 429 — jangan brute force. Jangan uji model pihak ketiga yang tidak memberi izin.

## Detection pattern
- LLM01: instruksi di konten pengguna (dokumen, komentar, nama file, gambar, audio) diikuti model sebagai perintah.
- LLM02: jawaban model menyingkap potongan prompt sistem, konteks tersembunyi, atau data akun test lain.
- LLM03: tool yang dipanggil model punya izin lebih luas dari yang dibutuhkan tugas pengguna.
- LLM04: model/adapter/dataset/plugin pihak ketiga tanpa tanda tangan atau hash yang bisa diverifikasi.
- LLM05: pemicu tertentu mengubah jawaban model (backdoor data latih / RAG yang diracuni).
- LLM06: input besar / rantai tool call membuat biaya atau waktu meledak tanpa batas.
- LLM07: jawaban model salah tapi percaya diri, tanpa grounding ke sumber terverifikasi.
- LLM08: prompt sistem, kunci, atau instruksi internal bocor lewat jawaban, error, atau metadata.
- LLM09: RAG mengembalikan dokumen di luar hak akses akun test (lintas pengguna/tenant).
- LLM10: output model dirender/dieksekusi mentah (HTML, query, perintah) tanpa sanitasi.

## Cara menguji
- Sisipkan instruksi netral di konten akun test, lihat apakah model menuruti (LLM01).
- Minta model merangkum data akun test lain — harus ditolak bila bukan milikmu (LLM02/LLM09).
- Periksa izin tool: bisakah tool dipakai untuk aksi di luar peran akun test? (LLM03).
- Kirim input raksasa / rantai tool berulang, lihat apakah ada batas biaya yang trip (LLM06).
- Amati apakah output model dirender tanpa sanitasi di halaman hasil (LLM10).

## Chain template
Konten tak tepercaya masuk konteks → model menuruti / membocorkan → output atau tool merugikan akun test → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Konten pengguna diperlakukan sebagai instruksi; konteks tersembunyi tidak dipisah dari data; output model dipercaya mentah; tool diberi izin berlebih; RAG tidak menegakkan ACL.

## Verifikasi
- Replay dengan akun test lain harus ditolak bila data bukan miliknya.
- Simpan prompt + jawaban + langkah replay, redaksi isi sensitif.
- Cocokkan temuan ke nomor LLM 2026 di atas (bukan 2025) saat menulis laporan.
