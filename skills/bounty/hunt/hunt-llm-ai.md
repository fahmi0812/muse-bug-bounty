# hunt-llm-ai — LLM / AI security (prompt injection, tool, output)

Kelas: LLM Security | CWE: CWE-74, CWE-20 | OWASP LLM Top 10 2025 (LLM01, LLM02, LLM05, LLM06, LLM07)

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan paksa model membocorkan data pengguna lain; uji hanya dengan data akun test sendiri.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Instruksi di dalam konten pengguna (dokumen, komentar, nama file) diikuti model sebagai perintah.
- Jawaban model menyingkap potongan prompt sistem atau data akun test lain.
- Output model diteruskan mentah ke halaman, query, atau perintah lain.
- Tool yang dipanggil model punya izin lebih luas dari yang dibutuhkan pengguna.

## Cara menguji
- Sisipkan instruksi netral di konten akun test, lihat apakah model menuruti.
- Minta model merangkum data akun test lain (harus ditolak bila bukan milikmu).
- Amati apakah output model dirender tanpa sanitasi di halaman hasil.
- Periksa izin tool: bisakah tool dipakai untuk aksi di luar peran akun test?

## Chain template
Injection lewat konten → model menuruti instruksi penyerang → output/tool merugikan akun test → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Konten pengguna diperlakukan sebagai instruksi; output model dipercaya mentah; tool diberi izin berlebih.

## Verifikasi
- Replay dengan akun test lain harus ditolak bila data bukan miliknya.
- Simpan prompt + jawaban + langkah replay, redaksi isi sensitif.
