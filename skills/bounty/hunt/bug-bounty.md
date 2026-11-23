# bug-bounty — Orkestrator bug bounty (urutan hunt, kapan berhenti, kapan lapor)

Kelas: Methodology / Orchestration | CWE: — | OWASP: —

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan kirim laporan tanpa bukti replay; jangan klaim dampak yang belum dibuktikan.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Urutan hunt
1. Baca program: scope, peran, budget, larangan.
2. Recon (web2-recon): peta endpoint + parameter + peran.
3. Auth dulu: session, oauth, forgot-password, lalu otorisasi (IDOR/BOLA).
4. Injection: sqli, nosqli, lfi, xss, lalu api-misconfig.
5. Logika bisnis: harga, kuota, status, urutan langkah.
6. Validasi tiap kandidat dengan Gate-0 sebelum masuk antrean review.

## Kapan berhenti
- Budget habis, rate limit kena, atau permukaan sudah tertutup semua.
- Tiga kandidat berturut-turut ditolak reviewer sebagai bukan temuan.
- Target merespons sama untuk semua variasi (tidak ada sinyal).

## Kapan lapor
- Ada replay dari nol dalam 10 menit dengan akun test.
- Dampak jelas: akun/data/uang korban, bukan teori.
- Evidence lengkap: request, respons, langkah replay, redaksi sensitif.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Hunt tanpa urutan membuang budget di permukaan yang sama; laporan tanpa bukti membuang waktu reviewer.

## Verifikasi
- Tiap laporan punya langkah replay yang sudah dijalankan dua kali.
- Simpan ringkasan hunt: permukaan tertutup, kandidat, verdict.
