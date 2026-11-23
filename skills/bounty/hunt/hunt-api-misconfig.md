# hunt-api-misconfig — API misconfiguration (konfigurasi API yang longgar)

Kelas: Security Misconfiguration | CWE: CWE-1188, CWE-200 | OWASP: A05:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan ubah data pengguna lain, jangan ambil data massal.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Endpoint mengembalikan field lebih banyak dari yang dipakai UI (data berlebih).
- Versi API lama masih aktif dan membolehkan akses yang versi baru tolak.
- Header keamanan hilang (tanpa proteksi konten, tanpa batas rate).
- Error detail menyingkap nama layanan, versi, atau struktur internal.

## Cara menguji
- Bandingkan respons API dengan yang dirender UI; catat field berlebih.
- Coba versi API lama yang disebut di dokumentasi atau bundle JS.
- Coba panggil endpoint sensitif tanpa token dan dengan token low.
- Catat header respons dan bedakan antara "tidak ada" dan "ada tapi longgar".

## Chain template
Misconfig (data berlebih / versi lama) → akses field sensitif milik akun test lain → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Konfigurasi default API dibiarkan longgar; versi lama tidak dimatikan; serialisasi mengembalikan semua field tanpa filter.

## Verifikasi
- Replay dengan akun low harus gagal bila field itu sensitif.
- Simpan request/response, redaksi isi sensitif.
