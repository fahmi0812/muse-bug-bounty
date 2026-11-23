# hunt-session — Session Management Flaws

Kelas: Broken Authentication | CWE: CWE-384 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan pakai session / cookie user nyata.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Session ID tidak berubah setelah login (fixation).
- Session lama tetap valid setelah logout atau ganti password.
- Session ID pendek, berurutan, atau bisa ditebak.
- Cookie sesi tanpa flag `HttpOnly` / `Secure` / `SameSite`.
- Token sesi tidak kedaluwarsa setelah lama tidak dipakai.

## Payload contoh
- Login dengan session ID yang kamu tetapkan sendiri — uji apakah server menerimanya.
- Logout, lalu pakai cookie lama — uji apakah masih valid.
- Ganti password, lalu pakai session lama — uji apakah di-revoke.
- Tebak session ID berurutan dari akun test lain.

## Bypass
- Coba session ID dari akun test A di request akun test B.
- Coba cookie tanpa `Secure` lewat HTTP bila tersedia.
- Bila diblokir, catat dan berhenti.

## Chain template
Session fixation / tidak di-revoke → pakai session akun test korban → akses akun tanpa password — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Siklus hidup session tidak dikelola: ID tidak di-rotasi saat login, tidak di-revoke saat logout / ganti password, entropi rendah.

## Verifikasi
- Replay dengan session akun test sendiri; session akun low-priv harus gagal setelah logout.
- Buktikan dengan dua akun test milikmu, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
