# hunt-ato — Account Takeover (ATO)

Kelas: Broken Authentication | CWE: CWE-287 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan pakai akun user nyata, jangan kirim email reset ke orang lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Reset password menghasilkan token yang bisa ditebak atau tidak kedaluwarsa.
- Ganti email / nomor HP akun tidak minta verifikasi ulang.
- Login SSO / OAuth menerima identitas tanpa cek kepemilikan.
- Session lama tetap hidup setelah ganti password.
- Akun bisa dibuat dengan email korban tanpa verifikasi (pre-hijack).

## Payload contoh
- Minta reset untuk akun test A, pakai token yang sama untuk akun test B.
- Ganti `email` di profil ke email akun test lain tanpa OTP.
- Daftar akun dengan email akun test lain yang belum terverifikasi, lalu verifikasi sendiri.

## Bypass
- Coba token reset lama setelah password diganti — uji apakah masih valid.
- Coba ubah `user_id` di body saat ganti email — uji cek kepemilikan.
- Bila diblokir, catat dan berhenti — jangan coba akun nyata.

## Chain template
Celah recovery / ganti email / SSO → ambil alih akun test korban → baca data, ubah password, kunci pemilik asli keluar — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Verifikasi kepemilikan akun (token, OTP, email) tidak mengikat ke identitas yang benar, atau tidak kedaluwarsa.

## Verifikasi
- Replay: akun test korban harus benar-benar berpindah tangan ke akun test penyerang.
- Buktikan dengan dua akun test milikmu, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
