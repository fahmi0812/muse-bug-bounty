# hunt-okta — Okta Identity

Kelas: Broken Authentication | CWE: CWE-287 | OWASP: A07:2021

Ditulis dari pola publik (CVE/penelitian publik) — konfigurasi Okta yang salah.

## Scope & larangan
- Hanya organisasi/program yang eksplisit mencantumkan Okta di scope.
- Jangan sentuh tenant pihak ketiga, jangan uji akun user nyata — hanya akun test milikmu.
- Jangan tebak password / brute force / tebak kode MFA. Berhenti saat kena rate limit / 429.
- Jangan ubah kebijakan sign-on atau MFA — hanya baca dan laporkan.

## Detection pattern
- Session token / cookie bisa dipakai ulang dari IP/perangkat lain tanpa re-auth (tidak ada device binding).
- Kebijakan MFA tidak berlaku untuk semua aplikasi atau semua grup — ada aplikasi yang lolos tanpa MFA.
- API token (SSWS) punya scope lebar dan tidak kedaluwarsa, atau dipakai di tempat yang seharusnya pakai OAuth.
- Kebijakan sign-on mengizinkan password-only untuk aplikasi sensitif.
- Session tidak dicabut setelah ganti password atau setelah admin menonaktifkan user.

## Payload contoh
- Login dengan akun test, salin session cookie ke browser/perangkat lain, cek apakah masih valid.
- Cek tiap aplikasi: mana yang tidak minta MFA untuk akun test.
- Cek API token test: scope apa saja yang bisa diakses.

## Bypass
- Coba session lama setelah ganti password — uji apakah masih hidup.
- Coba akses aplikasi sensitif dengan akun test yang seharusnya kena MFA.
- Bila diblokir, catat dan berhenti — jangan coba akun nyata.

## Chain template
Session replay / celah MFA / token lebar → akses aplikasi korban → baca data, ubah profil, kunci pemilik asli keluar — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, aplikasi)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Session dan kebijakan MFA tidak mengikat sesi ke perangkat/pemilik yang benar, atau tidak berlaku merata di semua aplikasi.

## Verifikasi
- Buktikan dengan dua akun test milikmu, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
