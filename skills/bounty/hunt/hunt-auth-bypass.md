# hunt-auth-bypass — Authentication Bypass

Kelas: Broken Authentication | CWE: CWE-287 | OWASP: A07:2021

CATATAN: skill ini pernah tercatat Snyk Fail di upstream — tinjau sebelum dipakai. Jangan pakai kredensial asli orang lain; uji hanya dengan akun test milikmu (low/high).

## Detection pattern
- Endpoint terproteksi merespons 200 tanpa token/cookie yang valid.
- Login menerima input kosong, atau merespons sama untuk kredensial benar dan salah.
- Reset password / OTP bisa ditebak atau diulang tanpa batas.
- Session lama tetap valid setelah logout / ganti password.

## Payload contoh
- Hapus header `Authorization` / cookie sesi, lalu ulangi request.
- Ganti nilai `role` di body dari `user` ke `admin` (hanya akun test).
- Ulangi request OTP dengan kode yang sama dua kali.

## Bypass
- Coba parameter `isAdmin=true` di body/query bila endpoint membacanya.
- Coba header `X-Forwarded-For` / `X-Original-URL` bila ada indikasi proxy.
- Bila diblokir rate limit, berhenti — jangan brute force.

## Chain template
Bypass login → akses data akun lain → eskalasi ke admin →
dampak (baca data / ubah data) — laporkan di titik bukti cukup.

## Verifikasi
- Replay dengan akun low-priv harus gagal; dengan high-priv berhasil.
- Buktikan dengan akun test sendiri, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
