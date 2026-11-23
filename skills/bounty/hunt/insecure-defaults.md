# insecure-defaults — Default Tidak Aman

Kelas: Security Misconfiguration | CWE: CWE-1188 | OWASP: A05:2021 Security Misconfiguration

Diadaptasi dari Trail of Bits (CC-BY-SA-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan pakai akun user nyata, jangan curi token orang lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Akun/pengguna default masih aktif: `admin/admin`, `admin/password`,
  atau kredensial bawaan pabrik yang tidak pernah diganti.
- Layanan berjalan dengan konfigurasi contoh: debug mode aktif, halaman
  error menampilkan stack trace, direktori listing terbuka.
- Fitur berbahaya aktif secara default: registrasi terbuka, upload tanpa
  batas, CORS `*` dengan credentials, cookie tanpa flag `Secure`/`HttpOnly`.
- Izin terlalu longgar sejak awal: file/direktori bisa dibaca siapa saja,
  endpoint admin tidak dicek peran, API key contoh masih valid.

## Payload contoh
- Login dengan kredensial default yang terdokumentasi publik untuk produk itu.
- Buka `/debug`, `/.env`, `/admin` tanpa login — uji apakah default
  membiarkan akses.
- Kirim request tanpa cookie/token ke endpoint yang seharusnya butuh
  auth — uji apakah default-nya terbuka.

## Refuting verifier (wajib sebelum melapor)
Default yang terlihat tidak aman BELUM tentu temuan. Buktikan dulu:
- Coba eksploitasi dengan akun test sendiri sampai dampak nyata
  (baca data, ubah data, atau login sebagai peran lain).
- Bila gagal karena ada pengaman lain (WAF, reverse proxy, flag
  non-default di deploy), catat sebagai "default tidak aman tapi
  terhalang X" — jangan laporkan sebagai temuan valid.
- Bila default hanya buruk di teori (mis. header hilang tapi tidak ada
  dampak), turunkan ke catatan hardening, bukan laporan kerentanan.

## Chain template
Default tidak aman → diverifikasi bisa dieksploitasi (refuting verifier
lolos) → akses/dampak nyata — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Konfigurasi bawaan produk/framework mengutamakan kemudahan, bukan
keamanan; tim deploy tidak pernah mengubah default sebelum go-live.

## Verifikasi
- Replay dengan akun low-priv harus gagal; dengan akun test korban (milikmu) berhasil.
- Buktikan dengan akun test sendiri, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
