# hunt-laravel — Laravel Framework

Kelas: Misconfiguration / Deserialization | CWE: CWE-200, CWE-502 | OWASP: A05:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan menjalankan exploit RCE ke target nyata — cukup buktikan primitifnya (debug aktif, endpoint Ignition terjangkau, versi rentan).
- Jangan membaca log/request milik pengguna lain di Telescope/Horizon; jangan pakai APP_KEY yang ditemukan untuk memalsukan sesi orang lain.

## Detection pattern
- Sinyal Laravel: cookie `laravel_session`, header `X-Powered-By: PHP`, `csrf-token` di HTML, path `/storage`, `/.env`, `/artisan`.
- Debug aktif: halaman error Whoops/Ignition pada URL tak ada — stack trace + env bocor.
- Endpoint `/_ignition/health-check` terjangkau + Laravel < 8.4.2 = CVE-2021-3129 (Ignition RCE) — cek versi, jangan kirim solusi eksekusi.
- `/telescope` (+ `/telescope/api/requests`, `/redis`, `/environment`) 200 tanpa login = log request, query DB, env bocor.
- `/horizon` (+ `/horizon/api/jobs/failed`) 200 tanpa login = payload job gagal berisi token/PII.
- `/.env` (termasuk `.env.production`/`.backup`/`.local`) mengembalikan `APP_KEY`/`DB_PASSWORD`.
- Override env via query: `?--env=local` / `?--env=testing` bila `register_argc_argv=On` (CVE-2024-52301; fixed 11.31.0 / 10.48.23 / 9.52.17).

## Sinyal uji
- `GET /definitely-does-not-exist-xyz` → cari `Whoops`/`Ignition`/`laravel` di body.
- `GET /_ignition/health-check` → 200 = Ignition aktif; padankan dengan versi Laravel sebelum mengklaim CVE.
- `GET /telescope/api/requests`, `/horizon/api/stats` → JSON dengan data nyata = akses tanpa auth.
- `GET /.env` → `APP_KEY` terbaca = ATO via cookie terenkripsi (jangan dipalsukan ke akun orang lain).
- Signed URL: ubah parameter non-signature / hapus `signature` — lolos = validasi tidak mencakup semua parameter.

## Bypass
- Mass assignment Eloquent: tambah field `is_admin`/`role`/`verified` pada update profil/registrasi — diterima = model tidak menjaga field.
- Cookie Laravel terenkripsi bisa dipalsukan bila APP_KEY bocor — buktikan hanya pada akun test sendiri.

## Chain template
Debug aktif + Ignition rentan → RCE. Atau: `.env` bocor → APP_KEY → dekripsi/palsu cookie sesi → ATO. Atau: Telescope/Horizon anonim → kredensial dari log/query → lateral.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
`APP_DEBUG=true` di produksi; Telescope/Horizon tanpa auth; `.env` bisa diakses web; model Eloquent `$guarded=[]` tidak tepat; `register_argc_argv=On` memungkinkan override env via query.

## Verifikasi
- Ignition: output perintah di respons = RCE; endpoint terjangkau saja + versi rentan = temuan dengan severity sesuai bukti.
- Telescope/Horizon: wajib ada data sensitif nyata (kredensial/token) di respons API.
- APP_KEY: cookie palsu diterima pada akun test sendiri = terbukti; jangan uji ke akun orang lain.
