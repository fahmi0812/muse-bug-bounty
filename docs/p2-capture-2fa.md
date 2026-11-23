# P2 — Capture session manual + MITM recording proxy (2FA/OTP/SSO)

> Status: **P2 / docs saja.** Captcha / OTP / 2FA penuh **tetap di
> Fase 2** (plan v3.1, P0-7). Dokumen ini menjelaskan cara *manual*
> yang diizinkan — bukan bypass, bukan captcha solving, bukan alat
> kategori K/L.
>
> **Yang dilarang:** captcha solving (otomatis/manual berbayar),
> bypass 2FA/OTP, brute-force OTP, SMS bomber, dan alat abuse apa pun.
> Kalau target memakai 2FA penuh dan tidak ada jalur manual, **stop**
> — permukaan di balik 2FA tidak diuji di v1.

## Yang diizinkan (manual, oleh manusia)

### 1. Capture session manual

Manusia login sendiri (browser sendiri) ke target berizin, lalu
menyalin session ke profil program untuk dipakai agen:

1. Login manual di browser (lewati 2FA/OTP sendiri, sebagai pengguna
   sah akun test yang disediakan program/lab).
2. Ekspor cookie / token / header auth dari browser (devtools).
3. Simpan ke profil program (`programs/<nama>.json`, field auth)
   dengan mode file 0600 — **jangan commit, jangan kirim ke siapa pun**.
4. Agen memakai session itu sebagai auth-minimal (P0-7: cookie/token/
   header statis, 2 peran low-priv vs high-priv).
5. Session kedaluwarsa → ulangi manual. Agen **tidak pernah** mencoba
   login ulang sendiri melewati 2FA/OTP.

Aturan simpan:

- Session = kredensial. Perlakukan seperti API key: 0600, gitignore,
  tidak di-log, hapus setelah run selesai bila memungkinkan.
- Satu session = satu peran (low-priv / high-priv), jangan dicampur.
- Jangan pakai akun pribadi / akun produksi — hanya akun test yang
  disediakan program atau lab.

### 2. MITM recording proxy (perekam lalu lintas, bukan penyerang)

Proxy perekam (pola Ghostsecurity Reaper / Claude-Red extension
capture — pola saja, bukan salinan kode) dipakai untuk **merekan**
lalu lintas HTTP(S) antara browser manusia dan target, supaya agen
bisa belajar alur aplikasi (urutan request, parameter, auth):

1. Jalankan proxy perekam lokal (mis. mitmproxy) di mesin sendiri.
2. Pasang sertifikat proxy **hanya di browser/lab sendiri**.
3. Jelajahi target manual lewat browser → proxy merekam request/
   response ke file lokal.
4. Agen membaca rekaman itu untuk membangun threat model + daftar
   endpoint — **tidak** untuk memutar ulang request destruktif tanpa
   review.
5. Rekaman berisi kredensial/session → simpan 0600, gitignore, hapus
   setelah dipakai.

Yang **bukan** MITM recording:

- Menyadap lalu lintas orang lain.
- Memasang sertifikat di perangkat orang lain.
- Mengubah respons untuk menipu target / pengguna lain.
- Memutar ulang request pembayaran / perubahan data tanpa review
  manusia (P1-2).

## 2FA / OTP / SSO — batas yang jelas

| Skenario | v1 | P2 (dokumen ini) |
| --- | --- | --- |
| Login biasa (user/pass) di lab | Auth-minimal (P0-7) | — |
| 2FA/OTP sekali saat login manual | — | Manusia lewati, session di-capture |
| OTP tiap request / step-up auth | Tidak diuji | Tidak diuji (stop) |
| SSO (OAuth/SAML) | Tidak diuji | Manusia login, session di-capture; agen tidak memalsukan token SSO |
| Captcha | Tidak diuji | Tidak diuji — captcha solving dilarang |
| Brute-force OTP / SMS bomber | Dilarang | Dilarang (kategori K) |

## Checklist capture

1. [ ] Akun test disediakan program/lab (bukan akun pribadi)?
2. [ ] Login dilakukan manusia, di browser sendiri?
3. [ ] Session disimpan 0600 + gitignore, tidak di-commit?
4. [ ] Peran low/high-priv terpisah?
5. [ ] Rekaman proxy hanya dari lalu lintas sendiri?
6. [ ] Kredensial di rekaman dihapus setelah run?
7. [ ] Tidak ada percobaan bypass / captcha solving / brute-force OTP?
