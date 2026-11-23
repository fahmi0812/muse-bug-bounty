# hunt-captcha-bypass — Missing CAPTCHA Validation (deteksi kontrol-hilang)

Kelas: Missing CAPTCHA Enforcement | CWE: CWE-307, CWE-799 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri, hanya sebagai deteksi kontrol-hilang.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- **DILARANG: menebak / brute-force kredensial, mem-bypass CAPTCHA, atau memakai alat solver CAPTCHA apa pun.** Skill ini HANYA mendeteksi apakah validasi CAPTCHA di sisi server TIDAK ADA.
- **DILARANG: menyelesaikan CAPTCHA secara otomatis, memakai layanan solver, atau memutar token CAPTCHA untuk brute-force.** Satu token hanya dipakai sekali, untuk aksi milik akun test sendiri.
- Uji dengan SATU pengiriman sah dari akun test sendiri, lalu amati — jangan spam pengiriman.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Formulir menampilkan CAPTCHA, tapi pengiriman tanpa field CAPTCHA tetap berhasil — validasi server tidak ada.
- Field CAPTCHA diisi kosong / `null` / `0` tetap diterima — server hanya cek keberadaan field, bukan isinya.
- Token CAPTCHA yang sama bisa dipakai ulang untuk pengiriman kedua — token bukan sekali-pakai.
- Token dari satu endpoint diterima di endpoint lain — token tidak terikat aksi/sesi.
- CAPTCHA hanya muncul setelah N gagal — N percobaan pertama tanpa CAPTCHA sama sekali.
- Endpoint API/mobile untuk aksi yang sama tidak memakai CAPTCHA sama sekali.

## Payload contoh
- Kirim formulir akun test dengan SEMUA field kecuali field CAPTCHA — catat apakah aksi berhasil.
- Kirim ulang dengan field CAPTCHA kosong — catat apakah diterima.
- Selesaikan SATU CAPTCHA secara manual, lalu pakai tokennya untuk satu pengiriman kedua akun test — catat apakah diterima lagi.

## Bypass
- Tidak ada teknik bypass di skill ini — yang diuji hanya ada/tidaknya validasi server.
- Bila CAPTCHA muncul dan memblokir, catat sebagai kontrol yang bekerja — jangan cari jalan memutar.
- Perbedaan antar endpoint (web vs API) dicatat sebagai inkonsistensi kontrol, bukan ajakan menyerang.

## Chain template
Validasi CAPTCHA tidak ada di server → aksi sensitif tanpa hambatan → login/registrasi/reset tanpa pelindung otomatisasi → laporkan sebagai kontrol-hilang.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
CAPTCHA hanya ditegakkan di sisi klien (tampilan), bukan divalidasi di server; token tidak sekali-pakai dan tidak terikat aksi.

## Verifikasi
- Replay tanpa CAPTCHA harus konsisten berhasil — bandingkan dengan baseline yang memakai CAPTCHA.
- Jangan pernah memakai token hasil solver atau otomatisasi — satu token manual, satu pengiriman uji.
- Simpan request/response, redaksi isi sensitif.
