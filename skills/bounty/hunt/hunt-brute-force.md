# hunt-brute-force — Missing Rate Limit (deteksi kontrol-hilang)

Kelas: Missing Rate Limiting | CWE: CWE-307, CWE-799 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri, hanya sebagai deteksi kontrol-hilang.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- **DILARANG: menebak / brute-force kredensial, password, OTP, atau token apa pun.** Skill ini HANYA mendeteksi apakah kontrol pembatas TIDAK ADA — bukan untuk menembus akun.
- **DILARANG: credential stuffing, password spraying, dan menebak kode OTP/reset.** DILARANG memakai daftar password bocor atau alat brute-force.
- Uji dengan MAKSIMAL 3–5 percobaan gagal dari akun test sendiri, lalu berhenti dan amati sinyal.
- Berhenti saat kena rate limit / 429 — itu bukti kontrol ADA, bukan hambatan.

## Detection pattern
- Setelah 3–5 login gagal dari akun test sendiri: tidak ada 429, tidak ada pesan "terlalu banyak percobaan", tidak ada CAPTCHA muncul, tidak ada lockout.
- Endpoint verifikasi OTP / reset password menerima banyak percobaan tanpa penundaan atau blokir.
- Respons login membedakan akun valid vs tidak (teks, status, atau waktu) — itu enumerasi, catat sebagai temuan terpisah.
- Kebijakan kata sandi lemah: panjang minimum rendah, tanpa cek kata sandi umum.
- Header `X-Forwarded-For` mengubah hitungan percobaan — catat bila ada, jangan eksploitasi.

## Payload contoh
- Login gagal 3–5 kali dengan kata sandi salah dari akun test sendiri — catat status + pesan tiap percobaan.
- Minta kode OTP/reset untuk akun test sendiri beberapa kali — catat ada/tidaknya penundaan atau blokir.
- Bandingkan respons login untuk email terdaftar vs tidak terdaftar dari akun test.

## Bypass
- Tidak ada teknik bypass di skill ini — yang diuji hanya ada/tidaknya kontrol.
- Bila kontrol muncul setelah N percobaan, catat ambangnya — itu kontrol yang bekerja, bukan celah.
- Shadow-throttling (pelan diam-diam) tetap dihitung sebagai kontrol — jangan klaim hilang bila respons melambat.

## Chain template
Rate limit tidak ada → percobaan tak terbatas dimungkinkan → risiko ATO bila kredensial bocor → laporkan sebagai kontrol-hilang, bukan sebagai akun yang berhasil ditembus.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Endpoint sensitif tidak punya pembatas percobaan: tanpa lockout, tanpa throttle, tanpa CAPTCHA.

## Verifikasi
- Replay 3–5 percobaan gagal harus konsisten tidak diblokir — satu kali lolos bukan bukti.
- Jangan pernah melaporkan akun yang berhasil ditebak — skill ini tidak menebak apa pun.
- Simpan request/response, redaksi isi sensitif.
