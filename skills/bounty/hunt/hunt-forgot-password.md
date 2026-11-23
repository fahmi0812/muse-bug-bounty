# hunt-forgot-password — Password Recovery Flaws

Kelas: Broken Authentication | CWE: CWE-640 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan kirim email reset ke alamat orang lain. Jangan pakai token reset user nyata.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Token reset muncul di respons API atau URL yang bisa dilihat.
- Token reset tidak kedaluwarsa atau bisa dipakai dua kali.
- Token reset bisa ditebak (pendek / berbasis waktu / berurutan).
- Respons "email tidak ditemukan" vs "email terkirim" membocorkan akun yang ada.
- Reset tidak minta verifikasi identitas apa pun selain email.

## Payload contoh
- Minta reset untuk akun test A, baca token dari respons / inbox akun test sendiri.
- Pakai token akun test A untuk reset akun test B.
- Pakai token yang sama dua kali.
- Uji enumerasi: bandingkan respons untuk email terdaftar vs tidak terdaftar.

## Bypass
- Coba ubah `email` / `user_id` di request reset ke akun test lain.
- Coba token lama setelah password diganti.
- Bila diblokir, catat dan berhenti.

## Chain template
Token reset bocor / bisa ditebak / tidak terikat akun → reset password akun test korban → ATO — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Token reset tidak acak, tidak terikat ke satu akun, tidak kedaluwarsa, atau bocor lewat respons.

## Verifikasi
- Replay: reset akun test korban harus berhasil hanya dengan token yang bocor / ditebak.
- Buktikan dengan dua akun test milikmu, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
