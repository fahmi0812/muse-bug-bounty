# hunt-saml — SAML Authentication Flaws

Kelas: Broken Authentication | CWE: CWE-347 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan pakai assertion / identitas user nyata. Jangan serang IdP di luar scope.
- Berhenti saat kena rate limit / 429.

## Detection pattern
- Assertion SAML diterima tanpa tanda tangan yang valid.
- Signature bisa dihapus (signature stripping) dan tetap diterima.
- `NameID` / atribut bisa diubah tanpa memutus validasi.
- Assertion dari IdP lain (`Issuer` berbeda) diterima.
- Assertion kedaluwarsa / dipakai ulang tetap diterima.

## Payload contoh
- Hapus elemen `<Signature>` dari assertion akun test, kirim ulang.
- Ganti `NameID` ke email akun test lain dengan tanda tangan asli.
- Pakai assertion lama (dari login sebelumnya) dua kali.
- Ganti `Issuer` ke IdP test lain.

## Bypass
- Coba wrapping: tanda tangan menunjuk elemen lain dari yang diproses.
- Coba komentar / encoding yang mengubah parsing XML.
- Bila IdP memblokir, catat dan berhenti.

## Chain template
Assertion dimanipulasi → login sebagai akun test korban (ATO) → baca / ubah data — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Validasi tanda tangan, issuer, dan audience tidak lengkap; parser XML memproses elemen yang berbeda dari yang ditandatangani.

## Verifikasi
- Replay: assertion yang dimanipulasi harus diterima server; assertion asli yang tidak diubah tetap valid.
- Buktikan dengan dua akun test milikmu, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
