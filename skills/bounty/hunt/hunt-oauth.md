# hunt-oauth — OAuth Flaws

Kelas: Broken Authentication | CWE: CWE-287 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan pakai akun user nyata, jangan curi token orang lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Parameter `redirect_uri` di `/oauth/authorize` tidak divalidasi ke domain sendiri.
- Parameter `state` kosong, tidak berubah, atau tidak dicek saat callback.
- Authorization code bisa dipakai dua kali atau ditukar tanpa `code_verifier` (PKCE).
- `client_id` aplikasi lain diterima sebagai milik aplikasi target.
- Token akses / ID token diterima tanpa cek `aud` atau `iss`.

## Payload contoh
- `redirect_uri=https://evil.example/callback` — uji validasi redirect.
- Hapus `state` dari callback — uji apakah tetap login.
- Tukar code yang sama dua kali — uji apakah code di-revoke setelah pakai.
- Ganti `aud` di ID token dengan client_id lain — uji cek audience.

## Bypass
- Coba `redirect_uri` dengan subdomain mirip / path traversal (`@`, `//`, `/.`).
- Coba `response_mode` / `response_type` lain bila parameter dikunci.
- Bila provider memblokir, catat dan berhenti — jangan spam callback.

## Chain template
OAuth redirect / state lemah → code dicuri atau ditukar → login sebagai akun lain (ATO) → baca / ubah data korban — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Validasi redirect/state/audience diserahkan ke client, atau tidak ada sama sekali; code sekali pakai tidak di-revoke.

## Verifikasi
- Replay dengan akun low-priv harus gagal; dengan akun test korban (milikmu) berhasil.
- Buktikan dengan akun test sendiri, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.

## Pendalaman
Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — parafrase, fokus deteksi + validasi.

### Pola deteksi tambahan
- State CSRF: `state` tetap sama antar sesi atau bisa dipakai ulang — uji dengan memulai flow dari akun test A lalu memakai callback code A di sesi akun test B (milik sendiri).
- Token/nonce bocor lewat Referer: setelah callback, periksa request keluar dari halaman landing — code atau token di header Referer = bocor ke pihak ketiga.
- Token endpoint tanpa autentikasi client: tukar code tanpa `client_secret`, atau dengan akun test yang belum terverifikasi email — uji apakah penukaran tetap berhasil.
- OIDC discovery: baca `.well-known/openid-configuration` — `registration_endpoint` yang terbuka berarti siapa pun bisa mendaftarkan client dengan `redirect_uri` sendiri.
- Cross-client token confusion: token dari client A dicoba ke API client B — bila diterima, API tidak mengecek audience.

### Chain tambahan
Open redirect di domain resmi → `redirect_uri` lolos validasi → code jatuh ke penyerang → tukar jadi sesi akun test korban (ATO).

### Catatan Gate-0 tambahan
- Code yang dicuri harus benar-benar bisa ditukar jadi sesi akun test lain; redirect ke domain luar tanpa code = open redirect saja, bukan ATO.
- Token yang bocor lewat Referer hanya berarti bila token itu masih hidup dan bisa dipakai — cek dengan replay ke API sebagai akun test.
