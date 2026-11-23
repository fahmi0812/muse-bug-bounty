# hunt-cache-poison — Web Cache Poisoning / Deception

Kelas: Injection | CWE: CWE-444 | OWASP: A03:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan racuni cache yang dipakai user nyata — uji di lab / akun test, hentikan bila cache bersama terdampak.
- Berhenti saat kena rate limit / 429.

## Detection pattern
- Respons yang di-cache berubah mengikuti header / parameter yang tidak dipakai aplikasi (mis. `X-Forwarded-Host`, `utm_*`).
- URL dengan ekstensi statis (`.js`, `.css`) mengembalikan isi halaman dinamis.
- Header `Cache-Control` / `X-Cache` menunjukkan respons dari cache.
- Parameter aneh masuk ke isi halaman yang di-cache.

## Payload contoh
- Tambah `?utm_test=<script>` atau header `X-Forwarded-Host: evil.example`, lalu minta URL yang sama tanpa payload — cek apakah racun tersimpan.
- Minta `/profil.js` atau `/profil.css` saat login akun test — cek apakah data akun masuk ke respons "statis".
- Uji header `X-Original-URL` / `X-Rewrite-URL` yang mengubah path.

## Bypass
- Coba parameter cache-buster yang berbeda untuk memisahkan entri cache.
- Coba header yang jarang dipakai (`X-Forwarded-Scheme`, `Accept` aneh).
- Bila cache bersama terdampak, hentikan dan laporkan segera.

## Chain template
Input tidak terpakai masuk ke cache → korban menerima halaman beracun (XSS / redirect / data akun lain) — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Cache key tidak mencakup semua input yang memengaruhi respons; aplikasi memakai input yang tidak divalidasi untuk membangun halaman.

## Verifikasi
- Replay: request kedua tanpa payload harus mengembalikan respons beracun dari cache.
- Buktikan dengan akun test sendiri, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
