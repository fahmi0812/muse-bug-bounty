# hunt-cors — CORS Misconfiguration

Kelas: Broken Access Control | CWE: CWE-942 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan curi data user nyata lewat origin lain.
- Berhenti saat kena rate limit / 429.

## Detection pattern
- `Access-Control-Allow-Origin` memantulkan origin apa pun + `Allow-Credentials: true`.
- Origin `null` diterima dengan credentials.
- Regex origin longgar: subdomain mirip (`evil-target.com`) lolos.
- Preflight dilewati / tidak dicek untuk request sensitif.
- `postMessage` diterima dari origin mana pun tanpa cek.

## Payload contoh
- Kirim `Origin: https://evil.example` ke endpoint sensitif, cek header respons.
- Kirim `Origin: null` dan `Origin: https://target.evil.example`.
- Baca respons lewat halaman test milikmu dengan `fetch(..., {credentials:'include'})`.

## Bypass
- Coba variasi origin: subdomain, port, skema, trailing dot.
- Coba header `Origin` kosong vs tidak ada.
- Bila diblokir, catat dan berhenti.

## Chain template
CORS memantulkan origin + credentials → situs jahat membaca respons akun test korban → curi data / lakukan aksi atas nama korban — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Origin tidak di-allowlist ketat; credentials diizinkan bersama wildcard / refleksi origin.

## Verifikasi
- Replay: dari origin test milikmu, baca respons sensitif akun test korban yang sedang login.
- Buktikan dengan akun test sendiri, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
