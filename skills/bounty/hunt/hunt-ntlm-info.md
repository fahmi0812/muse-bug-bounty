# hunt-ntlm-info — NTLM / Negotiate Information Disclosure

Kelas: Information Disclosure | CWE: CWE-200 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya endpoint publik target.
- Jangan pakai info yang bocor untuk relay, cracking, atau spray kredensial.
- Jangan kirim kredensial apa pun ke server target — uji anonim saja.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Header respons `WWW-Authenticate: NTLM` atau `Negotiate` pada endpoint anonim.
- Server membalas challenge NTLM (Type-2) tanpa kredensial — decode strukturnya.
- Field yang bocor: nama NetBIOS komputer, nama domain AD, FQDN server, nama forest, timestamp.
- Hostname pola default installer (`WIN-` + angka acak) menandai provisioning asal-asalan.
- Header `Server: Microsoft-IIS` / `Microsoft-HTTPAPI` memperkuat sinyal.

## Payload contoh
- GET anonim ke `/_api/web/CurrentUser`, `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml`, `/owa/` — catat header `WWW-Authenticate`.
- Kirim pesan NTLM Type-1 standar (tanpa kredensial) lewat koneksi keep-alive — baca challenge Type-2 yang dibalas.
- Decode pasangan AV dari challenge: nama komputer, domain DNS, forest, timestamp.

## Bypass
- Beberapa server butuh koneksi keep-alive agar challenge terkirim — jangan pakai request sekali-jalan bila gagal.
- Bila server hanya menawarkan NTLM di path tertentu, catat path-nya — jangan klaim seluruh host bocor.

## Chain template
Challenge NTLM anonim → domain AD + hostname internal terungkap → peta serangan untuk tahap berikutnya → laporkan sebagai info disclosure + konteks rantai.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Protokol NTLM memang membalas challenge berisi info target sebelum auth; server internet-facing membiarkan NTLM aktif di binding publik.

## Verifikasi
- Replay anonim harus menghasilkan challenge yang sama — bukan artefak satu sesi.
- Buktikan hanya pada info yang server berikan sendiri, tanpa kredensial.
- Simpan header respons, redaksi nilai sensitif sebelum laporan.
