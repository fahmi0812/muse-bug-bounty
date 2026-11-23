# hunt-tls-network — TLS / SSL & DNS Misconfiguration

Kelas: Crypto / DNS | CWE: CWE-295, CWE-319, CWE-200 | OWASP: A02:2021, A05:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya host program yang terdaftar.
- Jangan lakukan MitM terhadap korban nyata — bukti hanya dari konfigurasi yang teramati.
- Jangan laporkan hardening generik sebagai kerentanan — baca triase di bawah.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- CNAME menggantung / A record ke IP cloud tak teralokasi — takeover (lihat `hunt-subdomain`).
- DMARC `p=none` + email spoof dari domain target benar-benar masuk inbox — baru layak lapor.
- Transfer zona DNS (AXFR) mengembalikan daftar host internal.
- mTLS / client-cert bisa dilewati di layanan internal tanpa sertifikat.
- Sertifikat kedaluwarsa / tidak valid / cipher lemah yang masih dinegosiasikan.

## Payload contoh
- Cek header HSTS, sertifikat (tanggal, issuer, SAN), dan cipher yang ditawarkan via `openssl s_client`.
- Minta AXFR ke server DNS otoritatif target.
- Cek SPF/DKIM/DMARC lewat record TXT — lalu uji spoof hanya ke inbox milikmu sendiri.

## Bypass
- Ditawarkan ≠ bisa dieksploitasi — cipher lemah tanpa PoC dekripsi adalah Info/Low.
- Jangan laporkan sendirian: CAA hilang, HSTS hilang tanpa PoC MitM, header keamanan hilang, TLS 1.0/1.1 aktif tanpa korban downgrade, self-signed di host non-prod.
- Banyak program menyatakan kelas ini out-of-scope — kutip baris scope yang mengizinkan sebelum lapor.

## Chain template
AXFR / CNAME menggantung → peta host internal → takeover subdomain → konten di domain tepercaya → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Konfigurasi TLS/DNS dibiarkan default; record DNS dan sertifikat tidak dibersihkan saat layanan berubah.

## Verifikasi
- Replay harus menunjukkan konfigurasi yang sama — bukan hasil cache.
- Untuk DMARC: buktikan email masuk inbox dengan header verdict, bukan sekadar record `p=none`.
- Simpan output perintah + header, redaksi isi sensitif.
