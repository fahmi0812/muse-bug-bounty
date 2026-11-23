# hunt-open-redirect — Open Redirect

Kelas: Redirect | CWE: CWE-601 | OWASP: A01:2021

## Detection pattern
- Parameter `next`, `redirect`, `returnUrl` mengarahkan ke host luar.
- Respons 302 ke URL yang dikontrol penyerang.

## Payload contoh
- `https://example.com.evil.example/` — uji validasi host (domain contoh).
- `//evil.example/` — uji redirect skema-relatif.
- `/\evil.example/` — uji parser URL.

## Bypass
- Coba whitelist bypass dengan subdomain yang mirip.
- Coba encoding bila filter string aktif.

## Chain template
Open redirect → phishing (halaman login palsu) →
dampak (pencurian kredensial korban) — laporkan dengan bukti redirect.

## Verifikasi
- Replay dengan URL internal harus tetap internal.
- Buktikan redirect ke host kontrolmu sendiri (lab), bukan host korban.
- Simpan header Location + request.
