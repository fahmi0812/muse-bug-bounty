# hunt-subdomain — Subdomain Takeover

Kelas: Subdomain Takeover | CWE: CWE-200, CWE-862 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya subdomain program yang terdaftar.
- Jangan klaim/mendaftarkan layanan apa pun atas nama target — deteksi saja, tanpa takeover.
- Jangan pakai subdomain yang dikuasai untuk phishing atau menyajikan konten.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- CNAME mengarah ke layanan pihak ketiga yang sudah tidak diklaim: GitHub Pages, Heroku, S3, Azure, Netlify, Shopify, Zendesk, Fastly, Vercel.
- CNAME target NXDOMAIN / SERVFAIL sementara record induk masih ada.
- Respons HTTP khas layanan tak diklaim: "NoSuchBucket", "No such app", "There isn't a GitHub Pages site here", "Fastly error: unknown domain".
- Delegasi NS ke zona yang sudah tidak terdaftar.
- Subdomain staging/preview/dev yang ditinggalkan setelah fitur rilis.

## Payload contoh
- Enumerasi subdomain (subfinder, crt.sh), lalu resolve semuanya — tandai yang CNAME-nya ke provider.
- Cocokkan CNAME dengan fingerprint provider (nuclei `http/takeovers/` atau daftar fingerprint) — tanpa klaim apa pun.
- Minta subdomain lewat HTTPS, catat body + header (`X-Served-By`, `Server`) sebagai bukti.

## Bypass
- Sertifikat SSL wildcard milik provider (bukan perusahaan) memperkuat sinyal takeover.
- Subdomain untuk OAuth `redirect_uri` atau SSO bernilai tertinggi — prioritaskan itu.
- Bila provider sudah memperbaiki klaimnya, jangan laporkan sebagai bisa diambil alih.

## Chain template
CNAME menggantung → layanan bisa diklaim pihak lain → konten di domain tepercaya → phishing / intersepsi email reset → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Record DNS tidak dibersihkan saat layanan dihentikan; layanan mengizinkan siapa pun mengklaim nama yang menggantung.

## Verifikasi
- Replay DNS + HTTP harus menunjukkan fingerprint yang sama — bukan cache lama.
- Jangan pernah menyelesaikan klaim takeover — bukti fingerprint sudah cukup.
- Simpan output DNS + respons HTTP, redaksi isi sensitif.
