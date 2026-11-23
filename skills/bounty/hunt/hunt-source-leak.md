# hunt-source-leak — Source Code & Build Artifact Leakage

Kelas: Information Disclosure | CWE: CWE-200, CWE-540 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya artefak publik target.
- Jangan unduh `.git` lalu pakai histori untuk menyerang akun orang lain.
- Jangan pakai kredensial yang bocor untuk login — laporkan keberadaannya saja.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- File `.env`, `.env.production`, `.git/HEAD`, `swagger.json`, `openapi.json` merespons 200.
- Source map (`.js.map`) terbuka — rekonstruksi sumber TypeScript/ES6.
- `asset-manifest.json` / `_next/static/` memetakan semua bundle → cari map tiap bundle.
- File build-info / `info.json` menyingkap commit, versi dependensi, timestamp build.
- `.DS_Store` menyingkap daftar file direktori.

## Payload contoh
- Minta 10 path cepat: `/.env`, `/.env.production`, `/.git/HEAD`, `/swagger.json`, `/openapi.json`, `/api-docs`.
- Ambil hash bundle dari HTML saat ini, lalu minta `<hash>.js.map` — jangan pakai URL map lama (bundle berotasi tiap deploy).
- Baca `robots.txt` / `security.txt` untuk petunjuk path tersembunyi.

## Bypass
- Redeploy TIDAK memperbaiki source map — hanya mematikan generate map + purge CDN.
- 404 di URL map lama bukan bukti perbaikan — cek ulang dengan hash bundle terbaru.
- Bila map hanya berisi kode minified tanpa sumber, catat sebagai paparan rendah, bukan kritis.

## Chain template
Source map terbuka → rute API + logika auth + kunci terlihat → endpoint internal diuji → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Artefak build (map, env, git) ikut ter-deploy ke produksi; tidak ada stripping di pipeline deploy.

## Verifikasi
- Buktikan map masih terbuka dengan hash bundle terbaru, bukan URL lama.
- Jangan simpan isi kredensial yang bocor — catat jenis + lokasinya saja, lalu redaksi.
- Simpan request/response, redaksi isi sensitif.
