# hunt-js-bundle — JS Bundle / Source-Map Analysis

Kelas: Recon | CWE: CWE-200 | OWASP: A01:2021

## Detection pattern
- Source map (`.js.map`) tersedia publik.
- Bundle berisi endpoint internal, nama rute admin, atau secret.
- Modul lama / dependensi rentan terlihat dari nama file.

## Payload contoh
- Minta `main.js.map` untuk bundle yang dimuat halaman.
- Jalankan source-map-explorer pada bundle (lokal, baca saja).
- Cari string `/api/internal`, `/admin`, `api_key` di bundle.

## Bypass
- Coba path map alternatif (`/static/js/main.js.map`).
- Coba bundle versi lama yang mungkin masih tersimpan.

## Chain template
Bundle → endpoint tersembunyi → uji endpoint (skill hunt lain) →
dampak — laporkan endpoint yang ditemukan + bukti.

## Verifikasi
- Endpoint yang ditemukan harus diuji ulang dengan skill hunt yang relevan.
- Jangan simpan bundle utuh; simpan potongan yang relevan saja.
- Redaksi secret yang ditemukan.
