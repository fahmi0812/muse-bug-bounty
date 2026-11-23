# hunt-secrets — Secrets in Code / Response

Kelas: Sensitive Data Exposure | CWE: CWE-798 | OWASP: A02:2021

## Detection pattern
- API key / token / password muncul di respons API, JS bundle, atau error.
- Kredensial hardcode di source map / file statis.
- Token yang sama dipakai di banyak tempat tanpa rotasi.

## Payload contoh
- Cari pola `api_key`, `secret`, `token`, `password` di respons dan bundle.
- Periksa source map dan file `.js` untuk string kunci.
- Periksa header respons untuk token internal.

## Bypass
- Coba endpoint lama / versi API lama yang mungkin masih bocor.
- Coba file backup (`.bak`, `.old`) bila ada indikasi.

## Chain template
Secret bocor → pakai secret (akun test / lab) → akses layanan internal →
dampak — laporkan dengan bukti bocor, JANGAN pakai secret nyata ke layanan produksi.

## Verifikasi
- Buktikan secret itu valid hanya di lab / akun test; bila secret produksi bocor, laporkan segera dan JANGAN dipakai.
- Redaksi secret di laporan (tampilkan 4 karakter awal saja).
- Simpan lokasi + konteks bocornya.
