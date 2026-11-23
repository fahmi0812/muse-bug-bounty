# js-bundle-analysis — Analisis Bundle JS

Bundle frontend sering membocorkan lebih banyak daripada yang disadari
pemiliknya: endpoint tersembunyi, logika lama, kadang secret.

## Ambil bundle
- Unduh file JS utama + chunk dari halaman target (dalam scope).
- Cari source map (`.js.map`): bila tersedia, pakai
  `source-map-explorer` untuk memetakan file sumber asli.
- Tanpa source map: baca bundle apa adanya, cari string menarik.

## Yang dicari
- Endpoint API tersembunyi: `/api/...`, `/internal/...`, `/admin/...`.
- Parameter & nama field yang tidak tampil di UI.
- Secret: API key, token, kata `secret`, `password`, `private`.
- Komentar / kode mati: fitur lama, endpoint debug, TODO keamanan.
- Library + versi: cocokkan dengan CVE yang diketahui (cek manual).

## Cara kerja
1. Petakan semua string URL di bundle; pisahkan publik vs internal.
2. Uji endpoint yang menarik secara manual, satu per satu, dalam scope.
3. Secret yang ketemu: JANGAN dipakai untuk login / memanggil API
   berbayar. Catat keberadaannya sebagai temuan, lalu redaksi.
4. Endpoint internal yang merespons: lanjutkan dengan skill hunt
   yang cocok (mis. `hunt-api-bola`, `hunt-broken-access`).

## Batasan
- Hanya bundle dari target dalam scope; jangan unduh bundle pihak ketiga.
- Jangan jalankan kode bundle di luar browser / tanpa sandbox.
- Temuan secret tanpa dampak (mis. key publik yang memang publik)
  bukan otomatis bug — uji dampaknya dulu.
