# hunt-dos — Denial of Service / Unrestricted Resource Consumption

Kelas: Denial of Service / Unrestricted Resource Consumption | CWE: CWE-400 | OWASP: A04:2021

Ditulis dari CWE-400 / OWASP API Security — bukan adaptasi satu vendor.

## Scope & larangan

- Hanya program yang scope-nya tertulis, akun test sendiri.
- DILARANG menjatuhkan layanan produksi atau layanan milik orang lain.
  Uji hanya di lab / program yang mengizinkan, dengan beban kecil dan
  terukur (satu request, lalu amati; jangan banjir request).
- DILARANG memakai alat flood / stress test (hping, slowloris, dsb.)
  ke target nyata — itu di luar scope bounty.

## Pola deteksi

1. **Query berat tanpa batas:** satu request dengan parameter besar
   (mis. `limit=999999`, `pageSize` besar, pencarian tanpa filter)
   membuat respons lambat (>10 detik) atau timeout, sementara request
   normal <1 detik.
2. **Batching tanpa batas (GraphQL):** satu request berisi puluhan
   alias/query sekaligus dieksekusi semua tanpa batas jumlah.
3. **Regex mahal:** input yang memicu backtracking (pola berulang
   panjang) membuat CPU naik tajam pada satu request.
4. **Upload tanpa batas ukuran:** file besar diterima tanpa batas dan
   diproses penuh (parsing, thumbnail, unzip) sebelum ditolak.
5. **Tanpa rate limit:** endpoint mahal (pencarian, ekspor, laporan)
   bisa dipanggil berulang tanpa 429/lockout — gabungkan dengan
   observasi pola 1 (beban kecil, jangan banjir).

## Validasi (Gate-0)

- Ulangi 2× dengan beban yang sama di akun test sendiri: lambat di
  kedua percobaan, normal saat parameter dikecilkan.
- Bandingkan dengan request normal: buktikan perlambatan berasal dari
  parameter itu, bukan dari jaringan.
- Catat waktu respons + ukuran parameter + bukti CPU/timeout.
  Satu request lambat BUKAN bukti DoS bila server memang lambat untuk
  semua request.

## Chain

DoS via query -> resource habis -> layanan lambat/tidak responsif
untuk semua user -> (bila digabung) menutupi aktivitas lain.

## Root cause

Tidak ada batas pada ukuran input, jumlah operasi per request, atau
biaya komputasi per request; tidak ada rate limit di endpoint mahal.
