# hunt-sqli — SQL Injection

Kelas: Injection | CWE: CWE-89 | OWASP: A03:2021 Injection

## Detection pattern
- Error database muncul di respons saat input berisi kutip (`'`).
- Perilaku berubah saat menambahkan logika boolean (`AND 1=1` vs `AND 1=2`).
- Respons tertunda saat memakai fungsi sleep/delay (time-based).
- Data dari tabel lain muncul lewat UNION (union-based).
- Parameter numerik merespons berbeda pada input non-numerik.

## Payload contoh
- `'` — pemicu error / perubahan perilaku.
- `' OR '1'='1` — logika boolean (contoh generik, bukan bypass massal).
- `' UNION SELECT NULL,NULL--` — uji jumlah kolom (sesuaikan jumlah).
- `' AND SLEEP(2)--` — uji time-based, pakai delay kecil saja.

## Bypass
- Coba encoding / variasi spasi bila filter kata kunci aktif.
- Coba komentar SQL (`/**/`) sebagai pengganti spasi bila diblokir.
- Bila WAF memblokir, catat dan hentikan percobaan agresif.

## Chain template
SQLi (baca terbatas) → enum tabel/kolom → baca data sensitif →
dampak (mis. baca hash / data user lain) — laporkan di titik bukti cukup.

## Verifikasi
- Replay dengan input normal harus kembali normal.
- Buktikan dengan satu baris data yang memang bukan milik akunmu
  di lab / akun sendiri — jangan ambil data user nyata.
- Simpan request/response, redaksi token/cookie.
