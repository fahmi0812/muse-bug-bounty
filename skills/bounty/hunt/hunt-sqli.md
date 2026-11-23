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

## Pendalaman
Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — parafrase, fokus deteksi + validasi.

### Pola deteksi tambahan
- Error-based per jenis kutip: uji `'`, `''`, backtick, `")` — error yang berbeda per konteks mengungkap jenis query di belakangnya.
- Enumerasi kolom via ORDER BY: naikkan angka sampai error — jumlah kolom yang ketemu adalah titik awal UNION.
- Second-order SQLi: input tersimpan lalu dieksekusi di alur lain (mis. nama profil dipakai di query laporan) — uji dengan menaruh penanda lalu memicu alur kedua.
- NoSQL / array injection: operator (`$gt` / `$ne` / `$regex`) atau parameter array di body JSON — uji pada akun test sendiri; deteksi = login atau data kembali tanpa kredensial yang benar.
- Time-based per DBMS: fungsi delay berbeda tiap database (SLEEP / pg_sleep / WAITFOR) — bandingkan baseline waktu normal vs injeksi; delay harus konsisten dan berulang, bukan sekali.

### Chain tambahan
SQLi baca → enum tabel session / token → pakai session akun test lain → akses tanpa password.

### Catatan Gate-0 tambahan
- Buktikan data yang terbaca bukan milikmu: baca satu baris milik akun test keduamu; error saja tanpa data = lemah, bukan temuan.
- Delay satu kali bukan bukti — ulangi tiga kali dan bandingkan dengan baseline; server lambat bisa meniru time-based.
