# sql-wordlist — Wordlist SQL Terkurasi (Kecil)

> Atribusi: daftar ini dikurasi dari nol untuk repo ini — payload generik
> yang umum dipakai untuk deteksi SQLi. **Bukan impor verbatim** dari
> wordlist SQL-Wordlist: 1.000 baris pertama wordlist aslinya hanya angka
> 1–1000 (tidak bermakna sebagai payload) dan kualitasnya diragukan,
> jadi angka-angka itu dibuang di sini.

## Kapan dipakai

- Fuzzing parameter yang dicurigai SQLi (lihat `hunt-sqli.md`) dengan
  ffuf/sqlmap sebagai titik awal — digabung dengan payload bawaan
  ffuf/sqlmap dan skill hunt, bukan dipakai sendirian.
- File data: `data/sql-wordlist-curated.txt` (±50 baris payload bermakna).

## Peringatan kualitas

- Wordlist bukan bukti: tiap payload yang "kena" harus diverifikasi
  dengan replay + kontrol negatif (lihat `verify-adversarial.md`).
- Jangan pakai payload destruktif: file ini **tidak mengandung**
  `DROP TABLE` / `DELETE FROM` / penghapusan massal — dan jangan
  menambahkannya.
- Jangan brute-force massal ke target nyata: pakai delay kecil,
  hormati rate limit program (default 10 req/detik), hentikan bila
  WAF memblokir.
- Time-based: pakai delay kecil (1–2 detik) saja, jangan SLEEP(30).

## Kategori payload (di file data)

1. Deteksi (kutip, komentar, logika boolean).
2. Union-based (uji jumlah kolom, baca terbatas).
3. Error-based (ekstrak lewat pesan error).
4. Time-based (delay kecil).
5. Bypass filter ringan (komentar, case, spasi).

## Verifikasi non-destruktif

- Buktikan dengan satu baris data milik akun sendiri / lab — jangan
  ambil data user nyata.
- Replay input normal harus kembali normal.
- Simpan request/response, redaksi token/cookie.
