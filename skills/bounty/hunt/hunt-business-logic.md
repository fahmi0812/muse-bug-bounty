# hunt-business-logic — Business Logic Flaw

Kelas: Business Logic | CWE: CWE-840 | OWASP: A04:2021

## Detection pattern
- Alur bisa dilompati (lewati langkah bayar / verifikasi).
- Nilai negatif / nol diterima (harga, jumlah, diskon).
- Batas (kuota, percobaan) bisa diulang tanpa batas.
- Urutan langkah bisa diubah (konfirmasi sebelum bayar).

## Payload contoh
- Ubah `price` / `quantity` di body menjadi `0` atau negatif (akun test).
- Lewati langkah 2 dan langsung panggil langkah 3.
- Ulangi request klaim kupon yang sama dua kali.

## Bypass
- Coba ubah parameter di body bila UI tidak menampilkannya.
- Coba panggil endpoint langkah akhir secara langsung.

## Chain template
Lompati langkah → transaksi tidak valid → kerugian / akses gratis →
dampak — laporkan dengan transaksi test (batalkan / refund bila bisa).

## Verifikasi
- Replay alur normal harus melewati semua langkah.
- Gunakan akun + transaksi test; jangan rugikan pihak lain.
- Simpan urutan request + respons tiap langkah.
