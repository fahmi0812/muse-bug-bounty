# hunt-race-condition — Race Condition

Kelas: Concurrency | CWE: CWE-362 | OWASP: A04:2021

## Detection pattern
- Dua request bersamaan menghasilkan efek ganda (saldo, kupon, kuota).
- Tidak ada lock / transaksi atomik pada operasi kritis.
- Hasil berbeda saat request dikirim paralel vs berurutan.

## Payload contoh
- Kirim 2 request klaim kupon yang sama secara paralel (akun test).
- Kirim 2 request penarikan / transfer bersamaan (akun test, nominal kecil).
- Ulangi dengan jeda 0 dan jeda 100ms, bandingkan hasil.

## Bypass
- Coba paralelisme lebih tinggi bila 2 request tidak cukup.
- Coba endpoint berbeda yang menyentuh saldo yang sama.

## Chain template
Race → efek ganda → keuntungan / kerugian →
dampak — laporkan dengan bukti dua respons yang sama-sama sukses.

## Verifikasi
- Replay berurutan harus hanya sukses sekali.
- Pakai akun test + nominal kecil; batalkan efek bila bisa.
- Simpan timestamp + respons kedua request.
