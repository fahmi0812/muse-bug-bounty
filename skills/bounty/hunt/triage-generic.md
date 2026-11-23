# triage-generic — Triage Awal Kandidat

Kelas: Triage | CWE: CWE-707 | OWASP: — (proses)

## Detection pattern
- Ada perilaku menyimpang dari yang diharapkan aplikasi.
- Perilaku muncul konsisten di dua percobaan dengan input sama.
- Perilaku hilang saat input dikembalikan ke nilai normal.
- Ada dampak ke data/aksi akun lain, bukan sekadar tampilan aneh.
- Bukan error generik (500 tanpa detail bukan otomatis bug).

## Payload contoh
- `GET /api/profile?id=1001` sebagai user A, lalu sebagai user B.
- Ulangi request yang sama dari sesi bersih (tanpa cookie lama).
- Ganti satu parameter saja; catat mana yang mengubah hasil.

## Bypass
- N/A — ini skill penilaian, bukan eksploitasi.
- Jika kandidat "lolos" karena cache, ulangi dengan cache-buster.
- Jika hanya muncul sekali, anggap noise sampai terbukti ulang.

## Chain template
Sinyal mentah → replay bersih → kontrol negatif → verdict
(`triage-validation.md`) → laporan atau buang.

## Verifikasi
- Replay dari sesi bersih dengan langkah bernomor.
- Kontrol negatif: akun tanpa hak harus gagal.
- Bukti: request/response kunci, sudah diredaksi.
- Tidak bisa replay → UNVERIFIED.
