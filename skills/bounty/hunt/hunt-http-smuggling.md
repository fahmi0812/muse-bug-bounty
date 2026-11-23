# hunt-http-smuggling — HTTP request smuggling (dua parser, satu request)

Kelas: HTTP Desync | CWE: CWE-444 | OWASP: A03:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Uji hanya dengan request biasa ke endpoint sendiri; jangan kirim request yang mengotori antrean pengguna lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Respons server tidak konsisten saat panjang body dinyatakan dengan dua cara berbeda.
- Server depan dan server belakang membaca batas request dengan cara berbeda.
- Header yang mengatur panjang body diteruskan mentah tanpa normalisasi.
- Respons tertunda atau tercampur setelah request dengan header panjang yang aneh.

## Cara menguji
- Kirim request dengan dua penanda panjang body yang bertentangan (satu request, akun test sendiri), amati apakah respons konsisten.
- Kirim request dengan penanda panjang yang tidak biasa, amati apakah server menolak atau menormalisasi.
- Bila respons menjadi tidak konsisten, hentikan pengujian dan laporkan pola yang diamati — jangan lanjutkan dengan variasi.
- Catat versi/produk server dari header respons (baca saja).

## Chain template
Desync teramati → request berikutnya tercampur → data akun test bocor ke respons lain → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Dua lapisan server menafsirkan batas request secara berbeda; header panjang tidak dinormalisasi di depan.

## Verifikasi
- Replay dengan request normal harus selalu konsisten; request aneh harus ditolak atau dinormalisasi.
- Simpan request/response + urutan waktu, redaksi isi sensitif.
