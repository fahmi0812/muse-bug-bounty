# hunt-dom — DOM XSS (data pengguna dieksekusi di browser)

Kelas: Cross-Site Scripting (DOM) | CWE: CWE-79 | OWASP: A03:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Uji hanya di browser akun test sendiri; jangan kirim tautan berisi data uji ke orang lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Nilai dari URL atau input pengguna ditulis kembali ke halaman tanpa penyandian.
- Kode JavaScript aplikasi membaca data dari URL lalu menampilkannya sebagai markup.
- Library atau framework lama yang menempelkan HTML mentah dari data pengguna.
- Pesan kesalahan atau pratinjau yang menampilkan kembali input apa adanya.

## Cara menguji
- Baca bundle JavaScript aplikasi target, cari tempat data URL/input ditampilkan sebagai markup.
- Masukkan teks penanda yang tidak berbahaya (misalnya string unik) lewat parameter, lihat apakah muncul kembali tanpa penyandian.
- Bila penanda muncul sebagai teks biasa yang disandikan, catat aman dan berhenti.
- Bila penanda muncul sebagai markup aktif, buktikan hanya di sesi akun test sendiri lalu hentikan pengujian.

## Chain template
Input tampil sebagai markup aktif → sesi akun test terpengaruh → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Data pengguna ditampilkan sebagai markup tanpa penyandian; sink DOM yang berbahaya dipakai dengan data yang tidak dipercaya.

## Verifikasi
- Replay dengan input normal harus tampil sebagai teks biasa yang disandikan.
- Simpan URL uji + tangkapan respons, redaksi isi sensitif.
