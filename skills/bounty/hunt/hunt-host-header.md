# hunt-host-header — Host header injection (header Host dipercaya mentah)

Kelas: Host Header Injection | CWE: CWE-74, CWE-20 | OWASP: A03:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Uji hanya dengan akun test sendiri; jangan meracuni cache atau tautan pengguna lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Tautan reset kata sandi di email memakai host dari header permintaan, bukan host resmi.
- Respons halaman memakai nilai header Host tanpa validasi (tautan, redirect, canonical).
- Cache menyimpan respons berdasarkan header Host, sehingga host berbeda menghasilkan isi berbeda.
- Aplikasi menerima host apa pun tanpa allowlist.

## Cara menguji
- Minta reset kata sandi untuk akun test sendiri dengan header Host yang berbeda, periksa host apa yang tertulis di tautan email.
- Buka halaman akun test dengan header Host yang berbeda, amati apakah tautan/redirect mengikuti header itu.
- Coba host yang tidak dikenal, amati apakah aplikasi menolak atau menerimanya.
- Bila cache ikut berubah, hentikan pengujian dan laporkan pola yang diamati.

## Chain template
Host dipercaya mentah → tautan reset akun test memakai host penyerang → korban yang mengklik tautan itu kehilangan token → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Header Host dipakai mentah untuk membangun tautan dan kunci cache; tidak ada allowlist host resmi.

## Verifikasi
- Replay dengan host resmi harus normal; host asing harus ditolak atau diabaikan.
- Simpan request/response + isi email akun test, redaksi isi sensitif.
