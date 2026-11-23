# hunt-file-upload — Unrestricted File Upload

Kelas: Upload | CWE: CWE-434 | OWASP: A03:2021

## Detection pattern
- Upload menerima ekstensi eksekusi (`.php`, `.jsp`, `.html`) tanpa validasi.
- File yang diunggah bisa diakses lewat URL publik.
- Validasi hanya di sisi klien (Content-Type / ekstensi di JS).

## Payload contoh
- Unggah file `.html` berisi teks penanda (bukan skrip aktif) — uji apakah bisa diakses.
- Unggah file dengan ekstensi ganda `file.php.txt`.
- Ubah `Content-Type` dari `image/png` ke `text/html`.

## Bypass
- Coba kapitalisasi ekstensi (`.PHP`) bila filter case-sensitive.
- Coba null byte / karakter khusus bila ada filter nama.

## Chain template
Upload lolos → file bisa diakses publik → eksekusi / XSS tersimpan →
dampak — laporkan di titik file bisa diakses, tanpa eksekusi kode.

## Verifikasi
- Replay dengan file gambar valid harus lolos normal.
- Jangan unggah file eksekusi nyata; bukti cukup file penanda non-aktif.
- Hapus file test setelah verifikasi bila bisa.
