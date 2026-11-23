# hunt-jwt — JWT Weakness

Kelas: Broken Authentication | CWE: CWE-347 | OWASP: A07:2021

## Detection pattern
- Token memakai algoritma `none` dan diterima server.
- Signature tidak divalidasi (ubah payload, token tetap valid).
- Kunci lemah / publik (mis. kunci publik dipakai sebagai HMAC secret).
- `kid` / `jku` bisa diarahkan ke URL kontrol penyerang.

## Payload contoh
- Ubah `alg` ke `none` dan hapus signature (akun test saja).
- Ubah klaim `role` dari `user` ke `admin` tanpa ubah signature — uji validasi.
- Ganti `kid` dengan path file lokal (lab saja).

## Bypass
- Coba `alg: none` dengan variasi casing.
- Coba kunci kosong / kunci default yang umum di lab.

## Chain template
JWT lemah → ubah klaim → akses peran lain →
dampak (baca/ubah data akun lain) — laporkan dengan token test.

## Verifikasi
- Replay dengan token asli harus normal; token ubahan harus ditolak bila aman.
- Gunakan akun test sendiri; jangan pakai token user nyata.
- Redaksi token di bukti (tampilkan header/payload saja, bukan signature penuh).
