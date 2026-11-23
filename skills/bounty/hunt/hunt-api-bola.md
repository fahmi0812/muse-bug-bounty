# hunt-api-bola — Broken Object Level Authorization (BOLA)

Kelas: Broken Access Control | CWE: CWE-639 | OWASP: API1:2023

## Detection pattern
- Mengganti ID objek (`/users/123` → `/users/124`) mengembalikan data objek lain.
- Otorisasi tidak dicek per objek, hanya autentikasi.
- ID berurutan / mudah ditebak.

## Payload contoh
- Ganti `id` path/query dengan ID akun test kedua.
- Ganti `ownerId` di body request update.
- Minta objek dengan ID yang tidak dimiliki akun low-priv.

## Bypass
- Coba ID dalam format berbeda (UUID vs numerik) bila satu format diblokir.
- Coba method lain (GET vs POST) pada endpoint yang sama.

## Chain template
BOLA → baca data objek lain → ubah data objek lain →
dampak — laporkan dengan dua akun test (low vs pemilik).

## Verifikasi
- Replay dengan akun pemilik harus berhasil; akun lain harus 403.
- Pakai akun test sendiri; jangan akses data user nyata.
- Simpan request/response kedua akun (redaksi data sensitif).
