# hunt-broken-access — Broken Access Control

Kelas: Access Control | CWE: CWE-284 | OWASP: A01:2021 Broken Access Control

## Detection pattern
- Menu admin disembunyikan di UI, tapi endpoint-nya merespons user biasa.
- API mengizinkan aksi role tinggi tanpa cek role di server.
- Parameter `role` / `is_admin` bisa diubah di request.
- Fitur "hanya pemilik" bisa dipakai ke objek orang lain.

## Payload contoh
- `GET /admin/users` sebagai user biasa.
- `POST /api/users/7/promote {"role":"admin"}` sebagai user biasa.
- `DELETE /api/posts/123` untuk post milik user lain.
- Tambah header/cookie role secara manual lalu ulangi request.

## Bypass
- Coba method lain ke endpoint yang sama (GET ditolak, POST lolos).
- Coba endpoint lama / versi API lama (`/v1/admin/...`).
- Coba akses langsung tanpa melewati UI (curl / repeater).

## Chain template
Akses fungsi admin → ubah role / baca data sensitif → eskalasi penuh.

## Verifikasi
- Kontrol negatif: user biasa harus 403; admin harus 200.
- Buktikan perubahan benar terjadi di server (baca ulang datanya),
  bukan hanya respons 200.
- Pakai dua akun milik sendiri; jangan ubah data user nyata.
