# hunt-idor — Insecure Direct Object Reference

Kelas: Broken Access | CWE: CWE-639 | OWASP: A01:2021 Broken Access Control

## Detection pattern
- ID objek (angka/UUID) di URL atau body, tanpa cek kepemilikan.
- Mengganti ID menampilkan data akun lain.
- API mengembalikan objek lengkap padahal UI hanya menampilkan sebagian.
- ID berurutan / mudah ditebak (1001, 1002, …).

## Payload contoh
- `GET /api/orders/1002` saat login sebagai pemilik order 1001.
- `GET /api/users/42/profile` dengan ID user lain.
- Ubah `"id": 1001` menjadi `"id": 1002` di body request.
- Coba ID lama / yang sudah dihapus — kadang masih bisa dibaca.

## Bypass
- Coba ganti format ID (angka → UUID, atau sebaliknya).
- Coba method lain (GET gagal, coba POST/PUT ke endpoint sama).
- Coba tanpa parameter ID — kadang server pakai default orang lain.

## Chain template
IDOR baca → enum ID lain → kumpulkan data sensitif → (bila bisa tulis)
IDOR tulis → ubah data orang lain.

## Verifikasi
- Akun A tidak boleh membaca milik akun B; buktikan dengan dua akun
  milik sendiri (lab / akun test).
- Kontrol negatif: ID acak yang tidak ada harus 404, bukan data orang.
- Simpan respons kedua akun sebagai bukti perbandingan.
