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

## Pendalaman
Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — parafrase, fokus deteksi + validasi.

### Pola deteksi tambahan
- GraphQL `node()`: resolver global `node(id)` tanpa cek pemilik — uji dengan global ID milik akun test lain.
- ID bocor di bundle JS: cari pola ID di file JS statis — ID yang tidak tampil di UI tapi ada di bundle adalah permukaan enumerasi.
- Enum terarah: buat daftar ID di sekitar nilai yang dikenal (±500), filter respons berdasarkan panjang / status — hanya untuk akun test sendiri.
- Method tampering penuh: coba GET / POST / PUT / PATCH / DELETE / OPTIONS / HEAD ke endpoint yang sama — satu method bisa lupa cek otorisasi.
- Soft-delete IDOR: objek yang sudah dihapus masih bisa dibaca — uji ID lama milik akun testmu.

### Chain tambahan
IDOR ganti email + tanpa re-auth → minta reset password → link jatuh ke email penyerang → ATO.

### Catatan Gate-0 tambahan
- Kontrol negatif: ID acak yang tidak ada harus 404; bandingkan respons dua akun test milikmu, bukan sekadar status 200.
- Data yang "bocor" harus benar-benar milik akun lain — respons yang sama untuk semua akun (mis. data publik) bukan IDOR.
