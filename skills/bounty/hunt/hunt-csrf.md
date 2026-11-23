# hunt-csrf — Cross-Site Request Forgery

Kelas: CSRF | CWE: CWE-352 | OWASP: A01:2021 Broken Access Control

## Detection pattern
- Aksi sensitif (ganti email, password, transfer) tanpa token anti-CSRF.
- Token ada tapi tidak divalidasi server (hapus token → tetap berhasil).
- Token tidak terikat ke sesi (token akun A bisa dipakai akun B).
- Cek `Origin`/`Referer` tidak ada atau mudah dilewati.

## Payload contoh
- Form HTML lintas situs yang POST ke endpoint target (halaman PoC lokal).
- Hapus parameter `_csrf` / `csrf_token` dari request, ulangi.
- Ganti token dengan nilai acak, ulangi.
- Coba GET untuk aksi yang seharusnya POST.

## Bypass
- Coba token kosong vs token salah — keduanya lolos = tidak divalidasi.
- Coba ubah `Content-Type` ke `text/plain` bila ada cek header.
- Coba hapus header `Origin` bila validasi hanya saat header ada.

## Chain template
CSRF ganti email → reset password → ambil alih akun (jelaskan rantai
penuh, jangan eksekusi ambil alih akun nyata).

## Verifikasi
- PoC lintas situs dari origin berbeda harus berhasil di browser bersih.
- Kontrol: request tanpa cookie korban harus gagal.
- Dampak harus aksi nyata di server, bukan sekadar respons 200.
