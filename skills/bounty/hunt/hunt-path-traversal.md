# hunt-path-traversal — Path Traversal

Kelas: Broken Access Control | CWE: CWE-22 | OWASP: A01:2021

## Detection pattern
- Parameter nama file (`file`, `path`, `download`) menerima `../`.
- Respons mengembalikan isi file di luar direktori yang dimaksud.
- Error berisi path absolut server.

## Payload contoh
- `../` diulang pada parameter file (lab saja, target file milik lab).
- `....//` bila filter `../` sederhana aktif.
- Encoding `%2e%2e%2f` bila perlu.

## Bypass
- Coba absolute path bila traversal relatif diblokir.
- Coba null byte / ekstensi ganda bila ada filter ekstensi.

## Chain template
Traversal → baca file konfigurasi lab → bukti akses di luar scope path →
dampak (baca data sensitif) — laporkan di titik bukti cukup.

## Verifikasi
- Replay dengan path normal harus kembali normal.
- Buktikan hanya dengan file lab / akun sendiri; jangan baca file sistem nyata.
- Simpan request/response, redaksi isi file sensitif.
