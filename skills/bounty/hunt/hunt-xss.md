# hunt-xss — Cross-Site Scripting

Kelas: Injection | CWE: CWE-79 | OWASP: A03:2021 Injection

## Detection pattern
- Input tampil kembali di halaman tanpa encoding (reflected).
- Input tersimpan lalu tampil di halaman user lain (stored).
- Input masuk ke sink DOM (`innerHTML`, `eval`, `document.write`).
- Atribut/konteks berbeda: HTML, atribut, JS string, URL.
- CSP longgar / tidak ada membuat eksekusi lebih mudah.

## Payload contoh
- `<img src=x onerror=alert(1)>` — uji eksekusi di konteks HTML.
- `"><svg onload=alert(1)>` — uji keluar dari atribut.
- `javascript:alert(1)` — uji konteks URL/href.
- `'-alert(1)-'` — uji konteks string JS.

## Bypass
- Coba tag/event alternatif bila satu tag diblokir (`svg`, `details`).
- Coba encoding / case berbeda bila filter case-sensitive.
- Cek apakah filter hanya di satu sisi (client saja = lemah).

## Chain template
XSS reflected → butuh klik korban → curi aksi sesi (laporkan dampak
nyata, jangan klaim curi cookie bila cookie HttpOnly).

## Verifikasi
- `alert(1)` di browser bersih membuktikan eksekusi, bukan sekadar tampil.
- Stored: buktikan dari akun kedua (milik sendiri) bahwa payload tampil.
- Simpan screenshot + URL, redaksi data akun lain.
