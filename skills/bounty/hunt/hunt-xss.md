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

## Pendalaman
Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — parafrase, fokus deteksi + validasi.

### Pola deteksi tambahan
- Context probe: kirim satu string berisi semua pembatas (tanda kutip, `<`, `>`, backtick) lalu lihat yang mana lolos encoding — itu menentukan konteksnya (HTML / atribut / JS / URL).
- Blind / stored OOB: pasang beacon ke server log milikmu; yang dihitung adalah eksekusi di sesi bersih lain, bukan sekadar payload tampil di responsmu sendiri.
- Sanitizer bypass: kombinasi tag bersarang (math/style, svg/style) — sanitizer yang hanya memblokir satu tag bisa dilewati kombinasi.
- Link `javascript:` / markdown: konten yang dirender sebagai link — uji klik di sesi test sendiri.
- DOM sink via hash: ubah fragment URL lalu lihat apakah datanya masuk ke sink (`innerHTML` / `eval`) tanpa reload dari server.

### Chain tambahan
XSS reflected + cache poisoning → payload tersimpan di CDN → eksekusi ke semua pengunjung (kelas Kettle).

### Catatan Gate-0 tambahan
- `alert(1)` di browser bersih = bukti eksekusi; payload yang hanya tampil di HTML tanpa eksekusi bukan XSS.
- Stored harus dibuktikan dari akun kedua (milik sendiri) bahwa payload tampil di sesi lain — pantulan di sesimu sendiri tidak cukup.
