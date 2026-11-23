# hunt-ssti — Server-Side Template Injection

Kelas: Injection | CWE: CWE-94 | OWASP: A03:2021 Injection

## Detection pattern
- Input tampil kembali setelah dievaluasi (bukan sekadar dicetak).
- Ekspresi matematika di input dihitung server (`7*7` → `49`).
- Error template engine muncul (Jinja, Twig, Freemarker, dll).
- Field nama / pesan / template email memakai input user.

## Payload contoh
- `{{7*7}}` — uji Jinja/Twig (hasil `49` = dievaluasi).
- `${7*7}` — uji Freemarker / EL.
- `#{7*7}` — uji variasi expression language.
- `{{7*'7'}}` — uji string agar tidak tertukar dengan angka biasa.

## Bypass
- Coba sintaks engine lain bila satu sintaks tidak bereaksi.
- Coba lewat field berbeda (nama profil, komentar, template email).
- Bila output di-encode, cek sumber respons / error log.

## Chain template
SSTI hitung → baca objek / config engine → RCE (hanya di lab;
di target nyata berhenti di bukti evaluasi + dampak baca terbatas).

## Verifikasi
- `7*7` → `49` di server membuktikan evaluasi, bukan tampilan.
- Buktikan dengan ekspresi kedua yang berbeda hasilnya.
- Jangan jalankan perintah sistem di target nyata.
