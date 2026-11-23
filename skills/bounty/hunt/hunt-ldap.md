# hunt-ldap — LDAP & XPath Injection

Kelas: Injection | CWE: CWE-90, CWE-91 | OWASP: A03:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan mengekstrak atribut pengguna lain secara massal; blind exfil cukup buktikan oracle-nya pada atribut akun test sendiri.
- Jangan tebak/brute-force password via LDAP; jangan klaim hash AD bisa dibaca — `unicodePwd` write-only.

## Detection pattern
- Login/SSO/pencarian direktori (`/api/ldap/*`, `/people`, `/address-book`) dengan backend LDAP/AD.
- Error yang mengonfirmasi LDAP: `InvalidSearchFilterException`, `LDAP: error code 49`, `Bad search filter`, `javax.naming.*`, `System.DirectoryServices`, `ldap_search()`.
- Karakter spesial RFC 4515 (`* ( ) \ NUL /`) yang tidak di-escape mengubah perilaku (error sintaks / hasil berbeda).
- AD vs LDAP generik: `userPassword` `{SSHA}` hanya bisa dibaca di OpenLDAP/389-DS; di AD tidak ada atribut hash yang bisa dibaca — yang bisa diekspos: `sAMAccountName`, `memberOf`, `description` (sering berisi secret plaintext).

## Sinyal uji
- Baseline dulu: login format-valid + password salah → catat status/ukuran respons.
- Kirim satu `)` tak seimbang: aplikasi aman → sama dengan baseline; aplikasi rentan → 500 / filter-syntax error.
- Bypass auth: payload yang menutup grup `(uid=...)` lalu OR selalu-benar — sukses HANYA bila sesi valid + resource pasca-login bisa diakses (bukan sekadar halaman error berbeda).
- Kontrol negatif wajib: payload bentuk sama tapi logika SALAH harus gagal — bila keduanya "sukses", endpoint-nya yang rusak, bukan injeksi.
- Blind exfil: pasangkan kontrol TRUE vs FALSE (ukuran/status/marker), lalu ekstrak per karakter; tiap karakter positif diulang 3x agar stabil.
- XPath: payload `' or '1'='1` dengan quote/bracket seimbang (XPath tanpa komentar) — login ke konteks akun nyata = terbukti.

## Bypass
- DN injection beda dari filter injection: di DN, `, = + " \ < > ; /` yang bermakna, bukan `*` — uji keduanya, payload tidak bisa ditukar.
- NUL (`%00`) memotong filter di server berbasis C.

## Chain template
Filter login selalu-benar → masuk sebagai entri direktori pertama (admin) → panel SSO/admin. Atau: enumerasi `sAMAccountName`/`memberOf` → daftar admin → spray/phishing tertarget. Atau (non-AD): exfil `userPassword` → crack offline.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Input user digabung ke filter LDAP/DN tanpa escaping RFC 4515; kurung tidak diseimbangkan dengan aman; atribut sensitif (`description`, `userPassword`) bisa dibaca ACL longgar.

## Verifikasi
- Bypass wajib sesi valid + kontrol negatif gagal + satu paren dilepas menghasilkan syntax error (membuktikan filter dieksekusi).
- Blind exfil: nilai yang pulih diverifikasi lewat lookup langsung atau payload bypass yang memakainya.
- Jangan pernah klaim "ekstrak hash AD" — di AD yang bisa dibaca hanya enumerasi + `description`.
