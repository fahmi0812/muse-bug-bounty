# hunt-nosqli — NoSQL Injection

Kelas: Injection | CWE: CWE-943 | OWASP: A03:2021 Injection

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan ekstrak data user nyata, jangan hapus/ubah data.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Login/form menerima JSON dan perilaku berubah saat nilai diganti objek (`{"$ne": null}`).
- Operator query (`$gt`, `$regex`, `$where`) memengaruhi hasil pencarian/login.
- Error menampilkan sintaks MongoDB / nama koleksi.
- Pencarian mengembalikan data yang seharusnya terfilter oleh peran.

## Payload contoh
- `{"username": "akun-test", "password": {"$ne": ""}}` — uji operator pada login (akun test saja).
- `{"q": {"$regex": "^a"}}` — uji apakah regex memengaruhi pencarian.
- `{"$where": "sleep(100)"}` — JANGAN dipakai; uji time-based hanya dengan delay kecil di lab (`{"$where": "1==1"}` untuk deteksi, bukan sleep).
- Parameter URL `?id[$ne]=x` — uji parsing operator lewat query string.

## Bypass
- Coba operator lain (`$gt`, `$in`, `$exists`) bila satu operator diblokir.
- Coba JSON vs form-encoded bila satu format disaring.
- Bila WAF memblokir, catat dan berhenti — jangan spam variasi.

## Chain template
NoSQLi (bypass filter/login) → baca data koleksi lain → eskalasi peran → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Input JSON user diteruskan sebagai query NoSQL tanpa validasi tipe; operator query tidak pernah diblokir di lapisan aplikasi.

## Verifikasi
- Replay dengan input normal harus kembali normal; operator harus ditolak bila aman.
- Buktikan dengan akun test sendiri; jangan baca data user nyata.
- Simpan request/response, redaksi token/cookie.
