# hunt-graphql — GraphQL Abuse

Kelas: API | CWE: CWE-400 / CWE-862 | OWASP: API3 / API5

## Detection pattern
- Introspeksi aktif (`__schema`) di endpoint publik.
- Query dalam (nested) tanpa batas kedalaman / kompleksitas.
- Field sensitif (password, token, email) terekspos di skema.
- Otorisasi tidak dicek per field / per objek.

## Payload contoh
- Query introspeksi `__schema { types { name } }` (baca skema saja).
- Query nested 3-5 level — uji batas kedalaman.
- Minta field `password` / `email` pada objek user lain (akun test).

## Bypass
- Coba alias field bila nama field sensitif diblokir.
- Coba fragment bila query langsung diblokir.

## Chain template
Introspeksi → enum field sensitif → query objek lain (BOLA) →
dampak — laporkan dengan bukti field sensitif terekspos.

## Verifikasi
- Replay dengan akun low-priv harus gagal untuk field sensitif.
- Jangan ambil data user nyata; pakai akun test.
- Simpan query + respons (redaksi data sensitif).
