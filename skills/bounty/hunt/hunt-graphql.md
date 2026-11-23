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

## Pendalaman
Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — parafrase, fokus deteksi + validasi.

### Pola deteksi tambahan
- Field suggestion probe: kirim field yang tidak ada — respons "Did you mean: [field asli]?" berarti skema bisa dienumerasi walau introspeksi dimatikan.
- Batch amplification: satu request berisi banyak query ber-alias — uji apakah server mengeksekusi semuanya (tanda tidak ada batas kompleksitas).
- Subscription hijack: langganan channel milik akun test lain — uji apakah event real-time akun lain sampai ke sesimu.
- Alias batching pada mutasi verifikasi: satu request berisi beberapa alias mutasi yang sama — bila semuanya dievaluasi, rate limit per-request bisa dilewati; uji dengan 2–3 alias berkode salah pada akun test sendiri, jangan menebak kode.
- RC desync: beri akses lewat REST, cabut lewat REST, lalu tegaskan lagi lewat mutasi GraphQL — bila akses kembali, otorisasi REST dan GraphQL tidak sinkron.

### Chain tambahan
Introspeksi → enum field sensitif → BOLA via `node()` → ekstraksi massal lintas tenant.

### Catatan Gate-0 tambahan
- Field harus mengembalikan data akun test lain; skema terekspos saja tanpa data = bukan temuan.
- Subscription yang hanya menerima event milik sendiri bukan celah — buktikan event akun test lain benar-benar sampai.
