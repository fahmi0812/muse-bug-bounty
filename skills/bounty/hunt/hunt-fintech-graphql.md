# hunt-fintech-graphql — Fintech GraphQL / Money Movement

Kelas: Business Logic / Broken Access Control | CWE: CWE-862, CWE-840 | OWASP: A04:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high) — jangan pakai akun korban, jangan gerakkan uang nyata.
- Uji dengan jumlah minimal (sen/rupiah terkecil); jangan lakukan transfer/penarikan nyata ke akun luar.
- Jangan brute force idempotency key / nomor akun; berhenti saat kena rate limit / 429.

## Detection pattern
- API GraphQL di depan ledger/dompet/pembayaran: field `balance`, `transferFunds`, `withdraw`, `redeem`, `topUp`, `ledgerEntry`, `kycStatus`, `idempotencyKey`, skalar `Money`/`Decimal`.
- Introspeksi/schema memperlihatkan mutasi uang + tipe `User`/`Account` berisi `ssnLast4`, `routingNumber`, `governmentIdUrl` di samping field biasa.
- Mutasi menerima `amount` sebagai string/float dari klien (bukan hasil hitung server).
- Satu mutasi menulis beberapa entri ledger (debit + kredit + fee) — kandidat race/double-spend.

## Sinyal uji
- Idempotency: kirim mutasi yang sama (satu `idempotencyKey`) dua kali — dua `transactionId` berbeda yang sukses = idempotency tidak ditegakkan (replay = eksekusi ganda).
- Presisi desimal: jumlah sub-sen, notasi ilmiah, nilai sangat besar, jumlah negatif — bandingkan saldo sebelum/sesudah; drift pembulatan yang terakumulasi = temuan.
- IDOR sumber: mutasi transfer dengan `sourceAccountId` milik akun lain + `destAccountId` milikmu — sukses = ownership sumber tidak dicek (periksa hanya tujuan saja tidak cukup).
- PII nested: query `transaction { counterparty { ssnLast4 routingNumber kycStatus } }` sebagai pengguna tak terkait — field sensitif yang tampil = field-level authz hilang.
- Mass assignment: kirim field `status`/`override` pada input mutasi yang UI tidak pernah tampilkan.

## Bypass
- Alias batching: beberapa alias mutasi yang sama dalam satu request — bila lebih dari satu sukses untuk reward sekali pakai, resolver tidak menyerikan tulis per akun.
- Cek konsistensi mata uang: `sourceCurrency`/`targetCurrency` yang UI tidak pernah hasilkan — selisih kurs antara lookup dan tulis ledger = celah arbitrase.

## Chain template
Skema fintech terpetakan → mutasi uang tanpa idempotency/serialisasi → replay/alias batching → double-spend / saldo bertambah. Atau: IDOR sumber → debit akun korban → kredit ke akun sendiri. Buktikan dengan perubahan saldo sebelum/sesudah.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Validasi jumlah/fee hanya di klien; tulis ledger multi-entri tidak atomik; skalar `Money` jatuh ke float; idempotency key disimpan tapi tidak dicek; otorisasi field diterapkan per query atas, bukan per tipe; input admin dipakai ulang untuk mutasi publik.

## Verifikasi
- Wajib ada perubahan state ledger (saldo sebelum vs sesudah) — respons sukses saja bukan bukti.
- Race/double-spend: reproduksi 2x dari state bersih; bila hanya kadang berhasil, dokumentasikan jujur window-nya.
- Error verbose pada skalar `Money` yang rusak = temuan leak, bukan temuan logika — jangan dicampur.
