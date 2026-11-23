# report-writing — Menulis Laporan Bounty

## Template judul
`[Kelas] di [fitur/endpoint]: [dampak singkat]`
Contoh: `IDOR di /api/orders: user biasa membaca order user lain`
Hindari judul clickbait; satu temuan = satu laporan.

## Severity — CVSS 3.1
- Hitung skor CVSS 3.1 dari vektor, jangan tebak dari "rasa".
- Tulis vektor lengkap, mis. `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`.
- Jika dampak butuh interaksi korban, naikkan UI, turunkan skor jujur.
- Severity platform (HackerOne/Bugcrowd) mengikuti CVSS + konteks
  program, bukan keinginan hunter.

## Struktur laporan
1. Summary — 2–3 kalimat: apa, di mana, dampak.
2. Steps to Reproduce — bernomor, dari akun bersih, bisa diikuti orang lain.
3. Impact — siapa terdampak, data apa bocor / aksi apa terjadi.
4. Evidence — request/response + screenshot, sudah diredaksi.
5. Fix — saran perbaikan singkat dan spesifik (bukan "perbaiki keamanan").

## Pre-submit checklist
- [ ] Satu temuan per laporan, tidak digabung.
- [ ] Steps to Reproduce sudah dicoba ulang dari sesi bersih.
- [ ] CVSS + CWE + OWASP terisi dan konsisten dengan bukti.
- [ ] Bukti diredaksi (lihat `evidence-hygiene.md`).
- [ ] Dedup: cek Hacktivity / laporan program + temuan sendiri.
- [ ] Scope: endpoint ada di Allowed, bukan Denied.
- [ ] Tidak ada data orang lain di bukti; lab pakai akun sendiri.
- [ ] Draf dibaca ulang sekali — user yang submit, bukan agen.
