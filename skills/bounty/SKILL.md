---
name: bounty
description: Bug bounty web-first — cari kerentanan di target yang berizin, dari scope sampai laporan. Dipakai saat user minta hunt/triage bug bounty, cek scope program, atau tulis laporan. Jangan dipakai untuk target tanpa izin tertulis.
---

# Skill: bounty (Mode 1 — utama)

Mode utama repo ini. Mode 2 adalah CLI standalone `bounty` — alternatif
saja, bukan pengganti skill ini; alur dan larangan di bawah berlaku sama.

## Kapan dipakai

- User minta cari bug di sebuah target / program bounty.
- User minta triage, verifikasi, atau tulis laporan temuan.
- User minta threat model sebelum hunting.

## Larangan tegas (tidak bisa dinegosiasi)

- Tanpa scope tertulis di `programs/*.md` + hasil cek **Scope OK**, JANGAN scan.
- Tanpa auto-submit: laporan tidak pernah dikirim otomatis ke platform.
- Tanpa payment / deposit / pembelian apa pun.
- Tanpa target dari daftar K/L (abuse / bypass / spam / jailbreak).
- Tanpa membaca `.env`, kunci privat, kredensial, atau file rahasia lain.
- Tanpa payload destruktif massal, tanpa DoS, tanpa data orang lain.

## Alur (8 langkah)

1. **Scope.** Baca `programs/<nama>.md` yang relevan. Catat Allowed /
   Denied, budget, rate limit, jam otomasi. Jika target tidak ada di
   daftar Allowed → berhenti, laporkan ke user. Tulis `Scope OK` + sumber.
2. **Threat model.** Isi `templates/threat-model.md` (aset, aktor, trust
   boundary, STRIDE singkat, prioritas). Tanpa ini, hunting buta.
3. **Router skill.** Pilih top-5 skill dari `skills-index.json` yang
   paling cocok dengan threat model (berdasar `keywords` + `when`).
   Jangan jalankan semua skill sekaligus.
4. **Hunt.** Jalankan skill top-5 satu per satu, dari file
   `hunt/<nama>.md`. Catat kandidat + bukti mentah (request/response).
5. **Verifikasi adversarial.** Buka `verify-adversarial.md`: tugasnya
   MEMBANTAH kandidat, bukan membenarkannya. Replay dari nol di sesi
   bersih. Jika tidak bisa di-replay → label **UNVERIFIED**, jangan
   naikkan severity.
6. **Dedup.** Cek Hacktivity / laporan program + temuan sendiri.
   Duplikat → buang, catat alasannya.
7. **Review manual.** Baca ulang bukti sebelum menulis laporan.
   Pastikan tidak ada cookie, token, atau PII di bukti
   (lihat `evidence-hygiene.md`).
8. **Laporan.** Tulis draf dari `templates/report-hackerone.md` atau
   `templates/report-bugcrowd.md`, lalu `report-writing.md` checklist.
   Serahkan draf ke user — user yang submit.

## 7-Question Gate (sebelum klaim "ini bug")

Lihat `bb-methodology.md`. Jika satu pertanyaan gagal dijawab dengan
bukti, temuan turun ke `needs_validation` (lihat `triage-validation.md`).

## File terkait

- `skills-index.json` — router skill (30 entri).
- `hunt/*.md` — skill per kelas kerentanan.
- `bb-methodology.md`, `triage-validation.md`, `verify-adversarial.md`,
  `report-writing.md`, `evidence-hygiene.md`, `js-bundle-analysis.md`.
- `../../templates/` — laporan + threat model.
- `../../programs/` — scope program + lab.
