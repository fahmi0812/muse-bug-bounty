# Contributing — muse-bug-bounty

Terima kasih sudah mau berkontribusi. Repo ini kecil dan dijaga tetap
sederhana: nol dependensi, $0, tanpa auto-submit.

## Cara kontribusi

1. Fork repo, buat branch dari `main` (`feat/<nama>` / `fix/<nama>` /
   `docs/<nama>`).
2. Jalankan `npm test` — semua test harus hijau sebelum PR.
3. Buat PR dengan deskripsi singkat: apa yang diubah, kenapa, dan
   hasil test/bench bila relevan.
4. PR butuh 1 approve reviewer (bukan penulis) + CI hijau (lihat
   `docs/TEAM.md` untuk peran).

## Aturan kode

- Node.js >= 20, ESM (`"type": "module"`), nol dependensi baru tanpa
  alasan tertulis di PR. Jangan tambah dependensi hanya karena nyaman.
- Test pakai `node:test` + `node:assert/strict`, tanpa network /
  Docker / Strix (test harus jalan di mesin mana pun dengan `npm test`).
- Satu PR = satu perubahan. Jangan campur fitur + refactor + docs
  besar dalam satu PR.
- Jalankan `node --check` untuk file JS yang diubah.

## Aturan konten & safety (wajib)

- Jangan commit secret asli apa pun: API key, token, password,
  cookie/session. Pakai placeholder `REPLACE-ME` (lihat `.env.example`).
- Jangan salin kode AGPL (Shannon, ARTEX, VulnHunter) — pola saja,
  tulis ulang sendiri. Lisensi repo Apache-2.0; simpan notice Strix
  (Apache-2.0) bila menyentuh fork.
- Jangan tambah auto-submit ke platform bounty, pembayaran/deposit,
  captcha solving, bypass 2FA/OTP, atau alat kategori K/L (abuse/bypass).
- Jangan tambah target nyata / scope program tanpa izin tertulis
  program tersebut. Contoh program hanya `example.com` dan lab lokal.
- Perubahan safety (guard, scope gate, rate limit, budget default)
  = kelas A5: butuh approve maintainer + entri CHANGELOG.

## Docs

- Dokumen P2 ada di `docs/p2-*.md` — mode terpisah, docs saja, tanpa
  binary/berat. Tambah docs P2 baru dengan pola yang sama: kapan
  dipakai, checklist, batasan, larangan.
- Perbarui `CHANGELOG.md` untuk tiap rilis (fitur + batasan).

## Melapor masalah

- Bug / ide: buka issue GitHub dengan langkah reproduksi.
- Kerentanan keamanan: **jangan** buka issue publik — lihat
  `SECURITY.md`.
