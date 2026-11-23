# Security Policy — muse-bug-bounty

## Cara melapor kerentanan

Jangan buka issue publik untuk kerentanan keamanan.

- Lapor lewat **GitHub Security Advisory** (tab Security →
  Report a vulnerability) di repo `fahmi0812/muse-bug-bounty`, atau
  email maintainer repo bila tercantum di profil.
- Sertakan: deskripsi, langkah reproduksi, dampak, dan bila ada
  perbaikan yang disarankan. Jangan sertakan secret asli / data
  korban / PoC yang menyerang target nyata.
- Kami akan mengonfirmasi penerimaan laporan, memperbaiki, lalu
  mengumumkan di CHANGELOG setelah perbaikan rilis. Jangan publikasikan
  kerentanan sebelum perbaikan rilis (coordinated disclosure).

## Scope

Yang termasuk scope keamanan repo ini:

- Wrapper `bounty` (scope gate, pre-execution guard, rate limiter,
  store `bounty.db`, provider picker, installer).
- Skill Muse (`skills/bounty/`), template laporan, dan eval harness.
- CI + secret-leak guard (P1-1).

Yang **di luar scope** repo ini (laporkan ke pemiliknya, bukan ke sini):

- Kerentanan di Strix upstream (`usestrix/strix`) — lapor ke upstream.
- Kerentanan di lab eval (Juice Shop/DVWA/VAmPI) — lapor ke lab terkait.
- Kerentanan di target bounty nyata — lapor lewat program bounty
  resmi target itu (HackerOne/Bugcrowd/dll), **bukan** lewat repo ini.

## Aturan keamanan repo

- **Tidak ada auto-submit** ke platform bounty; submit selalu manual
  oleh manusia setelah review.
- **Tidak ada pembayaran/deposit** lewat tool ini.
- **Tidak ada secret asli** di repo (cek `.env.example` — hanya
  placeholder `REPLACE-ME`). `bounty.db`, `evidence/`,
  `providers.json`, `credentials.json`, `.env` masuk `.gitignore`
  dan bermode 0600.
- Secret-leak guard memindai output/log/laporan sebelum ditulis /
  di-commit; temuan secret = blokir.
- Scope gate fail-closed: scope kosong / host tak dikenal = ditolak.
- Pre-execution guard memblokir perintah destruktif (`rm -rf`,
  `git push/reset/clean`, tulis di luar workspace, baca `.env`/key).
- Rate limit default 10 req/detik + budget default $5/target.

## Bila secret terlanjur ter-commit

1. Rotasi secret itu di sumbernya **segera** (anggap sudah bocor).
2. Hapus dari histori (bukan cuma commit baru) dan beri tahu maintainer.
3. Jangan kirim secret asli lewat issue/PR/chat — pakai placeholder.
