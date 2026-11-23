# TEAM.md — muse-bug-bounty (v1.0.0)

Onboarding, peran, dan aturan main tim. Satu halaman ini cukup untuk
mulai berkontribusi tanpa menebak.

## Onboarding — 1 perintah

```bash
git clone https://github.com/fahmi0812/muse-bug-bounty.git && cd muse-bug-bounty && npm test
```

Lalu baca [`README.md`](../README.md) (dua mode + install) dan
[`CONTRIBUTING.md`](../CONTRIBUTING.md). Tidak ada langkah lain yang
wajib sebelum kontribusi pertama. Strix, Docker, dan provider hanya
dibutuhkan bila menjalankan hunting/bench sungguhan — bukan untuk
kontribusi kode/test/docs.

## Peran

| Peran | Boleh | Tidak boleh |
| --- | --- | --- |
| **Contributor (low)** | Docs, test, patch kecil, issue, review | Merge ke `main`, rilis, ubah scope/budget default |
| **Maintainer (high)** | Semua di atas + merge PR, rilis, ubah default | Push langsung ke `main` tanpa PR + CI hijau |
| **Reviewer** | Review PR, minta perubahan, approve | Approve PR sendiri |

- PR butuh minimal 1 approve reviewer (bukan penulis PR) + CI hijau.
- Perubahan A5 (safety envelope: guard, scope gate, rate limit,
  budget default, aturan auto-submit) butuh approve maintainer +
  dicatat di CHANGELOG.
- Tidak ada yang bekerja sendirian di area safety tanpa review.

## Aturan scope

- Hunting hanya ke target berizin, dengan scope tertulis di
  `programs/*.md`. Di luar scope = stop, tanpa kecuali.
- Lab eval (Juice Shop/DVWA/VAmPI) hanya lokal / Docker sendiri.
- Jangan pernah menguji target nyata dari repo ini tanpa program
  yang terdaftar + scope yang disetujui.
- RE / mobile / LLM red-team = mode P2 terpisah (lihat `docs/p2-*.md`)
  — hanya bila scope program mengizinkannya secara tertulis.

## Budget & rate limit (default, jangan diubah diam-diam)

- Budget: **$5/target** (`--max-budget`, default).
- Rate limit: **10 req/detik** global per target, hormati 429 + backoff.
- Naik budget di atas $5 atau ubah rate limit = keputusan maintainer,
  dicatat di PR + CHANGELOG, bukan edit diam-diam.
- `--max-turns` diturunkan untuk smoke test; `deep` hanya target final.

## Audit

- Tiap run tercatat: siapa, perintah apa, target apa, kapan
  (audit trail, P1-1). Log tidak menyimpan kredensial / PoC mentah
  tanpa redaksi.
- `bounty.db` + `evidence/` mode 0600, gitignore, tidak pernah
  di-commit. Secret-leak guard memindai output/log/laporan sebelum
  ditulis/di-commit.
- Rilis wajib lewat `bounty bench` dulu: FP turun / TP tidak turun
  vs baseline, median 3–5 run. Rilis yang gagal gate = ditahan.

## Larangan (tanpa kecuali)

- **Tidak ada auto-submit** ke HackerOne/Bugcrowd/dll. Submit selalu
  manual oleh manusia setelah review.
- **Tidak ada pembayaran/deposit** otomatis atau manual lewat tool ini.
- **Tidak ada captcha solving, bypass 2FA/OTP, brute-force OTP,
  SMS bomber**, atau alat kategori K/L (abuse/bypass).
- **Tidak ada salinan kode AGPL** (Shannon, ARTEX, VulnHunter) —
  pola saja, tulis ulang sendiri.
- **Tidak ada secret asli** di repo: pakai placeholder `REPLACE-ME`
  (lihat `.env.example`). Secret yang terlanjur masuk = rotasi +
  hapus dari histori (lihat `SECURITY.md`).
