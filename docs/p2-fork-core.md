# P2 — Fork core Strix penuh (opsi jangka panjang)

> Status: **P2 / docs saja.** Belum ada fork, belum ada patch core di luar
> 4 patch kecil v1 (scope gate, pre-execution guard, rate limiter, hook
> store — lihat plan v3.1 § Arsitektur). Dokumen ini menyiapkan jalurnya
> supaya kalau extension-first mentok, fork bisa dimulai tanpa menebak.

## Kapan fork diperlukan

Fork core penuh hanya bila salah satu terjadi dan terbukti di eval:

1. Extension-first tidak bisa mengubah perilaku Strix yang dibutuhkan
   (mis. alur agen internal, cara Strix memanggil tool, format output
   yang tidak bisa dipetakan lewat `--skills-dir`).
2. Patch yang dibutuhkan harus hidup di dalam loop utama Strix, bukan
   di wrapper `bounty`.
3. Baseline eval menunjukkan batas extension (TP/FP mentok) dan ada
   hipotesis konkret bahwa patch core memperbaikinya.

**Aturan:** fork bukan jalan pintas. Setiap patch core harus punya
alasan tertulis + metrik eval sebelum/sesudah (`bounty bench`, median
3–5 run). Tanpa itu, tetap extension-first.

## Struktur fork

- Fork: `fahmi0812/strix` (nama final diputuskan Fahmi; repo upstream
  tetap `usestrix/strix`, Apache-2.0 — simpan notice lisensi).
- Remote:
  - `origin` → fork sendiri.
  - `upstream` → `https://github.com/usestrix/strix.git`.
- Branch:
  - `main` — mirror upstream + merge rebase berkala, **tanpa patch
    langsung**.
  - `patch/<nama-fitur>` — satu branch per patch, mis.
    `patch/scope-gate-core`, `patch/rate-limiter-core`.
  - `bounty/<versi>` — branch integrasi: gabungan patch yang sudah
    lolos eval, tempat `bounty bench` dijalankan.
- Patch tidak pernah dicampur dalam satu branch: satu fitur = satu
  branch = satu PR ke `bounty/<versi>` = satu entri eval.

## Rebase berkala

Skrip: [`scripts/rebase-upstream.sh`](../scripts/rebase-upstream.sh).
Jalankan dari clone fork:

```bash
bash scripts/rebase-upstream.sh
```

Yang dilakukan skrip (aman, tanpa force-push ke branch orang lain):

1. `git fetch upstream` — ambil perubahan terbaru Strix.
2. Pastikan working tree bersih; kalau kotor, berhenti (jangan rebase
   dengan perubahan setengah jalan).
3. Checkout `main`, rebase ke `upstream/main` (fast-forward bila bisa).
4. Untuk tiap branch `patch/*`: rebase ke `main` yang baru, satu per
   satu; kalau konflik, berhenti di branch itu dan laporkan — selesaikan
   manual, jangan `--skip` buta.
5. Tidak pernah `git push --force` ke `main` fork tanpa konfirmasi
   eksplisit; push patch branch biasa saja.

Jadwal: rebase tiap rilis Strix minor, atau minimal tiap eval besar
(sebelum `bounty bench` rilis). Catat hasil rebase di CHANGELOG.

## Aturan patch

- Patch sekecil mungkin; satu patch = satu perilaku.
- Tiap patch: tes di `tests/` + entri eval (`bounty bench` sebelum vs
  sesudah, median 3–5 run).
- Patch yang menurunkan TP atau menaikkan FP di atas ambang → ditahan,
  tidak masuk `bounty/<versi>`.
- Jangan salin kode AGPL (Shannon, ARTEX, VulnHunter) ke fork
  Apache-2.0 — pola saja, tulis ulang sendiri.
- Lisensi: fork tetap Apache-2.0; file `LICENSE` + `NOTICE` upstream
  dipertahankan.

## Keluar dari fork (jalan kembali)

Kalau upstream Strix akhirnya menyediakan hook yang sama dengan patch
kita, patch dihapus dari `bounty/<versi>` dan kembali ke extension.
Fork tetap ada sebagai arsip; `main` fork terus di-rebase supaya
tetap bisa dipakai lagi nanti.
