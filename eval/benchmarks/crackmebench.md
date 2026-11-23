# CrackMeBench — eval reverse engineering (P1-3)

CrackMeBench = benchmark agen untuk binary reverse engineering
(CrackMe-style): diberi satu executable, agen harus memulihkan logika
validasi dan menghasilkan password / serial / artifact / keygen yang
diterima program itu. Skor = oracle executable (bukan penjelasan).
Sumber: https://arxiv.org/html/2605.10597 (Isaac David & Arthur
Gervais, University College London).

## Isi benchmark (v0, 20 tugas)

| Split | Jumlah | Isi |
|---|---|---|
| Generated (main-score) | 12 (S01–S12) | C/Rust/Go, template seeded: literal recovery, encoding terbalik, affine constraints, keygen, anti-debug, mini VM, opaque predicate, runtime-decrypted validator, toy crypto, checksum, Rust/Go keygen |
| Public (calibration) | 8 (P01–P08) | CrackMe publik yang sudah dikenal |

Tiap tugas: 1 binary + metadata publik + budget waktu + maks 3
submission yang dinilai. Submission: `password`, `artifact`, atau
`keygen` (script `/work/solve.py USERNAME` — harus generalisasi ke
username tersembunyi, bukan contoh yang di-hardcode). Agen jalan di
sandbox Docker Linux tanpa jaringan, dengan tool RE standar.

## Angka acuan (dari paper, bukan angka kita)

Budget 5 menit per tugas, pass@3 pada split generated (12 tugas):

| Model | pass@3 generated | pass@3 public (8 tugas) |
|---|---|---|
| GPT-5.5 | 11/12 (92%) | 3/8 |
| Claude Opus 4.7 | 7/12 (58%) | 2/8 |
| Kimi K2 | 5/12 (42%) | 1/8 |

Bagian tersulit (harder half, 6 tugas): GPT-5.5 5/6, Opus 4.7 2/6,
Kimi K2 1/6. Paper juga mencatat waktu, jejak perintah, token,
estimasi biaya, dan label kegagalan (mis. "found-check-but-not-inverse").

## Cara jalan (laptop)

1. Ambil harness + tugas dari repo/paper CrackMeBench (cek tautan di
   halaman arXiv di atas — repo rilis mengikuti paper).
2. Jalankan baseline: agen tanpa wrapper RE (atau Strix polos) vs
   `bounty` + runner RE (`bounty/lib/reverse.js`: GhidraMCP / REA /
   jadx) pada tugas yang sama, model sama, budget sama.
3. Laporkan pass@1 + pass@3 per split, waktu, dan biaya — median
   dari 3 run tiap sisi.

## Aturan jujur P1-3

- **Tidak ada angka CrackMeBench untuk tool ini.** Belum pernah
  dijalankan — dokumen ini hanya prosedur + angka acuan upstream.
- Scope CrackMeBench sengaja edukasional: BUKAN benchmark analisis
  malware, cracking komersial, atau bypass DRM. Runner RE di repo ini
  juga gated (`confirmed: true`) dan hanya untuk binary/APK yang
  in-scope dan disediakan operator.
- Tugas public (P01–P08) adalah kalibrasi, bukan skor utama —
  writeup/solusi publik bisa bocor ke model.
