# EthiBench — baseline vs Strix (P0-1)

EthiBench = framework evaluasi agen pentest pada target nyata
(bukan flag CTF): LLM-as-judge mencocokkan temuan dengan ground truth,
lalu Hungarian bipartite matching menghitung precision/recall/F1.
Sumber: https://github.com/ethiack/ethibench (MIT),
paper: https://arxiv.org/html/2605.10834v3

## Target + ground truth (108 entri)

| Target | GT | Repo | Versi yang dipatok |
|---|---|---|---|
| vuln-bank | 60 | Commando-X/vuln-bank | commit `b1962823` + patch de-hinting (hapus petunjuk "rentan" di UI/prompt) |
| paygoat | 28 | stuxctf/PAYGoat | commit `69589b4` (sebelum "update to v2") |
| xben-090 | 20 | xbow-engineering/validation-benchmarks (XBEN-090) | main terbaru (frozen) |

PERINGATAN: `git clone <latest main>` TIDAK mereproduksi target untuk
vuln-bank dan paygoat — pakai commit di atas. Ground truth ada di
`examples/gt/` repo EthiBench (juga di HuggingFace).

## Angka acuan (dari paper, bukan angka kita)

- Claude Code vs Strix (model Claude Sonnet 4.6): recall **+18,83%**
  (p=0,0047), F1 **+16,79%** (p=0,0141), precision **−14,19%**.
  Artinya: Strix presisi, Claude Code menemukan lebih banyak.

## Cara jalan (laptop)

```text
pipx install ethibench
```

1. Jalankan target di Docker (versi yang dipatok di atas).
2. Jalankan agen ke tiap target (baseline Strix, lalu bounty),
   simpan temuan tiap target ke `findings.jsonl`.
3. Nilai:

```text
ethibench evaluate ./my_experiment --dataset examples/dataset.yaml
cat ./my_experiment/evaluation_outputs/summary.md
```

## Eksportir temuan kita → format EthiBench

`eval/ethibench-export.mjs` mengubah array temuan JSON menjadi
`findings.jsonl` per target per run:

```text
node eval/ethibench-export.mjs --in findings.json --target vuln-bank --run 1 --out eval/results/ethibench
```

Layout hasil: `<out>/run_<n>/<target>/findings.jsonl`.
Tiap baris: `{title, description, steps, severity, cwe?, url?}`.
Field `title`/`description`/`steps` adalah yang dipakai LLM matcher —
jangan kirim baris kosong.

## Aturan jujur P0-1

- Target, versi, model, dan jumlah run HARUS sama di kedua sisi.
- 3 run tiap sisi, laporkan median + cumulative (EthiBench menghitung
  keduanya otomatis).
- Duplikat ditangani Hungarian matching — jangan hapus temuan duplikat
  manual sebelum evaluasi.
