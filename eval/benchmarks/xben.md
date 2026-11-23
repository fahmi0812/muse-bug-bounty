# XBEN — baseline vs Strix (P0-1)

XBEN = 104 tantangan CTF web (XBOW validation-benchmarks), level 1–3.
Skor = flag yang berhasil diekstrak (`flag_extracted: true`).
Sumber: https://github.com/usestrix/benchmarks (Apache-2.0), direktori `XBEN`.

## Angka acuan Strix (dari README upstream, bukan angka kita)

- Strix v0.4.0: **100/104 (96%)** black-box, model `gemini-3-pro-preview`.
- Per level: L1 45/45 (100%), L2 49/51 (96%), L3 6/8 (75%).
- Biaya rata-rata: **~$3,37 per tantangan**, ~19 menit per tantangan.
- 4 yang gagal: XBEN-056-24 (SSTI), XBEN-066-24 (HTTP Smuggling),
  XBEN-088-24 (Race Condition), XBEN-092-24 (PHP Deserialization).

## Cara jalan (laptop, butuh Docker + Python 3.12+ + Poetry + model)

```text
git clone https://github.com/usestrix/benchmarks
cd benchmarks/XBEN
poetry install
```

```text
export STRIX_LLM="openai/gpt-5"
export LLM_API_KEY="..."
```

Baseline Strix (semua 104 — mahal, ~$350 + berjam-jam):

```text
poetry run python run_infer.py
```

Subset dulu (disarankan untuk baseline pertama, 10 tantangan):

```text
poetry run python run_infer.py --benchmarks XBEN-001-24 XBEN-002-24
```

Hasil per tantangan: `runs/run_<id>/result.json`
(`benchmark_id`, `level`, `tags`, `execution.status`,
`evaluation.flag_extracted`).

## Baseline bounty (wrapper kita) vs baseline Strix

`run_infer.py` menjalankan Strix langsung. Untuk mengukur wrapper kita
di tantangan yang sama, jalankan `bounty run` ke target tiap tantangan
(docker compose per tantangan, URL dari `run_infer.py`) dengan model
dan budget yang sama, lalu bandingkan `flag_extracted` + biaya + waktu.

Aturan jujur P0-1:

- Model, budget, dan daftar tantangan HARUS sama di kedua sisi.
- 3 run tiap sisi, laporkan median (bukan run terbaik).
- Jangan klaim angka XBEN sebelum kedua sisi jalan di tantangan yang sama.
- Subset 10 tantangan (5 L1 + 3 L2 + 2 L3) cukup untuk sinyal awal;
  104 penuh hanya bila budget mengizinkan.
