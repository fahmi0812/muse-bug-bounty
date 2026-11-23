#!/bin/sh
# scripts/baseline-laptop.sh — jalankan baseline LIVE P0-1 di laptop.
# Prasyarat: Docker, Strix, Node >= 24, Python 3.11+, Poetry, pipx.
# Keluar 2 bila ada prasyarat yang hilang (bukan gagal diam-diam).
# PERINGATAN BIAYA: baseline penuh (lab lokal 3 run + XBEN subset 10)
# memakai model berbayar — atur STRIX_LLM + LLM_API_KEY dulu, dan
# periksa budget ($5/target di lab lokal; XBEN ~$3,37/tantangan
# menurut README upstream — angka mereka, bukan janji kita).
set -e
cd "$(dirname "$0")/.."

missing=""
for cmd in docker strix node python3 poetry pipx; do
  if ! command -v "$cmd" >/dev/null 2>&1; then missing="$missing $cmd"; fi
done
if [ -n "$missing" ]; then
  echo "Baseline LIVE tidak bisa jalan — tidak ada:$missing"
  echo "Instal dulu: Docker, Strix (curl -sSL https://strix.ai/install | bash), Node >= 24, Python 3.11+, Poetry, pipx."
  exit 2
fi

node --version
strix --version 2>/dev/null || echo "(strix --version tidak mengembalikan versi — lanjut)"
echo "== Langkah 1/3: lab lokal, 3 run, baseline vs bounty =="
npm run measure-baseline -- --runs=3 --mode=both

echo "== Langkah 2/3: XBEN subset (10 tantangan) =="
echo "Jalankan manual (lihat eval/benchmarks/xben.md):"
echo "  cd <clone usestrix/benchmarks>/XBEN && poetry install"
echo "  poetry run python run_infer.py --benchmarks <10 id tantangan>"
echo "  lalu bounty run ke target yang sama, model + budget sama."

echo "== Langkah 3/3: EthiBench (vuln-bank, paygoat, xben-090) =="
echo "Jalankan manual (lihat eval/benchmarks/ethibench.md):"
echo "  pipx install ethibench"
echo "  node eval/ethibench-export.mjs --in findings.json --target vuln-bank --run 1 --out eval/results/ethibench"
echo "  ethibench evaluate eval/results/ethibench --dataset <ethibench>/examples/dataset.yaml"
echo "Baseline pack siap. Hasil lab lokal ada di eval/results/baseline.json + latest.json."
