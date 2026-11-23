# Eval — bench `bounty` vs baseline Strix

## Cara bench

```bash
npm run bench              # 3 run per lab (default)
node eval/run-bench.mjs --runs=5
```

Tanpa Docker, bench jalan **mode no-docker**: lab Docker di-skip,
bench memakai mock findings deterministik (seed tetap, bukan random)
+ unit router/dedup/guard. Exit 0 = bench selesai, bukan gagal.

Dengan Docker, lab bisa dijalankan manual untuk verifikasi live:

```bash
docker compose -f eval/docker-compose.yml up -d
# Juice Shop http://localhost:3000, DVWA http://localhost:8080, VAmPI http://localhost:5000
# DVGA http://localhost:5013
docker compose -f eval/docker-compose.yml down
```

## Lab P1-3 (baru): DVGA + app LLM

| Lab | Image | URL | Oracle |
| --- | --- | --- | --- |
| DVGA (GraphQL) | `dolevf/dvga:latest` | http://localhost:5013 | `oracle/labels/dvga.json` (8 vuln: introspection, BOLA, batching, excessive data exposure, dst) |
| app LLM | placeholder `python:3.12-slim` | http://localhost:8000 | `oracle/labels/llm-app.json` (6 vuln: prompt injection, data exfiltration, RAG leakage, dst — mengikuti OWASP LLM Top 10 2026) |

Catatan penting:

- **DVGA** sudah lab nyata (image resmi `dolevf/dvga`). Semua vuln-nya lewat
  satu endpoint `POST /graphql` — pembeda TP adalah `vuln_class` + `CWE`,
  bukan path.
- **App LLM masih placeholder.** Belum ada satu image lab LLM resmi yang
  dipatok; service `llm-app` di `docker-compose.yml` memakai image Python
  resmi sebagai stand-in dan **tidak ikut `up` default** (profile `llm` —
  jalankan manual dengan `docker compose --profile llm up llm-app` bila
  diperlukan). Oracle `llm-app.json` mengikuti OWASP LLM Top 10 (2026)
  dan **harus diverifikasi ulang terhadap lab final** saat image dipilih.
  Sampai itu, checklist LLM/Agentic Top 10 belum tervalidasi penuh —
  angka bench `llm-app` adalah angka harness (mock), bukan klaim performa
  terhadap lab live.

## Mode no-docker — lab di-skip dengan pesan jelas

Tanpa Docker, bench **tidak gagal dan tidak pura-pura menguji lab live**:
ia mencetak pesan `Docker tidak ditemukan — mode no-docker: lab Docker
di-skip, bench jalan dengan mock findings + unit router`, lalu memakai mock
findings deterministik (seed tetap) + unit router/dedup/guard. Hasilnya
tersimpan dengan `mode: "no-docker"` di `eval/results/latest.json`.
Angka TP/FP mock mengukur harness-nya (skor, median, determinisme),
bukan performa terhadap lab live — verifikasi live tetap butuh Docker
dan `bounty bench` terhadap lab yang sedang jalan.

## Cara baca oracle

`eval/oracle/labels/<lab>.json` adalah ground truth tiap lab:
`{ lab, version, source, vulns: [{ endpoint, method, vuln_class, cwe, severity }] }`.
Sebuah temuan dihitung TP bila endpoint (ternormalisasi: lowercase,
tanpa trailing slash, `:param` → `:id`) + `vuln_class`-nya cocok dengan
satu entri oracle. Temuan di luar oracle = FP. Entri oracle yang tak
ditemukan = FN. Duplikat temuan yang sama dihitung sekali (dedup).

Oracle ini **awal** — dirawat seiring lab di-update (versi lab dicatat
di tiap file; verifikasi ulang endpoint saat lab di-upgrade).

## Ambang gate

Median lintas 3–5 run per lab (`eval/results/latest.json`):

- **FP median turun** vs baseline Strix, dan
- **TP median tidak turun** vs baseline Strix.

Baseline Strix diukur terpisah (Strix polos, tanpa wrapper `bounty`,
terhadap oracle yang sama) dan dicatat di `eval/results/baseline.json`
(belum ada — dibuat saat baseline pertama diukur). Bench mock di sini
mengukur harness-nya (skor, median, determinisme); angka TP/FP mock
bukan klaim performa terhadap lab live.

## Metrik

Per run: TP, FP, FN, precision = TP/(TP+FP), recall = TP/(TP+FN).
Dilaporkan per lab + median lintas run. Waktu routing (bila lib router
ada) juga dicatat sebagai `router_ms_median`.
