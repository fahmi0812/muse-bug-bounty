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
docker compose -f eval/docker-compose.yml down
```

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
