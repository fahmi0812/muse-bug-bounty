# P2-4 — Gerbang Upgrade Graf/Memori

**Aturan (dari gap report):** graf ala Cairn (fact-intent graph) dan memori
ala PentAGI (Postgres + pgvector + Neo4j) HANYA dibangun bila baseline P0-1
membuktikan planning/state adalah bottleneck. Tanpa bukti itu, ini adalah
churn arsitektur — stack berat (8 GB+ RAM) yang merusak janji "ringan seperti
Lumitome".

## Cara memutuskan

Jalankan setelah baseline live ada:

```text
bounty graph-gate [--baseline eval/results/baseline.json]
```

Perintah ini membaca `baseline.json` (per-lab TP baseline Strix vs bounty)
dan statistik store (`bounty.db`: kelas FP berulang dari `memory_lesson`,
pasangan permukaan x kelas yang masih `open` di `memory_coverage`, temuan
tanpa chain dari `v_finding_chain`), lalu memutuskan lewat
`bounty/lib/graph-gate.js` (`decideGraphUpgrade`).

## Sinyal upgrade (satu saja cukup)

| Sinyal | Ambang default | Artinya |
|---|---|---|
| `tp-down` | TP bounty < baseline di ≥ 2 lab | Perencanaan melewatkan temuan |
| `repeated-fp` | ≥ 3 kelas vuln ditolak berulang reviewer | Memori lintas-run tidak menahan FP |
| `open-coverage` | ≥ 5 pasangan permukaan x kelas masih `open` | Planner tidak menutup peta |
| `untraced-chains` | > 50% temuan tanpa chain | Graf SQL-view tidak cukup melacak asal |

Tanpa satu pun sinyal → **tetap SQL** (graf view + memori SQLite cukup).
Tanpa `baseline.json` → **tidak bisa diputuskan** (jalankan
`scripts/baseline-laptop.sh` dulu).

## Bila gerbang bilang "upgrade"

Baru saat itu bangun (tahapannya di luar repo ini sampai gerbang terbuka):

1. **Cairn-style fact-intent graph** — node fakta + node niat, bukan
   sekadar view SQL; evaluasi di EthiBench/CrackMeBench dulu.
2. **PentAGI-style memory** — Postgres + pgvector (selalu nyala) +
   Neo4j/Graphiti (opsional) + Langfuse observability; opt-in, bukan
   default — stack penuh butuh 8 GB+ RAM / 4+ CPU.
3. Ukur ulang di baseline yang sama. Bila TP/FP tidak membaik melebihi
   toleransi, **revert** — upgrade yang tidak terbukti adalah bloat.
