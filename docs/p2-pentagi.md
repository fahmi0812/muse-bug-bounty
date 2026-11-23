# P2 — PentAGI penuh (Postgres/pgvector, Graphiti/Neo4j, Langfuse/Grafana)

> Status: **P2 / opsional.** v1 memakai satu store SQLite `bounty.db`
> (ledger/brain/graph jadi view, bukan store terpisah). PentAGI penuh
> hanya bila `bounty.db` terbukti tidak cukup — mis. korpus temuan
> besar, pencarian semantik lintas program, atau observabilitas
> multi-agen. Pola yang diambil, bukan salinan kode.

## Kapan dipakai

| Kebutuhan | v1 (bounty.db) cukup? | PentAGI penuh bila… |
| --- | --- | --- |
| Simpan finding/evidence | Ya | — |
| Cari temuan serupa (teks) | Ya (LIKE / dedup key) | Korpus besar, butuh kemiripan semantik |
| Graf aset → endpoint → finding | Ya (view) | Graf multi-hop kompleks, query traversal berat |
| Jejak biaya/latensi per agen | Ya (entitas `run`) | Butuh tracing + dashboard live |
| Observabilitas multi-agen | Tidak | Tim > 1 agen paralel, butuh Langfuse/Grafana |

**Aturan:** jangan naik ke PentAGI hanya karena "lebih powerful".
Buktikan dulu di eval bahwa query di `bounty.db` lambat atau hasil
pencarian teks tidak cukup, lalu naikkan satu komponen saja.

## Komponen & skema

Compose opsional: [`eval/docker-compose-pentagi.yml`](../eval/docker-compose-pentagi.yml).
Semua kredensial di file itu **placeholder** (`REPLACE-ME`) — isi dari
`.env` lokal, jangan pernah commit nilai asli.

### Postgres + pgvector (store semantik)

- Tabel `findings_embedding`: `finding_id` (FK ke `bounty.db` / mirror),
  `embedding vector(1536)`, `program`, `vuln_class`, `cwe`.
- Alur: finding terverifikasi → embedding ditulis sekali → pencarian
  "temuan serupa" pakai `<=>` (cosine distance) + filter `program`.
- Postgres **bukan** pengganti `bounty.db`: `bounty.db` tetap sumber
  kebenaran (finding, verdict, evidence). Postgres hanya indeks
  pencarian; bisa dibangun ulang dari `bounty.db` kapan saja.

### Neo4j + Graphiti (graf pengetahuan)

- Node: `Program`, `Asset`, `Endpoint`, `Finding`, `Evidence`, `Chain`.
- Edge: `Program -HAS_ASSET-> Asset -HAS_ENDPOINT-> Endpoint
  -HAS_FINDING-> Finding -SUPPORTED_BY-> Evidence`,
  `Finding -CHAINS_WITH-> Finding`.
- Graphiti dipakai untuk membangun graf dari laporan/temuan secara
  bertahap (temporal), bukan import massal sekali jalan.
- Query contoh (Cypher): jalur chain dari satu finding ke finding lain
  dalam program yang sama; aset dengan finding terbanyak.

### Langfuse (tracing LLM)

- Trace per run: prompt, model, token, biaya, latensi, tool call.
- Dipakai untuk menjawab "run ini mahal karena apa" — bukan untuk
  mengubah perilaku agen saat jalan.
- Trace tidak menyimpan kredensial / PoC mentah; redaksi dulu
  (secret-leak guard, P1-1).

### Grafana (dashboard)

- Sumber: Postgres (metrik run) + Langfuse (trace) + log `bounty bench`.
- Panel minimal: TP/FP per rilis, USD/target, waktu/run, rate-limit
  hit, temuan per program.
- Dashboard ini pelengkap `eval/results/latest.json`, bukan penggantinya.

## Urutan naik (satu per satu, ukur tiap langkah)

1. Postgres/pgvector dulu (pencarian serupa) → ukur recall pencarian.
2. Neo4j/Graphiti (graf) → ukur apakah chain baru ditemukan.
3. Langfuse (tracing) → ukur biaya/latensi per agen.
4. Grafana terakhir (visualisasi dari 3 di atas).

Tiap langkah: jalankan `bounty bench` sebelum/sesudah; kalau metrik
tidak membaik, langkah itu dicabut.
