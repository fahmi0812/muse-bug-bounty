# hunt-rag-vector — RAG / Vector Store Weaknesses

Kelas: LLM08 Vector & Embedding Weaknesses | CWE: CWE-200, CWE-862 | OWASP: LLM08:2026

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan unggah dokumen berisi instruksi berbahaya atau data orang lain.
- Jangan akses vector DB di luar scope program — port terbuka di luar program bukan izin.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Port vector DB terbuka tanpa auth: Chroma, Weaviate, Qdrant, Milvus, pgvector.
- Respons chat menyertakan blok "sources" berisi teks chunk + ID dokumen tenant lain.
- Upload dokumen lalu tanya dari sesi/akun kedua yang bersih — hasil racun ikut muncul.
- Endpoint debug mengembalikan vektor mentah, bukan hanya teks hasil.
- Parameter `namespace` / `tenant_id` di API chat bisa diubah klien.

## Payload contoh
- Cek heartbeat/koleksi vector DB tanpa kredensial — 200 + isi dokumen = baca korpus penuh.
- Minta dokumen lewat ID berurutan (`/api/knowledge/document/00042` → 00041, 00043).
- Kirim query dengan `namespace` milik tenant lain dari akun test low.

## Bypass
- Isolasi tenant sering hanya di lapis aplikasi, bukan di vector DB — uji keduanya.
- Racun korpus harus terbukti lewat sesi kedua yang bersih; bila hanya muncul di sesi pengunggah, itu bukan poisoning persisten.
- Halusinasi model bukan temuan — buktikan dengan nilai yang bisa diverifikasi milik tenant lain.

## Chain template
Vector DB tanpa auth → baca korpus lintas tenant → dokumen internal bocor → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Isolasi tenant ditegakkan di API chat tapi tidak di lapis penyimpanan vektor; ingestion tidak memvalidasi asal dokumen.

## Verifikasi
- Ulangi dari sesi kedua yang bersih — racun harus muncul tanpa menyebut nama dokumenmu.
- Buktikan konten lintas tenant dengan nilai yang bisa diverifikasi, bukan sekadar "terlihat beda".
- Simpan request/response, redaksi isi sensitif.
