# hunt-llm-agentic — OWASP Agentic Top 10 2026 (ASI01–ASI10)

Kelas: Agentic AI Security | CWE: CWE-74, CWE-862, CWE-863, CWE-78 | OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)

Dipetakan dari OWASP Top 10 for Agentic Applications 2026, OWASP GenAI Security Project (CC BY-SA 4.0) — dirilis 9 Des 2025. Daftar ini untuk agen yang merencanakan, mengingat, memanggil tool, dan bertindak dengan identitas yang didelegasikan — bukan sekadar chatbot.

## Daftar ASI01–ASI10
- ASI01 Agent Goal Hijack — tujuan/rencana agen dialihkan lewat instruksi injeksi atau konten beracun.
- ASI02 Tool Misuse and Exploitation — tool sah dipakai secara berbahaya lewat chaining tak aman atau output tool yang dimanipulasi.
- ASI03 Identity and Privilege Abuse — kepercayaan yang didelegasikan / kredensial warisan / rantai peran dieksploitasi.
- ASI04 Agentic Supply Chain Vulnerabilities — agen, tool, plugin, registry, atau kanal update pihak ketiga yang dikompromikan.
- ASI05 Unexpected Code Execution (RCE) — kode yang dibuat atau dipanggil agen berubah jadi eksekusi tak diinginkan.
- ASI06 Memory and Context Poisoning — data beracun tersimpan di memori dan terus mengarahkan sesi berikutnya.
- ASI07 Insecure Inter-Agent Communication — pesan antar-agen tanpa autentikasi / tanda tangan.
- ASI08 Cascading Failures — satu agen gagal lalu memicu kegagalan berantai tanpa pemutus (circuit breaker).
- ASI09 Human-Agent Trust Exploitation — penjelasan percaya diri agen membuat manusia menyetujui aksi berbahaya.
- ASI10 Rogue Agents — agen menyimpang / dikompromikan dan bertindak di luar kebijakan sambil tampak sah.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high), hanya agen lab atau agen yang kamu miliki / diizinkan menguji.
- Jangan meracuni memori bersama yang dipakai pengguna lain; uji memori hanya di sesi akun test sendiri.
- Jangan picu tool yang berdampak nyata (kirim uang, hapus data, ubah akses) — amati niat agen, lalu hentikan sebelum eksekusi.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- ASI01: agen mengubah tujuannya setelah membaca dokumen/komentar yang berisi instruksi.
- ASI02: agen merangkai tool di luar urutan yang dibutuhkan tugas, atau memakai argumen tool dari konten tak tepercaya.
- ASI03: agen bertindak dengan hak lebih tinggi dari pengguna yang memerintahkannya (mis. membaca data admin).
- ASI05: teks dari model atau dari tool diteruskan ke eksekutor kode / shell tanpa sandbox.
- ASI06: instruksi yang disisipkan di satu sesi masih memengaruhi sesi baru (memori tidak dibersihkan / tidak divalidasi).
- ASI08: satu tool gagal, agen mencoba tool lain berulang kali tanpa batas, biaya/aksi meledak.
- ASI09: agen menekan pengguna agar menyetujui aksi sensitif dengan alasan urgensi / otoritas palsu.
- ASI10: agen menyembunyikan langkahnya, mengubah log, atau menolak dimatikan.

## Cara menguji
- Letakkan instruksi di dokumen yang dibaca agen, lihat apakah tujuannya berubah (ASI01).
- Periksa rantai tool: apakah argumen tool berasal dari konten tak tepercaya tanpa validasi? (ASI02).
- Minta agen memakai tool di luar peran akun test — harus ditolak (ASI03).
- Sisipkan instruksi di sesi 1, buka sesi 2, lihat apakah pengaruhnya masih ada (ASI06).
- Buat satu tool gagal, amati apakah agen berhenti dengan aman atau merambat ke tool lain tanpa batas (ASI08).

## Chain template
Konten beracun → agen mengubah tujuan / menyalahgunakan tool → aksi di luar izin akun test → laporkan di titik bukti cukup, sebelum dampak nyata terjadi.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Agen diberi identitas, memori, dan tool tanpa batasan least-privilege; konten tak tepercaya diperlakukan sebagai instruksi; tidak ada pemutus antar-langkah; manusia terlalu percaya pada penjelasan agen.

## Verifikasi
- Replay dengan akun test lain: agen harus menolak aksi di luar peran.
- Simpan jejak langkah agen (tool yang dipanggil + argumennya), redaksi isi sensitif.
- Cocokkan temuan ke nomor ASI di atas saat menulis laporan.
