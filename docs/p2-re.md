# P2 — RE native (mode terpisah)

> Status: **P2 / mode terpisah.** v1 web-first: analisis JS bundle /
> source-map saja (P0-4). RE native hanya bila targetnya aplikasi
> desktop / binary / .NET / WASM — dan hanya terhadap target yang
> scope-nya mengizinkan RE secara eksplisit. RE tanpa izin tertulis
> = di luar scope = dilarang.

## Kapan mode RE dipakai

- Target menyediakan binary / aplikasi desktop / file `.apk` / `.wasm`
  dalam scope program.
- Scope program menyebut RE diizinkan (mis. "reverse engineering
  diizinkan untuk binary yang disediakan").
- Tujuan: cari vuln di logika binary, bukan membajak lisensi / melewati
  proteksi / membocorkan IP orang lain.

Mode RE **terpisah** dari mode web: jalankan dengan profil sendiri,
store sendiri (`bounty.db` yang sama boleh, tapi tag `mode: re`),
dan jangan campur temuan web dengan temuan RE dalam satu laporan
tanpa label yang jelas.

## Tool & skill

| Tool | Pakai untuk | Catatan |
| --- | --- | --- |
| Ghidra (+ GhidraMCP, GhidrAssistMCP) | Analisis binary native, decompile | Proyek per binary, simpan di workspace lokal |
| jadx | Decompile APK / dex | Android |
| x64dbg | Debugging dinamis Windows | Lab Windows / VM saja |
| radare2 / rizin / cutter (+ r2ai, radare2-mcp) | Analisis + scripting binary | — |
| ILSpy / dnSpy / de4dot / dnlib | .NET: decompile, unpack, analisis assembly | — |
| LLM4Decompile | Decompile berbantuan LLM | Hasil LLM = kandidat, wajib verifikasi manual |
| binaryen / wabt | WASM: analisis & transformasi | — |
| reverse-engineering-assistant | Skill agen RE (pola, bukan salinan kode) | — |

Semua tool di atas dijalankan **lokal** (VM/lab sendiri). Jangan
upload binary target ke layanan online tanpa izin program.

## Checklist RE

1. [ ] Scope program mengizinkan RE? (tertulis — kalau tidak, STOP)
2. [ ] Binary dari sumber resmi program / lab, hash dicatat.
3. [ ] Kerja di VM/lab terisolasi, snapshot sebelum mulai.
4. [ ] Identifikasi: format, arsitektur, packer, bahasa (file, strings,
       header).
5. [ ] Analisis statis dulu (Ghidra/jadx/ILSpy): fungsi menarik,
       jalur input → sink berbahaya (mis. `strcpy`, deserialisasi,
       crypto lemah, hardcoded secret).
6. [ ] Analisis dinamis bila perlu (x64dbg/frida — lihat juga
       [p2-mobile.md](p2-mobile.md)): konfirmasi perilaku, bukan asumsi.
7. [ ] Tiap temuan: PoC replay + label `UNVERIFIED` sampai terbukti
       (aturan P0-2: "no exploit, no report" — pola Shannon).
8. [ ] Laporan: fungsi/offset, input pemicu, dampak, perbaikan —
       tanpa menyertakan binary target / potongan kode berhak cipta
       yang tidak perlu.
9. [ ] Tidak ada: bypass lisensi, crack, unpack proteksi komersial
       untuk dipakai ulang, atau publikasi exploit tanpa koordinasi.

## Skill agen RE

Skill `reverse-engineering-assistant` dipakai sebagai pola alur
(identifikasi → hipotesis attack path → verifikasi live → laporan).
Router skill (P0-6) memilih skill RE hanya bila target bertipe
binary dan program mengizinkan RE; target web tidak pernah
mendapat skill RE.

## Batasan

- RE = P2, setelah P1 hijau. Jangan mulai RE sebelum eval web hijau.
- Hasil decompile LLM (LLM4Decompile) sering salah — selalu
  cross-check dengan decompiler deterministik (Ghidra/jadx).
- Jangan salin kode AGPL (mis. pola Shannon) — tulis ulang sendiri.
