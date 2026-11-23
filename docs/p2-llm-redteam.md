# P2 — LLM red-team (garak + deepteam)

> Status: **P2 / hanya bila targetnya app LLM/RAG/chatbot.**
> Checklist LLM/Agentic Top 10 (P0-3) aktif di v1 tapi **tervalidasi
> mulai P1-3** — lab app-ber-LLM baru masuk setelah 3 lab pertama
> (Juice Shop/DVWA/VAmPI) hijau. Dokumen ini menyiapkan red-team-nya.

## Kapan dipakai

- Target = aplikasi ber-LLM: chatbot, RAG, agen, fitur AI di produk.
- Scope program mengizinkan pengujian prompt / model.
- **Bukan** untuk: menyerang model orang lain di luar scope, mengekstrak
  data latih, atau menjebol guardrail demi dipublikasikan tanpa koordinasi.

## Tool

| Tool | Pakai untuk |
| --- | --- |
| garak | Probe LLM: jailbreak, prompt injection, data leak, hallucination, encoding bypass |
| deepteam | Red-team agen/LLM: skenario multi-turn, evaluasi keamanan agen |

Keduanya dijalankan terhadap **endpoint target berizin** (atau lab
app-LLM lokal di P1-3), dengan budget dan rate limit yang sama
(default $5/target, 10 req/detik — hormati 429 + backoff).

## Mapping OWASP LLM Top 10 (2026)

| # | OWASP LLM Top 10 | Probe garak/deepteam | Catatan bounty |
| --- | --- | --- | --- |
| 1 | LLM01 Prompt Injection | Prompt injection langsung & tidak langsung (RAG) | Paling sering; buktikan dampak (aksi nyata, bukan sekadar teks) |
| 2 | LLM02 Sensitive Information Disclosure | Minta data sensitif / system prompt | Buktikan data yang keluar benar milik target |
| 3 | LLM03 Supply Chain | Dependensi / plugin / tool LLM | Cek versi, known CVE |
| 4 | LLM04 Data & Model Poisoning | (lab saja) | Sulit dibuktikan di black-box; lab P1-3 |
| 5 | LLM05 Improper Output Handling | XSS/SSRF via output LLM | Output LLM dirender tanpa sanitasi? |
| 6 | LLM06 Excessive Agency | Tool call di luar izin | Agen memanggil tool berbahaya tanpa konfirmasi? |
| 7 | LLM07 System Prompt Leakage | Ekstraksi system prompt | Buktikan prompt asli, bukan halusinasi |
| 8 | LLM08 Vector & Embedding Weakness | RAG poisoning / akses dokumen lain | Akses lintas tenant di RAG |
| 9 | LLM09 Misinformation | Halusinasi berbahaya | Dampak nyata (mis. instruksi salah yang merugikan) |
| 10 | LLM10 Unbounded Consumption | DoS biaya / token | Hormati rate limit; laporkan, jangan benar-benar DoS |

Mapping yang sama dipakai untuk **OWASP Agentic Top 10** (agen:
perencanaan, tool use, memori) — checklist P0-3.

## Checklist red-team LLM

1. [ ] Target app LLM + scope mengizinkan pengujian prompt?
2. [ ] Threat model dulu (`templates/threat-model.md`): apa yang
       dilindungi model ini (data, tool, aksi)?
3. [ ] Probe bertahap: mulai dari yang paling ringan (prompt injection
       langsung) → multi-turn (deepteam) → RAG.
4. [ ] Tiap temuan: buktikan **dampak nyata** — prompt yang "lolos"
       tanpa aksi/dampak = kandidat lemah, bukan finding.
5. [ ] Jangan: exfiltrasi data pengguna lain, DoS token, atau
       menguras kuota target.
6. [ ] Laporan: prompt pemicu (redaksi bila berisi PII), respons,
       dampak, perbaikan (validasi output, least-privilege tool,
       pemisah instruksi vs data).
7. [ ] Evaluasi di lab app-LLM (P1-3) dulu sebelum klaim ke target nyata.

## Batasan

- Red-team LLM = P2, setelah lab app-LLM hijau di P1-3.
- garak/deepteam menghasilkan banyak kandidat — verifier adversarial
  (P0-3) wajib menyaring sebelum jadi finding.
- Jangan pakai tool jailbreak dari kategori K/L (repo abuse/bypass)
  — hanya garak/deepteam yang tercantum di plan v3.1.
