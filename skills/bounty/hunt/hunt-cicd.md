# hunt-cicd — CI/CD Pipeline

Kelas: Code Injection / Misconfiguration | CWE: CWE-94, CWE-829 | OWASP: A08:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya repo/org yang terdaftar di program.
- Jangan membuka PR berbahaya, jangan menjalankan kode di runner milik target, jangan mencuri secret — buktikan alur datanya dari file workflow yang publik.
- Jangan menyentuh pipeline produksi; berhenti saat kena rate limit / 429.

## Detection pattern
- Jenkins: header `X-Jenkins` membocorkan versi; `/script` atau `/scriptText` mengembalikan 200 tanpa login (login page/403 = terlindungi, bukan temuan).
- Jenkins CLI file read (CVE-2024-23897): versi ≤ 2.441 / LTS ≤ 2.426.2 — cek versi dulu, jangan kirim argumen baca file ke target nyata.
- GitHub Actions: workflow `pull_request_target`/`workflow_run` yang checkout PR head DAN memakai `${{ github.event.* }}` di dalam `run:` — itu pola Pwnrequest.
- Runner `self-hosted` di repo publik + trigger PR = kode fork berjalan di host org.
- OIDC: trust policy IAM tanpa kondisi `sub` atau wildcard `repo:ORG/*` = role bisa diasumsikan workflow mana pun.
- State Terraform (`*.tfstate`) publik, secret di log/artefak build, token registrasi runner bocor.

## Sinyal uji
- Baca file workflow publik (`.github/workflows/`) dan lacak: apakah input tak tepercaya (judul/body PR, nama branch) mengalir ke sink eksekusi (`run:`, checkout head, build hook)?
- Jalankan `zizmor`/`actionlint` pada salinan workflow lokal — alat statis, tanpa menyentuh runner.
- Jenkins: `/script` 200 anonim saja belum cukup — hanya POST yang mengembalikan output perintah yang membuktikan konsol anon (jangan kirim perintah destruktif).
- `.tfstate` 200 saja bukan temuan — harus ada kredensial live di dalamnya (cek dengan parser lokal, jangan dipakai).

## Bypass
- `${{ }}` yang sudah dibungkus `env:` dan dikutip di shell = pola aman, bukan injectable.
- `pull_request_target` tanpa aliran input ke sink = bukan temuan.
- Secret yang ter-mask dan hanya muncul di log terproteksi = bukan kebocoran.

## Chain template
Workflow rentan (Pwnrequest / checkout PR head) → token `GITHUB_TOKEN`/secret terekspos → push ke branch terproteksi / lateral ke cloud. Atau: Jenkins anon → baca credential store → kredensial cloud/DB. Laporkan hanya dengan bukti aliran data + output.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Input tak tepercaya di-template ke shell sebelum dieksekusi; checkout PR head di konteks privileged; runner self-hosted tidak ephemeral; trust policy OIDC terlalu longgar; secret dicetak sebelum `::add-mask::`.

## Verifikasi
- Buktikan aliran data (trigger → input → sink), bukan sekadar keberadaan trigger.
- Blind injection wajib konfirmasi out-of-band (interactsh) — workflow "hijau" bukan bukti eksekusi.
- Token/secret yang diklaim bocor harus terbukti autentik (verifikasi read-only) — string saja bukan dampak.
