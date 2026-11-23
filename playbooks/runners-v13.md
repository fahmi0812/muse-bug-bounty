# Playbook — Runner batch 2 / 3.4 / 3.7 (v1.3)

Semua runner dipanggil lewat `bounty scan --tool <nama> --target URL
--program programs/<nama>.md`. Aturan yang sama untuk semua: scope gate
dulu, binary tidak ada = dilewati (exit 0), timeout 120 detik, hasil =
kandidat (`candidate`, UNVERIFIED) setelah dedup.

## arjun — parameter tersembunyi

```text
arjun -u <target> -o <file.json> --stable
```

Output JSON `{"parameters": [...]}`. Tiap parameter = kandidat
"Hidden Parameter Discovery" (low) — enumerasi, BUKAN klaim vuln
(sama alasannya seperti ffuf).

## graphql-cop — keamanan GraphQL

```text
graphql-cop -t <target> --format json
```

Output JSON array `{title, severity, cwe, url}`. Endpoint GraphQL
biasanya `/graphql` — pastikan path itu ada di `Allowed:` program.

## gitleaks / trufflehog — secret di repo

```text
gitleaks git <repo-url> --report-format json --report-path <file> --log-level warn
trufflehog git <repo-url> --json
```

Target HARUS URL repo git (mis. `https://github.com/org/repo`),
bukan URL aplikasi — keduanya memindai repo, bukan endpoint HTTP.
Host repo (mis. `github.com`) harus ada di `Scope:` program.
Temuan: `Exposed Secret (<RuleID / DetectorName>)`, CWE-798.
Trufflehog: `Verified=true` = high, sisanya medium.

## osv-scanner — vuln dependensi (3.4)

```text
osv-scanner --format json <checkout-lokal>
```

Butuh checkout lokal repo target: `OSV_PATH=/path/ke/repo` (env) atau
`localPath` saat memanggil `runTool`. Tanpa itu runner di-skip dengan
alasan jelas. Reachability: `reachable` HANYA bila nama paket ada di
bukti pemakaian (`reachablePackages`); tanpa bukti = `unproven`.
Tidak pernah diklaim `unreachable` tanpa bukti.

## garak / deepteam — LLM red-team (3.7)

```text
garak --model_type openai --model_name <model> --probes encoding,dan \
  --generators 1 --report_prefix <prefix>   # baca <prefix>.report.jsonl
deepteam red-team --model <model> --target <target> --attacks PromptInjection
```

Model default `gpt-4o-mini` (env `GARAK_MODEL` / `DEEPTEAM_MODEL`).
Target = URL endpoint LLM yang diuji (mis. `/api/chat`), tetap kena
scope gate. Hasil garak/deepteam = kandidat yang WAJIB diverifikasi
manual — evidence tiap temuan menulis itu eksplisit. CWE-74.

## Catatan ketidakpastian

Flag di atas mengikuti dokumentasi masing-masing tool (best-effort);
parser di `bounty/lib/runners.js` dibuat toleran (JSON / JSONL /
ringkasan teks) supaya perubahan kecil format output tidak meruntuhkan
runner. Bila tool asli menolak flag, runner mengembalikan error tanpa
menulis kandidat palsu — perbaiki flag di `buildArgs()`, bukan di parser.
