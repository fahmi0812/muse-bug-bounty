# [SEVERITY] [JUDUL] ([CWE-###], OWASP [A##:2025])

- **Target:** [TARGET]
- **Program:** [PROGRAM]
- **Severity:** [Critical / High / Medium / Low] — CVSS 3.1: [SKOR] ([VEKTOR])
- **CWE:** [CWE-###] | **OWASP:** [A##:2025] | **Verdict:** [confirmed / needs_validation / UNVERIFIED]
- **Reporter:** [NAMA] | **Tanggal:** [YYYY-MM-DD]

## Summary

[1-3 kalimat: apa vuln-nya, di mana, dan dampaknya.]

## Steps to Reproduce

1. [Langkah 1 — pakai akun test low-priv / high-priv, sebutkan peran.]
2. [Langkah 2 — request / klik yang dilakukan.]
3. [Langkah 3 — respons yang membuktikan vuln.]

> Bukti harus bisa di-replay. Tanpa replay, verdict = UNVERIFIED.

## Impact

[Dampak bila dieksploitasi: data apa yang bocor / diubah, siapa yang terdampak.]

## Evidence

- Request/response: [lampirkan, sudah diredaksi — token/cookie/PII diganti `[REDACTED]`]
- Screenshot / HAR: [lampirkan, sudah disanitasi]
- Chain (bila ada): [A → B → C]

## Fix

[Perbaikan yang disarankan, singkat dan konkret.]

## Pre-submit checklist

- [ ] Scope dicek — target ada di `programs/*.md`
- [ ] Dedup Hacktivity dicek — belum pernah dilaporkan
- [ ] Bukti diredaksi (cookie/token/PII)
- [ ] Severity + CVSS dihitung, bukan ditebak
- [ ] Tidak ada auto-submit — laporan ini dikirim manual oleh manusia
