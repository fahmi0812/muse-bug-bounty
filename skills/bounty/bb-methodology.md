# bb-methodology — Alur Hunt (5 fase, non-linear)

Fase boleh diulang dan dilompati balik; bukan garis lurus.

## Fase 1 — Scope & aturan
- Baca `programs/<nama>.md`. Tulis Scope OK / Scope TIDAK OK + alasannya.
- Catat budget, rate limit, jam otomasi, aturan dedup.
- Tanpa scope tertulis: berhenti.

## Fase 2 — Recon pasif
- Peta permukaan: route, form, parameter, API, bundle JS.
- Baca dokumentasi publik program; jangan brute-force agresif dulu.
- Simpan daftar endpoint + parameter di catatan kerja.

## Fase 3 — Threat model
- Isi `templates/threat-model.md`: aset, aktor, trust boundary, STRIDE.
- Pilih top-5 skill dari `skills-index.json` berdasar threat model.
- Prioritas: aset paling berharga + permukaan paling luas dulu.

## Fase 4 — Hunt & verifikasi
- Satu skill hunt per satu waktu; catat kandidat + bukti mentah.
- Verifikasi adversarial (`verify-adversarial.md`) segera, jangan ditunda.
- Kandidat gagal replay → UNVERIFIED, jangan naikkan severity.

## Fase 5 — Triage & laporan
- Verdict di `triage-validation.md`: confirmed / needs_validation / rejected.
- Dedup lawan Hacktivity + temuan sendiri.
- Draf laporan dari template; user yang submit.

## 7-Question Gate (jawab dengan bukti, sebelum klaim "bug")
1. Apa persisnya perilaku yang menyimpang?
2. Di endpoint/parameter mana, dengan request apa?
3. Apakah bisa di-replay dari sesi bersih?
4. Apakah akun lain / korban nyata terdampak?
5. Apakah di luar perilaku yang dimaksud aplikasi?
6. Apakah masuk scope program (bukan out-of-scope)?
7. Apakah bukti sudah bersih dari cookie/PII/token?

Satu jawaban "tidak tahu" → temuan `needs_validation`, bukan confirmed.
Dua atau lebih gagal → tolak atau kembalikan ke Fase 4.
