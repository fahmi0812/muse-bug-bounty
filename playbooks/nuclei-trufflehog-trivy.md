# Playbook: Nuclei + TruffleHog + Trivy

> Scope-gate dulu: baca `programs/<nama>.md`, pastikan target in-scope,
> lalu cetak `Scope OK`. Tanpa itu, jangan jalankan perintah di bawah.

## Kapan dipakai

- **Nuclei**: scanning sistematis setelah enumerasi — template terkurasi
  per kelas vuln, bukan semua template sekaligus.
- **TruffleHog**: cari secret bocor di repo / riwayat / respons.
- **Trivy**: SBOM + vuln dependensi untuk laporan (bukti pendukung).

## Nuclei — kurasi template + severity filter

```bash
# Update template (sekali, sebelum run)
nuclei -update-templates
```

```bash
# Scan dengan template terkurasi + severity filter (contoh aman)
nuclei -u https://example.com -t http/technologies/ -t http/vulnerabilities/ \
  -severity critical,high -rate-limit 10 -o nuclei-out.txt
```

- Pilih template per threat model (mis. hanya `http/misconfiguration/`
  bila itu fokusnya); jangan `-t .` membabi buta ke target nyata.
- Severity filter: mulai `critical,high`; turun ke `medium,low` hanya
  bila waktu/budget mengizinkan.
- Tiap temuan Nuclei = kandidat. Verifikasi manual + replay sebelum
  jadi finding (lihat `verify-adversarial.md`).

## TruffleHog — verifikasi + redaksi secret

```bash
# Scan repo lokal (yang berizin) — verified-only, tanpa secret mentah di output
trufflehog filesystem --only-verified /path/to/repo --json
```

```bash
# Scan riwayat git (berizin)
trufflehog git --only-verified https://github.com/org/repo --json
```

- `--only-verified`: hanya secret yang terverifikasi aktif — mengurangi
  false positive.
- **Redaksi wajib:** jangan tempel secret mentah ke laporan/bukti.
  Ganti dengan `[REDACTED]` + jenis secret + 4 karakter terakhir saja
  bila perlu identifikasi (lihat `evidence-hygiene.md`).
- **Jangan** memakai secret yang ditemukan untuk login / memanggil API
  asli. Secret aktif → laporkan lewat jalur aman program, lalu rotasi
  adalah urusan pemilik program.

## Trivy — SBOM di laporan

```bash
# SBOM + vuln dependensi dari repo / image lab (bukan target produksi)
trivy fs --format cyclonedx --output sbom.cdx.json /path/to/repo
trivy fs --severity HIGH,CRITICAL /path/to/repo
```

- Lampirkan SBOM (CycloneDX) sebagai bukti pendukung bila laporan
  menyangkut dependensi rentan.
- Bedakan: vuln dependensi yang reachable dari kode target vs yang
  hanya ada di lockfile (lihat `ghost-loop.md` fase Wraith).

## Export SARIF / PDF

```bash
# Nuclei ke SARIF (untuk import ke code scanning / review)
nuclei -u https://example.com -t http/vulnerabilities/ -severity critical,high \
  -sarif-export nuclei.sarif
```

- SARIF: format mesin-baca untuk temuan (Nuclei, Trivy, Semgrep).
- PDF: laporan akhir dibuat dari template (`templates/report-*.md`)
  dan diekspor ke PDF oleh user — jangan sertakan secret/PII mentah.

## Verifikasi non-destruktif

- Scanner hanya memberi kandidat; bukti eksploitasi tetap replay
  terkontrol di akun/lab sendiri.
- Hormati rate limit (default 10 req/detik), 429 + backoff, jam otomasi.
- Jangan scan di luar scope; jangan kirim payload destruktif.
