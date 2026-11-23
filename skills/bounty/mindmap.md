# mindmap — View Navigasi Hunting

> Atribusi: struktur peta terinspirasi `Ignitetechnologies/Mindmap` —
> isi di bawah ditulis ulang secara orisinal untuk repo ini.
> Mindmap ini **statis** (struktur navigasi), bukan program yang
> mengeksekusi tool.

## Kapan dipakai

- Butuh peta jalan hunt: dari recon sampai exploit, dan skill mana yang
  dipakai di tiap tahap. Dipakai saat merencanakan hunt atau saat tersesat
  di tengah hunt ("sudah di tahap apa, lanjut ke mana?").
- Struktur mesin-bacanya ada di `mindmap.json` (file pendamping).

## Peta (5 tahap)

```
recon → enumerasi → scanning → proxy → exploit
```

### 1. Recon (pasif dulu)

- Tujuan: kenal target tanpa menyentuh banyak.
- Tool/pola: Subfinder / Amass (subdomain), whois/DNS pasif, baca
  scope program, arsip web.
- Skill: `bb-methodology.md` (threat model), `js-bundle-analysis.md`.
- Keluar dari tahap ini dengan: daftar aset in-scope + threat model.

### 2. Enumerasi

- Tujuan: petakan permukaan: endpoint, parameter, teknologi.
- Tool/pola: FFUF (fuzz direktori/parameter), baca bundle JS, petakan API.
- Skill: `hunt-js-bundle.md`, `hunt-graphql.md`, `hunt-api-bola.md`.
- Keluar dengan: daftar endpoint + parameter kandidat.

### 3. Scanning

- Tujuan: cari kandidat vuln secara sistematis.
- Tool/pola: Nuclei (template terkurasi — lihat
  `playbooks/nuclei-trufflehog-trivy.md`), scanner secret, dependency check.
- Skill: semua `hunt-*`, `ghost-loop.md`, `vbsec-21.md`.
- Keluar dengan: daftar kandidat + bukti mentah.

### 4. Proxy

- Tujuan: lihat traffic live, replay, dan buktikan kandidat.
- Tool/pola: Burp / proxy MITM (lihat `ghost-loop.md` fase Reaper).
- Skill: `verify-adversarial.md`, `triage-validation.md`.
- Keluar dengan: kandidat CONFIRMED / UNVERIFIED / REJECTED.

### 5. Exploit (terbukti, non-destruktif)

- Tujuan: buktikan dampak dengan replay terkontrol — bukan merusak.
- Tool/pola: SQLMap (baca terbatas, lab/akun sendiri), Dalfox (XSS —
  lihat `playbooks/dalfox-amass.md`).
- Skill: `hunt-sqli.md`, `hunt-xss.md`, lalu `report-writing.md`.
- Aturan: "no exploit, no report" (lihat `shannon-tracing.md`) —
  tanpa replay yang berhasil, tidak ada laporan.
- Keluar dengan: draf laporan untuk user (user yang submit).

## Aturan peta

- Jangan lompat tahap: exploit tanpa recon/enumerasi = hunting buta.
- Tiap tahap selesai hanya bila output-nya tertulis (daftar aset,
  daftar endpoint, daftar kandidat, verdict).
- Kembali ke tahap sebelumnya bila bukti baru mengubah peta
  (mis. endpoint baru dari proxy → enumerasi lagi).
