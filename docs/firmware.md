# Firmware — jalur ringan (P2-1)

Firmware bounties jarang dibanding web, tapi ada: perangkat IoT, router,
kamera, dan appliance sering membayar untuk secret hardcoded, komponen
usang yang reachable, dan layanan network yang terbuka. Jalur ringan di
sini menangkap sebagian besar nilai itu tanpa biaya EMBA.

## Jalur ringan: 3 tool, berurutan

1. **binwalk-ng 4.0** — pindai signature + ekstrak.
   ```text
   binwalk -B -e -M -d 3 -n 5000 -j 268435456 -C ./extracted --log results.json firmware.bin
   ```
   `-B` scan signature, `-e` ekstrak, `-M -d 3` rekursif max 3 level,
   `-n`/`-j` batasi jumlah/ukuran file hasil ekstrak (anti bom dekompresi),
   `--log` hasil JSON. Perintah tetap `binwalk` (binwalk-ng adalah fork
   dari binwalk v3). **Jangan pakai `-J`** — itu flag JSON binwalk v2.
   Instal: `cargo install binwalk-ng`, atau image
   `ghcr.io/binwalk-ng/binwalk-ng:main`.

2. **unblob 26.6.4** — ekstrak rekursif + laporan JSON.
   ```text
   unblob -e ./extracted -d 10 --report report.json firmware.bin
   ```
   Rekursif default (kedalaman 10), chunk yang tidak dikenal ikut
   di-carve sebagai `.unknown`. Sandbox Landlock aktif di Linux —
   **jangan pakai `--no-sandbox`**. Instal: `pipx install unblob`.
   unblob menangani format yang tidak ada di binwalk (EROFS, Partclone,
   QNAP, Xiaomi HDR); binwalk menangani gambar yang tidak ada di unblob
   (Broadcom ProgramStore, Fritz!Box EVA). Pakai keduanya, bukan salah satu.

3. **cve-bin-tool 3.4** — SBOM + CVE scan atas hasil ekstraksi.
   ```text
   cve-bin-tool ./extracted --offline -f json -o cve-report.json
   cve-bin-tool --sbom-type cyclonedx --sbom-format json --sbom-output sbom.json ./extracted
   ```
   `--offline` memakai mirror NVD `https://cveb.in/` (default sejak 3.3)
   tanpa memanggil NVD langsung. Instal: `pipx install cve-bin-tool`.

Di wrapper ini ketiga tool itu ada di `bounty/lib/firmware.js`
(`runBinwalkNg`, `runUnblob`, `runCveBinTool`) dan akan di-wire ke
`bounty firmware` oleh parent. Binary hilang → `{skipped: true}` (bukan
error). Input hanya file lokal; timeout 600 detik per tool.

## Yang TIDAK dibuktikan oleh temuan ini

- **CVE di komponen ≠ kerentanan yang bisa dieksploitasi.** cve-bin-tool
  hanya bilang "komponen X versi Y punya CVE Z". Sebelum melapor,
  buktikan komponen itu benar-benar dipakai dan reachable di firmware
  ini (mis. binary-nya ada di rootfs hasil ekstraksi, versinya cocok,
  dan jalurnya bisa dipicu dari network/lokal). Tanpa itu, temuan = FP.
- **Temuan binwalk/unblob = info permukaan**, bukan klaim vuln.
  "SquashFS di offset 0x20040" hanya bilang di mana filesystem-nya.
- **Secret di firmware** (password hardcoded, kunci privat) dicek dengan
  `bounty/lib/secrets.js` atas file hasil ekstraksi — nilainya TIDAK
  PERNAH masuk temuan/store, hanya jenis + path file.

## EMBA — opt-in semalam saja, bukan runner default

EMBA (14–25 jam per image, image Docker ~20 GB, RAM 16 GB — MDPI 2026)
sengaja TIDAK di-wire sebagai runner. Kalau program firmware-nya memang
meminta audit mendalam, jalankan manual semalam di mesin terisolasi:

```text
docker pull embeddedanalyzer/emba:latest
docker run --rm -v /path/firmware:/firmware embeddedanalyzer/emba:latest -f /firmware/image.bin -l /tmp/emba-log
```

Hasil EMBA dibaca manual keesokan harinya; jangan jadikan bagian dari
`bounty run` otomatis. EMBA 2.0.4 memakai binwalk-ng sebagai extractor.

## Kapan firmware TIDAK berlaku

- Program tidak mencantumkan firmware/perangkat dalam scope → jangan
  analisis image-nya, walau image-nya "bocor" di internet.
- Image dari vendor yang bukan target program → di luar scope.
- Jangan menjalankan binary hasil ekstraksi (emulasi QEMU hanya bila
  program mengizinkan dan di mesin terisolasi).
