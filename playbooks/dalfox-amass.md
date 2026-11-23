# Playbook: Dalfox (XSS) + Amass (Subdomain)

> Scope-gate dulu: baca `programs/<nama>.md`, pastikan target in-scope,
> lalu cetak `Scope OK`. Tanpa itu, jangan jalankan perintah di bawah.

## Kapan dipakai

- **Amass**: awal recon — cari subdomain in-scope sebelum enumerasi
  (lihat `skills/bounty/mindmap.md` tahap recon).
- **Dalfox**: ada parameter/endpoint yang dicurigai XSS (reflected/stored/
  DOM) — setelah enumerasi, sebelum klaim finding (lihat
  `skills/bounty/hunt/hunt-xss.md`).

## Amass — subdomain (pasif dulu)

```bash
# Enumerasi pasif (tidak menyentuh target langsung)
amass enum -passive -d example.com -o amass-passive.txt
```

```bash
# Aktif hanya bila program mengizinkan scanning aktif + rate limit dipatuhi
amass enum -active -d example.com -o amass-active.txt
```

- Saring hasil ke host yang ada di `Allowed` program; subdomain di luar
  scope → buang, jangan dipindai.
- Simpan output lokal; jangan commit hasil mentah bila mengandung data sensitif.

## Dalfox — XSS

```bash
# Uji satu URL + parameter (mode aman: tanpa Blind XSS server sendiri)
dalfox url "https://example.com/search?q=test" --skip-bav
```

```bash
# Uji dari daftar URL (hasil enumerasi), satu per satu, rate dibatasi
dalfox file urls.txt --skip-bav --delay 200
```

- `--skip-bav`: lewati Blind XSS / payload berat yang butuh callback server.
- Jangan pakai `--blind` dengan server callback publik tanpa izin program.
- Dalfox menemukan kandidat, bukan finding: tiap hit harus direplay
  manual di browser bersih (`alert(1)` terlihat) + kontrol negatif
  (input normal tidak mengeksekusi).

## Scope-gate (wajib)

1. Baca `programs/<nama>.md` → catat Allowed/Denied, budget, rate limit.
2. Target tidak di Allowed → berhenti.
3. Patuhi rate limit program (default 10 req/detik) + hormati 429/backoff.
4. Jangan scan di luar jam otomasi program bila ada.

## Verifikasi non-destruktif

- XSS: buktikan eksekusi di browser sendiri; stored XSS buktikan dari
  akun kedua milik sendiri.
- Jangan curi cookie/sesi orang lain; jangan kirim payload ke korban nyata.
- Semua kandidat → `verify-adversarial.md` sebelum jadi finding.
