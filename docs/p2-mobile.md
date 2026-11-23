# P2 — Mobile (MobSF skill + checklist)

> Status: **P2 / mode terpisah.** v1 hanya menguji **API backend
> mobile** (sudah tercakup skill web/API Strix, P0). Analisis APK/IPA
> penuh + MobSF masuk Fase 2. Fokus tetap API backend: kebanyakan bug
> bounty mobile yang bernilai ada di server, bukan di aplikasi.

## Yang sudah tercakup v1 (API backend mobile)

- Endpoint API yang dipakai aplikasi mobile = endpoint web biasa:
  scope gate, auth low/high-priv, IDOR, broken auth, business logic
  (P0-2, P0-7).
- Token mobile (JWT / API key di header) diperlakukan seperti
  kredensial biasa: simpan 0600, jangan di-log, jangan di-commit.
- Jangan mengandalkan "aplikasi mobile = aman karena butuh aplikasi":
  semua endpoint harus diuji langsung (curl / Strix), bukan hanya
  lewat UI aplikasi.

## MobSF — kapan dipakai (P2)

| Kebutuhan | Tool |
| --- | --- |
| Analisis statis APK/IPA (manifest, permission, secret hardcoded, crypto) | MobSF REST API |
| CI/CD: scan tiap build aplikasi target (bila program menyediakan APK) | MobSF + pipeline |
| Dinamis (bila diizinkan scope) | MobSF dynamic analyzer / frida |

MobSF dijalankan **lokal** (server MobSF sendiri), bukan layanan
publik, dan hanya terhadap APK/IPA yang scope program izinkan.

### REST API (contoh — ganti host/port sesuai instalasi lokal)

```bash
# Upload APK untuk analisis statis (API key dari .env lokal)
curl -X POST http://127.0.0.1:8000/api/v1/upload \
  -H "Authorization: Bearer $MOBSF_API_KEY" \
  -F "file=@app-target.apk"

# Lihat hasil scan (ganti HASH dengan hash dari respons upload)
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Authorization: Bearer $MOBSF_API_KEY" \
  -d "hash=$MOBSF_SCAN_HASH"
```

API key MobSF = placeholder di atas; isi dari `.env` lokal.
Jangan hardcode key di skrip / CI.

### CI/CD (contoh pola)

```yaml
# .github/workflows/mobile-scan.yml (P2, contoh — belum aktif di v1)
# - job: jalankan MobSF terhadap APK yang disediakan program
# - simpan laporan sebagai artifact (bukan commit)
# - gagalkan job bila ada temuan High yang baru
# - APK tidak di-commit ke repo
```

## Checklist mobile (P2)

1. [ ] Scope program mencakup aplikasi mobile + API backend-nya?
2. [ ] APK/IPA dari sumber resmi program (bukan toko pihak ketiga).
3. [ ] API backend diuji seperti API web (auth, IDOR, rate limit).
4. [ ] MobSF statis: hardcoded secret/API key, crypto lemah,
       permission berlebih, export komponen, deep link.
5. [ ] Tiap temuan statis **diverifikasi** (apakah secret masih aktif?
       apakah komponen benar-benar bisa dieksploitasi?) — temuan
       scanner = kandidat, bukan finding (P0-2).
6. [ ] Frida / dynamic hanya bila scope mengizinkan instrumentasi.
7. [ ] Laporan pisahkan temuan aplikasi vs temuan API backend.
8. [ ] Jangan: bypass root detection / SSL pinning untuk menyerang
       pengguna lain; instrumentasi hanya di perangkat/lab sendiri
       terhadap target berizin.

## Batasan

- v1 **tidak** menginstal MobSF / frida. Dokumen ini persiapan P2.
- Analisis APK tanpa izin program = di luar scope.
- Temuan hardcoded secret wajib dicek masih aktif atau sudah
  dirotasi sebelum dilaporkan (hindari FP).
