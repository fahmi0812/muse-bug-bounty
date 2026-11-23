# hunt-ssrf — Server-Side Request Forgery

Kelas: SSRF | CWE: CWE-918 | OWASP: A10:2021 SSRF

## Detection pattern
- Fitur mengambil URL dari user: preview link, webhook, fetch gambar.
- Respons berbeda untuk URL internal vs eksternal (waktu/kode).
- Error berisi alamat/IP internal atau pesan DNS internal.
- Parameter `url`, `src`, `fetch`, `callback` yang diteruskan ke server.

## Payload contoh
- `http://169.254.169.254/latest/meta-data/` — endpoint metadata cloud
  (uji di lab / hanya baca metadata, jangan ambil kredensial).
- `http://localhost:3000/admin` — uji jangkauan layanan lokal.
- `http://internal.example.local/` — uji nama host internal.
- `https://example.com@attacker.example/` — uji parsing URL ambigu.

## Bypass
- Coba redirect 302 dari domain diizinkan ke target internal.
- Coba representasi IP alternatif (desimal, heksadesimal).
- Coba skema lain bila `http` diblokir (`gopher`/`file` bila relevan).

## Chain template
SSRF → baca layanan internal → baca metadata / endpoint admin internal
→ dampak (jangan lanjut ke kredensial cloud di target nyata).

## Verifikasi
- Buktikan server yang melakukan request, bukan browsermu (mis. lewat
  callback ke server log milikmu / respons berisi data internal).
- Replay dengan URL normal harus tetap berfungsi.
- Jangan ambil atau pakai kredensial cloud yang terbaca.

## Pendalaman
Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — parafrase, fokus deteksi + validasi.

### Pola deteksi tambahan
- Aturan OOB: callback harus dikaitkan ke SATU parameter — bila beberapa parameter memakai URL yang sama, isolasi satu per satu sebelum mengklaim.
- Blind vs full-read: minta server mengambil URL dengan isi yang dikenal — isi kembali = full-read; hanya callback tanpa isi = blind (skor dan langkahnya berbeda).
- Metadata per provider: GCP (`metadata.google.internal`), Azure (butuh header `Metadata: true`), Kubernetes (service account) — uji hanya baca metadata di lab, jangan ambil kredensial.
- Redirect SSRF: server redirect milikmu mengarah ke target internal — uji apakah server mengikuti redirect ke host internal.
- Port layanan internal: kubelet / etcd / Redis / Elasticsearch / Consul — respons berbeda per port menandai layanan; uji dengan timing + banner, jangan kirim perintah.

### Chain tambahan
SSRF blind + callback OOB → konfirmasi server-side → petakan port internal → baca metadata (berhenti sebelum kredensial).

### Catatan Gate-0 tambahan
- Callback harus datang dari server target (interactsh), bukan dari browsermu; URL penyerang yang hanya terpantul di respons bukan SSRF.
- Buktikan server yang melakukan request, bukan browsermu — lewat callback ke server log milikmu atau respons berisi data internal.
