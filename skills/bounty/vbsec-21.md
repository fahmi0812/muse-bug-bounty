# vbsec-21 — Checklist 21 Tipe Vuln Kode Hasil AI

> Atribusi: pola checklist terinspirasi vbsec (MIT) — isi di bawah ditulis
> ulang secara orisinal untuk repo ini, bukan salinan verbatim.
> Lisensi sumber: MIT.

## Kapan dipakai

- Pre-scan ringan sebelum hunting dalam: baca kode hasil AI / PR baru,
  cari 21 pola di bawah, tandai kandidat, lalu verifikasi dengan skill
  hunt yang sesuai. Bukan pengganti verifikasi live.
- Dipakai saat: review kode, audit repo target (bila scope mengizinkan
  baca kode), atau triage awal sebelum `hunt-*`.

## Cara pakai (cepat)

1. Jalan satu pass per file: cocokkan pola "Tanda" di bawah.
2. Tiap cocok = kandidat, bukan finding. Tulis file:baris + tipe.
3. Verifikasi non-destruktif: replay dengan input aman/terkontrol,
   cek apakah pola benar-benar dieksekusi (bukan dead code).
4. Yang tidak terbukti → buang, jangan dilaporkan.

## Bahasa contoh

Contoh singkat tersebar di 5 bahasa: JavaScript, Python, Go, Java, PHP.
Tanda `✗ rentan` / `✓ aman` di tiap tipe.

## 1. SQL Injection (CWE-89)

- Tanda: query dibangun dengan string concatenation / f-string / template.
- ✗ `db.query("SELECT * FROM users WHERE id=" + id)` (JS)
- ✓ `db.query("SELECT * FROM users WHERE id=?", [id])` — prepared statement.
- Perbaikan: parameterised query di semua bahasa; jangan escape manual.

## 2. Cross-Site Scripting (CWE-79)

- Tanda: input user dirender tanpa encoding; `innerHTML`, `|safe`.
- ✗ `el.innerHTML = userInput` (JS)
- ✓ `el.textContent = userInput` — atau template engine auto-escape.
- Perbaikan: encode per konteks (HTML/atribut/JS/URL); CSP sebagai lapis kedua.

## 3. Server-Side Request Forgery (CWE-918)

- Tanda: URL dari user di-`fetch`/`requests.get` tanpa allowlist.
- ✗ `requests.get(url)` (Python)
- ✓ Validasi skema http(s) + host ada di allowlist + blokir IP privat/metadata.
- Perbaikan: allowlist host, timeout, blokir 169.254.0.0/16 dan RFC1918.

## 4. Path Traversal (CWE-22)

- Tanda: path file dari user digabung tanpa normalisasi.
- ✗ `open("uploads/" + name)` (Python)
- ✓ `os.path.join(base, name)` lalu cek `realpath` masih di dalam `base`.
- Perbaikan: normalisasi + cek prefix direktori + allowlist ekstensi.

## 5. Command Injection (CWE-78)

- Tanda: input user masuk ke `exec`/`shell=True`/`os.system`.
- ✗ `exec.Command("sh", "-c", "convert " + file)` (Go)
- ✓ `exec.Command("convert", file)` — argv, tanpa shell.
- Perbaikan: tanpa shell; argumen sebagai array; allowlist nilai.

## 6. Insecure Deserialization (CWE-502)

- Tanda: `pickle.loads`, `unserialize`, `ObjectInputStream` pada data user.
- ✗ `pickle.loads(data)` (Python)
- ✓ `json.loads(data)` dengan skema tervalidasi.
- Perbaikan: format data aman (JSON + validasi skema); tanda tangan bila harus biner.

## 7. Broken Authentication / Session (CWE-287)

- Tanda: session id bisa ditebak, cookie tanpa HttpOnly/Secure, login tanpa
  rate limit, password disimpan plaintext/md5.
- ✗ `md5(password)` (PHP)
- ✓ `password_hash($pw, PASSWORD_ARGON2ID)` + session id acak 128-bit + cookie
  HttpOnly/Secure/SameSite.
- Perbaikan: hashing modern, lockout/rate limit, rotasi session setelah login.

## 8. IDOR / BOLA (CWE-639)

- Tanda: ID objek dari user dipakai tanpa cek kepemilikan.
- ✗ `getOrder(req.params.id)` tanpa cek pemilik (JS)
- ✓ Cek `order.userId === req.user.id` sebelum baca/ubah.
- Perbaikan: cek otorisasi di server tiap akses objek, bukan hanya di UI.

## 9. Hardcoded Secrets (CWE-798)

- Tanda: API key / password / token tertulis di kode, commit, atau bundle.
- ✗ `const KEY = "sk-live-..."` (JS)
- ✓ `process.env.API_KEY` + secret manager; scan pre-commit.
- Perbaikan: pindah ke env/vault, rotasi secret yang pernah bocor.

## 10. Weak Cryptography (CWE-327/338)

- Tanda: MD5/SHA1 untuk password, ECB, IV statis, `Math.random` untuk token.
- ✗ `Cipher.getInstance("AES/ECB/PKCS5Padding")` (Java)
- ✓ `AES/GCM/NoPadding` + IV acak per enkripsi; `SecureRandom`.
- Perbaikan: algoritma modern + library standar, jangan kripto buatan sendiri.

## 11. XML External Entity (CWE-611)

- Tanda: parser XML dengan external entity / DTD aktif.
- ✗ `DocumentBuilderFactory` tanpa `disallow-doctype-decl` (Java)
- ✓ Matikan DTD: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- Perbaikan: parser aman / JSON bila memungkinkan.

## 12. Server-Side Template Injection (CWE-94)

- Tanda: input user masuk ke template engine sebagai template.
- ✗ `render_template_string("Hello " + name)` (Python/Flask)
- ✓ Template statis + variabel: `render_template("hi.html", name=name)`.
- Perbaikan: jangan pernah render string user sebagai template.

## 13. Open Redirect (CWE-601)

- Tanda: parameter `next`/`returnUrl` dipakai langsung di redirect.
- ✗ `redirect(req.query.next)` (JS)
- ✓ Allowlist path relatif / host sendiri saja.
- Perbaikan: validasi host + path relatif, tolak URL absolut asing.

## 14. Cross-Site Request Forgery (CWE-352)

- Tanda: aksi state-changing (POST/PUT/DELETE) tanpa token anti-CSRF.
- ✗ Form POST tanpa token (semua bahasa).
- ✓ Token anti-CSRF per sesi + cek `Origin` + `SameSite=Lax/Strict`.
- Perbaikan: token acak terikat sesi; cookie SameSite bukan satu-satunya lapis.

## 15. Race Condition (CWE-362)

- Tanda: cek-lalu-pakai (check-then-act) tanpa transaksi/lock: saldo,
  kupon, redeem sekali-pakai.
- ✗ `if (balance >= x) { balance -= x; }` tanpa lock (Go/Java)
- ✓ Transaksi DB atomik / `UPDATE ... WHERE balance >= x` + cek rows affected.
- Perbaikan: operasi atomik di DB; idempotency key untuk retry.

## 16. Prototype Pollution (CWE-1321)

- Tanda: merge rekursif objek user tanpa blokir `__proto__`/`constructor`.
- ✗ `_.merge({}, userInput)` versi lama / merge manual (JS)
- ✓ Blokir kunci `__proto__`, `constructor`, `prototype`; pakai merge yang
  aman atau `Object.create(null)`.
- Perbaikan: denylist kunci berbahaya + library merge ter-patch.

## 17. Regular Expression DoS (CWE-1333)

- Tanda: regex dengan nested quantifier pada input user tanpa batas.
- ✗ `/^(a+)+$/` pada input tak terbatas (JS/Python)
- ✓ Regex sederhana + batas panjang input + timeout regex bila didukung.
- Perbaikan: sederhanakan pola, batasi panjang, uji dengan input panjang.

## 18. Log Injection (CWE-117)

- Tanda: input user ditulis mentah ke log (newline bisa memalsukan baris).
- ✗ `log.info("login: " + username)` (Java/Go)
- ✓ Encode newline (`\n` → `\\n`) / pakai logger terstruktur (JSON).
- Perbaikan: sanitasi log; jangan log secret/PII.

## 19. Insecure Randomness (CWE-338)

- Tanda: token/OTP/password reset dibuat dari `Math.random`/`rand()`.
- ✗ `Math.random().toString(36)` untuk token reset (JS)
- ✓ `crypto.randomBytes(32)` / `secrets.token_urlsafe(32)` (Python).
- Perbaikan: CSPRNG + panjang cukup (≥128 bit).

## 20. Slopsquatting (paket AI-halusinasi)

- Tanda: dependensi bernama mirip paket populer / nama paket yang
  "direkomendasikan" AI tapi tidak ada di registry resmi — klasik
  jebakan supply chain dari kode hasil AI.
- ✗ `npm install reqests` (typo dari `requests`-style) / paket tanpa
  riwayat, tanpa repo, baru dibuat, tanpa maintainer jelas.
- ✓ Cek paket di registry resmi: ada, versi + tanggal rilis masuk akal,
  repo + maintainer jelas, download wajar; pin versi + lockfile.
- Perbaikan: verifikasi tiap dependensi baru hasil saran AI; audit
  `npm audit` / `pip-audit`; hapus paket tak terverifikasi.

## 21. Prompt Injection / Penanganan Output LLM (CWE-707)

- Tanda: output LLM (atau input user yang diteruskan ke LLM) dieksekusi
  sebagai perintah/kode/SQL tanpa validasi.
- ✗ `eval(llmOutput)` / jalankan perintah dari teks LLM (Python/JS)
- ✓ Perlakukan output LLM sebagai data tak tepercaya: parse JSON
  tervalidasi skema, allowlist aksi, tanpa `eval`/shell.
- Perbaikan: pemisah instruksi vs data; validasi output; human-in-the-loop
  untuk aksi sensitif.

## Verifikasi non-destruktif

- Buktikan pola benar-benar reachable: input terkontrol → efek teramati
  (error, perubahan state akun sendiri, log).
- Jangan: hapus data, ubah data orang lain, kirim payload destruktif,
  brute-force massal.
- Tiap kandidat yang lolos verifikasi → lanjut ke skill `hunt-*` yang
  sesuai + `verify-adversarial.md` sebelum jadi finding.
