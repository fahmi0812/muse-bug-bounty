# hunt-k8s — Kubernetes & Docker

Kelas: Broken Access Control / Exposure | CWE: CWE-862, CWE-200 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu; jangan exec ke pod produksi atau workload orang lain.
- Buktikan dengan baca/cek hak akses saja — jangan membuat pod, jangan menghapus apa pun, jangan menjalankan perintah destruktif di cluster.
- Jangan klaim RCE dari status code saja; wajib ada output perintah / nilai secret yang terbaca.

## Detection pattern
- Port 6443/10250/10255/2379/8443 terbuka; `/version` API server anonim membocorkan `gitVersion` (menentukan CVE yang berlaku).
- API anonim: `SelfSubjectRulesReview` menunjukkan verb istimewa (baca Secret, `nodes/proxy`, `pods/exec`) — daftar `200` dengan `items: []` saja = RBAC-filtered, BUKAN admin.
- Kubelet 10250: `/run` mengembalikan output perintah langsung; `/exec` adalah stream SPDY/WebSocket (POST polos hanya 302, bukan bukti gagal). Kubelet 10255 read-only = info disclosure saja, tanpa exec.
- `nodes/proxy` via API server → `/run` lewat proxy = RCE pod tanpa menyentuh 10250.
- etcd 2379 tanpa auth: `get /registry/secrets --prefix` mengembalikan data (Secret plaintext bila tanpa `EncryptionConfiguration`).
- `docker.sock` terjangkau → container privileged + bind-mount host `/` = host root.
- Token SA di `/var/run/secrets/.../token`: decode `aud`/`exp` dulu — token projected bisa sudah mati atau audiensnya bukan API server.

## Sinyal uji
- `GET /version`, `/api`, `/healthz` (anonim) → fingerprint versi.
- `SelfSubjectReview` (siapa saya?) + `SelfSubjectRulesReview` (apa yang bisa saya lakukan?) — hanya itulah cek hak yang jujur.
- Kubelet: `GET /pods` (daftar) → `/run` dengan perintah baca saja (`id`) pada pod uji milikmu.
- etcd: `range`/`get` yang berhasil mengembalikan data kunci = akses nyata; error handshake TLS bukan akses.
- Dashboard `:8443/api/v1/<resource>` 200 dengan JSON resource nyata = akses tanpa token; halaman login HTML saja bukan bukti.

## Bypass
- Ingress-NGINX admission controller (CVE-2025-1974): versi < 1.11.5 / < 1.12.1 — cek versi dari `/healthz`/tag image, jangan kirim AdmissionReview berbahaya.
- CVE-2018-1002105: `gitVersion` < v1.10.11/1.11.5/1.12.3 — proxy API server ke backend dengan identitas API server.

## Chain template
API anonim + baca Secret terkonfirmasi → kredensial SA/TLS → kendali cluster. Atau: kubelet `/run` → exec pod → curi token SA → API server. Atau: docker.sock → container privileged → host root.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
`system:anonymous` diikat ke role kuat; `nodes/proxy` diberikan ke role rendah; kubelet/etcd/dashboard terekspos tanpa auth; token SA auto-mount tanpa batas; Tiller/Helm 2 tertinggal.

## Verifikasi
- Anon 200 ≠ cluster-admin — wajib SelfSubjectRulesReview + satu nilai Secret terbaca (redaksi sebelum lapor).
- Kubelet RCE wajib output literal (`id`/`hostname`) dari `/run` atau stream `/exec` yang selesai.
- Cek versi sebelum mengklaim CVE (runc, gitVersion, ingress-nginx) — versi cocok = petunjuk, PoC = bukti.
