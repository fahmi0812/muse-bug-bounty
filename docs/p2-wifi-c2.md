# P2-5 — WiFi / C2 / Post-Exploitation: Sengaja TIDAK Dibangun

Keputusan ini final dan dikunci di kode (`bounty/lib/guard.js`,
`KL_DENYLIST`: `wifite`, `aircrack`, `bettercap`, `sliver`, `covenant`,
`mythic`, `cobalt-strike` — perintah apa pun yang menyebutnya ditolak
oleh `checkCommand`).

## Alasan

1. **Di luar scope bounty.** Program bug bounty menguji aplikasi web/API/
   mobile yang terdaftar — bukan jaringan WiFi tetangga, bukan infrastruktur
   C2, bukan post-exploitation di mesin korban.
2. **Risiko hukum dan etika.** Serangan WiFi dan C2 hampir selalu menyentuh
   sistem yang bukan milik target program; satu perintah salah = akses
   tanpa izin.
3. **Merusak janji "ringan".** C2 butuh server, listener, dan operasi
   yang tidak muat di wrapper ringan ini.

## Yang tetap ada

- Deteksi kerentanan WiFi *konfigurasi* (mis. portal captive, TLS) hanya
  bila targetnya endpoint web program yang terdaftar — lewat runner web
  biasa, bukan tool WiFi.
- Bila suatu program bounty secara eksplisit mencantumkan WiFi/C2 di
  scope-nya, itu tetap di luar tool ini: gunakan tool khusus di luar
  `bounty` dengan izin tertulis program tersebut.
