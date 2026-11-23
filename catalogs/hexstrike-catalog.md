# HexStrike Catalog — Katalog On-Demand 150 Tool

> **BUKAN instalasi massal.** Katalog ini hanya daftar nama + kategori +
> kapan dipakai. Tool ditambah **per kebutuhan target**, satu per satu,
> setelah scope OK. Jangan install 150 tool sekaligus (bloat + risiko
> scope). Atribusi: katalog terinspirasi inventaris HexStrike (MIT) —
> nama tool adalah nama publik tool masing-masing pemiliknya.
>
> Total: 150 tool. Aturan tinjau ulang: katalog ditinjau tiap rilis P1
> besar / tiap eval lab di-update (lihat plan v3.1, maintenance katalog).

## Cara pakai katalog

1. Tentukan tahap hunt (lihat `skills/bounty/mindmap.md`).
2. Pilih **maksimal 1–2 tool** per kategori yang relevan dengan target.
3. Cek scope program mengizinkan tool itu (mis. scanning aktif vs pasif).
4. Tool memberi kandidat; verifikasi tetap manual
   (`verify-adversarial.md`).

## 1. Recon & subdomain (18)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 1 | subfinder | Subdomain pasif cepat |
| 2 | amass | Subdomain pasif + aktif (lihat `playbooks/dalfox-amass.md`) |
| 3 | assetfinder | Subdomain dari berbagai sumber |
| 4 | findomain | Subdomain cepat, multi-sumber |
| 5 | dnsx | Resolusi/validasi DNS massal |
| 6 | httpx | Cek host hidup + teknologi |
| 7 | naabu | Port scan cepat |
| 8 | katana | Crawling modern (JS-aware) |
| 9 | gau | Ambil URL dari arsip (Wayback dkk.) |
| 10 | waybackurls | URL historis dari Wayback |
| 11 | hakrawler | Crawl + ekstrak endpoint/JS |
| 12 | shuffledns | Brute-force subdomain massal |
| 13 | dnsrecon | Enumerasi DNS menyeluruh |
| 14 | theHarvester | Email/subdomain/host dari sumber OSINT |
| 15 | crt.sh | Subdomain dari log Certificate Transparency |
| 16 | censys | Cari aset terekspos di internet |
| 17 | shodan | Cari layanan terekspos di internet |
| 18 | chaos | Dataset subdomain ProjectDiscovery |

## 2. Web vulnerability scanner (16)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 19 | nuclei | Template scan terkurasi (lihat `playbooks/nuclei-trufflehog-trivy.md`) |
| 20 | nikto | Scan server web klasik |
| 21 | nmap | Port + deteksi layanan (script vuln bila diizinkan) |
| 22 | zap | Proxy + scanner aktif (OWASP ZAP) |
| 23 | burp-suite | Proxy + repeater + intruder manual |
| 24 | wpscan | WordPress (bila target WP + scope mengizinkan) |
| 25 | whatweb | Identifikasi teknologi web |
| 26 | wafw00f | Deteksi WAF di depan target |
| 27 | testssl.sh | Cek konfigurasi TLS |
| 28 | sslscan | Cek cipher/protokol TLS |
| 29 | dirsearch | Brute-force direktori web |
| 30 | gobuster | Brute-force direktori/DNS |
| 31 | feroxbuster | Brute-force direktori rekursif |
| 32 | arjun | Temukan parameter HTTP tersembunyi |
| 33 | xsstrike | Analisis XSS lanjutan (manual follow-up) |
| 34 | w3af | Framework scan web (kasus lama/legacy) |

## 3. XSS & SQLi (12)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 35 | dalfox | XSS otomatis (lihat `playbooks/dalfox-amass.md`) |
| 36 | sqlmap | SQLi — baca terbatas, lab/akun sendiri |
| 37 | ghauri | SQLi alternatif (bila sqlmap mentok) |
| 38 | nosqli | Uji NoSQL injection |
| 39 | graphql-cop | Audit keamanan GraphQL |
| 40 | graphqlmap | Uji injeksi GraphQL |
| 41 | xss-cheatsheet | Referensi payload XSS (bukan tool eksekusi) |
| 42 | dom-invader | Analisis DOM XSS (Burp extension) |
| 43 | kxss | Reflected XSS dari daftar URL |
| 44 | qsreplace | Ganti parameter URL untuk fuzzing |
| 45 | gf | Filter pola (XSS/SQLi/dll.) dari output |
| 46 | uro | Normalisasi/bersihkan daftar URL |

## 4. Secrets & kredensial bocor (8)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 47 | trufflehog | Secret di repo/riwayat (lihat playbook Nuclei) |
| 48 | gitleaks | Secret di git (lokal/CI) |
| 49 | git-secrets | Cegah commit secret |
| 50 | shhgit | Secret di repo publik GitHub |
| 51 | secretfinder | Secret di bundle JS |
| 52 | trufflehog-analyzer | Analisis hasil TruffleHog |
| 53 | noseyparker | Scan secret di filesystem |
| 54 | detect-secrets | Baseline secret pre-commit |

## 5. Network (12)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 55 | masscan | Port scan internet-scale (lab/izin tertulis) |
| 56 | rustscan | Port scan cepat |
| 57 | netcat | Uji konektivitas manual |
| 58 | socat | Relay/proxy TCP manual |
| 59 | tcpdump | Tangkap paket (lab sendiri) |
| 60 | wireshark | Analisis paket (lab sendiri) |
| 61 | mitmproxy | Proxy MITM (lihat `ghost-loop.md` Reaper) |
| 62 | bettercap | MITM jaringan lokal (lab) |
| 63 | responder | Uji LLMNR/NBT-NS (lab) |
| 64 | enum4linux | Enumerasi SMB (lab) |
| 65 | smbmap | Enumerasi share SMB (lab) |
| 66 | crackmapexec | Audit jaringan internal (lab/izin tertulis) |

## 6. Fuzzing (12)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 67 | ffuf | Fuzz direktori/parameter cepat |
| 68 | wfuzz | Fuzz web klasik |
| 69 | dirb | Brute-force direktori klasik |
| 70 | intruder (burp) | Fuzz manual via proxy |
| 71 | boofuzz | Fuzz protokol jaringan (lab) |
| 72 | afl++ | Fuzz binary (lab/RE) |
| 73 | libfuzzer | Fuzz library (lab/RE) |
| 74 | ffuf-postprocessing | Olah hasil ffuf |
| 75 | paramspider | Kumpulkan parameter dari arsip |
| 76 | fuzzuli | Wordlist fuzzing (referensi) |
| 77 | seclists | Koleksi wordlist (referensi, bukan eksekusi) |
| 78 | payloadsallthethings | Referensi payload (bukan tool eksekusi) |

## 7. Proxy & intercept (8)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 79 | caido | Proxy web modern, binding ke finding |
| 80 | charles-proxy | Proxy debug HTTP(S) |
| 81 | fiddler | Proxy debug HTTP(S) Windows |
| 82 | proxychains | Routing traffic via proxy (lab) |
| 83 | httprequest-smuggler | Uji request smuggling (lab/izin) |
| 84 | h2csmuggler | Uji HTTP/2 smuggling (lab/izin) |
| 85 | smuggler | Uji request smuggling (lab/izin) |
| 86 | chisel | Tunnel TCP/HTTP (lab) |

## 8. API & GraphQL (10)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 87 | postman | Uji API manual |
| 88 | insomnia | Uji API manual |
| 89 | openapi-fuzzer | Fuzz dari spesifikasi OpenAPI |
| 90 | restler | Fuzz REST stateful (lab) |
| 91 | schemathesis | Uji API dari OpenAPI/GraphQL |
| 92 | graphql-voyager | Visualisasi skema GraphQL |
| 93 | inql | Audit GraphQL (Burp extension) |
| 94 | clairvoyance | Ambil skema GraphQL |
| 95 | kiterunner | Enumerasi route API |
| 96 | apkleaks | Endpoint di APK (mobile, bila relevan) |

## 9. Cloud & container (12)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 97 | trivy | SBOM + vuln (lihat playbook Nuclei) |
| 98 | prowler | Audit keamanan AWS/Azure/GCP (akun sendiri) |
| 99 | scout-suite | Audit multi-cloud (akun sendiri) |
| 100 | cloudsploit | Audit cloud (akun sendiri) |
| 101 | kube-bench | Benchmark keamanan Kubernetes (klaster sendiri) |
| 102 | kube-hunter | Uji keamanan Kubernetes (klaster sendiri) |
| 103 | kubeaudit | Audit manifest Kubernetes |
| 104 | checkov | Scan IaC (Terraform/dll.) |
| 105 | tfsec | Scan Terraform |
| 106 | docker-bench-security | Benchmark Docker host (sendiri) |
| 107 | grype | Scan vuln image/container |
| 108 | syft | Hasilkan SBOM dari image |

## 10. OSINT pasif (10)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 109 | spiderfoot | Recon pasif menyeluruh (target organisasi) |
| 110 | recon-ng | Framework OSINT |
| 111 | maltego | Visualisasi relasi OSINT |
| 112 | sublist3r | Subdomain OSINT klasik |
| 113 | knockpy | Subdomain via wordlist + sumber |
| 114 | aquatone | Screenshot + review subdomain |
| 115 | eyewitness | Screenshot layanan web |
| 116 | gowitness | Screenshot web cepat |
| 117 | urlscan.io | Analisis URL pasif |
| 118 | virustotal | Cek reputasi URL/domain/file |

## 11. Exploitation helpers — lab / izin tertulis saja (10)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 119 | metasploit | Framework exploit — LAB SAJA, bukan target produksi |
| 120 | exploit-db | Referensi exploit publik (bukan eksekusi) |
| 121 | searchsploit | Cari exploit lokal dari Exploit-DB |
| 122 | msfvenom | Payload lab (RE/malware analysis) |
| 123 | netexec | Audit jaringan (pengganti crackmapexec) |
| 124 | impacket | Toolkit protokol jaringan (lab) |
| 125 | bloodhound | Pemetaan AD (lab/izin tertulis) |
| 126 | mimikatz | Kredensial Windows — LAB SAJA |
| 127 | hashcat | Cracking hash — LAB SAJA (hash milik sendiri) |
| 128 | john | Cracking password — LAB SAJA (hash milik sendiri) |

## 12. Reporting & forensik (10)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 129 | dradis | Manajemen temuan + laporan |
| 130 | faraday | Manajemen temuan kolaboratif |
| 131 | defectdojo | Manajemen vuln + laporan |
| 132 | serengeti | Template laporan (referensi) |
| 133 | obsidian | Catatan hunt (lokal) |
| 134 | exiftool | Metadata file bukti |
| 135 | strings | Analisis string binary (lab) |
| 136 | volatility | Forensik memori (lab) |
| 137 | autopsy | Forensik disk (lab) |
| 138 | plaso | Timeline forensik (lab) |

## 13. Utilitas & wordlist (12)

| # | Tool | Kapan dipakai |
|---|------|---------------|
| 139 | jq | Olah JSON hasil tool |
| 140 | yq | Olah YAML hasil tool |
| 141 | parallel | Jalankan tool paralel (hemat waktu) |
| 142 | tmux | Sesi panjang di terminal |
| 143 | ripgrep | Cari pola di kode cepat |
| 144 | fd | Cari file cepat |
| 145 | anew | Tambah baris unik ke file |
| 146 | unfurl | Pecah URL jadi komponen |
| 147 | nuclei-templates | Koleksi template Nuclei (referensi) |
| 148 | assetnote-wordlists | Koleksi wordlist (referensi) |
| 149 | ffuf-wordlists | Wordlist untuk ffuf (referensi) |
| 150 | rockyou | Wordlist password — LAB SAJA |

## Catatan akhir

- Nomor di tabel adalah nomor katalog (1–150); beberapa entri merujuk
  tool yang sudah muncul di kategori lain (ditandai "Sudah di §…") —
  tool yang sama tidak dihitung dua kali dalam total 150.
- Tool kategori 11 (exploitation helpers) hanya untuk lab / target
  dengan izin tertulis eksplisit — bukan untuk target bounty produksi
  tanpa izin itu.
- Tool kategori K/L (abuse/spam/bypass) TIDAK ada di katalog ini.
