# Instal binary runner — `scripts/install-tools.sh` (P2-6)

Skrip ini menginstal binary eksternal yang dipanggil `bounty` (runner, recon,
JS mining, OAST, LLM), dengan manajer paket resmi masing-masing. Ini adalah
**jalur instal yang didukung** untuk binary runner — menggantikan winget
(lihat "Status winget" di bawah).

## Cara pakai

```sh
sh scripts/install-tools.sh              # mode rencana: hanya cetak perintah
sh scripts/install-tools.sh --dry-run    # sama, eksplisit
sh scripts/install-tools.sh --yes        # benar-benar menginstal semuanya
sh scripts/install-tools.sh --yes --pd-only       # hanya tool ProjectDiscovery
sh scripts/install-tools.sh --yes --go-only       # hanya jsluice + interactsh-client
sh scripts/install-tools.sh --yes --python-only   # hanya garak + pyrit
```

Tanpa `--yes`, **tidak ada satu pun perintah instal yang dijalankan** —
skrip hanya mencetak rencana dan berhenti. Bila prasyarat hilang saat
`--yes` (go untuk kelompok Go/PD, pipx untuk kelompok Python), skrip
berhenti dengan exit 2 dan pesan yang jelas, sebelum menjalankan apa pun.
Skrip tidak pernah menginstal Strix (itu `scripts/install.sh` /
`bounty install --strix`), tidak menyentuh Docker, dan tidak menulis secret.

## Tabel tool

| Tool | Dari mana | Perintah instal | Dipakai `bounty` untuk |
|---|---|---|---|
| `pdtm` | Go | `go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest` | manajer tool ProjectDiscovery |
| `subfinder`, `dnsx`, `httpx`, `katana`, `nuclei` | pdtm | `pdtm -install subfinder,dnsx,httpx,katana,nuclei` | `bounty recon`, `bounty scan --tool nuclei` |
| `jsluice` | Go (BishopFox) | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` | `bounty scan --tool jsluice` |
| `interactsh-client` | Go (ProjectDiscovery) | `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` | `bounty oast` |
| `garak` | pipx (PyPI `garak`, NVIDIA) | `pipx install garak` | `bounty scan --tool garak-agent-breaker` |
| `pyrit` | pipx (PyPI `pyrit`, Microsoft) | `pipx install pyrit` | `bounty scan --tool pyrit` |

Semua versi memakai `@latest` / rilis terbaru PyPI — versi mengambang
mengikuti upstream. Untuk membekukan versi, ubah variabel `*_VERSION` di
atas `scripts/install-tools.sh` (mis. `PDTM_VERSION="v0.0.9"`) lalu jalankan
ulang. Tidak ada pin versi bawaan: repo ini tidak mematok versi untuk
tool-tool di atas (pin yang ada di repo — Ghidra 12.1.4, REA 6.8.0,
MobSF 4.5.3 — bukan bagian skrip ini).

Jalur terverifikasi 23 Nov 2026: `pdtm` (`go install .../pdtm/cmd/pdtm@latest`,
docs.projectdiscovery.io + pkg.go.dev), `interactsh-client`
(docs.projectdiscovery.io), `jsluice` BishopFox (sesuai pin yang sudah ada
di `bounty/lib/jsmining.js`; ada fork `projectdiscovery/jsluice`, tapi repo
ini memakai BishopFox), `garak` (PyPI `garak`, `python -m pip install -U garak`).

## PATH

Binary jatuh di tiga tempat — pastikan semuanya di `PATH`:

```sh
export PATH="$PATH:$(go env GOPATH)/bin:$HOME/.pdtm/go/bin:$HOME/.local/bin"
```

Perhatian: bila paket Python bernama `httpx` terinstal di `~/.local/bin`,
ia bisa menutupi `httpx` ProjectDiscovery. Pastikan `~/.pdtm/go/bin`
(atau `$(go env GOPATH)/bin`) lebih dulu di `PATH` daripada
`~/.local/bin`, atau panggil httpx PD dengan path absolut.

## Status winget

**Winget masih TIDAK live** — manifest di `winget/` butuh paket rilis
GitHub v1.0.0 (zip) + `InstallerSha256` asli (saat ini placeholder
`0000…`) + PR ke `microsoft/winget-pkgs`. Sampai tiga hal itu ada, winget
bukan jalur instal yang didukung; pakai skrip ini (`pdtm`/`go`/`pipx`)
sebagai gantinya.

## Best-effort / belum diuji live

Skrip ini belum pernah dijalankan dengan `--yes` di VM (tidak ada binary
`go`/`pipx` di VM) — yang diuji di sini hanya mode rencana (`--dry-run`)
dan penolakan prasyarat (exit 2). Flag `pdtm -install <daftar>` dan
perilaku `pipx install` pada pipx versi lama belum diuji live; bila gagal,
cek `pdtm -h` / `pipx --help` di mesin tersebut.
