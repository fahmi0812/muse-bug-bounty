#!/bin/sh
# scripts/install-tools.sh — Instal binary runner muse-bug-bounty (P2-6).
# Jalur instal yang DIDUKUNG (menggantikan winget — lihat docs/install-tools.md).
# POSIX sh, idempotent, tanpa network selain manajer paket resmi (go/pipx/pdtm).
#
# TIDAK dilakukan skrip ini: tidak instal Strix (itu scripts/install.sh /
# `bounty install --strix`), tidak menyentuh Docker, tidak menulis secret.
#
# Cara pakai:
#   sh scripts/install-tools.sh            # mode rencana: hanya cetak perintah
#   sh scripts/install-tools.sh --dry-run  # sama seperti di atas (eksplisit)
#   sh scripts/install-tools.sh --yes      # baru benar-benar menjalankan
#   sh scripts/install-tools.sh --yes --pd-only      # hanya tool ProjectDiscovery
#   sh scripts/install-tools.sh --yes --go-only      # hanya tool Go non-PD
#   sh scripts/install-tools.sh --yes --python-only  # hanya tool Python
# Tanpa --yes, TIDAK ADA satu pun perintah instal yang dijalankan.
#
# Yang diinstal (semua @latest — versi mengambang mengikuti upstream;
# untuk membekukan versi, ubah variabel *_VERSION di bawah ke tag rilis):
#   PD (via pdtm): subfinder, dnsx, httpx, katana, nuclei
#     pdtm sendiri: go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
#     (terverifikasi: docs.projectdiscovery.io + pkg.go.dev, 23 Nov 2026)
#   Go: jsluice (BishopFox — sesuai pin di bounty/lib/jsmining.js),
#       interactsh-client (projectdiscovery/interactsh — terverifikasi
#       docs.projectdiscovery.io, 23 Nov 2026)
#   Python (via pipx): garak (PyPI "garak", NVIDIA — terverifikasi pypi.org),
#       pyrit (PyPI "pyrit", Microsoft — sesuai bounty/lib/llm-runners.js)
# Best-effort (belum diuji live di VM — tidak ada binary go/pipx di VM):
#   flag `pdtm -install <daftar>` dan perilaku `pipx install` di mesin yang
#   sudah punya pipx versi lama; cek `pdtm -h` / `pipx --help` bila gagal.
set -eu

PDTM_VERSION="latest"
JSLUICE_VERSION="latest"
INTERACTSH_VERSION="latest"
GARAK_VERSION="latest"
PYRIT_VERSION="latest"

PD_TOOLS="subfinder,dnsx,httpx,katana,nuclei"

YES=0
MODE="all"

usage() {
  echo "Usage: $0 [--dry-run] [--yes] [--pd-only|--go-only|--python-only]"
  echo "  Tanpa --yes: mode rencana — hanya mencetak perintah, tidak menjalankan apa pun."
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) YES=0 ;;
    --yes) YES=1 ;;
    --pd-only) MODE="pd" ;;
    --go-only) MODE="go" ;;
    --python-only) MODE="python" ;;
    -h|--help) usage ;;
    *) echo "Argumen tidak dikenal: $1" >&2; usage ;;
  esac
  shift
done

# do_cmd <perintah...>: cetak perintah; jalankan hanya bila --yes.
do_cmd() {
  printf '%s\n' "$*"
  if [ "$YES" = 1 ]; then
    "$@"
  fi
}

# sudah_ada <nama> [dir-tambahan]: 0 bila binary ditemukan di PATH atau dir.
sudah_ada() {
  if command -v "$1" >/dev/null 2>&1; then return 0; fi
  if [ -n "${2:-}" ] && [ -x "$2/$1" ]; then return 0; fi
  return 1
}

need_go() {
  if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: go tidak ditemukan — instal Go dulu (https://go.dev/dl/) lalu jalankan ulang." >&2
    exit 2
  fi
}

need_pipx() {
  if ! command -v pipx >/dev/null 2>&1; then
    echo "ERROR: pipx tidak ditemukan — instal pipx dulu (python3 -m pip install --user pipx) lalu jalankan ulang." >&2
    exit 2
  fi
}

echo "== muse-bug-bounty: instal binary runner =="
if [ "$YES" = 0 ]; then
  echo "Mode rencana — tidak menjalankan apa pun."
  echo "Jalankan ulang dengan --yes untuk benar-benar menginstal."
fi

# --- Kelompok PD: pdtm + subfinder/dnsx/httpx/katana/nuclei ---
if [ "$MODE" = "all" ] || [ "$MODE" = "pd" ]; then
  echo ""
  echo "-- ProjectDiscovery (pdtm) --"
  if [ "$YES" = 1 ]; then need_go; fi
  if sudah_ada pdtm; then
    echo "# pdtm sudah ada — dilewati"
  else
    do_cmd go install -v "github.com/projectdiscovery/pdtm/cmd/pdtm@${PDTM_VERSION}"
  fi
  # pdtm mengunduh binary rilis ke $HOME/.pdtm/go/bin.
  if [ "$YES" = 1 ]; then
    if ! command -v pdtm >/dev/null 2>&1; then
      GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
      if [ -x "$GOBIN/pdtm" ]; then
        PATH="$GOBIN:$PATH"
      else
        echo "ERROR: pdtm tidak ditemukan setelah instal — cek PATH ke $GOBIN." >&2
        exit 2
      fi
    fi
    echo "# pdtm -install $PD_TOOLS"
    pdtm -install "$PD_TOOLS"
  else
    echo "pdtm -install $PD_TOOLS"
  fi
fi

# --- Kelompok Go non-PD: jsluice + interactsh-client ---
if [ "$MODE" = "all" ] || [ "$MODE" = "go" ]; then
  echo ""
  echo "-- Go (jsluice, interactsh-client) --"
  if [ "$YES" = 1 ]; then need_go; fi
  if sudah_ada jsluice; then
    echo "# jsluice sudah ada — dilewati"
  else
    do_cmd go install -v "github.com/BishopFox/jsluice/cmd/jsluice@${JSLUICE_VERSION}"
  fi
  if sudah_ada interactsh-client; then
    echo "# interactsh-client sudah ada — dilewati"
  else
    do_cmd go install -v "github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION}"
  fi
fi

# --- Kelompok Python: garak + pyrit via pipx ---
if [ "$MODE" = "all" ] || [ "$MODE" = "python" ]; then
  echo ""
  echo "-- Python (pipx: garak, pyrit) --"
  if [ "$YES" = 1 ]; then need_pipx; fi
  if sudah_ada garak; then
    echo "# garak sudah ada — dilewati"
  else
    if [ "$GARAK_VERSION" = "latest" ]; then
      do_cmd pipx install garak
    else
      do_cmd pipx install "garak==${GARAK_VERSION}"
    fi
  fi
  if sudah_ada pyrit; then
    echo "# pyrit sudah ada — dilewati"
  else
    if [ "$PYRIT_VERSION" = "latest" ]; then
      do_cmd pipx install pyrit
    else
      do_cmd pipx install "pyrit==${PYRIT_VERSION}"
    fi
  fi
fi

echo ""
if [ "$YES" = 0 ]; then
  echo "Tidak menjalankan apa pun — mode rencana."
  echo "Untuk menginstal: sh scripts/install-tools.sh --yes"
else
  echo "== Selesai =="
fi
echo "Pastikan PATH mencakup direktori binary berikut:"
echo "  export PATH=\"\$PATH:\$(go env GOPATH)/bin:\$HOME/.pdtm/go/bin:\$HOME/.local/bin\""
echo "Catatan: bila ada paket Python bernama httpx di ~/.local/bin, ia bisa"
echo "menutupi httpx ProjectDiscovery — pastikan ~/.pdtm/go/bin (atau"
echo "\$(go env GOPATH)/bin) lebih dulu di PATH daripada ~/.local/bin,"
echo "atau panggil httpx PD dengan path absolut."
