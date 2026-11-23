#!/usr/bin/env bash
# Installer muse-bug-bounty (Linux/macOS). Idempotent.
# Pilihan Docker: flag --docker / --no-docker, atau env BOUNTY_DOCKER=1/0,
# atau tanya interaktif [1] Ya / [2] Tidak (default 1).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER_CHOICE="${BOUNTY_DOCKER:-}"

usage() {
  echo "Usage: $0 [--docker|--no-docker]"
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --docker) DOCKER_CHOICE=1 ;;
    --no-docker) DOCKER_CHOICE=0 ;;
    -h|--help) usage ;;
    *) echo "Argumen tidak dikenal: $1" >&2; usage ;;
  esac
  shift
done

echo "== muse-bug-bounty installer =="

# 1. Node >= 20
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js tidak ditemukan. Instal Node >= 20 dulu (https://nodejs.org)." >&2
  exit 1
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "ERROR: Node $(node -v) terlalu lama — butuh Node >= 20." >&2
  exit 1
fi
echo "Node $(node -v) OK"

# 2. Pilihan Docker
if [ -z "$DOCKER_CHOICE" ]; then
  if [ -t 0 ]; then
    echo "Pakai Docker untuk lab eval lokal (Juice Shop/DVWA/VAmPI)?"
    echo "  [1] Ya (default)"
    echo "  [2] Tidak — bench jalan mode no-docker"
    printf "Pilihan [1/2]: "
    read -r ans || ans=""
    case "$ans" in
      2|tidak|Tidak|TIDAK) DOCKER_CHOICE=0 ;;
      *) DOCKER_CHOICE=1 ;;
    esac
  else
    DOCKER_CHOICE=1
    echo "Non-interaktif: default Docker = Ya (set BOUNTY_DOCKER=0 untuk tanpa Docker)."
  fi
fi

if [ "$DOCKER_CHOICE" = "1" ]; then
  echo "Docker: Ya"
  if command -v docker >/dev/null 2>&1; then
    echo "Docker ditemukan: $(docker --version 2>/dev/null || echo ok)"
  else
    echo "PERINGATAN: Docker dipilih tapi tidak ditemukan di PATH."
    echo "Instal Docker (https://docs.docker.com/get-docker/) atau jalankan ulang dengan --no-docker."
  fi
else
  echo "Docker: Tidak — bench jalan mode no-docker (lab Docker di-skip)."
fi

# 3. Simpan pilihan (idempotent)
mkdir -p "$REPO_DIR/.bounty"
printf '{\n  "docker": %s,\n  "installed_at": "%s"\n}\n' \
  "$([ "$DOCKER_CHOICE" = "1" ] && echo true || echo false)" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$REPO_DIR/.bounty/config.json"
echo "Pilihan disimpan di .bounty/config.json"

# 4. npm install global bila package.json ada
if [ -f "$REPO_DIR/package.json" ]; then
  if command -v npm >/dev/null 2>&1; then
    echo "Instal CLI bounty (npm install -g)..."
    (cd "$REPO_DIR" && npm install -g --ignore-scripts) || {
      echo "PERINGATAN: npm install -g gagal — coba manual: (cd $REPO_DIR && npm install -g)"
    }
  else
    echo "PERINGATAN: npm tidak ditemukan — lewati instal global."
  fi
fi

echo ""
echo "== Selesai =="
echo "Langkah berikutnya:"
echo "  1. Instal Strix (bukan bagian repo ini):"
echo "     curl -sSL https://strix.ai/install | bash"
echo "  2. Mode 2 (Standalone CLI) — wizard provider sekali saja:"
echo "     bounty install"
echo "  3. Coba kering dulu:"
echo "     bounty run --target https://example.com/api/users --program programs/example.md --dry-run"
echo "  4. Test & bench:"
echo "     npm test && npm run bench"
