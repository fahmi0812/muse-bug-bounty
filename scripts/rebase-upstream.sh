#!/usr/bin/env bash
# scripts/rebase-upstream.sh — rebase fork Strix ke upstream terbaru.
# Dipakai dari clone fork (origin = fork sendiri, upstream = usestrix/strix).
# Aman: berhenti bila working tree kotor atau ada konflik; tanpa force-push.
# Pemakaian: bash scripts/rebase-upstream.sh [--push]
set -euo pipefail

PUSH=false
if [ "${1:-}" = "--push" ]; then PUSH=true; fi

# 1. Pastikan ini repo git dengan remote upstream.
git rev-parse --git-dir >/dev/null 2>&1 || { echo "Bukan repo git." >&2; exit 1; }
git remote get-url upstream >/dev/null 2>&1 || {
  echo "Remote 'upstream' belum ada. Tambah dulu:" >&2
  echo "  git remote add upstream https://github.com/usestrix/strix.git" >&2
  exit 1
}

# 2. Working tree harus bersih.
if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree kotor — commit/stash dulu, lalu jalankan lagi." >&2
  git status --short >&2
  exit 1
fi

# 3. Ambil upstream terbaru, rebase main.
echo "== fetch upstream =="
git fetch upstream
echo "== rebase main ke upstream/main =="
git checkout main
git rebase upstream/main || {
  echo "Konflik di main — selesaikan manual (git rebase --continue / --abort)." >&2
  exit 1
}

# 4. Rebase tiap branch patch/* ke main yang baru.
echo "== rebase branch patch/* =="
for branch in $(git branch --format='%(refname:short)' | grep '^patch/' || true); do
  echo "-- $branch"
  git checkout "$branch"
  if ! git rebase main; then
    echo "Konflik di $branch — selesaikan manual, lalu lanjutkan branch berikutnya." >&2
    echo "  git rebase --continue   (setelah perbaiki konflik)" >&2
    echo "  git rebase --abort      (batalkan rebase branch ini)" >&2
    exit 1
  fi
done

git checkout main
echo "== selesai: main = $(git rev-parse --short HEAD) =="

# 5. Push hanya bila diminta eksplisit; main tidak pernah di-force-push di sini.
if [ "$PUSH" = true ]; then
  echo "== push main + patch/* =="
  git push origin main
  for branch in $(git branch --format='%(refname:short)' | grep '^patch/' || true); do
    git push origin "$branch"
  done
else
  echo "Tip: jalankan dengan --push untuk push hasil rebase ke origin."
fi
