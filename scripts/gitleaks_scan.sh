#!/usr/bin/env bash
# Scan BASE..HEAD with the gitleaks config and ignore file from the BASE
# commit. The PR checkout is not the scan source: gitleaks also reads
# <source>/.gitleaksignore, so a pull request cannot hide a leak by editing
# that file or by adding a gitleaks:allow comment.

set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: gitleaks_scan.sh <gitleaks-bin> <repo> <base-sha> <head-sha>" >&2
  exit 1
fi

GITLEAKS=$1
REPO=$2
BASE=$3
HEAD=$4

if [ ! -x "$GITLEAKS" ]; then
  echo "gitleaks binary is missing" >&2
  exit 1
fi

git -C "$REPO" cat-file -e "${BASE}^{commit}"
git -C "$REPO" cat-file -e "${HEAD}^{commit}"
range_count=$(git -C "$REPO" rev-list --count "${BASE}..${HEAD}")
if [ "$range_count" -eq 0 ]; then
  echo "gitleaks scan range is empty" >&2
  exit 1
fi

work=""
cleanup() {
  if [ -n "$work" ]; then
    git -C "$REPO" worktree remove --force "$work" >/dev/null 2>&1 || true
    rm -rf "$work"
  fi
}
trap cleanup EXIT

work=$(mktemp -d)
rmdir "$work"
git -C "$REPO" worktree add --detach "$work" "$BASE" >/dev/null

if [ ! -f "$work/.gitleaks.toml" ]; then
  echo "base commit has no .gitleaks.toml" >&2
  exit 1
fi

"$GITLEAKS" detect \
  --source "$work" \
  --config "$work/.gitleaks.toml" \
  --gitleaks-ignore-path "$work" \
  --ignore-gitleaks-allow \
  --redact \
  --no-banner \
  --no-color \
  --log-level error \
  --exit-code 2 \
  --log-opts="-m ${BASE}..${HEAD}"
