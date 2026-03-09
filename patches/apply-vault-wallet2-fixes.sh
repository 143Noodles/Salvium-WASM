#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$SCRIPT_DIR/v1.1-wallet2-vault-return-fixes.patch"
TARGET_REPO="${1:-$SCRIPT_DIR/../salvium-repo}"

if [ ! -f "$PATCH_FILE" ]; then
  echo "Patch file not found: $PATCH_FILE" >&2
  exit 1
fi

if [ ! -f "$TARGET_REPO/src/wallet/wallet2.cpp" ]; then
  echo "wallet2.cpp not found under: $TARGET_REPO" >&2
  exit 1
fi

cd "$TARGET_REPO"

if [ -d .git ]; then
  git apply --3way --verbose "$PATCH_FILE" || git apply --verbose "$PATCH_FILE"
else
  git apply --verbose "$PATCH_FILE"
fi
