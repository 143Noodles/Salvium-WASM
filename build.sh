#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
IMAGE_PREFIX="salvium-wasm"

if [[ ${1:-} == "--clean" ]]; then
    docker image rm -f \
        "${IMAGE_PREFIX}-simd" \
        "${IMAGE_PREFIX}-baseline" \
        >/dev/null 2>&1 || true
elif [[ $# -gt 0 ]]; then
    echo "Usage: $0 [--clean]" >&2
    exit 2
fi

mkdir -p "$OUTPUT_DIR"

build_variant() {
    local variant="$1"
    local feature_flags="$2"
    local js_name="$3"
    local wasm_name="$4"
    local image="${IMAGE_PREFIX}-${variant}"
    local container_id

    echo "Building ${variant} wallet runtime..."
    docker build \
        --build-arg "WASM_FEATURE_FLAGS=${feature_flags}" \
        --tag "$image" \
        "$SCRIPT_DIR"

    container_id="$(docker create "$image")"
    trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true' RETURN
    docker cp "$container_id:/workspace/build/SalviumWallet.js" "$OUTPUT_DIR/$js_name"
    docker cp "$container_id:/workspace/build/SalviumWallet.wasm" "$OUTPUT_DIR/$wasm_name"
    docker rm "$container_id" >/dev/null
    trap - RETURN

    if grep -Eq 'new Function|(^|[^[:alnum:]_])eval\(' "$OUTPUT_DIR/$js_name"; then
        echo "ERROR: $js_name contains dynamic JavaScript execution." >&2
        exit 1
    fi
}

build_variant \
    simd \
    "-mbulk-memory -msimd128" \
    "SalviumWallet.js" \
    "SalviumWallet.wasm"

build_variant \
    baseline \
    "-mno-bulk-memory -mno-simd128" \
    "SalviumWalletBaseline.js" \
    "SalviumWalletBaseline.wasm"

(
    cd "$OUTPUT_DIR"
    sha256sum \
        SalviumWallet.js \
        SalviumWallet.wasm \
        SalviumWalletBaseline.js \
        SalviumWalletBaseline.wasm \
        > SHA256SUMS
)

echo "Build complete:"
ls -lh \
    "$OUTPUT_DIR/SalviumWallet.js" \
    "$OUTPUT_DIR/SalviumWallet.wasm" \
    "$OUTPUT_DIR/SalviumWalletBaseline.js" \
    "$OUTPUT_DIR/SalviumWalletBaseline.wasm" \
    "$OUTPUT_DIR/SHA256SUMS"
