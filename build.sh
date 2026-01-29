#!/bin/bash
# ============================================================================
# Salvium Wallet WASM Build Script (Linux/macOS)
# ============================================================================
# Usage:
#   ./build.sh          - Build and extract WASM files
#   ./build.sh --clean  - Remove existing image and rebuild from scratch
# ============================================================================

set -e

IMAGE_NAME="salvium-wasm"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"

# Parse arguments
CLEAN_BUILD=false
if [ "$1" == "--clean" ]; then
    CLEAN_BUILD=true
fi

echo "============================================"
echo "Salvium Wallet WASM Production Build"
echo "============================================"

# Clean build if requested
if [ "$CLEAN_BUILD" = true ]; then
    echo "Cleaning previous build..."
    docker rmi -f $IMAGE_NAME 2>/dev/null || true
fi

# Build the Docker image
echo ""
echo "Building Docker image (this may take 10-15 minutes on first run)..."
echo ""

docker build -t $IMAGE_NAME .

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Docker build failed!"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Extract WASM files from the image
echo ""
echo "Extracting WASM files to: $OUTPUT_DIR"

CONTAINER_ID=$(docker create $IMAGE_NAME)
echo "Created container: $CONTAINER_ID"

docker cp "$CONTAINER_ID:/workspace/build/SalviumWallet.js" "$OUTPUT_DIR/"
docker cp "$CONTAINER_ID:/workspace/build/SalviumWallet.wasm" "$OUTPUT_DIR/"
docker rm $CONTAINER_ID > /dev/null

# Verify files exist
if [ ! -f "$OUTPUT_DIR/SalviumWallet.js" ] || [ ! -f "$OUTPUT_DIR/SalviumWallet.wasm" ]; then
    echo ""
    echo "ERROR: Failed to extract WASM files!"
    exit 1
fi

# Show results
echo ""
echo "============================================"
echo "BUILD COMPLETE"
echo "============================================"
echo ""
echo "Output files:"
ls -lh "$OUTPUT_DIR"/SalviumWallet.*
echo ""
echo "Files are in: $OUTPUT_DIR"
echo "============================================"
