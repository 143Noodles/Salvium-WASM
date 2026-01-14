# ============================================================================
# Salvium Wallet WASM Build Script (Windows PowerShell)
# ============================================================================
# Usage:
#   .\build.ps1          - Build and extract WASM files
#   .\build.ps1 -Clean   - Remove existing image and rebuild from scratch
# ============================================================================

param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$ImageName = "salvium-wasm"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDir = Join-Path $ScriptDir "output"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Salvium Wallet WASM Production Build" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Clean build if requested
if ($Clean) {
    Write-Host "Cleaning previous build..." -ForegroundColor Yellow
    docker rmi -f $ImageName 2>$null
}

# Build the Docker image
Write-Host ""
Write-Host "Building Docker image (this may take 10-15 minutes on first run)..." -ForegroundColor Yellow
Write-Host ""

docker build -t $ImageName .

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Docker build failed!" -ForegroundColor Red
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Extract WASM files from the image
Write-Host ""
Write-Host "Extracting WASM files to: $OutputDir" -ForegroundColor Yellow

$ContainerId = (docker create $ImageName) | Out-String
$ContainerId = $ContainerId.Trim()

Write-Host "Created container: $ContainerId" -ForegroundColor Gray

try {
    docker cp "${ContainerId}:/workspace/build/SalviumWallet.js" "$OutputDir\"
    docker cp "${ContainerId}:/workspace/build/SalviumWallet.wasm" "$OutputDir\"
} finally {
    docker rm $ContainerId | Out-Null
}

# Verify files exist
$jsFile = Join-Path $OutputDir "SalviumWallet.js"
$wasmFile = Join-Path $OutputDir "SalviumWallet.wasm"

if (-not (Test-Path $jsFile) -or -not (Test-Path $wasmFile)) {
    Write-Host ""
    Write-Host "ERROR: Failed to extract WASM files!" -ForegroundColor Red
    exit 1
}

# Show results
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "BUILD COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output files:" -ForegroundColor Cyan
Get-ChildItem "$OutputDir\SalviumWallet.*" | Format-Table Name, @{Label="Size"; Expression={"{0:N2} MB" -f ($_.Length / 1MB)}}
Write-Host ""
Write-Host "Files are in: $OutputDir" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Green
