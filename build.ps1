param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDir = Join-Path $ScriptDir "output"
$ImagePrefix = "salvium-wasm"

if ($Clean) {
    foreach ($Variant in @("simd", "baseline")) {
        docker image rm -f "$ImagePrefix-$Variant" 2>$null
    }
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

function Build-Variant {
    param(
        [string]$Variant,
        [string]$FeatureFlags,
        [string]$JavaScriptName,
        [string]$WasmName
    )

    $Image = "$ImagePrefix-$Variant"
    Write-Host "Building $Variant wallet runtime..." -ForegroundColor Cyan

    docker build `
        --build-arg "WASM_FEATURE_FLAGS=$FeatureFlags" `
        --tag $Image `
        $ScriptDir
    if ($LASTEXITCODE -ne 0) {
        throw "Docker build failed for $Variant."
    }

    $ContainerId = (docker create $Image).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $ContainerId) {
        throw "Could not create a container for $Variant."
    }

    try {
        docker cp "${ContainerId}:/workspace/build/SalviumWallet.js" (Join-Path $OutputDir $JavaScriptName)
        if ($LASTEXITCODE -ne 0) {
            throw "Could not extract $JavaScriptName."
        }

        docker cp "${ContainerId}:/workspace/build/SalviumWallet.wasm" (Join-Path $OutputDir $WasmName)
        if ($LASTEXITCODE -ne 0) {
            throw "Could not extract $WasmName."
        }
    }
    finally {
        docker rm -f $ContainerId | Out-Null
    }

    if (Select-String `
        -Path (Join-Path $OutputDir $JavaScriptName) `
        -Pattern "new Function|(^|[^A-Za-z0-9_])eval\(" `
        -Quiet) {
        throw "$JavaScriptName contains dynamic JavaScript execution."
    }
}

Build-Variant `
    -Variant "simd" `
    -FeatureFlags "-mbulk-memory -msimd128" `
    -JavaScriptName "SalviumWallet.js" `
    -WasmName "SalviumWallet.wasm"

Build-Variant `
    -Variant "baseline" `
    -FeatureFlags "-mno-bulk-memory -mno-simd128" `
    -JavaScriptName "SalviumWalletBaseline.js" `
    -WasmName "SalviumWalletBaseline.wasm"

$Artifacts = @(
    "SalviumWallet.js",
    "SalviumWallet.wasm",
    "SalviumWalletBaseline.js",
    "SalviumWalletBaseline.wasm"
)

$ChecksumLines = foreach ($Artifact in $Artifacts) {
    $Hash = Get-FileHash -Algorithm SHA256 (Join-Path $OutputDir $Artifact)
    "$($Hash.Hash.ToLowerInvariant())  $Artifact"
}
$ChecksumLines | Set-Content -Path (Join-Path $OutputDir "SHA256SUMS") -Encoding ascii

Write-Host "Build complete:" -ForegroundColor Green
Get-ChildItem ($Artifacts | ForEach-Object { Join-Path $OutputDir $_ })
Get-Item (Join-Path $OutputDir "SHA256SUMS")
