# WASM Wallet Patches

This directory contains patches for the Salvium wallet source code that are required for the WASM wallet to function correctly.

**NOTE:** Patches are automatically applied during the Docker build process. You don't need to manually apply them unless you're building outside of Docker.

## v5.30.0: m_salvium_txs Fix

**File:** `v5.30.0-m_salvium_txs-fix.patch`

**Issue:** STAKE/AUDIT transaction YIELD outputs were not being marked as spent, causing balance inflation (~66K SAL in production).

**Root Cause:** 
- When STAKE/AUDIT transactions are processed, their `return_address` was not being added to `m_salvium_txs` map
- When YIELD/PROTOCOL outputs come at maturity, the wallet looks up `address_spend_pubkey` in `m_salvium_txs` to find the origin transfer
- Without the origin transfer index (`m_td_origin_idx`), the key image cannot be generated
- Without the key image, the output is never marked as spent when used in a later transaction

**Fix:** 
Adds code to insert the `return_address` into `m_salvium_txs` when processing STAKE/AUDIT transactions, enabling proper YIELD output key image generation.

## Automatic Application

Patches are automatically applied during Docker build in the Dockerfile:

```dockerfile
COPY patches/v5.30.0-m_salvium_txs-fix.patch /workspace/patches/
RUN cd /workspace/salvium \
    && git apply --verbose /workspace/patches/v5.30.0-m_salvium_txs-fix.patch
```

## Manual Application (for non-Docker builds)

If you're building outside of Docker after updating Salvium source code:

```bash
cd wasm-build/salvium-repo

# Apply the patch
git apply ../patches/v5.30.0-m_salvium_txs-fix.patch

# If the patch fails (e.g., due to line number changes), try with 3-way merge:
git apply --3way ../patches/v5.30.0-m_salvium_txs-fix.patch
```

### To check if patch is already applied:

```bash
cd wasm-build/salvium-repo
git apply --check ../patches/v5.30.0-m_salvium_txs-fix.patch
```

If it says "error: patch does not apply", the patch may already be applied or the code has changed significantly.

### To reverse a patch:

```bash
cd wasm-build/salvium-repo
git apply -R ../patches/v5.30.0-m_salvium_txs-fix.patch
```

## Build Process

Normal Docker build (patches auto-applied):

```powershell
cd wasm-build
.\build_and_deploy.ps1 -fast
```

## Submitting Upstream

These patches should ideally be submitted as pull requests to the official Salvium repository so they benefit all users and don't need to be maintained separately.
