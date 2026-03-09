# WASM Wallet Patches

This directory contains two kinds of overlays:

- patches applied to the fresh upstream clone during Docker builds
- patches kept around so we can re-apply Vault-specific `wallet2` fixes after syncing `salvium-repo/src` to a newer upstream version

## Auto-applied During Docker Build

- `v5.41.0-fix-get-sources-index-oob.patch`

The Dockerfile copies `patches/` into the build context and applies that upstream fix to `/workspace/salvium` before the local vendored source tree is copied in.

## Vendored `wallet2` Overlay

- `v1.1-wallet2-vault-return-fixes.patch`

This patch targets `salvium-repo/src/wallet/wallet2.cpp`. It restores Vault-specific stake return handling that was lost when `wallet2.cpp` was refreshed to the 1.1 source:

- recover type-2 `PROTOCOL` returns when normal view scanning misses them
- avoid counting the locked STAKE return output as spendable incoming funds
- look up protocol return origins by `onetime_address`
- recover no-change STAKE/AUDIT origins from `m_confirmed_txs`
- re-seed `m_salvium_txs` with STAKE/AUDIT `return_address` values

These fixes are already present in the vendored `salvium-repo/src/wallet/wallet2.cpp` tracked in this workspace. The patch file exists so future upstream refreshes can be re-patched instead of re-discovered manually.

## Re-applying After an Upstream Refresh

If `salvium-repo/src/` gets replaced from a newer upstream wallet release, run:

```bash
./patches/apply-vault-wallet2-fixes.sh
```

Optionally pass a different target tree:

```bash
./patches/apply-vault-wallet2-fixes.sh /path/to/salvium-repo
```

The helper uses `git apply --3way` when the target is a git checkout, and falls back to plain `git apply` otherwise.

## Manual Checks

From inside `salvium-repo/`:

```bash
git apply --check ../patches/v1.1-wallet2-vault-return-fixes.patch
```

If the check fails because the patch is already present, that is expected. If it fails because the context moved, refresh the patch from the current vendored file after updating the overlay.

## Updating the Overlay

When Vault-specific `wallet2` logic changes:

1. update `salvium-repo/src/wallet/wallet2.cpp`
2. regenerate `patches/v1.1-wallet2-vault-return-fixes.patch` from the before/after diff against `src/wallet/wallet2.cpp`
3. keep the helper script pointing at the same patch file so the refresh workflow stays stable
