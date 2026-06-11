# Salvium Wallet WASM

The WebAssembly wallet core powering [Salvium Vault](https://vault.salvium.tools) — a full Salvium wallet (scanning, balances, staking, transaction construction) compiled from the upstream C++ codebase to run entirely in the browser. Keys never leave the client; the module is designed for **stateless operation** against untrusted infrastructure: all chain data is injected by the host application, and the wallet verifies everything locally.

## Highlights

- **Full wallet core in the browser**: restore from seed, scan, stake, sweep, and build transactions client-side — no server ever sees keys or amounts.
- **Compact Scan Protocol (CSP)**: blocks are converted server-side into a compact scanning format; the wallet view-tag-scans them in parallel Web Workers and ingests only matched transactions sparsely. A full restore of a years-old wallet completes in minutes — benchmarked faster than the native CLI wallet on the same hardware.
- **Chain-truth self-correction**: every scan can cross-check the wallet's local spent-state against the chain's complete public spent set, confirming real spends and releasing stale optimistic flags. The wallet converges to chain truth automatically.
- **Exact balance history**: per-output birth/spend accounting (`get_native_balance_history`) yields the wallet's true balance at any block height — no reconstruction heuristics.
- **Salvium protocol coverage**: staking with return/yield tracking, burns, converts, audits, protocol tokens, and Carrot addresses.
- **Deterministic state round-trip**: the entire wallet state exports/imports as a portable cache blob (`export_wallet_cache_hex` / `import_wallet_cache_hex`), enabling instant reopen without rescanning.
- **High-performance crypto**: `donna64` elliptic-curve fast paths, batched view-tag computation, and memoized derivation caches for hot scanning loops.

## Prerequisites

- **Docker** — the build is fully containerized (Emscripten, Boost, OpenSSL, Libsodium pinned inside the image).

## Build

```bash
./build.sh          # Linux / macOS
.\build.ps1         # Windows PowerShell
```

The build clones the upstream Salvium source, overlays the tracked wallet modifications (see `salvium-repo/` and `patches/`), compiles with Emscripten, and emits `SalviumWallet.js` + `SalviumWallet.wasm` into `output/`.

> The `.js` glue and `.wasm` binary are a matched pair — always deploy both from the same build.

## Usage

```javascript
const factory = require('./output/SalviumWallet.js');

factory().then(module => {
    const wallet = new module.WasmWallet('mainnet');
    wallet.create_random("password", "English");
    console.log("Address:", wallet.get_address());
});
```

In production the module runs inside a Web Worker; all I/O is injected by the host (see *Stateless operation* below).

## API Overview

The module exposes ~130 bindings. The full, authoritative surface is the `EMSCRIPTEN_BINDINGS` block at the bottom of `src/wasm_bindings.cpp`; the groups below are the map.

### Wallet lifecycle
`create_random`, `restore_from_seed`, `restore_from_recovery_key_hex`, `init_view_only`, `export_wallet_cache_hex` / `import_wallet_cache_hex` (full state round-trip for instant reopen).

### Keys & addresses
Address/subaddress getters, seed and key export, `validate_address`, Carrot address + key derivation.

### Scanning (CSP)
`ingest_sparse_transactions` (sparse matched-tx ingest, with deferred-rebuild support for batch pipelines), `scan_tx`, view-tag batch computation, `get_key_images_csv`, server-side `convert_epee_to_csp*` converters and sparse extractors.

### Spent-state & chain truth
`mark_spent_by_key_images`, `get_optimistic_spent_key_images_csv`, `release_unspent_key_images` (reverse audit against the chain's public spent set), `reconcile_unconfirmed_txs` (pending-transaction hygiene with expiry), `flush_derived_state`.

### Balances & history
`get_balance` / `get_unlocked_balance` (per asset), `get_transfers_as_json` (CLI-parity transaction history incl. stakes, returns, change markers), `get_native_balance_history` (exact balance-by-height series from the transfer table, stake-lock aware).

### Transactions
Probe/create/complete split transaction construction (`prepare_transaction_json` / `complete_transaction_json`), standard + stake + sweep transactions, fee estimation, deterministic decoy handling via injected output distributions.

### Stateless operation (host-injected I/O)
`inject_json_rpc_response`, `inject_decoy_outputs*`, `inject_fee_estimate`, `inject_hardfork_info`, `inject_blocks_response` — the wallet performs no network I/O of its own; the host supplies daemon responses and the wallet validates them.

### Diagnostics
`get_wallet_diagnostic`, crypto benchmarks (`diagnose_crypto_speed`, `compare_ref10_donna64`), wallet health/integrity checks.

## Repository structure

- **`Dockerfile`** — pinned build environment and full compilation recipe.
- **`src/`** — C++ embind bindings (`wasm_bindings.cpp`), `donna64` fast crypto, and platform stubs (HTTP/storage are stubbed; the host injects all I/O).
- **`salvium-repo/`** — tracked overlay files for the upstream wallet (`wallet2`, `tx_builder`, crypto-ops); everything else is cloned fresh at build time.
- **`patches/`** — the patch series applied to upstream during the build, with documentation.

## Upstream

Tracks Salvium mainnet (currently synced with v1.1.0 wallet fixes). Consensus-critical code is unmodified upstream source; modifications are confined to wallet-layer scanning, accounting, and the WASM interface.
