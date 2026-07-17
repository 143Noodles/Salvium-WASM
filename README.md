# Salvium Wallet WASM

The WebAssembly wallet core powering [Salvium Vault](https://vault.salvium.tools) — a Salvium wallet (scanning, balances, staking, and transaction construction) compiled from the upstream C++ codebase to run in the browser. Seed material and private keys stay on the client. The host injects all network data, while the module performs wallet ownership checks and transaction cryptography locally.

This is a light-wallet runtime, not a validating node. It does not validate proof-of-work or independently establish the canonical chain, so availability, ordering, and completeness of the supplied chain view remain part of the host application's trust model.

## Highlights

- **Wallet core in the browser**: restore from seed, scan, stake, sweep, and build transactions client-side without disclosing seed material or private keys to the server.
- **Compact Scan Protocol (CSP)**: blocks are converted server-side into a compact scanning format; the wallet view-tag-scans them in parallel Web Workers and ingests only matched transactions sparsely. A full restore of a years-old wallet completes in minutes — benchmarked faster than the native CLI wallet on the same hardware.
- **Chain-truth self-correction**: every scan can cross-check the wallet's local spent-state against the chain's complete public spent set, confirming real spends and releasing stale optimistic flags. The wallet converges to chain truth automatically.
- **Exact balance history**: per-output birth/spend accounting (`get_native_balance_history`) yields the wallet's true balance at any block height — no reconstruction heuristics.
- **Salvium protocol coverage**: staking with return/yield tracking, burns, converts, audits, protocol tokens, and Carrot addresses.
- **Deterministic state round-trip**: the entire wallet state exports/imports as a portable cache blob (`export_wallet_cache_hex` / `import_wallet_cache_hex`), enabling instant reopen without rescanning.
- **Imported-cache ownership proof**: cached output ownership is revalidated against canonical full transactions before balances are trusted, with atomic repair/neutralization and a validation marker that is serialized only after the complete proof succeeds.
- **High-performance crypto**: `donna64` elliptic-curve fast paths, batched view-tag computation, and memoized derivation caches for hot scanning loops.

## Prerequisites

- **Docker** — the build is fully containerized.
- **Node.js 18+** — optional, for the runtime parity validator.

## Build

```bash
./build.sh           # Linux / macOS
.\build.ps1          # Windows PowerShell
```

Use `./build.sh --clean` or `.\build.ps1 -Clean` to discard the local build
images first.

The build:

- pins the upstream Salvium source commit and Emscripten base-image digest;
- verifies the downloaded Boost, OpenSSL, and Libsodium archives;
- overlays the reviewed downstream files in `source-overrides/`;
- produces SIMD and baseline variants with `DYNAMIC_EXECUTION=0`;
- rejects JavaScript glue containing `new Function` or `eval(`;
- fails the link on every undefined C/C++ symbol;
- compiles the canonical upstream hard-fork schedule and transaction sanity
  checks rather than maintaining permissive duplicates; and
- uses the portable upstream CryptoNight slow hash for password-derived wallet
  operations.

The four matched runtime files are written to `output/`:

```text
SalviumWallet.js
SalviumWallet.wasm
SalviumWalletBaseline.js
SalviumWalletBaseline.wasm
```

`output/SHA256SUMS` records their hashes. The `.js` glue and `.wasm` binary
for each variant are a matched pair and must always be deployed together.
The hashes for the tested v1.1.3c release are retained in
`release/v1.1.3c/SHA256SUMS`; from `output/`, verify them with:

```bash
sha256sum -c ../release/v1.1.3c/SHA256SUMS
```

Validate both modules, their runtime versions, and their public API parity:

```bash
node scripts/validate-build.cjs output
```

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

### Imported-cache trust
`begin_output_ownership_revalidation`, `get_runtime_full_tx_candidate_hashes`,
`cache_runtime_full_txs_from_sparse`, `repair_stale_output_ownership`, and
`cancel_output_ownership_revalidation` form a serialized fail-closed proof:
the host supplies canonically verified source transactions, the wallet repairs
or neutralizes stale ordinary/return ownership, and only a complete result is
marked trusted in the exported cache.

### Balances & history
`get_balance` / `get_unlocked_balance` (per asset), `get_transfers_as_json` (CLI-parity transaction history incl. stakes, returns, change markers), `get_native_balance_history` (exact balance-by-height series from the transfer table, stake-lock aware).

### Transactions
Probe/create/complete split transaction construction (`prepare_transaction_json` / `complete_transaction_json`), standard + stake + sweep transactions, fee estimation, deterministic decoy handling via injected output distributions.

### Stateless operation (host-injected I/O)
`inject_json_rpc_response`, `inject_decoy_outputs*`, `inject_fee_estimate`, `inject_hardfork_info`, `inject_blocks_response` — the module performs no network I/O of its own. The host supplies daemon responses; the module applies wallet-level parsing, ownership, and transaction checks, subject to the light-client trust boundary described above.

### Diagnostics
`get_wallet_diagnostic`, `benchmark_key_derivation`, and wallet
health/integrity checks.

## Repository structure

- **`Dockerfile`** — pinned build environment and full compilation recipe.
- **`build.sh` / `build.ps1`** — build and extract both production variants.
- **`scripts/validate-build.cjs`** — load and structurally compare both variants.
- **`release/`** — published artifact checksums by runtime release.
- **`src/`** — C++ embind bindings (`wasm_bindings.cpp`), `donna64` fast crypto, and fail-closed WASM platform adapters. The host injects network I/O; native process notifications and RPC-payment mining are unavailable.
- **`source-overrides/`** — reviewed downstream source files copied over the pinned upstream commit before compilation.

## Upstream

Tracks Salvium mainnet v1.1.3c wallet behavior (runtime line
`5.54.11-hf14-v113c`). The pinned base commit is combined with the reviewed
v1.1.3c and WASM-specific files in `source-overrides/`; wallet-layer scanning,
accounting, transaction construction, platform adaptation, and the WASM
interface are maintained here.

## License

This repository is distributed under the BSD 3-Clause license. Files derived
from Salvium, Monero, CryptoNote, and other upstream projects retain their
original copyright and license notices. See [LICENSE](LICENSE).
