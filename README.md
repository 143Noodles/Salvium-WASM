# Salvium Wallet WASM

This repository contains the WebAssembly (WASM) build system for the Salvium Wallet core cryptography and logic. It compiles the C++ Salvium codebase into WASM modules usable in web and Javascript environments.

## Features

- **Core Cryptography**: Ed25519, scalar multiplication, hashing (Keccak, Blake2b, Groestl, etc.).
- **Wallet Logic**: Address generation, transaction scanning, output selection, and ring signature generation.
- **Multisig Support**: Subaddress and multisig wallet compatibility.
- **Optimized**: Uses `donna64` for high-performance elliptic curve operations.

## Prerequisites

- **Docker**: The build process is containerized to ensure a consistent environment (Emscripten, Boost, OpenSSL, Libsodium).

## Build Instructions

### Linux / macOS

```bash
./build.sh
```

### Windows (PowerShell)

```powershell
.\build.ps1
```

The build script will:
1.  Create a Docker image containing all dependencies (Emscripten, Boost, OpenSSL, Libsodium).
2.  Compile the Salvium C++ source code and bindings.
3.  Link the final `SalviumWallet.wasm` and `SalviumWallet.js`.
4.  Extract the output files to the `output/` directory.

## Usage

Include the generated `SalviumWallet.js` in your HTML or import it in your JavaScript project. The WASM module provides the `WasmWallet` class and several global utility functions.

```javascript
const factory = require('./output/SalviumWallet.js');

factory().then(module => {
    console.log("Salvium WASM Module Loaded");
    
    // Create a new wallet instance
    const wallet = new module.WasmWallet();
    
    // Initialize a random wallet
    wallet.create_random("password", "English");
    console.log("Address:", wallet.get_address());
});
```

## API Reference

### WasmWallet Class

#### Wallet Management
- `create_random(password, language)`: Create a new wallet with random seed.
- `restore_from_seed(seed, password, restore_height)`: Restore wallet from mnemonic seed.
- `restore_from_recovery_key_hex(recovery_key_hex, password, restore_height)`: Restore from raw recovery key.
- `init_view_only(view_key, address, password, restore_height)`: Initialize watch-only wallet.

#### Keys & Address
- `get_address()`: Get primary address.
- `get_seed()`: Get mnemonic seed.
- `get_secret_view_key()`, `get_public_view_key()`: View keys.
- `get_secret_spend_key()`, `get_public_spend_key()`: Spend keys.
- `get_carrot_address()`: Get Carrot (privacy protocol) address.
- `get_carrot_keys()`: Get various Carrot-specific keys (s_master, k_prove_spend, etc.).

#### Balance & Sync
- `get_balance(asset_type)`: Get total balance.
- `get_unlocked_balance(asset_type)`: Get spendable balance.
- `get_blockchain_height()`: Get daemon chain height.
- `get_wallet_height()`: Get wallet scanned height.
- `process_blocks(blob)`: Process parsed block object.
- `process_blocks_binary(ptr, size)`: Process binary block data.
- `ingest_blocks_binary(ptr, size)`: Fast ingest of block data.
- `scan_blocks_fast(ptr, size)`: Optimized block scanning (Worker support).

#### Transfers & Transactions
- `get_transfers_as_json()`: Get history as JSON string.
- `create_transaction_json(dest_addr, amount, ...)`: Create standard transaction.
- `create_stake_transaction_json(amount)`: Create staking transaction.
- `estimate_fee_json(params)`: Estimate transaction fees.
- `prepare_transaction_json(...)`: Phase 1 of split tx creation.
- `complete_transaction_json(...)`: Phase 2 of split tx creation.

#### CSP (Compact Scan Protocol)
- `ingest_sparse_transactions(ptr, size)`: Ingest sparse transaction format.
- `scan_tx(blob)`: Scan single transaction blob.
- `get_key_images()`: Get known key images.
- `get_key_images_csv()`: Export key images for remote checking.

### Global Utility Functions

#### Crypto Utilities
- `compute_view_tag(view_key, pubkey, index)`: Compute matching tag for output filtering.
- `compute_view_tags_batch(...)`: Batch computation.
- `validate_address(address, nettype)`: Validate Salvium address.
- `get_version()`: Get WASM module version.

#### Server-Side & Parsing
- `convert_epee_to_csp(ptr, size, height)`: Convert full blocks to Compact Scan format.
- `convert_epee_to_csp_with_index(...)`: Convert with fast-lookup index.
- `extract_sparse_txs(...)`: Extract specific TXs from block bundle.
- `extract_stake_info(ptr, size)`: Extract staking metadata.
- `extract_all_stakes(...)`: Extract all stakes from block bundle.
- `inspect_epee_block(...)`: Debug block structure.

#### Cache Injection (for Stateless Operation)
- `inject_decoy_outputs(ptr, size)`: Inject decoys for ring signatures.
- `inject_blocks_response(ptr, size)`: Inject block data for refresh.
- `inject_fee_estimate(json)`: Inject current network fees.
- `inject_hardfork_info(version)`: Set protocol version.

#### Debugging
- `diagnose_crypto_speed()`: Benchmark crypto primitives.
- `compare_ref10_donna64()`: Verify optimization correctness.
- `debug_iteration_by_iteration()`: Step-by-step crypto debug.
- `get_wallet_diagnostic()`: Dump wallet internal state.

## Structure

- **Dockerfile**: Defines the build environment and compilation steps.
- **src/**: C++ bindings and stubs for the WASM interface.
- **salvium-repo/**: Source code modifications and specific wallet logic.
- **patches/**: Patches applied to the upstream Salvium repository during the build.
