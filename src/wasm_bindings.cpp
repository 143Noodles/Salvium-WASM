// wasm_bindings.cpp - Embind bindings to expose wallet2 to JavaScript
// This file creates the JavaScript API for the Salvium WASM wallet

#include <cstdio>
#include <emscripten.h>
#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <iostream>

// ============================================================================
// PRODUCTION BUILD: Disable all debug fprintf/std_cerr calls
// This improves performance by eliminating string formatting and syscall
// overhead Set to 0 to enable debug output
// ============================================================================
#define WASM_PRODUCTION 1

#if WASM_PRODUCTION
// Redirect fprintf(stderr, ...) to no-op using statement expression
// Avoids "left operand is void, right is int" error with ternary
#define fprintf(stream, ...)                                                   \
  (stream == stderr ? (void)0 : (void)::fprintf(stream, __VA_ARGS__))
// Disable std_cerr output
namespace {
struct NullStream {
  template <typename T> NullStream &operator<<(const T &) { return *this; }
  NullStream &operator<<(std::ostream &(*)(std::ostream &)) { return *this; }
} nullstream;
} // namespace
#define std_cerr nullstream
#endif

#include "string_coding.h"
#include <algorithm> // for std::sort, std::unique
#include <chrono>    // for benchmarking
#include <cstdint>   // for uintptr_t
#include <cstring>   // for memcpy
#include <iomanip>   // for std::setw, std::setfill
#include <memory>
#include <set> // for std::set (CSP v6 key_images lookup)
#include <sstream>
#include <stdexcept> // for std::runtime_error
#include <string>
#include <type_traits> // for std::remove_const, std::remove_reference
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <limits>
#include <limits>


// Include wallet2 and dependencies
#include "carrot_core/config.h" // For CARROT_DOMAIN_SEP_INPUT_CONTEXT_COINBASE
#include "carrot_core/core_types.h" // For input_context_t, view_tag_t
#include "carrot_core/enote_utils.h" // For make_carrot_view_tag, make_carrot_uncontextualized_shared_key_receiver
#include "carrot_impl/format_utils.h" // For is_carrot_transaction_v1
#include "common/base58.h"
#include "crypto/crypto.h"
extern "C" {
#include "crypto/random.h" // For crypto_get/set_random_state
}
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_protocol/enums.h"
#include "device/device.hpp" // For hw::get_device
#include "mnemonics/electrum-words.h"
#include "mx25519.h"               // For mx25519_pubkey, mx25519_privkey
#include "wallet/scanning_tools.h" // For view_incoming_scan_transaction
#include "wallet/wallet2.h"

// Include crypto-ops.h for direct access to ge_* functions (for debugging)
extern "C" {
#include "crypto/crypto-ops.h"
}

#include "net/http.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "serialization/keyvalue_serialization.h"
#include "storages/portable_storage.h"
#include "storages/portable_storage_template_helper.h"

// Include rapidjson for parsing JSON in inject_decoy_outputs_from_json
#include "rapidjson/document.h"

// ============================================================================
// DONNA64 DIRECT ACCESS
// Include donna64 functions directly so we can benchmark them vs ref10
// ============================================================================
extern "C" {
// Donna64 optimized key derivation (from donna64_ge.c)
int donna64_generate_key_derivation(unsigned char *derivation,
                                    const unsigned char *tx_pub,
                                    const unsigned char *view_sec);

// Fast batch derivation (from donna64_crypto_hook.c)
int fast_batch_key_derivations(unsigned char *derivations_out,
                               const unsigned char *tx_pubs_in,
                               const unsigned char *view_sec_in, int count);

// Donna64 benchmark function
int donna64_benchmark(int iterations);

// Donna64 version (returns 0xMMmmpp)
int donna64_get_version(void);

// Debug macro - map to std::cout for WASM debug
#undef DEBUG_LOG
#define DEBUG_LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)

// Helper for debug printing keys
static std::string key_to_hex_debug(const unsigned char *key) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < 32; ++i) {
    oss << std::setw(2) << (int)key[i];
  }
  return oss.str();
}

// ========================================================================
// DONNA64 DEBUG FUNCTIONS - For diagnosing derivation bugs
// ========================================================================
// Full trace with hardcoded test vectors - fills global debug buffers
// Returns 100 for success, 0-31 for first mismatch byte, -1/-2 for errors
int donna64_debug_full_trace(void);

// Get debug bytes from last donna64_debug_full_trace call
int donna64_debug_get_scalar_e(int index);   // scalar decomposition e[i], 0-63
int donna64_debug_get_point_P(int index);    // decompressed point P, 0-31
int donna64_debug_get_precomp_1P(int index); // precomputed 1P
int donna64_debug_get_precomp_2P(int index); // precomputed 2P
int donna64_debug_get_precomp_8P(int index); // precomputed 8P
int donna64_debug_get_after_scalarmult(
    int index); // point after scalarmult (before cofactor)
int donna64_debug_get_iter0(int index);  // sum after first iteration (i=63)
int donna64_debug_get_iter1(int index);  // sum after second iteration (i=62)
int donna64_debug_get_iter2(int index);  // sum after third iteration (i=61)
int donna64_debug_get_iter32(int index); // sum after midpoint iteration (i=31)
int donna64_debug_get_iter62_16P(
    int index); // 16*P state before addition in iter 62
int donna64_debug_get_all_iter(
    int iter_num, int byte_index); // ALL iterations (iter_num 0-63, byte 0-31)
int donna64_debug_get_flags(void); // decompress_ok | (scalarmult_ok << 1)
int donna64_debug_get_byte(int index); // final result byte

// Four doublings debug test - captures each step of P -> 2P -> 4P -> 8P -> 16P
int donna64_debug_test_four_doublings(void);
int donna64_debug_get_dbl_1P(int index);
int donna64_debug_get_dbl_2P(int index);
int donna64_debug_get_dbl_4P(int index);
int donna64_debug_get_dbl_8P(int index);
int donna64_debug_get_dbl_16P(int index);

// Direct scalar multiplication (without cofactor ??8)
// Returns 0 on success, -1 if point is invalid
int donna64_ge_scalarmult(unsigned char *r, const unsigned char *p,
                          const unsigned char *scalar);
}

using namespace emscripten;

// Version string for the WASM module
// 3.5.1-carrot-D_e-fallback: FIX - D_e can be tx_pub_key OR additional_pubkey!
//                            Previous fix (3.5.0) was wrong - it required
//                            additional_pubkey for D_e. But for Carrot txs
//                            WITHOUT per-output additional_pubkeys, tx_pub_key
//                            IS D_e. Now correctly falls back to tx_pub_key
//                            when additional_pubkey is missing. This matches
//                            wallet2's scanning_tools.cpp behavior (line
//                            658-660).
// 3.5.0-carrot-D_e-fix: CRITICAL FIX - For Carrot outputs, D_e is in
// additional_pubkey (per-output), NOT tx_pub_key!
//                       Previous code used tx_pub_key for Carrot ECDH, but
//                       Carrot uses per-output D_e stored in additional_pubkey.
//                       This caused 97-100% false positive rate for Carrot
//                       outputs!
// 2.7.0-derivation-fix: CRITICAL FIX - CSP scanner now uses
// donna64_generate_key_derivation to match
//                       hwdev.generate_key_derivation!
//                       crypto::generate_key_derivation (ref10) produces
//                       DIFFERENT derivations than
//                       crypto::wallet::generate_key_derivation (donna64). This
//                       was causing CSP Phase 1 to find view tag matches, but
//                       Phase 2 rescan to miss them!
// 2.6.0-carrot-fix: CRITICAL FIX - scan_csp_batch now accepts BOTH legacy view
// key AND Carrot k_view_incoming!
//                   Salvium Carrot transactions use k_view_incoming for view
//                   tag computation, not m_view_secret_key. Without this fix,
//                   ALL Carrot transactions were being missed during CSP
//                   scanning!
// 2.5.0-txi-v2: TXI v2 format with output indices + protocol_tx for 100x faster
// sparse extraction! 2.4.0-idx-fix: CRITICAL FIX - Added protocol_tx to
// convert_epee_to_csp to match extract_sparse_txs index order! 2.3.0-sparse-v2:
// Fixed sparse format to include output indices (required for
// process_new_transaction!) 2.2.0-txi: Added convert_epee_to_csp_with_index for
// TXI generation (instant sparse extraction!) 2.1.0-sparse: Added sparse
// transaction extraction for bandwidth-optimized targeted rescan 2.0.0-csp:
// Added server-side convert_epee_to_csp for backend Epee???CSP conversion
// 1.9.0-csp: Added scan_csp_batch for zero-copy Compact Scan Protocol (CSP)
// scanning 1.8.0-viewtag: Added compute_view_tag and compute_view_tags_batch
// for JS pre-filtering 1.7.0-pruned: Backend now sends pruned blocks
// (prune:true), ~60% smaller 1.6.0-donna64-diag: Added diagnostic functions for
// crypto speed comparison 1.5.0-donna64: Integrated donna64 optimized crypto
// (10-14x faster key derivation!)
// - shadow_headers/crypto/wallet/ops.h redirects crypto to donna64
// - Uses 64-bit field elements (5 limbs ?? 51 bits) instead of ref10's 32-bit
// (10 limbs)
// 3.5.13-audit-txtype-fix: CRITICAL FIX - tx_type was being read from wrong
// location! The tx_type field is serialized AFTER extra in transaction_prefix,
// NOT inside extra. Previous code searched for 0xDE tag in extra (which is
// TX_EXTRA_MYSTERIOUS_MINERGATE_TAG). This caused AUDIT transactions to be
// parsed with wrong type, preventing detection. Also fixed
// extract_salvium_data_spend_pubkey to skip tx_prefix fields properly.
// 3.5.12-phase1-speed: MAJOR OPTIMIZATION - Removed spend_key computation from
// Phase 1! Phase 1 only needs (tx_idx, out_idx) for Phase 2 sparse TX fetch.
// wallet2::process_new_transaction handles full ownership verification.
// This saves ~50% CPU time per match (2 key derivations + 2 scalar mults
// removed). 3.5.11-csp-coinbase-passthrough: CSP Phase 1 now passes through ALL
// coinbase type-0 outputs (miner_tx/protocol_tx). Previously these were
// skipped, causing protocol_tx stake returns to be missed. Very few per block
// (~1-2), so minimal performance impact. 3.5.10-stake-return-fix: CRITICAL FIX
// - STAKE transactions use protocol_tx_data.return_address for the return
// output in protocol_tx at maturity. Must add to subaddress map.
// 3.5.9-dual-derivation: CRITICAL FIX - Try BOTH additional pubkey AND main
// tx_pub_key for legacy outputs. Change outputs use main pubkey even when
// additional pubkeys exist. This was causing ~50% of transactions to be missed!
// 3.5.17: AUDIT TX fix - parse_audit_tx_minimal now correctly extracts
// tx_pub_key from salvium_data.spend_pubkey 4.0.0-csp-v6-spent: CSP v6 adds ALL
// input key_images for spent output detection!
//                     - Per TX: input_count(2) + input_key_images[](32 each)
//                     for RingCT
//                     - scan_csp_batch accepts optional key_images_hex
//                     parameter
//                     - Returns "spent" array with matches against our key
//                     images
// 4.1.0-stake-cache: Add extract_stake_info() for server-side stake cache
// building
//                    Server builds cache of ALL stakes for efficient return
//                    detection Wallets query cache instead of passing through
//                    72k coinbase outputs
// 4.2.0-stake-filter: scan_csp_batch_with_stake_filter() accepts stake return
// heights
//                     Only coinbase outputs at specified heights are passed
//                     through Eliminates ~65% of false positive coinbase
//                     passthrough matches
// 4.3.0-parallel: Added init_view_only for parallel worker initialization
//                 Restored m_existing_txs_cache optimization for sparse ingest
// 4.3.1-parallel-opt: Added dynamic lookahead to init_view_only (4 args)
// 4.3.2-subaddr-fix: Fixed CN map type (carrot::subaddress_index_extended)
// 4.3.3-csv-only: init_view_only_with_map no longer calls
// generate_subaddress_map 4.3.4-diagnostic: Added get_wallet_diagnostic() for
// debugging 4.3.5-init-flag: Fixed missing m_initialized = true in
// init_view_only_with_map 4.3.6-zero-lookahead: Set lookahead=0 before
// generate() to prevent 10k auto-generated keys 4.3.9-min-lookahead: Changed to
// (1,1) because wallet2 throws error on (0,0) 4.4.0-svb: CRITICAL FIX -
// init_view_only_with_map now accepts view_balance_secret_hex!
//            For Carrot transactions, k_view_incoming is derived from
//            s_view_balance, NOT from the traditional m_view_secret_key. This
//            was causing 0 matches!
// 4.4.1-carrot-fix: CRITICAL FIX - Pass Carrot spend pubkey to workers!
//            The Carrot spend pubkey differs from legacy CN spend pubkey.
//            Workers were using wrong address, causing 0 Carrot matches.
// 4.4.4-carrot-subaddr-debug: REBUILD account.cpp to include
// insert_subaddresses debug logging
//            Tracks PreCarrot entries, Carrot addresses generated, and actually
//            inserted.
// 4.4.5-generate-fix: CRITICAL FIX - generate() was being called with SWAPPED
// arguments!
//            The 5-arg version passes viewkey to spendkey position. Using 4-arg
//            version instead.
// 4.4.6-derive-type-fix: CRITICAL FIX - CSV export/import now includes
// derive_type field!
//            Format changed from "pubkey:major:minor" to
//            "pubkey:major:minor:derive_type" Workers were treating ALL keys as
//            PreCarrot, causing Carrot address collisions. Only ~2127/20502
//            Carrot addresses were unique (18375 duplicates)! Now exports
//            derive_type from get_subaddress_map_ref() and imports it properly.
// v4.4.7:    Removed verbose debug logging for cleaner production builds.
// v4.5.0:    Added add_return_addresses() for workers to receive stake/audit
// return addresses.
//            Workers process TXs in parallel batches without the AUDIT/STAKE
//            that adds return_address. This caused protocol_tx (stake returns)
//            to be missed. Now workers receive return_addresses from server's
//            stake cache during init.
// v5.0.0:    Added register_stake_return_info() for post-Carrot STAKE return
// detection.
//            Post-Carrot (HF10 block 334750+) requires full
//            return_output_info_t in the return_output_map, not just subaddress
//            map entries. STAKE TXs with no change output never trigger
//            insert_return_output_info(), so we must manually populate the
//            return_output_map from stake cache data before Phase 3 scanning.
// v5.3.1:    CRITICAL FIX - parse_audit_tx_manually was missing return_address!
//            AUDIT transactions have prefix fields (amount_burnt,
//            return_address, return_pubkey, asset_types) between tx.type and
//            rct_signatures. This caused tx.return_address to remain null,
//            preventing AUDIT return outputs from being detected.
// v5.4.0:    CRITICAL FIX for PROTOCOL return output detection in CSP scanner!
//            Protocol returns (from STAKE/AUDIT) have output_key =
//            return_address directly, without key derivation. The scanner was
//            only trying derive_subaddress_public_key which fails for direct
//            output keys. Now checks if output_key itself is in subaddress_map
//            first.
// v5.3.2:    Added debug_parse_audit_tx() for diagnostics
// v5.14.0:   CRITICAL FIX for STAKE/AUDIT amounts! Was showing amount_in (total
//            inputs spent) instead of amount_burnt (actual stake/audit amount).
//            Example: TX 8a160f12 was showing -229712.87 but should show
//            -200000.
// v5.16.0:   CRITICAL FIX for pre-Carrot STAKE return_address! Manual parsing
//            sets tx.return_address, but code was reading
//            tx.protocol_tx_data.return_address. This caused PROTOCOL return
//            txs (stake unlocks) to be missed for pre-HF10 STAKE transactions.
//            Now checks tx.return_address first, then falls back to
//            tx.protocol_tx_data.return_address.
// v5.19.0:   CRITICAL FIX for pure-Carrot transactions without tag 0x01!
//            Post-HF10 Carrot transactions may have NO standard tx_pub_key
//            (tag 0x01) - instead all keys are stored as Carrot ephemeral
//            pubkeys. CSP generation was skipping these transactions because
//            get_tx_pub_key_from_extra() returned null_pkey. Now falls back
//            to first Carrot D_e or first additional_pubkey when tx_pub_key
//            is null. This fixes 7 missing incoming transactions at heights
//            381911-382118 which were pure-Carrot transactions.
// v5.25.0 - Debug: Add key image diagnostics for spent detection issues.
//           TX2 (28792031) shows +75936 SAL change but misses -250 SAL spent.
//           Need to trace why key images aren't being populated.
// v5.33.0 - CRITICAL FIX: Add missing block_version parameter to
// process_new_transaction
//            calls. v1.0.7 wallet2 API requires this param but it was missing,
//            causing all parameters to be shifted and misinterpreted - root
//            cause of 'indirect call signature mismatch' crashes in Phase 3b.
// v5.36.0 - CRITICAL FIX: Synthetic outgoing STAKE entries!
//            STAKE transactions detected via change outputs were NOT recorded
//            in out_payments, causing balance inflation. Now:
//            1. Detects STAKE txs where return_address matches our wallet
//            2. Creates synthetic outgoing entries with amount_burnt
//            3. Skips change outputs from incoming list
// v5.41.0:   Added create_stake_transaction_json() for STAKE tx creation
//            Allows web wallet to stake SAL/SAL1 for yield rewards
// v5.42.0:   CRITICAL FIX - get_subaddress_spend_keys_csv() index out of bounds
//            Added m_initialized check, null guards, and empty map handling
//            to prevent WASM runtime errors during scan startup.
// v5.43.0:   CRITICAL FIX - Rewrote get_subaddress_spend_keys_csv() to copy
//            map contents to vectors before iteration. WASM unordered_map
//            iterators can cause traps. Also added per-entry try-catch blocks.
// v5.47.3:   Added key_image_known tracking to diagnose spent detection gap
// v5.48.0:   RE-ENABLED spent detection disabled since v5.36.3 (root cause of balance inflation)
// v5.49.0:   FIX for STAKE txs without change - search m_confirmed_txs for PROTOCOL key_image derivation
// v5.49.1:   Added verbose debug logging for PROTOCOL tx processing
// v5.50.0:   CRITICAL FIX for Carrot stake return key_image derivation!
//            TWO BUGS FIXED:
//            1. register_stake_return_info() was CLEARING return_output_map, wiping out
//               correctly-derived key_images from Phase 2 STAKE tx scanning. This caused
//               ALL stake return outputs to get zero key_images → spent detection failed.
//            2. Extended m_confirmed_txs fallback to Carrot PROTOCOL outputs with zero key_images.
//            Result: ~158k SAL balance inflation fixed.
// v5.51.0:   Added create_return_transaction_json() for RETURN tx creation
//            Allows web wallet to return funds to the original sender.
//            Takes txid (64 hex chars) and finds transfer indices automatically.
// v5.52.0:   Added create_sweep_all_transaction_json() for sweep_all functionality
//            Sweeps ALL unlocked outputs to a destination address.
//            Uses wallet2::create_transactions_all() internally.
static const char *WASM_VERSION =
  "5.52.0"; // Add create_sweep_all_transaction_json(dest_address, mixin, priority)

#define WASM_DEBUG_LOGGING 0
#if WASM_DEBUG_LOGGING
#include <iostream>
#define DEBUG_LOG(...)                                                         \
  {                                                                            \
    char buf[2048];                                                            \
    snprintf(buf, sizeof(buf), __VA_ARGS__);                                   \
    std::cout << buf;                                                          \
    std::cout.flush();                                                         \
  }
#else
#define DEBUG_LOG(...) ((void)0)
#endif

// 3.5.8-clean: Disabled debug logging for production

// 3.5.7-stake-input-fix: CRITICAL FIX - extract_salvium_data_spend_pubkey was
// missing asset_type field
//                        STAKE/AUDIT transactions have txin_to_key with
//                        asset_type (string) field Missing this field caused
//                        infinite loop in manual blob parsing

// 3.5.6-embind-export-fix: CRITICAL FIX - scan_csp_batch was NOT being exported
// to JavaScript
//                          Embind can't handle default parameters, so created
//                          wrapper function. scan_csp_batch_impl = internal
//                          function with implementation scan_csp_batch =
//                          wrapper function for embind export

// 3.4.0-csp-v4-carrot-filter: CSP v4 format adds is_coinbase flag for Carrot
// view tag filtering
//                             Carrot addresses only need to check outputs in
//                             coinbase transactions Adds view_tag check for
//                             Carrot addresses to filter outputs early
// 3.3.13-stake-return-track: Track STAKE transaction heights for return block
// prediction
//                            When a STAKE tx is ingested and matched, record
//                            its block height. Stake returns happen at
//                            stake_height + 21600 (STAKE_LOCK_PERIOD).
//                            CSPScanService can use stake_heights[] to fetch
//                            protocol_tx at those specific return blocks
//                            (type-0 outputs can't be CSP filtered).
// 3.3.12-csp-phase1-fix: CRITICAL FIX for CSP Phase 1 false positive rate!
//                        Problem: 100k+ Phase 1 matches for wallet with 3.1k
//                        TXs (10x expected) Root causes fixed:
//                        1. Type-0 outputs (no stored view tag) were ALL
//                        matching - now SKIPPED
//                           Type-0 outputs cannot be filtered by view tag;
//                           Phase 2 handles them
//                        2. Type-1 outputs tried both tx_pub_key AND
//                        additional_pubkey, doubling
//                           false positive rate. Now uses ONLY
//                           additional_pubkey if present, otherwise main
//                           tx_pub_key (not both).
//                        Result: Phase 1 matches should be ~0.4% (1/256)
//                        instead of 4%+
// 3.3.11-audit-return-fix: CRITICAL FIX for pre-Carrot AUDIT return outputs at
// maturity!
//                          When an AUDIT tx is processed, we now add BOTH:
//                          1. salvium_data.spend_pubkey (for P_change output
//                          detection)
//                          2. tx.return_address (for protocol_tx return output
//                          at maturity) Previously only spend_pubkey was added,
//                          causing AUDIT returns to be missed because
//                          protocol_tx uses return_address as output key.
// 3.3.3-carrot-passthrough: CRITICAL FIX for Carrot return outputs (stake
// unlocks)!
//                            CSP scanner now passes ALL carrot_v1 outputs
//                            through Phase 1 because:
//                            - Return outputs use RingCT input_context from
//                            original STAKE tx
//                            - CSP doesn't have STAKE tx key_image, can't
//                            compute correct view tag
//                            - wallet2::process_new_transaction verifies via
//                            return_output_map
// 3.3.0-sorted-ingest-two-pass: CRITICAL FIX for STAKE/AUDIT and PROTOCOL
// transactions!
//                               ingest_sparse_transactions now:
//                               1. Sorts transactions by block height before
//                               processing
//                               2. Implements two-pass processing for "ghost"
//                               transactions STAKE/AUDIT tx change outputs
//                               (P_change) must be in subaddress map BEFORE
//                               PROTOCOL returns are processed. Sorting ensures
//                               proper order. Ghost transactions (prescan match
//                               but not added) are retried after first pass
//                               completes, when subaddress map is fully
//                               populated.
// 3.2.3-additional-pubkey-priority: For type-0 outputs (no view tag) with
// additional_pubkey,
//                                   use additional_pubkey derivation FIRST
//                                   instead of main tx_pub.
//                                   Subaddress/protocol_tx outputs use
//                                   per-output additional pubkeys.
// 3.2.2-carrot-ecdh-fix: CRITICAL FIX - Carrot view tag computation now uses
// correct X25519 ECDH!
//                        For Carrot v1 transactions, tx_pub_key in CSP is D_e
//                        (enote_ephemeral_pubkey) which is ALREADY in X25519
//                        format, not Ed25519. Uses
//                        carrot::make_carrot_uncontextualized_shared_key_receiver
//                        for s_sr = k_view_incoming * D_e, then
//                        carrot::make_carrot_view_tag with proper
//                        input_context.
// 3.0.6-debug-additional-pubkey: debug_csp_find_tx now uses per-output
// additional pubkeys for subaddress derivations 3.0.5-debug-csp-v3: Updated
// debug_csp_find_tx to support CSP v2/v3 formats for transaction debugging
// 2.9.0-csp-v3-subaddress: CRITICAL FIX - CSP v3 format now includes per-output
// additional tx pubkeys!
//                          Transactions to subaddresses use
//                          additional_tx_pub_keys for view tag derivation, NOT
//                          the main tx_pub_key. CSP v2 only stored the main
//                          pubkey, causing CSP Phase 1 to compute wrong view
//                          tags for subaddress outputs, resulting in 75-90% of
//                          transactions being missed. CSP v3 adds:
//                          has_additional_pubkey(1) per output, and
//                          additional_pubkey(32) inline when
//                          has_additional_pubkey=1.
// 2.8.15-viewtag-zero-fix: CRITICAL FIX - CSP scan_csp_batch now treats
// stored_view_tag=0 as "no view tag"
//                           and reports it as a match. Pre-view-tag outputs
//                           (txout_to_key) are stored with view_tag=0 in CSP
//                           buffer, but computed view tag is rarely 0. This was
//                           causing 97%+ of pre-hardfork transactions to be
//                           filtered out by CSP! Now all outputs with
//                           stored_view_tag=0 are passed through to wallet2 for
//                           full derivation check.
// 2.8.14-asset-indices-fix: CRITICAL FIX - ingest_sparse_transactions was
// passing empty
//                           asset_type_output_indices vector, causing
//                           wallet2::process_new_transaction to throw "vector"
//                           (std::out_of_range) at line 2656 where it does
//                           asset_type_o_indices.at(local_output_index). Now
//                           uses same indices as output_indices since SAL/SAL1
//                           share the same global output index space.
// 2.8.13-donna64-fast-restore: Restored fast fe_add/fe_sub (no carry prop) and
// optimized fe_sq/fe_sq2.
//                              The v2.8.12 carry propagation in fe_add/fe_sub
//                              caused massive slowdown. The proper fix is to
//                              add fe_reduce_weak() at strategic points in
//                              ge_p2_dbl.
// 2.8.12-donna64-fe-carry-fix: CRITICAL FIX - Added carry propagation to fe_add
// and fe_sub.
//                              Without carry propagation, chained add/sub
//                              operations in point doubling (ge_p2_dbl) caused
//                              limbs to exceed 2^60, corrupting the scalar
//                              multiplication. This was the root cause of
//                              donna64 producing wrong key derivations vs
//                              ref10.
// 2.8.7-donna64-limb-normalize: CRITICAL FIX - Added "Snapshot & Reload"
// normalization after each
//                                loop iteration. ge_add produces valid
//                                coordinates but with "dirty" limbs (values
//                                potentially up to 2^60+). When fed into 4
//                                consecutive doublings, these overflow uint128
//                                during squaring. The fix forces full reduction
//                                by serializing to bytes and deserializing
//                                back.
// 2.8.6-donna64-full-iter-debug: Added iter62_16P capture + full all_iters dump
// 2.8.4-donna64-p2fix: CRITICAL FIX - Use P2 accumulator to match ref10's
// ge_scalarmult
//                      The bug was using P3 accumulator with ge_p3_dbl on first
//                      double, while ref10 uses P2 accumulator with ge_p2_dbl
//                      throughout.
// 2.8.3-donna64-debug4: Added iter0 comparison (donna64 vs input point after
// first loop iteration) 2.8.2-donna64-debug3: Added 2P comparison test (ref10
// vs donna64 point doubling) 2.8.1-donna64-debug2: Added
// compare_scalarmult_no_cofactor() to test scalar*P without ??8
// 2.8.0-donna64-debug: Added compare_ref10_donna64() function for comprehensive
//                      ref10 vs donna64 comparison with full intermediate value
//                      capture. Outputs: point_P, scalar_e[64],
//                      precomp_{1,2,8}P, iter0, after_scalarmult

// Helper to convert a 32-byte key to hex string
static std::string key_to_hex(const unsigned char *data) {
  std::string result;
  result.reserve(64);
  static const char hex_chars[] = "0123456789abcdef";
  for (size_t i = 0; i < 32; ++i) {
    result.push_back(hex_chars[data[i] >> 4]);
    result.push_back(hex_chars[data[i] & 0x0f]);
  }
  return result;
}

// ============================================================================
// ZERO-COPY MEMORY MANAGEMENT
// These functions allow JavaScript to write directly into WASM heap memory,
// avoiding expensive copies through Embind string conversion.
// ============================================================================

// Allocate memory in WASM heap - returns a pointer that JS can use with
// HEAPU8.set()
uintptr_t allocate_binary_buffer(size_t size) {
  if (size == 0 || size > 100 * 1024 * 1024) { // Max 100MB safety limit
    return 0;
  }
  try {
    return reinterpret_cast<uintptr_t>(new uint8_t[size]);
  } catch (...) {
    return 0;
  }
}

// Free memory allocated by allocate_binary_buffer
void free_binary_buffer(uintptr_t ptr) {
  if (ptr != 0) {
    delete[] reinterpret_cast<uint8_t *>(ptr);
  }
}

// ============================================================================
// WasmWallet - JavaScript-friendly wrapper around tools::wallet2
// ============================================================================
// Forward declaration (definition is later in this file)
static bool parse_audit_tx_minimal(const std::string &tx_blob,
                                   cryptonote::transaction &tx);

// Forward declarations for HTTP cache functions (defined later in extern "C"
// block) These are needed by prepare_transaction_json and
// complete_transaction_json
extern "C" {
bool wasm_http_has_pending_get_outs_request();
const char *wasm_http_get_pending_get_outs_request_base64();
void wasm_http_clear_pending_get_outs_request();
}

// Global wallet instance for stateless functions (scan_csp_batch) to access
static tools::wallet2 *g_wallet_instance = nullptr;

class WasmWallet {
private:
  std::unique_ptr<tools::wallet2> m_wallet;
  mutable std::string m_last_error; // mutable so const methods can set it
  bool m_initialized;
  std::string m_daemon_address;

  // Helper to check if wallet has a transaction (linear search)
  // This is needed because wallet2::have_tx is not available or private
  bool wallet_has_tx(const crypto::hash &txid) const {
    if (!m_wallet)
      return false;
    size_t count = m_wallet->get_num_transfer_details();
    for (size_t i = 0; i < count; ++i) {
      const auto &td = m_wallet->get_transfer_details(i);
      if (td.m_txid == txid)
        return true;
    }
    return false;
  }

  // ========================================================================
  // SCAN RESULT CACHING (for scan_blocks_fast optimization)
  // ========================================================================
  // These store results from the last scan_blocks_fast() call so that
  // get_last_scan_result() can return them without re-scanning.
  // This avoids JSON serialization on the hot path - worker calls
  // scan_blocks_fast(), checks return value (0=MISS, 1=HIT), and only calls
  // get_last_scan_result() if HIT.
  mutable std::vector<uint64_t>
      m_last_scan_hits; // Block heights with wallet outputs
  mutable uint64_t m_last_scan_start_height = 0;
  mutable uint64_t m_last_scan_end_height = 0;
  mutable size_t m_last_scan_blocks_count = 0;
  mutable std::string
      m_last_scan_last_block_hash; // Hex string of last block hash

  // OPTIMIZATION v4.3.0: Cached set of existing transaction hashes for O(1)
  // duplicate checking Updated incrementally instead of rebuilt on each
  // ingest_sparse_transactions call
  mutable std::unordered_set<crypto::hash> m_existing_txs_cache;
  mutable size_t m_existing_txs_cache_size =
      0; // Track wallet size for cache invalidation

  // CACHE v5.33.0: Transaction timestamps for current session
  // Since wallet2 transfer_details lacks timestamp, we must cache it during
  // ingest
  std::unordered_map<crypto::hash, uint64_t> m_tx_timestamps;

  // ========================================================================
  // SPLIT TRANSACTION ARCHITECTURE (Prepare + Complete)
  // ========================================================================
  // Stores state between prepare_transaction_json and complete_transaction_json
  // This ensures the same inputs are used in both phases.
  struct PreparedTxState {
    bool valid = false;
    std::string uuid; // Unique identifier for this preparation
    std::vector<size_t> selected_transfers; // Indices into m_transfers
    std::string dest_address;
    uint64_t amount;
    uint32_t mixin_count;
    uint32_t priority;
    std::string asset_type;
    std::vector<uint8_t> extra; // Payment ID etc.
    uint64_t estimated_fee;
  };
  PreparedTxState m_prepared_tx;

  // Helper to generate a simple UUID
  std::string generate_tx_uuid() {
    std::ostringstream oss;
    oss << std::hex;
    for (int i = 0; i < 16; ++i) {
      oss << (crypto::rand<uint8_t>() & 0xFF);
    }
    return oss.str();
  }

  // Helper to find which of our transfers are in a get_outs request
  // This parses the request and matches global_output_indices back to our
  // transfers
  std::vector<size_t>
  find_selected_transfers_from_request(const std::string &request_body,
                                       const std::string &asset_type) {
    std::vector<size_t> result;

    // Parse the binary request to extract output indices (epee binary format)
    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req;
    epee::serialization::portable_storage ps;
    if (!ps.load_from_binary(request_body)) {
      return result;
    }
    if (!req.load(ps)) {
      return result;
    }

    // Build a set of global indices from the request
    std::unordered_set<uint64_t> requested_indices;
    for (const auto &out : req.outputs) {
      requested_indices.insert(out.index);
    }

    // Find which of our transfers match
    for (size_t i = 0; i < m_wallet->m_transfers.size(); ++i) {
      const auto &td = m_wallet->m_transfers[i];
      if (td.asset_type != asset_type)
        continue;
      if (td.m_spent)
        continue;

      if (requested_indices.count(td.m_global_output_index)) {
        result.push_back(i);
      }
    }

    return result;
  }

public:
  WasmWallet()
      : m_initialized(false), m_daemon_address("seed01.salvium.io:19081") {
    // Create HTTP client factory (returns stub clients that do nothing)
    auto http_factory = std::make_unique<net::http::client_factory>();

    m_wallet = std::make_unique<tools::wallet2>(
        cryptonote::MAINNET,    // Network type
        1,                      // KDF rounds
        true,                   // Unattended mode
        std::move(http_factory) // HTTP client factory (stub)
    );
    g_wallet_instance = m_wallet.get();
  }

  ~WasmWallet() {
    if (g_wallet_instance == m_wallet.get()) {
      g_wallet_instance = nullptr;
    }
  }

  // ========================================================================
  // Wallet Creation / Restoration
  // ========================================================================

  bool create_random(const std::string &password, const std::string &language) {
    try {
      // Set seed language BEFORE generating
      m_wallet->set_seed_language(language);

      // Generate random keys
      crypto::secret_key recovery_key;
      crypto::random32_unbiased((unsigned char *)recovery_key.data);

      // Create wallet from random seed
      m_wallet->generate("", password, recovery_key, false, false, false);

      // CRITICAL: Generate subaddress map in the account for output scanning!
      // view_incoming_scan_transaction() uses account.get_subaddress_map_cn()
      // which is populated by generate_subaddress_map(), NOT by m_subaddresses.
      const size_t SUBADDRESS_LOOKAHEAD_MAJOR = 50;
      const size_t SUBADDRESS_LOOKAHEAD_MINOR = 200;
      m_wallet->get_account().generate_subaddress_map(
          {SUBADDRESS_LOOKAHEAD_MAJOR, SUBADDRESS_LOOKAHEAD_MINOR});

      m_initialized = true;
      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // Note: Using double instead of uint64_t for JavaScript compatibility
  // JavaScript numbers are doubles (53-bit integer precision), which is enough
  // for block heights
  bool restore_from_seed(const std::string &seed, const std::string &password,
                         double restore_height_d) {
    try {
      uint64_t restore_height = static_cast<uint64_t>(restore_height_d);

      // Parse mnemonic
      crypto::secret_key recovery_key;
      std::string language;

      if (!crypto::ElectrumWords::words_to_bytes(seed, recovery_key,
                                                 language)) {
        m_last_error = "Invalid mnemonic seed";
        return false;
      }

      // Restore wallet - recover=true to use the recovery_key from seed
      m_wallet->generate("", password, recovery_key, true, false, false);

      // IMPORTANT: Set the seed language so get_seed() works later
      m_wallet->set_seed_language(language);

      m_wallet->set_refresh_from_block_height(restore_height);

      // CRITICAL FIX v5.4.1: Also update m_blockchain size so
      // get_wallet_height() returns the correct value. Without this, after
      // reload the wallet reports height 0 and rescans from the beginning
      // instead of continuing.
      if (restore_height > 0) {
        crypto::hash null_hash = crypto::null_hash;
        m_wallet->m_blockchain.clear();
        for (uint64_t i = 0; i < restore_height; ++i) {
          m_wallet->m_blockchain.push_back(null_hash);
        }
      }

      // CRITICAL FIX: Generate subaddress map in the account for output
      // scanning! view_incoming_scan_transaction() uses
      // account.get_subaddress_map_cn() which is populated by
      // generate_subaddress_map(), NOT by m_subaddresses. Without this, CSP
      // Phase 2 will find 0 transactions!
      const size_t SUBADDRESS_LOOKAHEAD_MAJOR = 50;
      const size_t SUBADDRESS_LOOKAHEAD_MINOR = 200;
      m_wallet->get_account().generate_subaddress_map(
          {SUBADDRESS_LOOKAHEAD_MAJOR, SUBADDRESS_LOOKAHEAD_MINOR});

      m_initialized = true;
      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // Restore wallet from a 32-byte recovery key (seed bytes) provided as hex.
  // This enables deterministic full-wallet restore without requiring the
  // mnemonic word list in the WASM environment.
  bool restore_from_recovery_key_hex(const std::string &recovery_key_hex,
                                     const std::string &password,
                                     double restore_height_d) {
    try {
      uint64_t restore_height = static_cast<uint64_t>(restore_height_d);

      crypto::secret_key recovery_key;
      if (!epee::string_tools::hex_to_pod(recovery_key_hex, recovery_key)) {
        m_last_error = "Invalid recovery key hex";
        return false;
      }

      // Restore wallet - recover=true to use the provided recovery key
      m_wallet->generate("", password, recovery_key, true, false, false);
      m_wallet->set_refresh_from_block_height(restore_height);

      // CRITICAL FIX v5.4.1: Also update m_blockchain size so
      // get_wallet_height() returns the correct value. Without this, after
      // reload the wallet reports height 0 and rescans from the beginning
      // instead of continuing.
      if (restore_height > 0) {
        crypto::hash null_hash = crypto::null_hash;
        m_wallet->m_blockchain.clear();
        for (uint64_t i = 0; i < restore_height; ++i) {
          m_wallet->m_blockchain.push_back(null_hash);
        }
      }

      // Ensure subaddress map exists for scanning (matches restore_from_seed)
      const size_t SUBADDRESS_LOOKAHEAD_MAJOR = 1;
      const size_t SUBADDRESS_LOOKAHEAD_MINOR = 200;
      m_wallet->get_account().generate_subaddress_map(
          {SUBADDRESS_LOOKAHEAD_MAJOR, SUBADDRESS_LOOKAHEAD_MINOR});

      m_initialized = true;
      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // ========================================================================
  // Worker Initialization (v4.3.0)
  // ========================================================================
  // Initialize view-only wallet from keys (for parallel workers)
  bool init_view_only(const std::string &view_secret_key_hex,
                      const std::string &spend_public_key_hex,
                      const std::string &password = "",
                      int lookahead_minor = 50000) {
    try {
      crypto::secret_key view_secret_key;
      crypto::public_key spend_public_key;

      if (!epee::string_tools::hex_to_pod(view_secret_key_hex,
                                          view_secret_key)) {
        m_last_error = "Invalid view secret key hex";
        return false;
      }
      if (!epee::string_tools::hex_to_pod(spend_public_key_hex,
                                          spend_public_key)) {
        m_last_error = "Invalid spend public key hex";
        return false;
      }

      // Check if spend public key is valid
      if (!crypto::check_key(spend_public_key)) {
        m_last_error = "Invalid spend public key";
        return false;
      }

      // Derive view public key from view secret key
      crypto::public_key view_public_key;
      if (!crypto::secret_key_to_public_key(view_secret_key, view_public_key)) {
        m_last_error = "Failed to derive view public key";
        return false;
      }

      cryptonote::account_public_address address;
      address.m_spend_public_key = spend_public_key;
      address.m_view_public_key = view_public_key;

      // v4.4.4-CRITICAL-FIX: Use the 4-arg generate() for view-only wallets
      // Previously we used 5-arg version with swapped arguments which corrupted
      // keys!
      m_wallet->generate("", password, address, view_secret_key);

      // CRITICAL FIX: Explicitly initialize Carrot keys for view-only wallet!
      // This derives k_view_incoming from the view secret key.
      m_wallet->get_account().create_from_svb_key(address, view_secret_key);

      // CRITICAL: Generate subaddress map in the account for output scanning!
      // view_incoming_scan_transaction() uses account.get_subaddress_map_cn()
      // which is populated by generate_subaddress_map(), NOT by m_subaddresses.
      const size_t SUBADDRESS_LOOKAHEAD_MAJOR = 50;
      m_wallet->get_account().generate_subaddress_map(
          {SUBADDRESS_LOOKAHEAD_MAJOR, (size_t)lookahead_minor});

      m_initialized = true;
      return true;
    } catch (const std::exception &e) {
      m_last_error = std::string("init_view_only: ") + e.what();
      return false;
    }
  }

  // Uses CSV string format: "pubkey:major:minor,pubkey:major:minor,..."
  // This function does NOT generate subaddress lookahead - it ONLY uses the
  // imported keys v4.4.1-carrot-fix: Added carrot_spend_pubkey_hex parameter
  // for correct Carrot address v4.4.0-svb: Added view_balance_secret_hex
  // parameter for proper Carrot key derivation The view_balance_secret
  // (s_view_balance) is REQUIRED for scanning Carrot transactions. It derives
  // k_view_incoming which is used by view_incoming_scan_transaction. Pass empty
  // string for view_balance_secret_hex to use legacy behavior (view_secret_key
  // as svb). The carrot_spend_pubkey_hex is the Carrot address spend pubkey
  // from the main wallet, which DIFFERS from the legacy CN spend pubkey and
  // must be used for Carrot address matching.
  bool
  init_view_only_with_map(const std::string &view_secret_key_hex,
                          const std::string &spend_public_key_hex,
                          const std::string &subaddress_keys_csv,
                          const std::string &password = "",
                          const std::string &view_balance_secret_hex = "",
                          const std::string &carrot_spend_pubkey_hex = "") {
    try {
      // v4.3.3: REFACTORED - Do NOT call init_view_only() which generates
      // subaddress lookahead Instead, duplicate only the essential
      // initialization WITHOUT generate_subaddress_map

      crypto::secret_key view_secret_key;
      crypto::public_key spend_public_key;
      crypto::secret_key s_view_balance; // v4.4.0: Carrot view-balance secret
      crypto::public_key
          carrot_spend_pubkey; // v4.4.1: Carrot address spend pubkey

      if (!epee::string_tools::hex_to_pod(view_secret_key_hex,
                                          view_secret_key)) {
        m_last_error = "Invalid view secret key hex";
        return false;
      }
      if (!epee::string_tools::hex_to_pod(spend_public_key_hex,
                                          spend_public_key)) {
        m_last_error = "Invalid spend public key hex";
        return false;
      }

      // v4.4.1: Parse carrot_spend_pubkey if provided (CRITICAL for Carrot
      // address matching!)
      bool have_carrot_spend_pubkey = false;
      if (!carrot_spend_pubkey_hex.empty()) {
        if (!epee::string_tools::hex_to_pod(carrot_spend_pubkey_hex,
                                            carrot_spend_pubkey)) {
          m_last_error = "Invalid carrot_spend_pubkey hex";
          return false;
        }
        if (!crypto::check_key(carrot_spend_pubkey)) {
          m_last_error = "Invalid carrot_spend_pubkey (not on curve)";
          return false;
        }
        have_carrot_spend_pubkey = true;
      }

      // v4.4.0: Parse view_balance_secret if provided, otherwise fall back to
      // view_secret_key (legacy behavior)
      if (!view_balance_secret_hex.empty()) {
        if (!epee::string_tools::hex_to_pod(view_balance_secret_hex,
                                            s_view_balance)) {
          m_last_error = "Invalid view_balance_secret hex";
          return false;
        }
      } else {
        // Legacy behavior: use view_secret_key as svb (WRONG for Carrot, but
        // backward compatible)
        s_view_balance = view_secret_key;
      }

      if (!crypto::check_key(spend_public_key)) {
        m_last_error = "Invalid spend public key";
        return false;
      }

      // Derive view public key from view secret key
      crypto::public_key view_public_key;
      if (!crypto::secret_key_to_public_key(view_secret_key, view_public_key)) {
        m_last_error = "Failed to derive view public key";
        return false;
      }

      cryptonote::account_public_address address;
      address.m_spend_public_key = spend_public_key;
      address.m_view_public_key = view_public_key;

      // v4.3.7: Set lookahead to minimum (1,1) BEFORE generate() to prevent
      // expensive subaddress generation generate() calls setup_new_blockchain()
      // -> add_subaddress_account() -> expand_subaddresses() which uses
      // lookahead values. Default is 50x200 = 10,000 keys! (expensive
      // derivations) We can't set to 0 because wallet2 throws "Subaddress
      // major/minor lookahead may not be zero"
      m_wallet->set_subaddress_lookahead(1, 1);

      // v4.4.4-CRITICAL-FIX: Initialize wallet as view-only with CORRECT
      // argument order! The 4-arg generate(wallet, password, address, viewkey)
      // is for view-only wallets. The 5-arg generate(wallet, password, address,
      // spendkey, viewkey) is for full wallets. Previously we were using the
      // 5-arg version with arguments SWAPPED, which resulted in:
      //   - m_spend_secret_key = view_secret_key (WRONG!)
      //   - m_view_secret_key = null (WRONG!)
      // This broke Carrot key derivation because s_view_balance was being set
      // from the wrong key!
      m_wallet->generate("", password, address, view_secret_key);

      // v4.4.1-carrot-fix: Create a Carrot-specific address with the correct
      // spend pubkey The Carrot spend pubkey is DIFFERENT from the legacy CN
      // spend pubkey. It's computed as: k_generate_image*G + k_prove_spend*G
      // Since workers don't have k_prove_spend (needs spend secret), we pass
      // the correct value from main wallet.
      cryptonote::account_public_address carrot_address = address;
      if (have_carrot_spend_pubkey) {
        carrot_address.m_spend_public_key = carrot_spend_pubkey;
        carrot_address.m_is_carrot = true;
      }

      // v4.4.0: Initialize Carrot keys using the CORRECT s_view_balance secret!
      // This derives k_view_incoming = H_n(s_view_balance) which is needed for
      // Carrot scanning. Previously we were incorrectly using view_secret_key
      // which gave wrong k_view_incoming! v4.4.1: Pass carrot_address which has
      // the correct Carrot spend pubkey
      m_wallet->get_account().create_from_svb_key(carrot_address,
                                                  s_view_balance);

      // DO NOT call generate_subaddress_map() - we will import keys from CSV
      // instead!

      // We need to populate TWO maps:
      // 1. account internal subaddress_map - used by
      // view_incoming_scan_transaction
      // 2. wallet2::m_subaddresses - used by process_new_transaction

      // Access account for insert_subaddresses
      auto &account = m_wallet->get_account();

      // Clear existing entries in wallet2::m_subaddresses (should already be
      // empty)
      m_wallet->m_subaddresses.clear();

      // Parse CSV string: "pubkey:major:minor:derive_type,..." (v4.4.6 format
      // with derive_type) Also supports legacy format: "pubkey:major:minor,..."
      // (treated as PreCarrot) Build a map to insert into account (which uses
      // subaddress_index_extended)
      std::unordered_map<crypto::public_key, carrot::subaddress_index_extended>
          entries_to_insert;
      size_t count = 0;
      size_t precarrot_count = 0;
      size_t carrot_count = 0;
      size_t pos = 0;
      size_t next;

      while (pos < subaddress_keys_csv.size()) {
        // Find next comma or end of string
        next = subaddress_keys_csv.find(',', pos);
        if (next == std::string::npos)
          next = subaddress_keys_csv.size();

        std::string entry = subaddress_keys_csv.substr(pos, next - pos);

        // Parse "pubkey:major:minor" or "pubkey:major:minor:derive_type"
        size_t colon1 = entry.find(':');
        if (colon1 != std::string::npos && colon1 == 64) {
          size_t colon2 = entry.find(':', colon1 + 1);
          if (colon2 != std::string::npos) {
            std::string key_hex = entry.substr(0, colon1);
            uint32_t major =
                std::stoul(entry.substr(colon1 + 1, colon2 - colon1 - 1));

            // Check for optional derive_type (v4.4.6 format)
            size_t colon3 = entry.find(':', colon2 + 1);
            uint32_t minor;
            carrot::AddressDeriveType derive_type =
                carrot::AddressDeriveType::PreCarrot; // Default for legacy

            if (colon3 != std::string::npos) {
              // v4.4.6 format with derive_type
              minor = std::stoul(entry.substr(colon2 + 1, colon3 - colon2 - 1));
              int derive_type_int = std::stoi(entry.substr(colon3 + 1));
              // 0=Auto, 1=PreCarrot, 2=Carrot
              if (derive_type_int == 0)
                derive_type = carrot::AddressDeriveType::Auto;
              else if (derive_type_int == 1)
                derive_type = carrot::AddressDeriveType::PreCarrot;
              else if (derive_type_int == 2)
                derive_type = carrot::AddressDeriveType::Carrot;
            } else {
              // Legacy format without derive_type
              minor = std::stoul(entry.substr(colon2 + 1));
            }

            crypto::public_key pkey;
            if (epee::string_tools::hex_to_pod(key_hex, pkey)) {
              // wallet2::m_subaddresses uses plain cryptonote::subaddress_index
              cryptonote::subaddress_index index = {major, minor};
              m_wallet->m_subaddresses[pkey] = index;

              // Build entry for account's internal map (uses
              // subaddress_index_extended) v4.4.6-derive-type-fix: USE THE
              // ACTUAL derive_type from CSV!
              // - PreCarrot entries: insert_subaddresses() will generate
              // matching Carrot address
              // - Carrot entries: insert_subaddresses() will just insert them
              // as-is (no regeneration) Previously all were hardcoded to
              // PreCarrot, causing duplicate Carrot generation!
              carrot::subaddress_index_extended ext_index{
                  .index = {major, minor},
                  .derive_type = derive_type,
                  .is_return_spend_key = false};
              entries_to_insert[pkey] = ext_index;
              count++;

              if (derive_type == carrot::AddressDeriveType::PreCarrot) {
                precarrot_count++;
              } else if (derive_type == carrot::AddressDeriveType::Carrot) {
                carrot_count++;
              }
            }
          }
        }

        pos = next + 1;
      }

      // Use insert_subaddresses to add to account's internal map
      account.insert_subaddresses(entries_to_insert);

      // VERIFY: Check account internal map was populated
      const auto &account_map = account.get_subaddress_map_cn();
      size_t account_map_size = account_map.size();

      // CRITICAL: Set m_initialized flag!
      m_initialized = true;

      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // Optimized export that reads directly from map to avoid derivation freeze
  // Export from account's subaddress_map (with derive_type) to preserve which
  // keys are PreCarrot vs Carrot v4.4.6-derive-type-fix: Changed format to
  // "pubkey:major:minor:derive_type,..." derive_type values: 0=Auto,
  // 1=PreCarrot, 2=Carrot (per carrot::AddressDeriveType enum) Workers MUST
  // know derive_type to avoid regenerating Carrot addresses that already exist!
  // v5.45.0: RESTORED - Full rebuild with consistent no-pthread flags should fix WASM traps
  // NOTE: Returning very large strings via embind can trap on some runtimes.
  // Prefer the chunked API from JS when available.
  std::string get_subaddress_spend_keys_csv() const {
    // Check initialization before accessing wallet
    if (!m_initialized || !m_wallet) {
      return "";
    }

    std::string csv;
    try {
      const auto &ext_map = m_wallet->get_account().get_subaddress_map_ref();
      const auto &sub_map = m_wallet->m_subaddresses;

      size_t ext_map_size = ext_map.size();
      size_t m_subaddr_size = sub_map.size();

      if (ext_map_size == 0 && m_subaddr_size == 0) {
        return "";
      }

      // Keep reserve conservative to reduce risk of massive realloc.
      size_t total_entries = ext_map_size + m_subaddr_size;
      if (total_entries > 0) {
        constexpr size_t kApproxEntryBytes = 80;
        constexpr size_t kMaxReserveBytes = 16 * 1024 * 1024;
        size_t reserve_bytes = std::min(total_entries * kApproxEntryBytes, kMaxReserveBytes);
        csv.reserve(reserve_bytes);
      }

      bool first = true;

      for (const auto &pair : ext_map) {
        int derive_type_int = static_cast<int>(pair.second.derive_type);
        if (derive_type_int < 0 || derive_type_int > 2) {
          derive_type_int = 1;
        }

        if (!first)
          csv += ',';
        first = false;

        csv += epee::string_tools::pod_to_hex(pair.first);
        csv += ':';
        csv += std::to_string(pair.second.index.major);
        csv += ':';
        csv += std::to_string(pair.second.index.minor);
        csv += ':';
        csv += std::to_string(derive_type_int);
      }

      if (ext_map.empty()) {
        for (const auto &pair : sub_map) {
          if (!first)
            csv += ',';
          first = false;

          csv += epee::string_tools::pod_to_hex(pair.first);
          csv += ':';
          csv += std::to_string(pair.second.major);
          csv += ':';
          csv += std::to_string(pair.second.minor);
          csv += ":1";
        }
      }

      return csv;
    } catch (...) {
      return "";
    }
  }


  // ------------------------------------------------------------------------
  // Subaddress map export helpers
  // ------------------------------------------------------------------------
  // Returning a multi-megabyte std::string through embind can trap with
  // `RuntimeError: index out of bounds` on some builds/runtimes.
  // To make this robust, we expose a chunked API so JS can join it.
  int get_subaddress_spend_keys_csv_len() const {
    if (!m_initialized || !m_wallet) {
      return 0;
    }

    try {
      const auto &ext_map = m_wallet->get_account().get_subaddress_map_ref();
      size_t ext_map_size = ext_map.size();
      size_t m_subaddr_size = m_wallet->m_subaddresses.size();

      // Approx length: each entry ~80 bytes incl delimiter.
      size_t approx = (ext_map_size + m_subaddr_size) * 80;
      if (approx > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
      }
      return static_cast<int>(approx);
    } catch (...) {
      return 0;
    }
  }

  std::string get_subaddress_spend_keys_csv_prefix(int max_chars) const {
    if (!m_initialized || !m_wallet || max_chars <= 0) {
      return "";
    }

    try {
      const auto &ext_map = m_wallet->get_account().get_subaddress_map_ref();
      const auto &sub_map = m_wallet->m_subaddresses;

      std::string out;
      out.reserve(static_cast<size_t>(std::min(max_chars, 1024)));

      out += "ext_map=";
      out += std::to_string(ext_map.size());
      out += ",m_subaddresses=";
      out += std::to_string(sub_map.size());
      out += "|";

      int added = 0;
      for (const auto &pair : ext_map) {
        if (static_cast<int>(out.size()) >= max_chars || added >= 5) {
          break;
        }
        std::string key_hex = epee::string_tools::pod_to_hex(pair.first);
        if (added > 0)
          out += ',';
        out += key_hex;
        out += ':';
        out += std::to_string(pair.second.index.major);
        out += ':';
        out += std::to_string(pair.second.index.minor);
        out += ':';
        out += std::to_string(static_cast<int>(pair.second.derive_type));
        added++;
      }

      if (added == 0) {
        for (const auto &pair : sub_map) {
          if (static_cast<int>(out.size()) >= max_chars || added >= 5) {
            break;
          }
          std::string key_hex = epee::string_tools::pod_to_hex(pair.first);
          if (added > 0)
            out += ',';
          out += key_hex;
          out += ':';
          out += std::to_string(pair.second.major);
          out += ':';
          out += std::to_string(pair.second.minor);
          out += ":1";
          added++;
        }
      }

      if (static_cast<int>(out.size()) > max_chars) {
        out.resize(static_cast<size_t>(max_chars));
      }
      return out;
    } catch (...) {
      return "";
    }
  }

  int get_subaddress_spend_keys_csv_chunk_count(int chunk_size) const {
    if (!m_initialized || !m_wallet || chunk_size <= 0) {
      return 0;
    }

    // Use approximate length for count to avoid building full string.
    int approx_len = get_subaddress_spend_keys_csv_len();
    if (approx_len <= 0) {
      return 0;
    }

    int count = (approx_len + chunk_size - 1) / chunk_size;
    if (count < 1)
      count = 1;
    return count;
  }

  std::string get_subaddress_spend_keys_csv_chunk(int chunk_index,
                                                  int chunk_size) const {
    if (!m_initialized || !m_wallet || chunk_size <= 0 || chunk_index < 0) {
      return "";
    }

    try {
      const auto &ext_map = m_wallet->get_account().get_subaddress_map_ref();
      const auto &sub_map = m_wallet->m_subaddresses;

      // Generate deterministic CSV but only return the requested slice.
      // We do this by streaming into a local buffer and skipping bytes until we
      // reach the desired region.
      const size_t start = static_cast<size_t>(chunk_index) *
                           static_cast<size_t>(chunk_size);
      const size_t end = start + static_cast<size_t>(chunk_size);

      std::string out;
      out.reserve(static_cast<size_t>(chunk_size));

      size_t pos = 0;
      bool first = true;

      auto maybe_append = [&](const std::string &s) {
        if (pos >= end) {
          return;
        }

        size_t s_begin = 0;
        size_t s_end = s.size();
        if (pos + s_end <= start) {
          pos += s_end;
          return;
        }

        if (pos < start) {
          s_begin = start - pos;
        }

        size_t remaining = end - std::max(pos, start);
        size_t take = std::min(remaining, s_end - s_begin);

        if (take > 0) {
          out.append(s.data() + s_begin, take);
        }

        pos += s_end;
      };

      auto emit_entry = [&](const std::string &entry) {
        if (!first) {
          maybe_append(",");
        }
        first = false;
        maybe_append(entry);
      };

      for (const auto &pair : ext_map) {
        int derive_type_int = static_cast<int>(pair.second.derive_type);
        if (derive_type_int < 0 || derive_type_int > 2) {
          derive_type_int = 1;
        }

        std::string entry;
        entry.reserve(80);
        entry += epee::string_tools::pod_to_hex(pair.first);
        entry += ':';
        entry += std::to_string(pair.second.index.major);
        entry += ':';
        entry += std::to_string(pair.second.index.minor);
        entry += ':';
        entry += std::to_string(derive_type_int);

        emit_entry(entry);

        if (pos >= end) {
          break;
        }
      }

      // Only if ext_map is empty, include legacy map entries.
      if (ext_map.empty() && pos < end) {
        for (const auto &pair : sub_map) {
          std::string entry;
          entry.reserve(80);
          entry += epee::string_tools::pod_to_hex(pair.first);
          entry += ':';
          entry += std::to_string(pair.second.major);
          entry += ':';
          entry += std::to_string(pair.second.minor);
          entry += ":1";

          emit_entry(entry);

          if (pos >= end) {
            break;
          }
        }
      }

      return out;
    } catch (...) {
      return "";
    }
  }

  // ========================================================================
  // ADD RETURN ADDRESSES - v4.5.0
  // Adds stake/audit return addresses to subaddress map for protocol_tx
  // detection. Workers don't process AUDIT/STAKE TXs that add return_address to
  // subaddr map, so we need to pre-populate from the server's stake cache.
  // Format: CSV of hex public keys - "aabbccdd...,eeff0011..."
  // ========================================================================
  int add_return_addresses(const std::string &return_addresses_csv) {
    if (!m_initialized) {
      return -1;
    }

    try {
      auto &account = m_wallet->get_account();
      const auto &subaddr_map = account.get_subaddress_map_cn();

      // Build entries to insert
      std::unordered_map<crypto::public_key, carrot::subaddress_index_extended>
          entries_to_insert;
      int count = 0;
      int skipped = 0;

      // Parse CSV: "aabbcc...,ddeeff..."
      size_t pos = 0;
      size_t next;

      while (pos < return_addresses_csv.size()) {
        next = return_addresses_csv.find(',', pos);
        if (next == std::string::npos)
          next = return_addresses_csv.size();

        std::string key_hex = return_addresses_csv.substr(pos, next - pos);
        pos = next + 1;

        // Skip empty entries
        if (key_hex.empty() || key_hex.size() != 64)
          continue;

        crypto::public_key pkey;
        if (epee::string_tools::hex_to_pod(key_hex, pkey)) {
          // Only add if not already present
          if (subaddr_map.find(pkey) == subaddr_map.end()) {
            carrot::subaddress_index_extended return_idx{
                .index = {0, 0},
                .derive_type = carrot::AddressDeriveType::PreCarrot,
                .is_return_spend_key = true};
            entries_to_insert[pkey] = return_idx;

            // Also add to wallet2::m_subaddresses for process_new_transaction
            m_wallet->m_subaddresses[pkey] = {0, 0};
            count++;
          } else {
            skipped++;
          }
        }
      }

      // Batch insert into account's internal map
      if (!entries_to_insert.empty()) {
        account.insert_subaddresses(entries_to_insert);
      }

      DEBUG_LOG("[WasmWallet] add_return_addresses: added %d, skipped %d "
                "(already present)\n",
                count, skipped);

      return count;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return -2;
    }
  }

  /**
   * Register return_output_info for Carrot-era STAKE TXs.
   *
   * For STAKE TXs after Carrot fork (HF10, height 334750), the protocol_tx
   * return detection requires return_output_info to be in return_output_map.
   * Normally this is populated when scanning the STAKE TX's change output. But
   * STAKE TXs without change (staking entire balance) have no output matching
   * our view tag, so they never get scanned during Phase 2.
   *
   * This function allows explicit registration of return info from STAKE TXs
   * found in the server's stake cache.
   *
   * CSV format (simpler than JSON, consistent with add_return_addresses):
   *   "tx_first_key_image:K_o:K_r,tx_first_key_image:K_o:K_r,..."
   *
   * Each entry is colon-separated:
   *   - tx_first_key_image: 64-char hex (first key_image from TX inputs, for
   * input_context)
   *   - K_o: 64-char hex (stake output key = P_change for no-change STAKE)
   *   - K_r: 64-char hex (return address from stake cache)
   *
   * Returns JSON: { "success": true, "registered": N, "skipped": M, "errors": E
   * }
   */
  std::string register_stake_return_info(const std::string &stakes_csv) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    try {
      auto &account = m_wallet->get_account();

      // FIX v5.50.0: Do NOT clear the return_output_map!
      // Phase 2 scanning adds entries with CORRECT key_images for STAKE txs
      // with change outputs. Clearing would wipe those out and replace them
      // with zero key_images, breaking spent detection for ~158k SAL worth
      // of stake returns.
      //
      // OLD BUG: account.return_output_map.clear();
      //
      // Instead, we only add entries that don't already exist. Entries from
      // Phase 2 have correct key_images; entries we add here have placeholders
      // but that's okay for no-change STAKE detection.

      // Get existing return_output_map to avoid overwriting valid entries
      const auto &existing_map = account.get_return_output_map_ref();

      std::unordered_map<crypto::public_key, carrot::return_output_info_t>
          new_entries;
      int registered = 0;
      int errors = 0;
      int skipped = 0;

      // Parse CSV: "ki:ko:kr,ki:ko:kr,..."
      size_t pos = 0;
      size_t next_comma;

      while (pos < stakes_csv.size()) {
        next_comma = stakes_csv.find(',', pos);
        if (next_comma == std::string::npos)
          next_comma = stakes_csv.size();

        std::string entry = stakes_csv.substr(pos, next_comma - pos);
        pos = next_comma + 1;

        // Skip empty entries
        if (entry.empty())
          continue;

        // Parse "ki:ko:kr"
        size_t colon1 = entry.find(':');
        size_t colon2 = (colon1 != std::string::npos)
                            ? entry.find(':', colon1 + 1)
                            : std::string::npos;

        if (colon1 == std::string::npos || colon2 == std::string::npos) {
          errors++;
          continue;
        }

        std::string ki_hex = entry.substr(0, colon1);
        std::string ko_hex = entry.substr(colon1 + 1, colon2 - colon1 - 1);
        std::string kr_hex = entry.substr(colon2 + 1);

        if (ki_hex.size() != 64 || ko_hex.size() != 64 || kr_hex.size() != 64) {
          errors++;
          continue;
        }

        // Parse hex strings
        crypto::key_image tx_first_ki;
        crypto::public_key K_o, K_r;

        if (!epee::string_tools::hex_to_pod(ki_hex, tx_first_ki) ||
            !epee::string_tools::hex_to_pod(ko_hex, K_o) ||
            !epee::string_tools::hex_to_pod(kr_hex, K_r)) {
          errors++;
          continue;
        }

        // Skip if already registered
        if (existing_map.find(K_r) != existing_map.end()) {
          skipped++;
          continue;
        }

        // Compute input_context from tx_first_key_image
        carrot::input_context_t input_context =
            carrot::make_carrot_input_context(tx_first_ki);

        // For STAKE TX without change, K_o (stake output) IS the P_change
        crypto::public_key K_change = K_o;

        // Compute k_return using s_view_balance
        crypto::secret_key k_return;
        account.s_view_balance_dev.make_internal_return_privkey(input_context,
                                                                K_o, k_return);

        // Compute K_return = k_return * G for verification
        crypto::public_key K_return_computed;
        crypto::secret_key_to_public_key(k_return, K_return_computed);

        // Verify: K_r should equal K_return + K_o
        crypto::public_key K_r_verify = rct::rct2pk(
            rct::addKeys(rct::pk2rct(K_return_computed), rct::pk2rct(K_o)));
        if (K_r_verify != K_r) {
          // If K_r does not verify against this wallet's s_view_balance key,
          // this stake does NOT belong to this wallet. Do not register it.
          skipped++;
          continue;
        }

        // SIMPLIFIED APPROACH: Store minimal info with placeholder values
        // scan_return_output only uses input_context, K_o, K_change - it
        // re-derives the rest The key_image, x, y are only needed when
        // spending, which we don't do (view-only)
        crypto::key_image placeholder_ki;
        memset(&placeholder_ki, 0, sizeof(placeholder_ki));
        crypto::secret_key placeholder_sum_g, placeholder_sender_extension_t;
        memset(&placeholder_sum_g, 0, sizeof(placeholder_sum_g));
        memset(&placeholder_sender_extension_t, 0,
               sizeof(placeholder_sender_extension_t));
        crypto::public_key placeholder_K_spend_pubkey;
        memset(&placeholder_K_spend_pubkey, 0,
               sizeof(placeholder_K_spend_pubkey));

        // Create return_output_info entry using v1.0.7 constructor signature
        carrot::return_output_info_t roi(
            input_context, K_o, K_change, placeholder_K_spend_pubkey,
            placeholder_ki, placeholder_sum_g, placeholder_sender_extension_t);

        new_entries[K_r] = roi;
        registered++;
      }

      // Batch insert
      if (!new_entries.empty()) {
        account.insert_return_output_info(new_entries);
      }

      DEBUG_LOG("[WasmWallet] register_stake_return_info: registered=%d, "
                "skipped=%d, errors=%d\n",
                registered, skipped, errors);

      std::ostringstream oss;
      oss << R"({"success":true,"registered":)" << registered
          << R"(,"skipped":)" << skipped << R"(,"errors":)" << errors << "}";
      return oss.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      std::ostringstream oss;
      oss << R"({"success":false,"error":")" << e.what() << R"("})";
      return oss.str();
    }
  }

  // ========================================================================
  // Key / Address Access
  // ========================================================================

  std::string get_address() const {
    if (!m_initialized)
      return "";
    try {
      return m_wallet->get_account().get_public_address_str(
          m_wallet->nettype());
    } catch (...) {
      return "";
    }
  }

  std::string get_secret_view_key() const {
    if (!m_initialized)
      return "";
    try {
      const auto &keys = m_wallet->get_account().get_keys();
      return key_to_hex((const unsigned char *)&keys.m_view_secret_key);
    } catch (...) {
      return "";
    }
  }

  std::string get_public_view_key() const {
    if (!m_initialized)
      return "";
    try {
      const auto &addr = m_wallet->get_account().get_keys().m_account_address;
      return epee::string_tools::pod_to_hex(addr.m_view_public_key);
    } catch (...) {
      return "";
    }
  }

  std::string get_public_spend_key() const {
    if (!m_initialized)
      return "";
    try {
      const auto &addr = m_wallet->get_account().get_keys().m_account_address;
      return epee::string_tools::pod_to_hex(addr.m_spend_public_key);
    } catch (...) {
      return "";
    }
  }

  std::string get_secret_spend_key() const {
    if (!m_initialized)
      return "";
    try {
      const auto &keys = m_wallet->get_account().get_keys();
      return key_to_hex((const unsigned char *)&keys.m_spend_secret_key);
    } catch (...) {
      return "";
    }
  }

  // ========================================================================
  // Carrot Keys (6 secret keys)
  // ========================================================================

  std::string get_carrot_s_master() const {
    if (!m_initialized)
      return "";
    try {
      const auto &keys = m_wallet->get_account().get_keys();
      return key_to_hex((const unsigned char *)&keys.s_master);
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_k_prove_spend() const {
    if (!m_initialized)
      return "";
    try {
      const auto &keys = m_wallet->get_account().get_keys();
      return key_to_hex((const unsigned char *)&keys.k_prove_spend);
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_s_view_balance() const {
    if (!m_initialized)
      return "";
    try {
      const auto &keys = m_wallet->get_account().get_keys();
      return key_to_hex((const unsigned char *)&keys.s_view_balance);
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_k_view_incoming() const {
    if (!m_initialized)
      return "";
    try {
      const auto &keys = m_wallet->get_account().get_keys();
      return key_to_hex((const unsigned char *)&keys.k_view_incoming);
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_k_generate_image() const {
    if (!m_initialized)
      return "";
    try {
      const auto &keys = m_wallet->get_account().get_keys();
      return key_to_hex((const unsigned char *)&keys.k_generate_image);
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_s_generate_address() const {
    if (!m_initialized)
      return "";
    try {
      const auto &keys = m_wallet->get_account().get_keys();
      return key_to_hex((const unsigned char *)&keys.s_generate_address);
    } catch (...) {
      return "";
    }
  }

  // ========================================================================
  // Carrot Addresses
  // ========================================================================

  std::string get_carrot_address() const {
    if (!m_initialized)
      return "";
    try {
      return m_wallet->get_account().get_carrot_public_address_str(
          m_wallet->nettype());
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_account_spend_pubkey() const {
    if (!m_initialized)
      return "";
    try {
      const auto &addr =
          m_wallet->get_account().get_keys().m_carrot_account_address;
      return epee::string_tools::pod_to_hex(addr.m_spend_public_key);
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_account_view_pubkey() const {
    if (!m_initialized)
      return "";
    try {
      const auto &addr =
          m_wallet->get_account().get_keys().m_carrot_account_address;
      return epee::string_tools::pod_to_hex(addr.m_view_public_key);
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_main_spend_pubkey() const {
    if (!m_initialized)
      return "";
    try {
      const auto &addr =
          m_wallet->get_account().get_keys().m_carrot_main_address;
      return epee::string_tools::pod_to_hex(addr.m_spend_public_key);
    } catch (...) {
      return "";
    }
  }

  std::string get_carrot_main_view_pubkey() const {
    if (!m_initialized)
      return "";
    try {
      const auto &addr =
          m_wallet->get_account().get_keys().m_carrot_main_address;
      return epee::string_tools::pod_to_hex(addr.m_view_public_key);
    } catch (...) {
      return "";
    }
  }

  std::string get_seed(const std::string &language) const {
    if (!m_initialized)
      return "";
    try {
      epee::wipeable_string seed;
      epee::wipeable_string passphrase; // Empty passphrase
      if (m_wallet->get_seed(seed, passphrase)) {
        return std::string(seed.data(), seed.size());
      }
      return "";
    } catch (...) {
      return "";
    }
  }

  // ========================================================================
  // Balance - returned as strings for JavaScript BigInt compatibility
  // ========================================================================

  // v5.47.2 FIX: Use balance_per_subaddress() instead of balance()
  // wallet2::balance() includes m_locked_coins which causes double-counting
  // when bulk-ingesting transactions (STAKE tx adds to m_locked_coins, but
  // YIELD tx doesn't properly remove it during out-of-order ingest).
  // JavaScript tracks stakes separately, so we don't need m_locked_coins.
  uint64_t get_balance_without_locked_coins(const std::string& asset_type) const {
    uint64_t total = 0;
    for (const auto &pair : m_wallet->balance_per_subaddress(0, asset_type, false)) {
      total += pair.second;
    }
    return total;
  }

  std::string get_balance() const {
    if (!m_initialized)
      return "0";
    try {
      // v5.47.2 FIX: Use balance_per_subaddress() sum to exclude m_locked_coins
      // which can be incorrect during out-of-order bulk ingest.
      uint64_t bal_sal = get_balance_without_locked_coins("SAL");
      uint64_t bal_sal1 = get_balance_without_locked_coins("SAL1");
      return std::to_string(bal_sal + bal_sal1);
    } catch (...) {
      return "0";
    }
  }

  std::string get_unlocked_balance() const {
    if (!m_initialized)
      return "0";
    try {
      // SAL (pre-hardfork) and SAL1 (post-hardfork) are the same currency
      uint64_t unlocked_sal = m_wallet->unlocked_balance(0, "SAL", false);
      uint64_t unlocked_sal1 = m_wallet->unlocked_balance(0, "SAL1", false);
      return std::to_string(unlocked_sal + unlocked_sal1);
    } catch (...) {
      return "0";
    }
  }

  // ========================================================================
  // Diagnostic - Comprehensive wallet state for debugging balance issues
  // ========================================================================

  std::string get_wallet_diagnostic() const {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized"})";
    }

    try {
      std::ostringstream oss;

      // Balance breakdown - use BOTH old (with locked_coins) and new (without)
      // to compare and verify the fix
      uint64_t bal_sal_old = m_wallet->balance(0, "SAL", false);
      uint64_t bal_sal1_old = m_wallet->balance(0, "SAL1", false);
      uint64_t bal_sal = get_balance_without_locked_coins("SAL");
      uint64_t bal_sal1 = get_balance_without_locked_coins("SAL1");
      uint64_t unlocked_sal = m_wallet->unlocked_balance(0, "SAL", false);
      uint64_t unlocked_sal1 = m_wallet->unlocked_balance(0, "SAL1", false);

      // Transfer details count
      size_t num_transfers = m_wallet->get_num_transfer_details();

      // Blockchain state
      uint64_t blockchain_height = m_wallet->get_blockchain_current_height();
      size_t m_blockchain_size = m_wallet->m_blockchain.size();

      // CRITICAL: Subaddress map diagnostics - this is key for CSP Phase 2!
      // wallet2 uses m_subaddresses map to detect outputs
      size_t subaddresses_map_size = m_wallet->m_subaddresses.size();
      size_t num_accounts = m_wallet->get_num_subaddress_accounts();
      size_t num_subaddr_account0 =
          (num_accounts > 0) ? m_wallet->get_num_subaddresses(0) : 0;

      // Note: carrot_and_legacy_account doesn't expose a get_subaddresses()
      // method The wallet2::m_subaddresses map is the canonical source for
      // subaddress lookup
      bool has_carrot_subaddresses = false;
      size_t carrot_subaddr_count = 0;
      // Subaddress info is already captured in subaddresses_map_size above

      // CRITICAL: Account subaddress map - this is what scanning ACTUALLY uses!
      // view_incoming_scan_transaction() calls account.get_subaddress_map_cn()
      size_t account_subaddr_map_size =
          m_wallet->get_account().get_subaddress_map_cn().size();

      // Get wallet's primary address (critical for verifying key derivation)
      std::string primary_address = m_wallet->get_address_as_str();

      // Get first subaddress from map to verify population
      std::string first_subaddr_hex = "";
      if (!m_wallet->m_subaddresses.empty()) {
        auto it = m_wallet->m_subaddresses.begin();
        const crypto::public_key &pk = it->first;
        first_subaddr_hex = epee::string_tools::pod_to_hex(pk);
      }

      // Get account public spend key
      const auto &account_keys = m_wallet->get_account().get_keys();
      std::string pub_spend_key = epee::string_tools::pod_to_hex(
          account_keys.m_account_address.m_spend_public_key);
      std::string pub_view_key = epee::string_tools::pod_to_hex(
          account_keys.m_account_address.m_view_public_key);

      // Get per-subaddress info to understand transfer breakdown
      // Count transfers by type using transfer_details
      size_t miner_tx_count = 0;
      size_t user_tx_count = 0;
      size_t protocol_tx_count = 0; // Yield/staking rewards
      uint64_t total_amount = 0;
      uint64_t spent_amount = 0;
      size_t spent_count = 0;
      
      // v5.47.1: Track asset type breakdown to debug balance discrepancy
      uint64_t sal_total = 0, sal_spent = 0, sal_unspent = 0;
      uint64_t sal1_total = 0, sal1_spent = 0, sal1_unspent = 0;
      size_t sal_count = 0, sal1_count = 0, other_count = 0;
      
      // v5.47.3: Track key_image_known status to debug spent detection gap
      size_t ki_known_count = 0, ki_unknown_count = 0;
      size_t ki_known_unspent = 0, ki_unknown_unspent = 0;
      uint64_t ki_unknown_unspent_amount = 0; // SAL value of outputs without key images (can't detect spent)

      // Iterate through transfer_details (outputs belonging to wallet)
      // We need to count them ourselves since wallet2 doesn't expose this
      // directly Use the transfers vector
      const auto &transfers = m_wallet->m_transfers;
      for (size_t i = 0; i < transfers.size(); ++i) {
        const auto &td = transfers[i];
        total_amount += td.m_amount;
        
        // v5.47.3: Track key_image_known
        if (td.m_key_image_known) {
          ki_known_count++;
          if (!td.m_spent) ki_known_unspent++;
        } else {
          ki_unknown_count++;
          if (!td.m_spent) {
            ki_unknown_unspent++;
            ki_unknown_unspent_amount += td.m_amount;
          }
        }
        
        // Track by asset type (field is 'asset_type' not 'm_asset_type')
        const std::string &asset = td.asset_type;
        if (asset == "SAL") {
          sal_total += td.m_amount;
          sal_count++;
          if (td.m_spent) sal_spent += td.m_amount;
          else sal_unspent += td.m_amount;
        } else if (asset == "SAL1") {
          sal1_total += td.m_amount;
          sal1_count++;
          if (td.m_spent) sal1_spent += td.m_amount;
          else sal1_unspent += td.m_amount;
        } else {
          other_count++;
        }

        if (td.m_spent) {
          spent_amount += td.m_amount;
          spent_count++;
        }

        // Check if it's a coinbase (miner) transaction
        if (td.m_tx.vin.size() == 1 &&
            td.m_tx.vin[0].type() == typeid(cryptonote::txin_gen)) {
          miner_tx_count++;
        } else {
          user_tx_count++;
        }
      }

      oss << "{"
          << "\"balance_sal\":\"" << bal_sal << "\","
          << "\"balance_sal1\":\"" << bal_sal1 << "\","
          << "\"balance_total\":\"" << (bal_sal + bal_sal1) << "\","
          // v5.47.2: Also show OLD balance (with locked_coins) for comparison
          << "\"balance_sal_old\":\"" << bal_sal_old << "\","
          << "\"balance_sal1_old\":\"" << bal_sal1_old << "\","
          << "\"balance_total_old\":\"" << (bal_sal_old + bal_sal1_old) << "\","
          << "\"unlocked_sal\":\"" << unlocked_sal << "\","
          << "\"unlocked_sal1\":\"" << unlocked_sal1 << "\","
          << "\"unlocked_total\":\"" << (unlocked_sal + unlocked_sal1) << "\","
          << "\"num_transfers\":" << num_transfers << ","
          << "\"transfers_count\":" << transfers.size() << ","
          << "\"miner_tx_outputs\":" << miner_tx_count << ","
          << "\"user_tx_outputs\":" << user_tx_count << ","
          << "\"total_received_atomic\":\"" << total_amount << "\","
          << "\"spent_amount_atomic\":\"" << spent_amount << "\","
          << "\"spent_output_count\":" << spent_count << ","
          // v5.47.3: Key image tracking - explains why spent detection fails
          << "\"ki_known_count\":" << ki_known_count << ","
          << "\"ki_unknown_count\":" << ki_unknown_count << ","
          << "\"ki_known_unspent\":" << ki_known_unspent << ","
          << "\"ki_unknown_unspent\":" << ki_unknown_unspent << ","
          << "\"ki_unknown_unspent_amount\":\"" << ki_unknown_unspent_amount << "\","
          // v5.47.1: Asset type breakdown
          << "\"sal_outputs\":" << sal_count << ","
          << "\"sal_total\":\"" << sal_total << "\","
          << "\"sal_spent\":\"" << sal_spent << "\","
          << "\"sal_unspent\":\"" << sal_unspent << "\","
          << "\"sal1_outputs\":" << sal1_count << ","
          << "\"sal1_total\":\"" << sal1_total << "\","
          << "\"sal1_spent\":\"" << sal1_spent << "\","
          << "\"sal1_unspent\":\"" << sal1_unspent << "\","
          << "\"other_asset_outputs\":" << other_count << ","
          << "\"blockchain_height\":" << blockchain_height << ","
          << "\"m_blockchain_size\":" << m_blockchain_size << ","
          << "\"is_initialized\":" << (m_initialized ? "true" : "false")
          << ","
          // SUBADDRESS DIAGNOSTICS (critical for CSP Phase 2)
          << "\"subaddresses_map_size\":" << subaddresses_map_size << ","
          << "\"account_subaddr_map_size\":" << account_subaddr_map_size
          << "," // THE ONE THAT MATTERS!
          << "\"num_accounts\":" << num_accounts << ","
          << "\"num_subaddr_account0\":" << num_subaddr_account0 << ","
          << "\"has_carrot_subaddresses\":"
          << (has_carrot_subaddresses ? "true" : "false") << ","
          << "\"carrot_subaddr_count\":" << carrot_subaddr_count
          << ","
          // KEY DIAGNOSTICS (verify key derivation)
          << "\"primary_address\":\"" << primary_address << "\","
          << "\"pub_spend_key\":\"" << pub_spend_key << "\","
          << "\"pub_view_key\":\"" << pub_view_key << "\","
          << "\"first_subaddr_pubkey\":\"" << first_subaddr_hex << "\",";

      // CRITICAL CHECK: Is the main spend key in the account subaddress map?
      const auto &acct_subaddr_map =
          m_wallet->get_account().get_subaddress_map_cn();
      bool main_spend_key_in_map =
          (acct_subaddr_map.find(
               account_keys.m_account_address.m_spend_public_key) !=
           acct_subaddr_map.end());

      // Also check Carrot main address
      bool carrot_spend_key_in_map =
          (acct_subaddr_map.find(
               account_keys.m_carrot_account_address.m_spend_public_key) !=
           acct_subaddr_map.end());

      // v5.47.1: m_locked_coins diagnostic - THIS IS LIKELY THE BUG!
      // When bulk-ingesting TXs, locked_coins doesn't get erased properly
      uint64_t locked_coins_total = 0;
      size_t locked_coins_count = m_wallet->m_locked_coins.size();
      for (const auto &lc : m_wallet->m_locked_coins) {
        locked_coins_total += lc.second.m_amount;
      }

      // Also compute what balance SHOULD be without locked_coins
      uint64_t manual_balance_sal = sal_unspent;   // From m_transfers iteration
      uint64_t manual_balance_sal1 = sal1_unspent; // From m_transfers iteration
      uint64_t manual_balance_total = manual_balance_sal + manual_balance_sal1;

      oss << "\"main_spend_key_in_map\":"
          << (main_spend_key_in_map ? "true" : "false") << ","
          << "\"carrot_spend_key_in_map\":"
          << (carrot_spend_key_in_map ? "true" : "false") << ","
          // v5.47.1: Locked coins info
          << "\"locked_coins_count\":" << locked_coins_count << ","
          << "\"locked_coins_total\":\"" << locked_coins_total << "\","
          // Manual balance (without locked_coins)
          << "\"manual_balance_sal\":\"" << manual_balance_sal << "\","
          << "\"manual_balance_sal1\":\"" << manual_balance_sal1 << "\","
          << "\"manual_balance_total\":\"" << manual_balance_total << "\""
          << "}";

      return oss.str();
    } catch (const std::exception &e) {
      return "{\"error\":\"" + std::string(e.what()) + "\"}";
    } catch (...) {
      return R"({"error":"Unknown error getting diagnostic"})";
    }
  }

  // ========================================================================
  // Key Image Tracking - For spent detection
  // ========================================================================

  /**
   * Get key images for all owned outputs.
   * Returns JSON array of {tx_hash, output_index, key_image, amount, spent,
   * key_image_known} This is used to track spent status of our outputs.
   */
  std::string get_key_images() const {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized","key_images":[]})";
    }
    try {
      std::ostringstream oss;
      oss << "{\"key_images\":[";

      const auto &transfers = m_wallet->m_transfers;
      bool first = true;
      size_t known_count = 0;
      size_t unknown_count = 0;

      for (size_t i = 0; i < transfers.size(); ++i) {
        const auto &td = transfers[i];

        if (!first)
          oss << ",";
        first = false;

        oss << "{"
            << "\"index\":" << i << ","
            << "\"tx_hash\":\"" << epee::string_tools::pod_to_hex(td.m_txid)
            << "\","
            << "\"output_index\":" << td.m_internal_output_index << ","
            << "\"global_index\":" << td.m_global_output_index << ","
            << "\"amount\":\"" << td.m_amount << "\","
            << "\"spent\":" << (td.m_spent ? "true" : "false") << ","
            << "\"spent_height\":" << td.m_spent_height << ","
            << "\"key_image_known\":"
            << (td.m_key_image_known ? "true" : "false") << ",";

        if (td.m_key_image_known) {
          oss << "\"key_image\":\""
              << epee::string_tools::pod_to_hex(td.m_key_image) << "\"";
          known_count++;
        } else {
          oss << "\"key_image\":null";
          unknown_count++;
        }
        oss << "}";
      }

      oss << "],\"total\":" << transfers.size()
          << ",\"key_images_known\":" << known_count
          << ",\"key_images_unknown\":" << unknown_count
          << ",\"m_key_images_map_size\":" << m_wallet->m_key_images.size()
          << "}";

      return oss.str();
    } catch (const std::exception &e) {
      return std::string("{\"error\":\"") + e.what() + "\",\"key_images\":[]}";
    }
  }

  /**
   * CSP v6: Get key images as comma-separated hex string for spent detection.
   * Only returns key images for UNSPENT outputs (no point checking
   * already-spent ones). This format is suitable for passing to
   * scan_csp_batch_with_spent().
   *
   * @return Comma-separated 64-char hex key images (e.g.,
   * "aabb...cc,ddeeff...00")
   */
  // NOTE: Returning large strings via embind can trap on some runtimes.
  // Prefer using the chunked API from JS when available.
  std::string get_key_images_csv() const {
    if (!m_initialized) {
      return "";
    }
    try {
      std::ostringstream oss;
      bool first = true;

      const auto &transfers = m_wallet->m_transfers;
      for (size_t i = 0; i < transfers.size(); ++i) {
        const auto &td = transfers[i];

        // Only include known key images for unspent outputs
        if (td.m_key_image_known && !td.m_spent) {
          if (!first)
            oss << ",";
          first = false;
          oss << epee::string_tools::pod_to_hex(td.m_key_image);
        }
      }

      return oss.str();
    } catch (...) {
      return "";
    }
  }

  int get_key_images_csv_len() const {
    if (!m_initialized || !m_wallet) {
      return 0;
    }

    try {
      const auto &transfers = m_wallet->m_transfers;

      size_t count = 0;
      for (size_t i = 0; i < transfers.size(); ++i) {
        const auto &td = transfers[i];
        if (td.m_key_image_known && !td.m_spent) {
          count++;
        }
      }

      size_t approx = count == 0 ? 0 : (count * 64) + (count - 1);

      if (approx > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
      }
      return static_cast<int>(approx);
    } catch (...) {
      return 0;
    }
  }

  std::string get_key_images_csv_prefix(int max_chars) const {
    if (!m_initialized || !m_wallet || max_chars <= 0) {
      return "";
    }

    try {
      const auto &transfers = m_wallet->m_transfers;
      size_t total = transfers.size();

      std::string out;
      out.reserve(static_cast<size_t>(std::min(max_chars, 1024)));

      out += "transfers=";
      out += std::to_string(total);
      out += "|";

      int added = 0;
      for (size_t i = 0; i < transfers.size() && added < 5; ++i) {
        const auto &td = transfers[i];
        if (!(td.m_key_image_known && !td.m_spent)) {
          continue;
        }

        if (added > 0)
          out += ',';
        out += epee::string_tools::pod_to_hex(td.m_key_image);
        added++;

        if (static_cast<int>(out.size()) >= max_chars) {
          break;
        }
      }

      if (static_cast<int>(out.size()) > max_chars) {
        out.resize(static_cast<size_t>(max_chars));
      }
      return out;
    } catch (...) {
      return "";
    }
  }

  int get_key_images_csv_chunk_count(int chunk_size) const {
    if (!m_initialized || !m_wallet || chunk_size <= 0) {
      return 0;
    }

    int approx_len = get_key_images_csv_len();
    if (approx_len <= 0) {
      return 0;
    }

    int count = (approx_len + chunk_size - 1) / chunk_size;
    if (count < 1)
      count = 1;
    return count;
  }

  std::string get_key_images_csv_chunk(int chunk_index, int chunk_size) const {
    if (!m_initialized || !m_wallet || chunk_size <= 0 || chunk_index < 0) {
      return "";
    }

    try {
      const auto &transfers = m_wallet->m_transfers;

      const size_t start = static_cast<size_t>(chunk_index) *
                           static_cast<size_t>(chunk_size);
      const size_t end = start + static_cast<size_t>(chunk_size);

      std::string out;
      out.reserve(static_cast<size_t>(chunk_size));

      size_t pos = 0;
      bool first = true;

      auto maybe_append = [&](const std::string &s) {
        if (pos >= end) {
          return;
        }

        size_t s_begin = 0;
        size_t s_end = s.size();
        if (pos + s_end <= start) {
          pos += s_end;
          return;
        }

        if (pos < start) {
          s_begin = start - pos;
        }

        size_t remaining = end - std::max(pos, start);
        size_t take = std::min(remaining, s_end - s_begin);

        if (take > 0) {
          out.append(s.data() + s_begin, take);
        }

        pos += s_end;
      };

      auto emit_entry = [&](const std::string &entry) {
        if (!first) {
          maybe_append(",");
        }
        first = false;
        maybe_append(entry);
      };

      for (size_t i = 0; i < transfers.size(); ++i) {
        const auto &td = transfers[i];

        if (!(td.m_key_image_known && !td.m_spent)) {
          continue;
        }

        emit_entry(epee::string_tools::pod_to_hex(td.m_key_image));

        if (pos >= end) {
          break;
        }
      }

      return out;
    } catch (...) {
      return "";
    }
  }

  // Returns CSV: "ki:height,ki:height,..." for spent outputs only.
  std::string get_spent_key_images_csv() const {
    if (!m_initialized || !m_wallet) {
      return "";
    }

    try {
      std::ostringstream oss;
      bool first = true;

      const auto &transfers = m_wallet->m_transfers;
      for (size_t i = 0; i < transfers.size(); ++i) {
        const auto &td = transfers[i];

        if (!(td.m_key_image_known && td.m_spent)) {
          continue;
        }

        if (!first)
          oss << ",";
        first = false;

        oss << epee::string_tools::pod_to_hex(td.m_key_image) << ":"
            << td.m_spent_height;
      }

      return oss.str();
    } catch (...) {
      return "";
    }
  }

  int get_spent_key_images_csv_len() const {
    if (!m_initialized || !m_wallet) {
      return 0;
    }

    try {
      const auto &transfers = m_wallet->m_transfers;

      size_t count = 0;
      for (size_t i = 0; i < transfers.size(); ++i) {
        const auto &td = transfers[i];
        if (td.m_key_image_known && td.m_spent) {
          count++;
        }
      }

      size_t approx = 0;
      if (count > 0) {
        // 64 hex + ':' + ~10 digits + commas.
        approx = (count * (64 + 1 + 10)) + (count - 1);
      }

      if (approx > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
      }
      return static_cast<int>(approx);
    } catch (...) {
      return 0;
    }
  }

  int get_spent_key_images_csv_chunk_count(int chunk_size) const {
    if (!m_initialized || !m_wallet || chunk_size <= 0) {
      return 0;
    }

    int approx_len = get_spent_key_images_csv_len();
    if (approx_len <= 0) {
      return 0;
    }

    int count = (approx_len + chunk_size - 1) / chunk_size;
    if (count < 1)
      count = 1;
    return count;
  }

  std::string get_spent_key_images_csv_chunk(int chunk_index,
                                            int chunk_size) const {
    if (!m_initialized || !m_wallet || chunk_size <= 0 || chunk_index < 0) {
      return "";
    }

    try {
      const auto &transfers = m_wallet->m_transfers;

      const size_t start = static_cast<size_t>(chunk_index) *
                           static_cast<size_t>(chunk_size);
      const size_t end = start + static_cast<size_t>(chunk_size);

      std::string out;
      out.reserve(static_cast<size_t>(chunk_size));

      size_t pos = 0;
      bool first = true;

      auto maybe_append = [&](const std::string &s) {
        if (pos >= end) {
          return;
        }

        size_t s_begin = 0;
        size_t s_end = s.size();
        if (pos + s_end <= start) {
          pos += s_end;
          return;
        }

        if (pos < start) {
          s_begin = start - pos;
        }

        size_t remaining = end - std::max(pos, start);
        size_t take = std::min(remaining, s_end - s_begin);

        if (take > 0) {
          out.append(s.data() + s_begin, take);
        }

        pos += s_end;
      };

      auto emit_entry = [&](const std::string &entry) {
        if (!first) {
          maybe_append(",");
        }
        first = false;
        maybe_append(entry);
      };

      for (size_t i = 0; i < transfers.size(); ++i) {
        const auto &td = transfers[i];

        if (!(td.m_key_image_known && td.m_spent)) {
          continue;
        }

        const std::string entry =
            epee::string_tools::pod_to_hex(td.m_key_image) + ":" +
            std::to_string(td.m_spent_height);
        emit_entry(entry);

        if (pos >= end) {
          break;
        }
      }

      return out;
    } catch (...) {
      return "";
    }
  }

  // ========================================================================
  // RETURN ADDRESS EXPORT - For detecting incoming RETURN transactions
  // ========================================================================
  /**
   * Get all return addresses from the return_output_map as CSV.
   *
   * When we send a TRANSFER transaction, we embed our return address in it.
   * If the recipient creates a RETURN transaction to send funds back, the
   * output is sent to our return address. The CSP scanner needs to know
   * these return addresses to detect incoming RETURN transactions.
   *
   * Format: "pubkey1,pubkey2,..." (64-char hex public keys)
   * These are the K_r values from return_output_map.
   *
   * @return CSV of return address public keys
   */
  std::string get_return_addresses_csv() const {
    if (!m_initialized || !m_wallet) {
      return "";
    }

    try {
      auto &account = m_wallet->get_account();
      const auto &return_map = account.get_return_output_map_ref();

      if (return_map.empty()) {
        return "";
      }

      std::ostringstream oss;
      bool first = true;

      for (const auto &entry : return_map) {
        // entry.first is the K_r (return pubkey)
        if (!first) {
          oss << ",";
        }
        first = false;
        oss << epee::string_tools::pod_to_hex(entry.first);
      }

      return oss.str();
    } catch (const std::exception &e) {
      DEBUG_LOG("[WasmWallet] get_return_addresses_csv exception: %s\n", e.what());
      return "";
    } catch (...) {
      return "";
    }
  }

  /**
   * Check if any of our key images appear in the given transaction inputs.
   * This is used to detect if a transaction spends our outputs.
   *
   * @param tx_blob_hex - Hex-encoded transaction blob
   * @return JSON with match info: {matched: bool, spent_outputs: [{key_image,
   * amount, index}]}
   */
  std::string check_tx_spends_our_outputs(const std::string &tx_blob_hex) {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized","matched":false})";
    }
    try {
      // Parse transaction
      std::string tx_blob;
      if (!epee::string_tools::parse_hexstr_to_binbuff(tx_blob_hex, tx_blob)) {
        return R"({"error":"Failed to parse hex","matched":false})";
      }

      cryptonote::transaction tx;
      crypto::hash tx_hash, tx_prefix_hash;
      if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash,
                                                       tx_prefix_hash)) {
        return R"({"error":"Failed to parse tx","matched":false})";
      }

      std::ostringstream oss;
      oss << "{\"tx_hash\":\"" << epee::string_tools::pod_to_hex(tx_hash)
          << "\","
          << "\"spent_outputs\":[";

      bool first = true;
      size_t match_count = 0;

      // Check each input against our key_images map
      for (const auto &in : tx.vin) {
        if (in.type() != typeid(cryptonote::txin_to_key))
          continue;

        const cryptonote::txin_to_key &in_to_key =
            boost::get<cryptonote::txin_to_key>(in);

        // Look up in m_key_images map
        auto it = m_wallet->m_key_images.find(in_to_key.k_image);
        if (it != m_wallet->m_key_images.end()) {
          // Found a match! This tx spends one of our outputs
          const auto &td = m_wallet->m_transfers[it->second];

          if (!first)
            oss << ",";
          first = false;

          oss << "{"
              << "\"key_image\":\""
              << epee::string_tools::pod_to_hex(in_to_key.k_image) << "\","
              << "\"transfer_index\":" << it->second << ","
              << "\"amount\":\"" << td.m_amount << "\","
              << "\"was_already_spent\":" << (td.m_spent ? "true" : "false")
              << "}";
          match_count++;
        }
      }

      oss << "],\"matched\":" << (match_count > 0 ? "true" : "false")
          << ",\"match_count\":" << match_count
          << ",\"input_count\":" << tx.vin.size() << "}";

      return oss.str();
    } catch (const std::exception &e) {
      return std::string("{\"error\":\"") + e.what() + "\",\"matched\":false}";
    }
  }

  /**
   * Mark outputs as spent by processing a transaction's inputs.
   * Call this for transactions that spend our outputs but weren't scanned
   * normally.
   *
   * @param tx_blob_hex - Hex-encoded transaction blob
   * @param block_height - Block height where this tx was confirmed
   * @return JSON with results
   */
  std::string process_spent_outputs(const std::string &tx_blob_hex,
                                    uint64_t block_height) {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized","processed":false})";
    }
    try {
      // Parse transaction
      std::string tx_blob;
      if (!epee::string_tools::parse_hexstr_to_binbuff(tx_blob_hex, tx_blob)) {
        return R"({"error":"Failed to parse hex","processed":false})";
      }

      cryptonote::transaction tx;
      crypto::hash tx_hash, tx_prefix_hash;
      if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash,
                                                       tx_prefix_hash)) {
        return R"({"error":"Failed to parse tx","processed":false})";
      }

      std::ostringstream oss;
      size_t marked_spent = 0;

      // Check each input against our key_images map and mark as spent
      for (const auto &in : tx.vin) {
        if (in.type() != typeid(cryptonote::txin_to_key))
          continue;

        const cryptonote::txin_to_key &in_to_key =
            boost::get<cryptonote::txin_to_key>(in);

        auto it = m_wallet->m_key_images.find(in_to_key.k_image);
        if (it != m_wallet->m_key_images.end()) {
          auto &td = m_wallet->m_transfers[it->second];
          if (!td.m_spent) {
            td.m_spent = true;
            td.m_spent_height = block_height;
            marked_spent++;
          }
        }
      }

      oss << "{\"processed\":true"
          << ",\"tx_hash\":\"" << epee::string_tools::pod_to_hex(tx_hash)
          << "\""
          << ",\"outputs_marked_spent\":" << marked_spent
          << ",\"block_height\":" << block_height << "}";

      return oss.str();
    } catch (const std::exception &e) {
      return std::string("{\"error\":\"") + e.what() +
             "\",\"processed\":false}";
    }
  }

  /**
   * Mark outputs as spent directly by key image list.
   * This is the most efficient way to mark spent outputs when we know
   * the key images from a spent index lookup (Phase 1b).
   *
   * Format: "ki1:height1,ki2:height2,..." where ki is 64-char hex key image
   *
   * @param spent_csv - Comma-separated "keyimage:height" pairs
   * @return JSON with count of marked spent outputs
   */
  std::string mark_spent_by_key_images(const std::string &spent_csv) {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized","marked":0})";
    }

    if (spent_csv.empty()) {
      return R"({"marked":0,"skipped":0,"not_found":0})";
    }

    try {
      size_t marked = 0;
      size_t skipped = 0;
      size_t not_found = 0;

      // Parse CSV: "ki1:height1,ki2:height2,..."
      std::istringstream stream(spent_csv);
      std::string item;

      while (std::getline(stream, item, ',')) {
        if (item.empty())
          continue;

        // Find the colon separator between key_image and height
        size_t colon_pos = item.find(':');
        if (colon_pos == std::string::npos || colon_pos != 64) {
          // Invalid format, skip
          continue;
        }

        std::string ki_hex = item.substr(0, 64);
        uint64_t height = 0;
        try {
          height = std::stoull(item.substr(65));
        } catch (...) {
          continue; // Invalid height
        }

        // Parse key image from hex
        crypto::key_image ki;
        if (!epee::string_tools::hex_to_pod(ki_hex, ki)) {
          continue; // Invalid hex
        }

        // Look up in m_key_images map
        auto it = m_wallet->m_key_images.find(ki);
        if (it != m_wallet->m_key_images.end()) {
          auto &td = m_wallet->m_transfers[it->second];
          if (!td.m_spent) {
            td.m_spent = true;
            td.m_spent_height = height;
            marked++;
          } else {
            skipped++; // Already spent
          }
        } else {
          not_found++; // Key image not in our transfers
        }
      }

      std::ostringstream oss;
      oss << "{\"marked\":" << marked << ",\"skipped\":" << skipped
          << ",\"not_found\":" << not_found << "}";

      return oss.str();
    } catch (const std::exception &e) {
      return std::string("{\"error\":\"") + e.what() + "\",\"marked\":0}";
    }
  }

  // ========================================================================
  // Transaction Scanning (Manual)
  // ========================================================================

  bool scan_tx(const std::string &tx_blob_hex) {
    if (!m_initialized) {
      m_last_error = "Wallet not initialized";
      return false;
    }

    try {
      // Parse transaction blob
      std::string tx_blob;
      if (!epee::string_tools::parse_hexstr_to_binbuff(tx_blob_hex, tx_blob)) {
        m_last_error = "Failed to parse transaction hex";
        return false;
      }

      cryptonote::transaction tx;
      crypto::hash tx_hash, tx_prefix_hash;
      if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash,
                                                       tx_prefix_hash)) {
        m_last_error = "Failed to parse transaction";
        return false;
      }

      // Scan transaction for mempool detection
      // Note: We don't have block height/timestamp here, so we use 0
      // Set is_pool=true since these are unconfirmed mempool transactions
      std::vector<uint64_t> tx_o_indices;
      std::vector<uint64_t> tx_asset_indices;

      m_wallet->process_new_transaction(tx_hash, tx, tx_o_indices,
                                        tx_asset_indices,
                                        0,     // height
                                        0,     // version
                                        0,     // timestamp
                                        false, // is_miner_tx
                                        true,  // is_pool - TRUE for mempool txs!
                                        false, // double_spend_seen
                                        true // ignore_callbacks - MUST be true
                                             // in WASM to prevent callback trap
      );

      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  std::string get_mempool_tx_info(const std::string &tx_blob_hex) {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized"})";
    }
    try {
      std::string tx_blob;
      if (!epee::string_tools::parse_hexstr_to_binbuff(tx_blob_hex, tx_blob)) {
        return R"({"error":"Failed to parse hex"})";
      }
      cryptonote::transaction tx;
      crypto::hash tx_hash, tx_prefix_hash;
      if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash,
                                                       tx_prefix_hash)) {
        return R"({"error":"Failed to parse tx"})";
      }

      uint64_t amount = 0;
      uint64_t fee = 0;
      bool is_incoming = false;
      std::string asset_type = "SAL";
      uint64_t timestamp = 0;

      if (m_wallet->get_unconfirmed_tx_info(tx_hash, amount, fee, is_incoming,
                                            asset_type, timestamp)) {
        std::ostringstream oss;
        oss << "{"
            << "\"amount\":" << amount << ","
            << "\"fee\":" << fee << ","
            << "\"is_incoming\":" << (is_incoming ? "true" : "false") << ","
            << "\"asset_type\":\"" << asset_type << "\","
            << "\"timestamp\":" << timestamp << "}";
        return oss.str();
      } else {
        return R"({"error":"Transaction not found in wallet"})";
      }
    } catch (const std::exception &e) {
      std::ostringstream oss;
      oss << R"({"error":")" << e.what() << R"("})";
      return oss.str();
    }
  }

  // ========================================================================
  // Daemon Connection
  // ========================================================================

  bool set_daemon(const std::string &address) {
    try {
      m_daemon_address = address;
      // Note: In WASM, actual daemon connection happens via JavaScript
      // fetch/XHR This just stores the address for use by the RPC proxy
      m_wallet->set_daemon(address);
      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  std::string get_daemon_address() const { return m_daemon_address; }

  bool init_daemon(const std::string &address) {
    try {
      m_daemon_address = address.empty() ? "seed01.salvium.io:19081" : address;

      // Initialize wallet with daemon
      // In WASM, the actual HTTP calls will be proxied through JavaScript
      boost::optional<epee::net_utils::http::login> daemon_login;
      m_wallet->init(m_daemon_address, daemon_login, {}, 0, true,
                     epee::net_utils::ssl_support_t::e_ssl_support_autodetect);

      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // ========================================================================
  // Sync Status - returned as strings for JavaScript BigInt compatibility
  // ========================================================================

  std::string get_blockchain_height() const {
    if (!m_initialized)
      return "0";
    try {
      std::string error;
      uint64_t height = m_wallet->get_daemon_blockchain_height(error);
      if (!error.empty()) {
        return "0";
      }
      return std::to_string(height);
    } catch (...) {
      return "0";
    }
  }

  std::string get_wallet_height() const {
    if (!m_initialized)
      return "0";
    try {
      return std::to_string(m_wallet->get_blockchain_current_height());
    } catch (...) {
      return "0";
    }
  }

  bool refresh() {
    if (!m_initialized) {
      m_last_error = "Wallet not initialized";
      return false;
    }
    try {
      m_wallet->refresh(m_wallet->is_trusted_daemon());
      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // ========================================================================
  // Block Scanning - Manual control for WASM environment
  // ========================================================================

  // Get the short chain history (block hashes) for building a getblocks request
  // Returns JSON with offset, genesis hash, and recent block hashes
  // Uses export_blockchain() which is public (get_short_chain_history is
  // private)
  std::string get_short_chain_history_json() const {
    if (!m_initialized) {
      return R"({"offset":0,"genesis":"","block_ids":[]})";
    }
    try {
      // export_blockchain returns tuple<size_t offset, crypto::hash genesis,
      // std::vector<crypto::hash> hashes>
      auto [offset, genesis, hashes] = m_wallet->export_blockchain();

      std::ostringstream oss;
      oss << "{";
      oss << "\"offset\":" << offset << ",";
      oss << "\"genesis\":\"" << epee::string_tools::pod_to_hex(genesis)
          << "\",";
      oss << "\"height\":" << (offset + hashes.size()) << ",";
      oss << "\"block_ids\":[";

      // Build short chain history similar to get_short_chain_history():
      // Include recent blocks at different intervals for efficient sync
      // Pattern: last 20 blocks, then exponentially spaced
      std::vector<size_t> indices_to_include;
      size_t n = hashes.size();

      // Add last 20 blocks
      for (size_t i = 0; i < std::min((size_t)20, n); ++i) {
        indices_to_include.push_back(n - 1 - i);
      }
      // Add exponentially spaced older blocks
      size_t step = 1;
      for (size_t i = 20; i < n; i += step) {
        indices_to_include.push_back(n - 1 - i);
        step *= 2;
      }
      // Always include first block
      if (n > 0) {
        indices_to_include.push_back(0);
      }

      // Remove duplicates and sort
      std::sort(indices_to_include.begin(), indices_to_include.end());
      indices_to_include.erase(
          std::unique(indices_to_include.begin(), indices_to_include.end()),
          indices_to_include.end());

      bool first = true;
      for (size_t idx : indices_to_include) {
        if (idx < n) {
          if (!first)
            oss << ",";
          first = false;
          oss << "\"" << epee::string_tools::pod_to_hex(hashes[idx]) << "\"";
        }
      }

      oss << "]}";
      return oss.str();
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return R"({"offset":0,"genesis":"","block_ids":[],"error":")" +
             std::string(e.what()) + "\"}";
    }
  }

  // Get the wallet's current refresh start height
  double get_refresh_start_height() const {
    if (!m_initialized)
      return 0;
    try {
      return static_cast<double>(m_wallet->get_refresh_from_block_height());
    } catch (...) {
      return 0;
    }
  }

  // Set the wallet's refresh start height (for restore)
  bool set_refresh_start_height(double height) {
    if (!m_initialized) {
      m_last_error = "Wallet not initialized";
      return false;
    }
    try {
      m_wallet->set_refresh_from_block_height(static_cast<uint64_t>(height));
      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // Process a batch of blocks from raw daemon binary response
  // ?????? ACTUAL SCANNING: Now calls process_new_transaction thanks to
  // private=public hack JavaScript manages sync state, C++ processes binary and
  // SCANS for outputs Input: raw binary response from daemon's /getblocks.bin
  // endpoint Returns JSON with scan results including outputs found
  //
  // v1.6.0: Added timing diagnostics to measure parse vs scan time
  std::string ingest_blocks_binary(const std::string &binary_data) {
    using namespace std::chrono;
    auto total_start = high_resolution_clock::now();

    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    if (binary_data.empty()) {
      return R"({"success":false,"error":"Empty binary data"})";
    }

    // Validate input size
    if (binary_data.size() < 10) {
      std::ostringstream oss;
      oss << "{\"success\":false,\"error\":\"Binary data too small: "
          << binary_data.size() << " bytes\"}";
      return oss.str();
    }

    // Check for epee portable storage signature (0x01 0x11 0x01 0x01 0x01 0x01
    // 0x02 0x01)
    const unsigned char *data =
        reinterpret_cast<const unsigned char *>(binary_data.data());
    bool has_epee_header = (data[0] == 0x01 && data[1] == 0x11 &&
                            data[2] == 0x01 && data[3] == 0x01);

    std::ostringstream debug_info;
    debug_info << "data_size=" << binary_data.size()
               << ",first_bytes=" << std::hex << (int)data[0] << ","
               << (int)data[1] << "," << (int)data[2] << "," << (int)data[3]
               << ",has_epee_header=" << (has_epee_header ? "true" : "false")
               << std::dec;

    if (!has_epee_header) {
      return "{\"success\":false,\"error\":\"Invalid binary format - not epee "
             "portable storage\",\"debug\":\"" +
             debug_info.str() + "\"}";
    }

    // ========================================================================
    // TIMING: Phase 1 - Epee Deserialization
    // ========================================================================
    auto parse_start = high_resolution_clock::now();

    try {
      // 1. Deserialize the daemon response using epee
      cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;

      bool parse_ok = false;
      try {
        parse_ok = epee::serialization::load_t_from_binary(res, binary_data);
      } catch (const std::exception &parse_ex) {
        return "{\"success\":false,\"error\":\"epee parse exception: " +
               std::string(parse_ex.what()) + "\",\"debug\":\"" +
               debug_info.str() + "\"}";
      } catch (...) {
        return "{\"success\":false,\"error\":\"epee parse unknown "
               "exception\",\"debug\":\"" +
               debug_info.str() + "\"}";
      }

      auto parse_end = high_resolution_clock::now();
      double parse_ms =
          duration<double, std::milli>(parse_end - parse_start).count();

      if (!parse_ok) {
        m_last_error = "Failed to parse daemon binary response";
        return "{\"success\":false,\"error\":\"Failed to parse daemon binary "
               "response\",\"debug\":\"" +
               debug_info.str() + "\"}";
      }

      // Check daemon status
      if (res.status != CORE_RPC_STATUS_OK) {
        m_last_error = "Daemon returned status: " + res.status;
        return "{\"success\":false,\"error\":\"Daemon returned status: " +
               res.status + "\"}";
      }

      if (res.blocks.empty()) {
        return R"({"success":true,"scanned_count":0,"outputs_found":0,"message":"No blocks in response"})";
      }

      uint64_t start_height = res.start_height;
      uint64_t current_height = res.current_height;

      // ========================================================================
      // TIMING: Phase 2 - Scanning (the crypto-heavy loop)
      // ========================================================================
      auto scan_start = high_resolution_clock::now();

      // 2. ACTUAL SCANNING: Parse all blocks and call process_new_transaction
      size_t blocks_scanned = 0;
      size_t txs_scanned = 0;
      size_t outputs_found = 0;
      size_t total_user_txs = 0;
      size_t total_outputs_in_user_txs = 0;
      uint64_t last_height = start_height;

      // Track transfers before/after for debugging
      size_t transfers_before = m_wallet->get_num_transfer_details();

      // Track which block heights contain outputs belonging to this wallet
      // ("hits") This is used by parallel scanning workers to filter blocks
      std::vector<uint64_t> hit_heights;

      // Verify we have output indices (required for scanning)
      bool has_output_indices = !res.output_indices.empty();
      bool has_asset_indices = !res.asset_type_output_indices.empty();

      for (size_t block_idx = 0; block_idx < res.blocks.size(); ++block_idx) {
        // Track transfers before processing this block to detect hits
        size_t transfers_before_block = m_wallet->get_num_transfer_details();
        const auto &entry = res.blocks[block_idx];
        uint64_t block_height = start_height + block_idx;

        // Parse the block
        cryptonote::block blk;
        if (!cryptonote::parse_and_validate_block_from_blob(entry.block, blk)) {
          m_last_error =
              "Failed to parse block at height " + std::to_string(block_height);
          continue;
        }

        // Get block version for protocol rules
        uint8_t block_version = blk.major_version;
        uint64_t block_timestamp = blk.timestamp;

        // Get output indices for this block (if available)
        std::vector<uint64_t> miner_tx_o_indices;
        std::vector<uint64_t> miner_tx_asset_indices;

        if (has_output_indices && block_idx < res.output_indices.size()) {
          // First tx in block_output_indices is the miner tx
          if (!res.output_indices[block_idx].indices.empty()) {
            miner_tx_o_indices =
                res.output_indices[block_idx].indices[0].indices;
          }
        }
        if (has_asset_indices &&
            block_idx < res.asset_type_output_indices.size()) {
          if (!res.asset_type_output_indices[block_idx].indices.empty()) {
            miner_tx_asset_indices =
                res.asset_type_output_indices[block_idx].indices[0].indices;
          }
        }

        // CRITICAL: Get block hash for m_blockchain tracking
        crypto::hash block_hash = cryptonote::get_block_hash(blk);

        // 2a. Process Miner Transaction (coinbase)
        try {
          crypto::hash miner_tx_hash =
              cryptonote::get_transaction_hash(blk.miner_tx);
          m_wallet->process_new_transaction(
              miner_tx_hash, blk.miner_tx, miner_tx_o_indices,
              miner_tx_asset_indices, block_height, block_version,
              block_timestamp,
              true,  // is_miner_tx
              false, // is_pool
              false, // double_spend_seen
              true   // ignore_callbacks - MUST be true in WASM to prevent
                     // callback trap
          );
          txs_scanned++;
        } catch (const std::exception &e) {
          // Log but continue - miner tx scan failed
        }

        // 2a2. Process Protocol Transaction (yield/staking rewards) - THIS WAS
        // MISSING! Protocol tx is at index 1 in block_output_indices
        if (blk.protocol_tx.vout.size() > 0) {
          std::vector<uint64_t> protocol_tx_o_indices;
          std::vector<uint64_t> protocol_tx_asset_indices;

          if (has_output_indices && block_idx < res.output_indices.size()) {
            if (res.output_indices[block_idx].indices.size() > 1) {
              protocol_tx_o_indices =
                  res.output_indices[block_idx].indices[1].indices;
            }
          }
          if (has_asset_indices &&
              block_idx < res.asset_type_output_indices.size()) {
            if (res.asset_type_output_indices[block_idx].indices.size() > 1) {
              protocol_tx_asset_indices =
                  res.asset_type_output_indices[block_idx].indices[1].indices;
            }
          }

          try {
            crypto::hash protocol_tx_hash =
                cryptonote::get_transaction_hash(blk.protocol_tx);
            m_wallet->process_new_transaction(
                protocol_tx_hash, blk.protocol_tx, protocol_tx_o_indices,
                protocol_tx_asset_indices, block_height, block_version,
                block_timestamp,
                true, // is_miner_tx (treat same as miner for coinbase handling)
                false, // is_pool
                false, // double_spend_seen
                true   // ignore_callbacks - MUST be true in WASM to prevent
                       // callback trap
            );
            txs_scanned++;
          } catch (const std::exception &e) {
            // Log but continue - protocol tx scan failed
          }
        }

        // 2b. Process User Transactions
        // User txs start at index 2 in block_output_indices (0=miner,
        // 1=protocol, 2+=user)
        for (size_t tx_idx = 0; tx_idx < entry.txs.size(); ++tx_idx) {
          const auto &tx_blob = entry.txs[tx_idx];

          cryptonote::transaction tx;
          crypto::hash tx_hash;
          if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob.blob, tx,
                                                           tx_hash)) {
            continue;
          }

          total_user_txs++;
          total_outputs_in_user_txs += tx.vout.size();

          // Get output indices for this tx (tx_idx + 2 because 0=miner,
          // 1=protocol)
          std::vector<uint64_t> tx_o_indices;
          std::vector<uint64_t> tx_asset_indices;

          if (has_output_indices && block_idx < res.output_indices.size()) {
            size_t indices_idx = tx_idx + 2; // +2 to skip miner and protocol tx
            if (indices_idx < res.output_indices[block_idx].indices.size()) {
              tx_o_indices =
                  res.output_indices[block_idx].indices[indices_idx].indices;
            }
          }
          if (has_asset_indices &&
              block_idx < res.asset_type_output_indices.size()) {
            size_t indices_idx = tx_idx + 2;
            if (indices_idx <
                res.asset_type_output_indices[block_idx].indices.size()) {
              tx_asset_indices = res.asset_type_output_indices[block_idx]
                                     .indices[indices_idx]
                                     .indices;
            }
          }

          // THE KEY CALL: Scan transaction for outputs belonging to this wallet
          try {
            m_wallet->process_new_transaction(
                tx_hash, tx, tx_o_indices, tx_asset_indices, block_height,
                block_version,
                block_timestamp, // FIX v5.31.3: Pass actual block timestamp
                                 // instead of 0
                false,           // miner_tx
                false,           // pool
                false,           // double_spend_seen
                true // ignore_callbacks - MUST be true in WASM to prevent
                     // callback trap
            );
            txs_scanned++;
          } catch (const std::exception &e) {
            // Log but continue scanning
          }
        }

        // CRITICAL: Push block hash to m_blockchain to track progress
        // The wallet uses m_blockchain.size() as its "height" and expects
        // sequential blocks. Without this, subsequent syncs will fail.
        m_wallet->m_blockchain.push_back(block_hash);

        // Check if this block contained any outputs for our wallet (a "hit")
        // This is used by parallel workers to filter blocks for the master
        // wallet
        size_t transfers_after_block = m_wallet->get_num_transfer_details();
        if (transfers_after_block > transfers_before_block) {
          hit_heights.push_back(block_height);
        }

        blocks_scanned++;
        last_height = block_height;
      }

      // 3. Update wallet's internal blockchain height (for
      // get_refresh_from_block_height()) This is used by getblocks.bin to know
      // where to resume
      if (last_height > 0) {
        m_wallet->set_refresh_from_block_height(last_height + 1);
      }

      // ========================================================================
      // TIMING: End of scanning phase
      // ========================================================================
      auto scan_end = high_resolution_clock::now();
      double scan_ms =
          duration<double, std::milli>(scan_end - scan_start).count();
      auto total_end = high_resolution_clock::now();
      double total_ms =
          duration<double, std::milli>(total_end - total_start).count();

      // Calculate timing breakdown
      double scan_percent = (scan_ms / total_ms) * 100.0;
      double parse_percent = (parse_ms / total_ms) * 100.0;
      double other_ms = total_ms - parse_ms - scan_ms;
      double ms_per_tx = (txs_scanned > 0) ? (scan_ms / txs_scanned) : 0.0;

      // 4. Check if we found any outputs by comparing balance
      // Sum BOTH SAL and SAL1 (pre-fork and post-fork asset types)
      uint64_t balance_sal = m_wallet->balance(0, "SAL", false);
      uint64_t balance_sal1 = m_wallet->balance(0, "SAL1", false);
      uint64_t balance = balance_sal + balance_sal1;

      uint64_t unlocked_sal = m_wallet->unlocked_balance(0, "SAL", false);
      uint64_t unlocked_sal1 = m_wallet->unlocked_balance(0, "SAL1", false);
      uint64_t unlocked = unlocked_sal + unlocked_sal1;

      size_t num_transfers = m_wallet->get_num_transfer_details();
      uint64_t wallet_blockchain_height = m_wallet->m_blockchain.size();

      // Calculate new transfers found this batch
      size_t transfers_after = m_wallet->get_num_transfer_details();
      size_t new_transfers = transfers_after - transfers_before;

      // 5. Return results as JSON with timing diagnostics
      std::ostringstream oss;
      oss << std::fixed << std::setprecision(2);
      oss << "{"
          << "\"success\":true,"
          << "\"start_height\":" << start_height << ","
          << "\"daemon_height\":" << current_height << ","
          << "\"last_scanned_height\":" << last_height << ","
          << "\"wallet_height\":" << wallet_blockchain_height << ","
          << "\"blocks_scanned\":" << blocks_scanned << ","
          << "\"txs_scanned\":" << txs_scanned << ","
          << "\"user_txs_in_batch\":" << total_user_txs << ","
          << "\"user_tx_outputs_in_batch\":" << total_outputs_in_user_txs << ","
          << "\"new_transfers_this_batch\":" << new_transfers << ","
          << "\"num_transfers\":" << num_transfers << ","
          << "\"has_output_indices\":"
          << (has_output_indices ? "true" : "false") << ","
          << "\"balance\":\"" << balance << "\","
          << "\"balance_sal\":\"" << balance_sal << "\","
          << "\"balance_sal1\":\"" << balance_sal1 << "\","
          << "\"unlocked_balance\":\"" << unlocked << "\","
          << "\"timing\":{"
          << "\"total_ms\":" << total_ms << ","
          << "\"parse_ms\":" << parse_ms << ","
          << "\"scan_ms\":" << scan_ms << ","
          << "\"other_ms\":" << other_ms << ","
          << "\"parse_pct\":" << parse_percent << ","
          << "\"scan_pct\":" << scan_percent << ","
          << "\"ms_per_tx\":" << ms_per_tx << "},"
          << "\"hits\":[";

      // Add hit heights as JSON array
      for (size_t i = 0; i < hit_heights.size(); ++i) {
        if (i > 0)
          oss << ",";
        oss << hit_heights[i];
      }

      oss << "],"
          << "\"hit_count\":" << hit_heights.size() << ","
          << "\"message\":\"Blocks scanned with process_new_transaction + "
             "protocol_tx\""
          << "}";
      return oss.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    } catch (...) {
      m_last_error = "Unknown error in ingest_blocks_binary";
      return R"({"success":false,"error":"Unknown error in ingest_blocks_binary"})";
    }
  }

  // Process blocks from a JavaScript Uint8Array (avoids UTF-8 encoding issues)
  // This is the preferred method for binary data from fetch() responses
  // OPTIMIZED: Uses vecFromJSArray for fast bulk copy instead of byte-by-byte
  std::string ingest_blocks_from_uint8array(const emscripten::val &uint8array) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    // Get the length of the typed array
    size_t length = uint8array["length"].as<size_t>();
    if (length == 0) {
      return R"({"success":false,"error":"Empty binary data"})";
    }

    // FAST PATH: Use vecFromJSArray for efficient bulk copy
    // This uses Emscripten's optimized memory copy instead of byte-by-byte
    // iteration
    std::vector<uint8_t> bytes =
        emscripten::vecFromJSArray<uint8_t>(uint8array);

    // Convert to string (single memory copy within C++)
    std::string binary_data(reinterpret_cast<char *>(bytes.data()),
                            bytes.size());

    // Now call the main implementation
    return ingest_blocks_binary(binary_data);
  }

  // ========================================================================
  // ZERO-COPY BLOCK INGESTION
  // JavaScript writes directly to WASM heap, then calls this with the pointer.
  // This completely bypasses Embind's string conversion overhead.
  // Usage from JS:
  //   const ptr = Module._allocate_binary_buffer(buffer.byteLength);
  //   Module.HEAPU8.set(new Uint8Array(buffer), ptr);
  //   const result = wallet.ingest_blocks_raw(ptr, buffer.byteLength);
  //   Module._free_binary_buffer(ptr);
  // ========================================================================
  std::string ingest_blocks_raw(uintptr_t data_ptr, size_t data_size) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    if (data_ptr == 0 || data_size == 0) {
      return R"({"success":false,"error":"Invalid pointer or size"})";
    }

    // Safety: Validate pointer range (basic sanity check)
    if (data_size > 100 * 1024 * 1024) { // Max 100MB safety limit
      return "{\"success\":false,\"error\":\"Data too large (over 100MB)\"}";
    }

    // Cast pointer - the data is already in WASM memory, no copy needed here!
    // We construct a std::string which does copy internally, but this is
    // a single fast memcpy within C++, not a slow JS-to-WASM boundary copy.
    const char *data = reinterpret_cast<const char *>(data_ptr);
    std::string binary_data(data, data_size);

    // Now call the main implementation
    return ingest_blocks_binary(binary_data);
  }

  // ========================================================================
  // FAST-FORWARD BLOCKCHAIN STATE (for parallel scanner MISS chunks)
  // Updates m_blockchain with block hashes WITHOUT scanning transactions.
  // This allows the wallet to track sync progress even for blocks that
  // don't contain wallet outputs.
  //
  // Worker flow:
  //   1. Worker scans blocks, finds no outputs ??? reports MISS with block
  //   hashes
  //   2. Main thread calls fast_forward_blocks with the hashes
  //   3. Wallet's m_blockchain is updated but no scanning occurs
  //   4. Balance unchanged, but height advances correctly
  // ========================================================================
  std::string fast_forward_blocks(const std::string &binary_data) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    if (binary_data.empty()) {
      return R"({"success":false,"error":"Empty binary data"})";
    }

    // Check for epee portable storage signature
    const unsigned char *data =
        reinterpret_cast<const unsigned char *>(binary_data.data());
    bool has_epee_header = (data[0] == 0x01 && data[1] == 0x11 &&
                            data[2] == 0x01 && data[3] == 0x01);

    if (!has_epee_header) {
      return R"({"success":false,"error":"Invalid binary format - not epee portable storage"})";
    }

    try {
      // Deserialize the daemon response
      cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
      bool parse_ok = epee::serialization::load_t_from_binary(res, binary_data);

      if (!parse_ok) {
        return R"({"success":false,"error":"Failed to parse daemon binary response"})";
      }

      if (res.status != CORE_RPC_STATUS_OK) {
        return "{\"success\":false,\"error\":\"Daemon returned status: " +
               res.status + "\"}";
      }

      if (res.blocks.empty()) {
        return R"({"success":true,"blocks_forwarded":0})";
      }

      uint64_t start_height = res.start_height;
      size_t blocks_forwarded = 0;
      uint64_t last_height = start_height;

      // Fast-forward: Just parse blocks to get hashes, don't scan transactions
      for (size_t block_idx = 0; block_idx < res.blocks.size(); ++block_idx) {
        const auto &entry = res.blocks[block_idx];
        uint64_t block_height = start_height + block_idx;

        // Parse block just to get hash
        cryptonote::block blk;
        if (!cryptonote::parse_and_validate_block_from_blob(entry.block, blk)) {
          continue; // Skip invalid blocks
        }

        // Get block hash and push to m_blockchain
        crypto::hash block_hash = cryptonote::get_block_hash(blk);
        m_wallet->m_blockchain.push_back(block_hash);

        blocks_forwarded++;
        last_height = block_height;
      }

      // Update refresh height
      if (last_height > 0) {
        m_wallet->set_refresh_from_block_height(last_height + 1);
      }

      std::ostringstream oss;
      oss << "{"
          << "\"success\":true,"
          << "\"start_height\":" << start_height << ","
          << "\"last_height\":" << last_height << ","
          << "\"blocks_forwarded\":" << blocks_forwarded << ","
          << "\"wallet_height\":" << m_wallet->m_blockchain.size() << "}";
      return oss.str();

    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    } catch (...) {
      return R"({"success":false,"error":"Unknown error in fast_forward_blocks"})";
    }
  }

  // Fast-forward from Uint8Array
  std::string
  fast_forward_blocks_from_uint8array(const emscripten::val &uint8array) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    size_t length = uint8array["length"].as<size_t>();
    if (length == 0) {
      return R"({"success":false,"error":"Empty binary data"})";
    }

    std::vector<uint8_t> bytes =
        emscripten::vecFromJSArray<uint8_t>(uint8array);
    std::string binary_data(reinterpret_cast<char *>(bytes.data()),
                            bytes.size());
    return fast_forward_blocks(binary_data);
  }

  // ========================================================================
  // BLIND FAST-FORWARD (OPTIMIZED FOR MISS CHUNKS)
  // ========================================================================
  // For MISS chunks, we don't need to parse the binary at all!
  // The worker already scanned and found nothing. We just need to:
  //   1. Update the wallet's blockchain height
  //   2. Store the last block hash for chain linking
  //
  // This is 100x faster than fast_forward_blocks() because:
  //   - No binary parsing (epee deserialization is expensive)
  //   - No block blob parsing
  //   - Just increment a counter and store one hash
  //
  // Usage: After worker reports MISS with {count, lastBlockHash}
  // ========================================================================
  bool advance_height_blind(double target_height_d,
                            const std::string &last_block_hash_hex) {
    if (!m_initialized) {
      m_last_error = "Wallet not initialized";
      return false;
    }

    try {
      uint64_t target_height = static_cast<uint64_t>(target_height_d);

      // Parse the last block hash (for chain linking / reorg detection)
      crypto::hash last_hash;
      if (!last_block_hash_hex.empty()) {
        if (!epee::string_tools::hex_to_pod(last_block_hash_hex, last_hash)) {
          m_last_error = "Invalid block hash hex";
          return false;
        }
      } else {
        // If no hash provided, use a placeholder (not ideal, but functional)
        last_hash = crypto::null_hash;
      }

      // FIX: Use correct hashchain API
      // - crop(height) to shrink
      // - push_back() to grow (calculate delta correctly)
      uint64_t current_size = m_wallet->m_blockchain.size();

      if (target_height > current_size) {
        // Need to grow: push_back the difference
        uint64_t to_add = target_height - current_size;
        for (uint64_t i = 0; i < to_add; ++i) {
          m_wallet->m_blockchain.push_back(last_hash);
        }
        fprintf(stderr,
                "[WASM] advance_height_blind: grew %llu -> %llu (added %llu)\n",
                (unsigned long long)current_size,
                (unsigned long long)target_height, (unsigned long long)to_add);
      } else if (target_height < current_size) {
        // Need to shrink: use crop
        m_wallet->m_blockchain.crop(target_height);
        fprintf(stderr, "[WASM] advance_height_blind: shrunk %llu -> %llu\n",
                (unsigned long long)current_size,
                (unsigned long long)target_height);
      } else {
        fprintf(stderr, "[WASM] advance_height_blind: already at height %llu\n",
                (unsigned long long)target_height);
      }

      // Update refresh height
      uint64_t new_height = m_wallet->m_blockchain.size();
      m_wallet->set_refresh_from_block_height(new_height);

      return true;

    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // ========================================================================
  // FAST SCAN - Returns integer status (no JSON overhead)
  // ========================================================================
  // For workers scanning chunks, we want to know HIT or MISS as fast as
  // possible. This function scans and stores results internally, returning just
  // 0 or 1.
  //
  // Returns:
  //   0 = MISS (no outputs found)
  //   1 = HIT (outputs found, call get_last_scan_result() for details)
  //  -1 = Error (call get_last_error())
  //
  // After calling this:
  //   - If returns 1: Call get_last_scan_result() to get hit details
  //   - Cached results: m_last_scan_* members
  // ========================================================================
  int scan_blocks_fast(uintptr_t data_ptr, size_t data_size) {
    if (!m_initialized) {
      m_last_error = "Wallet not initialized";
      return -1;
    }

    if (data_ptr == 0 || data_size == 0) {
      m_last_error = "Invalid pointer or size";
      return -1;
    }

    // Reset cached scan results
    m_last_scan_hits.clear();
    m_last_scan_start_height = 0;
    m_last_scan_end_height = 0;
    m_last_scan_blocks_count = 0;
    m_last_scan_last_block_hash.clear();

    const char *data = reinterpret_cast<const char *>(data_ptr);

    // Validate epee header
    const unsigned char *udata = reinterpret_cast<const unsigned char *>(data);
    if (data_size < 10 || udata[0] != 0x01 || udata[1] != 0x11) {
      m_last_error = "Invalid binary format - not epee portable storage";
      return -1;
    }

    try {
      std::string binary_data(data, data_size);

      // Deserialize
      cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
      if (!epee::serialization::load_t_from_binary(res, binary_data)) {
        m_last_error = "Failed to parse daemon binary response";
        return -1;
      }

      if (res.status != CORE_RPC_STATUS_OK) {
        m_last_error = "Daemon returned status: " + res.status;
        return -1;
      }

      if (res.blocks.empty()) {
        // Empty response = MISS
        return 0;
      }

      uint64_t start_height = res.start_height;
      m_last_scan_start_height = start_height;

      bool has_output_indices = !res.output_indices.empty();
      bool has_asset_indices = !res.asset_type_output_indices.empty();

      size_t transfers_before = m_wallet->get_num_transfer_details();
      crypto::hash last_block_hash;

      for (size_t block_idx = 0; block_idx < res.blocks.size(); ++block_idx) {
        size_t transfers_before_block = m_wallet->get_num_transfer_details();
        const auto &entry = res.blocks[block_idx];
        uint64_t block_height = start_height + block_idx;

        // Parse block
        cryptonote::block blk;
        if (!cryptonote::parse_and_validate_block_from_blob(entry.block, blk)) {
          continue;
        }

        uint8_t block_version = blk.major_version;
        uint64_t block_timestamp = blk.timestamp;
        last_block_hash = cryptonote::get_block_hash(blk);

        // Get output indices
        std::vector<uint64_t> miner_tx_o_indices, miner_tx_asset_indices;
        std::vector<uint64_t> protocol_tx_o_indices, protocol_tx_asset_indices;

        if (has_output_indices && block_idx < res.output_indices.size()) {
          if (!res.output_indices[block_idx].indices.empty())
            miner_tx_o_indices =
                res.output_indices[block_idx].indices[0].indices;
          if (res.output_indices[block_idx].indices.size() > 1)
            protocol_tx_o_indices =
                res.output_indices[block_idx].indices[1].indices;
        }
        if (has_asset_indices &&
            block_idx < res.asset_type_output_indices.size()) {
          if (!res.asset_type_output_indices[block_idx].indices.empty())
            miner_tx_asset_indices =
                res.asset_type_output_indices[block_idx].indices[0].indices;
          if (res.asset_type_output_indices[block_idx].indices.size() > 1)
            protocol_tx_asset_indices =
                res.asset_type_output_indices[block_idx].indices[1].indices;
        }

        // Process miner tx
        try {
          crypto::hash miner_tx_hash =
              cryptonote::get_transaction_hash(blk.miner_tx);
          m_wallet->process_new_transaction(
              miner_tx_hash, blk.miner_tx, miner_tx_o_indices,
              miner_tx_asset_indices, block_height, block_version,
              block_timestamp, true, false, false, false);
        } catch (...) {
        }

        // Process protocol tx
        if (blk.protocol_tx.vout.size() > 0) {
          try {
            crypto::hash protocol_tx_hash =
                cryptonote::get_transaction_hash(blk.protocol_tx);
            m_wallet->process_new_transaction(
                protocol_tx_hash, blk.protocol_tx, protocol_tx_o_indices,
                protocol_tx_asset_indices, block_height, block_version,
                block_timestamp, true, false, false, false);
          } catch (...) {
          }
        }

        // Process user transactions
        for (size_t tx_idx = 0; tx_idx < entry.txs.size(); ++tx_idx) {
          cryptonote::transaction tx;
          crypto::hash tx_hash;
          bool parse_success = cryptonote::parse_and_validate_tx_from_blob(
              entry.txs[tx_idx].blob, tx, tx_hash);

          // Fallback mechanism for AUDIT/STAKE transactions that fail standard
          // parsing
          bool used_fallback = false;
          if (!parse_success) {
            used_fallback = true;
            parse_success =
                parse_audit_tx_manually(entry.txs[tx_idx].blob, tx, tx_hash);
          }

          if (!parse_success)
            continue;

          // Merge Strategy for STAKE/AUDIT: Backfill critical fields from
          // manual parser Standard parser might miss
          // amount_burnt/return_address
          if (tx.type == cryptonote::transaction_type::STAKE ||
              tx.type == cryptonote::transaction_type::AUDIT) {
            cryptonote::transaction tx_manual;
            crypto::hash hash_manual;
            if (parse_audit_tx_manually(entry.txs[tx_idx].blob, tx_manual,
                                        hash_manual)) {
              tx.return_address = tx_manual.return_address;
              tx.amount_burnt = tx_manual.amount_burnt;
              if (tx_manual.return_pubkey != crypto::null_pkey) {
                tx.return_pubkey = tx_manual.return_pubkey;
              }
              // For AUDIT: Extract spend_pubkey if possible
              if (tx.type == cryptonote::transaction_type::AUDIT) {
                crypto::public_key extracted_spend_pubkey;
                if (extract_salvium_data_spend_pubkey(entry.txs[tx_idx].blob,
                                                      extracted_spend_pubkey)) {
                  tx.rct_signatures.salvium_data.spend_pubkey =
                      extracted_spend_pubkey;
                  tx.rct_signatures.salvium_data.salvium_data_type =
                      rct::SalviumZeroAudit;
                }
              }
            }
          }

          std::vector<uint64_t> tx_o_indices, tx_asset_indices;
          if (has_output_indices && block_idx < res.output_indices.size()) {
            size_t idx = tx_idx + 2;
            if (idx < res.output_indices[block_idx].indices.size())
              tx_o_indices = res.output_indices[block_idx].indices[idx].indices;
          }
          if (has_asset_indices &&
              block_idx < res.asset_type_output_indices.size()) {
            size_t idx = tx_idx + 2;
            if (idx < res.asset_type_output_indices[block_idx].indices.size())
              tx_asset_indices =
                  res.asset_type_output_indices[block_idx].indices[idx].indices;
          }

          try {
            // AUDIT FIX: Add logic to update subaddress map for AUDIT detection
            // (Similar to ingest_sparse_transactions)
            if (tx.type == cryptonote::transaction_type::AUDIT &&
                tx.rct_signatures.salvium_data.salvium_data_type ==
                    rct::SalviumZeroAudit) {
              auto &account = m_wallet->get_account();
              auto audit_spend_pubkey =
                  tx.rct_signatures.salvium_data.spend_pubkey;
              const auto &subaddr_map = account.get_subaddress_map_cn();

              if (subaddr_map.find(audit_spend_pubkey) == subaddr_map.end()) {
                carrot::subaddress_index_extended subaddr_idx{
                    .index = {0, 0},
                    .derive_type = carrot::AddressDeriveType::PreCarrot,
                    .is_return_spend_key = true};
                account.insert_subaddresses(
                    {{audit_spend_pubkey, subaddr_idx}});
              }

              auto audit_return_address = tx.return_address;
              if (audit_return_address != crypto::null_pkey &&
                  subaddr_map.find(audit_return_address) == subaddr_map.end()) {
                carrot::subaddress_index_extended return_idx{
                    .index = {0, 0},
                    .derive_type = carrot::AddressDeriveType::PreCarrot,
                    .is_return_spend_key = true};
                account.insert_subaddresses(
                    {{audit_return_address, return_idx}});
              }
            }

            m_wallet->process_new_transaction(
                tx_hash, tx, tx_o_indices, tx_asset_indices, block_height,
                block_version, block_timestamp, false, false, false, false);

            // ================================================================
            // v5.35.8 FIX: Mark spent outputs during fast scan
            // CRITICAL: Check if this tx SPENDS any of our outputs by matching
            // input key images against m_key_images.
            // ================================================================
            for (const auto &in : tx.vin) {
              if (in.type() != typeid(cryptonote::txin_to_key))
                continue;

              const cryptonote::txin_to_key &in_to_key =
                  boost::get<cryptonote::txin_to_key>(in);

              auto ki_it = m_wallet->m_key_images.find(in_to_key.k_image);
              if (ki_it != m_wallet->m_key_images.end()) {
                size_t transfer_idx = ki_it->second;
                if (transfer_idx < m_wallet->m_transfers.size()) {
                  auto &spent_td = m_wallet->m_transfers[transfer_idx];
                  if (!spent_td.m_spent) {
                    spent_td.m_spent = true;
                    spent_td.m_spent_height = block_height;
                  }
                }
              }
            }

            // STAKE RETURN FIX: Add return address to map AFTER processing
            if (tx.type == cryptonote::transaction_type::STAKE) {
              crypto::public_key stake_return_address = crypto::null_pkey;
              if (tx.return_address != crypto::null_pkey)
                stake_return_address = tx.return_address;
              else if (tx.protocol_tx_data.return_address != crypto::null_pkey)
                stake_return_address = tx.protocol_tx_data.return_address;

              if (stake_return_address != crypto::null_pkey) {
                auto &account = m_wallet->get_account();
                const auto &subaddr_map = account.get_subaddress_map_cn();
                if (subaddr_map.find(stake_return_address) ==
                    subaddr_map.end()) {
                  carrot::subaddress_index_extended return_idx{
                      .index = {0, 0},
                      .derive_type = carrot::AddressDeriveType::PreCarrot,
                      .is_return_spend_key = true};
                  account.insert_subaddresses(
                      {{stake_return_address, return_idx}});
                }
              }
            }
          } catch (...) {
          }
        }

        // Track blockchain
        m_wallet->m_blockchain.push_back(last_block_hash);

        // Check for HIT
        if (m_wallet->get_num_transfer_details() > transfers_before_block) {
          m_last_scan_hits.push_back(block_height);
        }

        m_last_scan_end_height = block_height;
      }

      m_last_scan_blocks_count = res.blocks.size();
      m_last_scan_last_block_hash =
          epee::string_tools::pod_to_hex(last_block_hash);

      // Update refresh height
      if (m_last_scan_end_height > 0) {
        m_wallet->set_refresh_from_block_height(m_last_scan_end_height + 1);
      }

      // Return HIT (1) or MISS (0)
      return m_last_scan_hits.empty() ? 0 : 1;

    } catch (const std::exception &e) {
      m_last_error = e.what();
      return -1;
    }
  }

  // Get details from last scan (call after scan_blocks_fast returns 1)
  std::string get_last_scan_result() const {
    uint64_t balance_sal = m_wallet->balance(0, "SAL", false);
    uint64_t balance_sal1 = m_wallet->balance(0, "SAL1", false);
    uint64_t balance = balance_sal + balance_sal1;

    std::ostringstream oss;
    oss << "{"
        << "\"start_height\":" << m_last_scan_start_height << ","
        << "\"end_height\":" << m_last_scan_end_height << ","
        << "\"blocks_scanned\":" << m_last_scan_blocks_count << ","
        << "\"last_block_hash\":\"" << m_last_scan_last_block_hash << "\","
        << "\"balance\":\"" << balance << "\","
        << "\"hit_count\":" << m_last_scan_hits.size() << ","
        << "\"hits\":[";

    for (size_t i = 0; i < m_last_scan_hits.size(); ++i) {
      if (i > 0)
        oss << ",";
      oss << m_last_scan_hits[i];
    }

    oss << "]}";
    return oss.str();
  }

  // Get just the last block hash (for MISS chunks to send to master)
  std::string get_last_scan_block_hash() const {
    return m_last_scan_last_block_hash;
  }

  // Get scan block count
  double get_last_scan_block_count() const {
    return static_cast<double>(m_last_scan_blocks_count);
  }

  // Legacy process_blocks_binary - alias to ingest_blocks_binary for
  // compatibility
  std::string process_blocks_binary(const std::string &binary_data) {
    return ingest_blocks_binary(binary_data);
  }

  // Simple test function to verify WASM is working
  std::string test_wasm() const {
    std::ostringstream oss;
    oss << "{"
        << "\"wasm_ok\":true,"
        << "\"initialized\":" << (m_initialized ? "true" : "false") << ","
        << "\"version\":\"" << WASM_VERSION << "\""
        << "}";
    return oss.str();
  }

  // Set wallet height manually (for sync progress tracking)
  bool set_wallet_height(double height_d) {
    if (!m_initialized) {
      m_last_error = "Wallet not initialized";
      return false;
    }
    try {
      uint64_t target_height = static_cast<uint64_t>(height_d);

      // Update refresh height
      m_wallet->set_refresh_from_block_height(target_height);

      // Update blockchain height (fill with null hashes if needed)
      // This ensures get_wallet_height() returns the correct value
      // preventing the UI from triggering repeated scans
      uint64_t current_height = m_wallet->m_blockchain.size();
      if (target_height > current_height) {
        crypto::hash null_hash = crypto::null_hash;
        size_t needed = target_height - current_height;
        for (size_t i = 0; i < needed; ++i) {
          m_wallet->m_blockchain.push_back(null_hash);
        }
      }

      return true;
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return false;
    }
  }

  // Legacy process_blocks - uses HTTP cache approach (may not work reliably)
  // Prefer process_blocks_binary for direct binary data processing
  std::string process_blocks() {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }
    try {
      uint64_t height_before = m_wallet->get_blockchain_current_height();
      uint64_t balance_before = m_wallet->balance(0, "SAL", false) +
                                m_wallet->balance(0, "SAL1", false);

      // Call refresh - it will use the cached HTTP responses
      // NOTE: This may fail because wallet2 sends its own request parameters
      m_wallet->refresh(m_wallet->is_trusted_daemon());

      uint64_t height_after = m_wallet->get_blockchain_current_height();
      uint64_t balance_after = m_wallet->balance(0, "SAL", false) +
                               m_wallet->balance(0, "SAL1", false);

      std::ostringstream oss;
      oss << "{"
          << "\"success\":true,"
          << "\"height_before\":" << height_before << ","
          << "\"height_after\":" << height_after << ","
          << "\"blocks_processed\":" << (height_after - height_before) << ","
          << "\"balance_before\":" << balance_before << ","
          << "\"balance_after\":" << balance_after << ","
          << "\"balance_changed\":"
          << (balance_after != balance_before ? "true" : "false") << "}";
      return oss.str();
    } catch (const std::exception &e) {
      m_last_error = e.what();
      std::ostringstream oss;
      oss << R"({"success":false,"error":")" << e.what() << R"("})";
      return oss.str();
    } catch (...) {
      m_last_error = "Unknown error in process_blocks";
      return R"({"success":false,"error":"Unknown error in process_blocks"})";
    }
  }

  // ========================================================================
  // Error Handling
  // ========================================================================

  std::string get_last_error() const { return m_last_error; }

  bool is_initialized() const { return m_initialized; }

  // ========================================================================
  // Subaddresses (Phase 6 - Step 2)
  // ========================================================================

  // Get the number of subaddresses in a given account
  // Note: Using double for JavaScript compatibility
  double get_num_subaddresses(double account_d) const {
    if (!m_initialized)
      return 0;
    try {
      uint32_t account = static_cast<uint32_t>(account_d);
      return static_cast<double>(m_wallet->get_num_subaddresses(account));
    } catch (...) {
      return 0;
    }
  }

  // Create a new subaddress in the given account
  // Returns JSON: {"address": "...", "index": {"major": 0, "minor": 1},
  // "label": "..."}
  std::string create_subaddress(double account_d, const std::string &label) {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized"})";
    }

    try {
      uint32_t account = static_cast<uint32_t>(account_d);

      // Add a new subaddress
      m_wallet->add_subaddress(account, label);

      // Get the index of the newly created subaddress (last one in the account)
      uint32_t new_index = m_wallet->get_num_subaddresses(account) - 1;

      // Get the address as string
      std::string address =
          m_wallet->get_subaddress_as_str({account, new_index});

      // Build JSON response
      std::ostringstream json;
      json << "{"
           << R"("address":")" << address << R"(",)"
           << R"("index":{"major":)" << account << R"(,"minor":)" << new_index
           << R"(},)"
           << R"("label":")" << label << R"(")"
           << "}";

      return json.str();
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return std::string(R"({"error":")") + e.what() + R"("})";
    }
  }

  // Get a subaddress by index
  // Returns JSON: {"address": "...", "index": {"major": 0, "minor": 1},
  // "label": "..."}
  std::string get_subaddress(double account_d, double index_d) const {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized"})";
    }

    try {
      uint32_t account = static_cast<uint32_t>(account_d);
      uint32_t index = static_cast<uint32_t>(index_d);

      // Get the address as string
      std::string address = m_wallet->get_subaddress_as_str({account, index});

      // Get the label
      std::string label = m_wallet->get_subaddress_label({account, index});

      // Build JSON response
      std::ostringstream json;
      json << "{"
           << R"("address":")" << address << R"(",)"
           << R"("index":{"major":)" << account << R"(,"minor":)" << index
           << R"(},)"
           << R"("label":")" << label << R"(")"
           << "}";

      return json.str();
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return std::string(R"({"error":")") + e.what() + R"("})";
    }
  }

  // Get all subaddresses in an account as JSON array (with balances)
  std::string get_all_subaddresses(double account_d) const {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized"})";
    }

    try {
      uint32_t account = static_cast<uint32_t>(account_d);
      uint32_t num_subaddresses = m_wallet->get_num_subaddresses(account);

      // Get per-subaddress balances for both SAL and SAL1 (to match dashboard)
      // Note: Only ONE asset will have actual balance, the other will be 0
      std::map<uint32_t, uint64_t> sal_balance_map =
          m_wallet->balance_per_subaddress(account, "SAL", false);
      std::map<uint32_t, uint64_t> sal1_balance_map =
          m_wallet->balance_per_subaddress(account, "SAL1", false);

      // Get unlocked balances too
      auto sal_unlocked_map =
          m_wallet->unlocked_balance_per_subaddress(account, "SAL", false);
      auto sal1_unlocked_map =
          m_wallet->unlocked_balance_per_subaddress(account, "SAL1", false);

      std::ostringstream json;
      json << "[";

      for (uint32_t i = 0; i < num_subaddresses; ++i) {
        if (i > 0)
          json << ",";

        std::string address = m_wallet->get_subaddress_as_str({account, i});
        std::string label = m_wallet->get_subaddress_label({account, i});

        // Sum SAL + SAL1 balances (only one will have value)
        uint64_t balance = 0;
        if (sal_balance_map.count(i) > 0)
          balance += sal_balance_map[i];
        if (sal1_balance_map.count(i) > 0)
          balance += sal1_balance_map[i];

        // Sum unlocked balances
        uint64_t unlocked_balance = 0;
        if (sal_unlocked_map.count(i) > 0)
          unlocked_balance += sal_unlocked_map[i].first;
        if (sal1_unlocked_map.count(i) > 0)
          unlocked_balance += sal1_unlocked_map[i].first;

        json << "{"
             << R"("address":")" << address << R"(",)"
             << R"("index":{"major":)" << account << R"(,"minor":)" << i
             << R"(},)"
             << R"("label":")" << label << R"(",)"
             << R"("balance":)" << balance << R"(,)"
             << R"("unlocked_balance":)" << unlocked_balance
             << "}";
      }

      json << "]";
      return json.str();
    } catch (const std::exception &e) {
      m_last_error = e.what();
      return std::string(R"({"error":")") + e.what() + R"("})";
    }
  }

  // ========================================================================
  // Transfers (Phase 6 - Step 1)
  // ========================================================================

  // Note: Using double instead of uint64_t for JavaScript compatibility
  // JavaScript numbers are doubles (53-bit integer precision), which is enough
  // for block heights
  std::string get_transfers_as_json(double min_height_d, double max_height_d,
                                    bool include_in, bool include_out,
                                    bool include_pending) {
    if (!m_initialized) {
      return R"({"error":"Wallet not initialized"})";
    }

    // Convert from double to uint64_t for internal use
    uint64_t min_height = static_cast<uint64_t>(min_height_d);
    uint64_t max_height = static_cast<uint64_t>(max_height_d);

    try {
      // Pre-fetch wallet2 lists so we can de-duplicate across categories.
      std::list<std::pair<crypto::hash, tools::wallet2::payment_details>>
          payments;
      std::list<
          std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>>
          out_payments;
      std::list<
          std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>>
          pending_payments;

      // NOTE: wallet2's get_payments and get_payments_out use half-open ranges
      // (min, max] where min is EXCLUSIVE and max is INCLUSIVE. To include
      // min_height in results, we pass adjusted_min = min_height - 1 (or 0 if
      // min_height is already 0).
      uint64_t adjusted_min = (min_height > 0) ? (min_height - 1) : 0;

      if (include_in) {
        m_wallet->get_payments(payments, adjusted_min, max_height);
      }
      if (include_out) {
        m_wallet->get_payments_out(out_payments, adjusted_min, max_height);
      }
      if (include_pending) {
        m_wallet->get_unconfirmed_payments_out(pending_payments);
      }

      // v5.11.0 FIX: Separate tracking for incoming vs outgoing txids
      // Previously, we added ALL txids to known_txids which prevented STAKE tx
      // change outputs from appearing in the incoming list (because STAKE txs
      // appear in BOTH out_payments and transfer_details).
      // Now we only use known_in_txids to de-duplicate incoming entries,
      // and known_out_txids separately for tracking outgoing.
      std::unordered_set<crypto::hash>
          known_in_txids; // For de-duplicating incoming
      std::unordered_set<crypto::hash> known_out_txids; // For info only
      known_in_txids.reserve(payments.size());
      known_out_txids.reserve(out_payments.size() + pending_payments.size());

      for (const auto &p : payments) {
        known_in_txids.insert(p.second.m_tx_hash);
      }
      for (const auto &p : out_payments) {
        known_out_txids.insert(p.first);
      }
      for (const auto &p : pending_payments) {
        known_out_txids.insert(p.first);
      }

      // Build JSON manually - avoid epee serialization
      std::ostringstream json;
      json << "{";

      bool first_category = true;

      // ================================================================
      // v5.36.0 FIX: SYNTHETIC OUTGOING STAKE ENTRIES
      // ================================================================
      // Declared at outer scope so it's accessible in both include_in and
      // include_out blocks.
      // ================================================================
      struct SyntheticStake {
        crypto::hash txid;
        uint64_t amount_burnt;
        uint64_t block_height;
        uint64_t unlock_time;
        uint64_t timestamp;
        int tx_type;
      };
      std::vector<SyntheticStake> synthetic_stakes;
      std::unordered_set<crypto::hash> stake_txids; // For skipping change

      // Incoming payments
      if (include_in) {
        if (!first_category)
          json << ",";
        first_category = false;
        json << R"("in":[)";

        bool first = true;
        for (const auto &p : payments) {
          if (!first)
            json << ",";
          first = false;

          const auto &pd = p.second;
          json << "{"
               << R"("txid":")" << epee::string_tools::pod_to_hex(pd.m_tx_hash)
               << R"(",)"
               << R"("payment_id":")" << epee::string_tools::pod_to_hex(p.first)
               << R"(",)"
               << R"("amount":)" << pd.m_amount << ","
               << R"("asset_type":")" << pd.m_asset_type << R"(",)"
               << R"("fee":)" << pd.m_fee << ","
               << R"("block_height":)" << pd.m_block_height << ","
               << R"("unlock_time":)" << pd.m_unlock_time << ","
               << R"("timestamp":)" << pd.m_timestamp << ","
               << R"("coinbase":)" << (pd.m_coinbase ? "true" : "false") << ","
               << R"("type":"in",)"
               << R"("tx_type":)" << static_cast<int>(pd.m_tx_type) << ","
               << R"("subaddr_major":)" << pd.m_subaddr_index.major << ","
               << R"("subaddr_minor":)" << pd.m_subaddr_index.minor << "}";
        }

        // EXTRA INCOMING:
        // Some tx types (AUDIT/STAKE/PROTOCOL) can add transfer_details
        // without appearing in get_payments(). Surface them here so the Vault
        // can verify presence by height.
        struct ExtraInAgg {
          uint64_t amount = 0;
          uint64_t block_height = 0;
          uint64_t unlock_time = 0;
          uint32_t subaddr_major = 0;
          uint32_t subaddr_minor = 0;
          int tx_type = 0;
          std::string asset_type;
          uint64_t timestamp = 0; // Added for WASM export stability
        };

        std::unordered_map<crypto::hash, ExtraInAgg> extra_by_txid;
        std::vector<crypto::hash> extra_order;

        // ================================================================
        // v5.35.4 FIX: DIRECT CHANGE DETECTION via TX INPUT KEY IMAGES
        // ================================================================
        // The v5.21.0 heights_with_spends approach fails when:
        // - Outputs don't have key images generated yet
        // - Spent index lookup fails
        // - mark_spent_by_key_images didn't run
        //
        // NEW APPROACH: For each transfer_details, directly examine the
        // transaction's inputs. If ANY input has a key_image that matches
        // our m_key_images map, then this is OUR OUTGOING tx and the
        // output is CHANGE - skip displaying it as incoming.
        //
        // This works even for fresh-scanned wallets because:
        // - td.m_tx contains the full transaction
        // - m_wallet->m_key_images maps key_image -> transfer index
        // - If we have the secret spend key, key images are computed on ingest
        // ================================================================

        // Helper lambda to check if a tx spends our outputs
        // Note: td.m_tx is transaction_prefix which contains vin
        auto tx_spends_our_outputs =
            [this](const cryptonote::transaction_prefix &tx) -> bool {
          for (const auto &in : tx.vin) {
            if (in.type() != typeid(cryptonote::txin_to_key))
              continue;
            const auto &txin = boost::get<cryptonote::txin_to_key>(in);
            if (m_wallet->m_key_images.find(txin.k_image) !=
                m_wallet->m_key_images.end()) {
              return true; // This tx spends one of our outputs
            }
          }
          return false;
        };

        // Build set of txids that are our outgoing transactions (spend our
        // outputs) by scanning all transfer_details for txs that have our
        // key_images in inputs
        const size_t transfer_count = m_wallet->get_num_transfer_details();
        std::unordered_set<crypto::hash> our_outgoing_txids;

        for (size_t i = 0; i < transfer_count; ++i) {
          const auto &td = m_wallet->get_transfer_details(i);
          if (td.m_block_height < min_height || td.m_block_height > max_height)
            continue;

          // Check if this tx spends our outputs (makes it an outgoing tx)
          if (tx_spends_our_outputs(td.m_tx)) {
            our_outgoing_txids.insert(td.m_txid);
          }
        }

        // ================================================================
        // v5.36.0: Detect STAKE/AUDIT transactions to create synthetic outgoing
        // ================================================================
        for (size_t i = 0; i < transfer_count; ++i) {
          const auto &td = m_wallet->get_transfer_details(i);
          if (td.m_block_height < min_height || td.m_block_height > max_height)
            continue;

          // Check if this is a STAKE/AUDIT transaction
          bool is_stake_type =
              (td.m_tx.type == cryptonote::transaction_type::STAKE ||
               td.m_tx.type == cryptonote::transaction_type::AUDIT ||
               static_cast<int>(td.m_tx.type) == 6);
          if (!is_stake_type)
            continue;

          // Skip if already processed (and added to stake_txids)
          if (stake_txids.find(td.m_txid) != stake_txids.end())
            continue;

          // Check if it's a Restake (spends locked stake)
          // Heuristic: Input comes from a STAKE output with matching amount
          // (Locked)
          bool spends_locked_stake = false;
          for (const auto &in : td.m_tx.vin) {
            if (in.type() != typeid(cryptonote::txin_to_key))
              continue;
            const auto &txin = boost::get<cryptonote::txin_to_key>(in);
            auto it = m_wallet->m_key_images.find(txin.k_image);
            if (it != m_wallet->m_key_images.end()) {
              size_t idx = it->second;
              if (idx < m_wallet->get_num_transfer_details()) {
                const auto &src_td = m_wallet->get_transfer_details(idx);
                if ((src_td.m_tx.type == cryptonote::transaction_type::STAKE ||
                     static_cast<int>(src_td.m_tx.type) == 6) &&
                    src_td.m_amount == src_td.m_tx.amount_burnt) {
                  spends_locked_stake = true;
                  break;
                }
              }
            }
          }

          if (spends_locked_stake) {
            // RESTAKE:
            // - We KEEP the change (it's the Stake Return).
            // - We SKIP synthetic out (to avoid double counting outflow).
            // - So we do NOTHING here. The default "incoming" pass (loop 3931)
            // will pick up the change.
            continue;
          }

          // NEW STAKE (Liquid -> Stake):
          // - We ADD synthetic out.
          // - We SKIP change (because we manually handle net amount via
          // synthetic out).

          // Check if return_address matches our subaddress map (we're the
          // staker)
          crypto::public_key return_addr = crypto::null_pkey;
          if (td.m_tx.return_address != crypto::null_pkey) {
            return_addr = td.m_tx.return_address;
          } else if (td.m_tx.protocol_tx_data.return_address !=
                     crypto::null_pkey) {
            return_addr = td.m_tx.protocol_tx_data.return_address;
          }

          bool is_our_stake = false;
          if (return_addr != crypto::null_pkey) {
            const auto &subaddr_map =
                m_wallet->get_account().get_subaddress_map_cn();
            if (subaddr_map.find(return_addr) != subaddr_map.end()) {
              is_our_stake = true;
            }
          }

          // Fallback: check if tx spends our outputs
          if (!is_our_stake && tx_spends_our_outputs(td.m_tx)) {
            is_our_stake = true;
          }

          if (is_our_stake && td.m_tx.amount_burnt > 0) {
            // Add to stake_txids so we SKIP change in the next loop (3931)
            stake_txids.insert(td.m_txid);

            SyntheticStake stake;
            stake.txid = td.m_txid;
            stake.amount_burnt = td.m_tx.amount_burnt;
            stake.block_height = td.m_block_height;
            stake.unlock_time = td.m_tx.unlock_time;
            stake.tx_type = static_cast<int>(td.m_tx.type);

            // Get timestamp from cache
            auto ts_it = m_tx_timestamps.find(td.m_txid);
            stake.timestamp =
                (ts_it != m_tx_timestamps.end()) ? ts_it->second : 0;

            synthetic_stakes.push_back(stake);
          }
        }

        // Legacy: also track heights with spent outputs (for backup detection)
        std::unordered_set<uint64_t> heights_with_spends;
        for (size_t i = 0; i < transfer_count; ++i) {
          const auto &td = m_wallet->get_transfer_details(i);
          if (td.m_spent && td.m_spent_height >= min_height &&
              td.m_spent_height <= max_height) {
            heights_with_spends.insert(td.m_spent_height);
          }
        }

        for (size_t i = 0; i < transfer_count; ++i) {
          const auto &td = m_wallet->get_transfer_details(i);
          const uint64_t h = td.m_block_height;
          if (h < min_height || h > max_height)
            continue;

          // Skip if already in INCOMING payments (already displayed as
          // incoming)
          if (known_in_txids.find(td.m_txid) != known_in_txids.end())
            continue;

          // v5.13.0 FIX: Skip change outputs for outgoing transactions.
          // This handles txs that ARE in confirmed_transfer_details.
          if (known_out_txids.find(td.m_txid) != known_out_txids.end()) {
            continue;
          }

          // v5.36.0 FIX: Skip change outputs from STAKE/AUDIT transactions
          // These are now recorded as synthetic outgoing entries
          if (stake_txids.find(td.m_txid) != stake_txids.end()) {
            continue;
          }

          // v5.35.4 FIX: Skip change outputs detected via input key images
          // If this tx spends our outputs, any outputs to us are CHANGE
          if (our_outgoing_txids.find(td.m_txid) != our_outgoing_txids.end()) {
            // This is our outgoing tx - skip the change output
            // Only skip for TRANSFER and STAKE types (user-initiated sends)
            // v5.35.10: Added explicit match for type 6 (STAKE) just in case
            if (td.m_tx.type == cryptonote::transaction_type::TRANSFER ||
                td.m_tx.type == cryptonote::transaction_type::STAKE ||
                static_cast<int>(td.m_tx.type) == 6) {
              continue;
            }
          }

          // v5.21.0 BACKUP: Height-based detection as fallback
          // If this output was received at a height where we also SPENT
          // outputs, it's likely change from our own outgoing tx
          if (heights_with_spends.find(h) != heights_with_spends.end()) {
            if (td.m_tx.type == cryptonote::transaction_type::TRANSFER ||
                td.m_tx.type == cryptonote::transaction_type::STAKE ||
                static_cast<int>(td.m_tx.type) == 6) {
              continue;
            }
          }

          auto it = extra_by_txid.find(td.m_txid);
          if (it == extra_by_txid.end()) {
            ExtraInAgg agg;
            agg.block_height = h;
            agg.unlock_time = td.m_tx.unlock_time;
            agg.subaddr_major = td.m_subaddr_index.major;
            agg.subaddr_minor = td.m_subaddr_index.minor;
            agg.tx_type = static_cast<int>(td.m_tx.type);

            // v5.12.0: Use td.asset_type (the correct field from
            // transfer_details) NOT td.m_tx.source_asset_type which is often
            // empty for MINER/PROTOCOL txs
            agg.asset_type = td.asset_type.empty() ? "SAL" : td.asset_type;

            // Lookup timestamp from cache
            auto ts_it = m_tx_timestamps.find(td.m_txid);
            if (ts_it != m_tx_timestamps.end()) {
              agg.timestamp = ts_it->second;
            }

            extra_by_txid.emplace(td.m_txid, agg);
            extra_order.push_back(td.m_txid);
          }

          extra_by_txid[td.m_txid].amount += td.m_amount;
        }

        for (const auto &txid : extra_order) {
          const auto &agg = extra_by_txid[txid];
          if (!first)
            json << ",";
          first = false;

          json << "{" << R"("txid":")" << epee::string_tools::pod_to_hex(txid)
               << R"(",)"
               << R"("payment_id":"",)"
               << R"("amount":)" << agg.amount << ","
               << R"("asset_type":")" << agg.asset_type << R"(",)"
               << R"("fee":0,)"
               << R"("block_height":)" << agg.block_height << ","
               << R"("unlock_time":)" << agg.unlock_time << ","
               << R"("timestamp":)" << agg.timestamp << ","
               << R"("coinbase":false,)"
               << R"("type":"in",)"
               << R"("tx_type":)" << agg.tx_type << ","
               << R"("subaddr_major":)" << agg.subaddr_major << ","
               << R"("subaddr_minor":)" << agg.subaddr_minor << "}";
        }
        json << "]";
      }

      // Outgoing payments (confirmed)
      if (include_out) {
        if (!first_category)
          json << ",";
        first_category = false;
        json << R"("out":[)";

        bool first = true;
        for (const auto &p : out_payments) {
          if (!first)
            json << ",";
          first = false;

          const auto &pd = p.second;

          // Get the asset type for this transaction
          // IMPORTANT: For scanned transactions, m_tx.source_asset_type might
          // be empty if the transaction type doesn't serialize it (e.g.,
          // PROTOCOL, MINER, UNSET) or if it wasn't properly deserialized.
          std::string asset_type = pd.m_tx.source_asset_type;

          // v5.10.0: Default empty asset_type to "SAL" for proper calculation
          // Empty asset_type causes issues because asset_type != "SAL" is true,
          // which triggers the non-SAL branch with wrong fee handling
          if (asset_type.empty()) {
            asset_type = "SAL";
          }

          std::string tx_hash_hex = epee::string_tools::pod_to_hex(p.first);

          // Safe calculation to prevent uint64 underflow
          uint64_t amount_in = pd.m_amount_in;
          uint64_t amount_out = pd.m_amount_out;
          uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change;

          // Calculate fee (SAL: fee = amount_in - amount_out)
          uint64_t fee = 0;
          if (amount_in >= amount_out) {
            fee = amount_in - amount_out;
          }

          // Calculate amount based on asset type
          uint64_t amount = 0;

          // STAKE/AUDIT special case: For these tx types, we want to show the
          // actual staked/audited amount from amount_burnt, NOT amount_in.
          // amount_in = total inputs spent, amount_burnt = actual stake amount
          // The difference (amount_in - amount_burnt - fee) is change that goes
          // back to us. v5.11.0 FIX: Use amount_burnt from tx prefix for
          // correct stake amounts!
          if (pd.m_tx.type == cryptonote::transaction_type::STAKE ||
              pd.m_tx.type == cryptonote::transaction_type::AUDIT) {
            // For STAKE/AUDIT: show amount_burnt (the actual staked/audited
            // amount) This is a PUBLIC field in the transaction prefix that
            // shows exactly how much was staked/audited (e.g., 200,000 SAL1),
            // not the total inputs.
            amount = pd.m_tx.amount_burnt;
          } else if (asset_type != "SAL") {
            // For non-SAL transfers (e.g., SAL1):
            // When m_dests is populated (wallet created tx): sum destination
            // amounts When m_dests is empty (scanned tx from another wallet):
            //   m_amount_in = total source asset spent (SAL1)
            //   m_change = source asset change received (SAL1)
            //   So: amount sent = m_amount_in - m_change
            //
            // v5.10.0 FIX: For SAL1 outgoing transactions, the fee is paid in
            // SAL, not SAL1. So m_amount_out = m_amount_in - SAL_fee is WRONG
            // (subtracts SAL fee from SAL1 amount). We should only use
            // amount_in and change (both in SAL1) for the calculation.
            if (!pd.m_dests.empty()) {
              for (const auto &dest : pd.m_dests) {
                amount += dest.amount;
              }
            } else if (amount_in > 0) {
              // Scanned transaction - amount_in and change are in source asset
              // (SAL1) FIX: Don't require amount_in >= change, just do safe
              // subtraction
              if (amount_in >= change) {
                amount = amount_in - change;
              } else {
                // Edge case: change > amount_in (shouldn't happen but handle
                // gracefully)
                amount = 0;
              }
            } else {
              amount = 0;
            }
          } else {
            // For SAL transfers: amount = amount_in - change - fee
            // v5.10.0 FIX: Add better fallback handling
            if (amount_in >= change + fee) {
              amount = amount_in - change - fee;
            } else if (amount_out > change) {
              // Fallback: use amount_out - change if amount_in is unreliable
              amount = amount_out - change;
            } else if (amount_in > change) {
              // Second fallback: if we at least have amount_in > change,
              // calculate without fee (better than 0)
              amount = amount_in - change;
            } else if (amount_in > 0 && change == 0) {
              // Third fallback: if change is 0, amount is amount_in minus fee
              amount = (amount_in >= fee) ? (amount_in - fee) : 0;
            } else {
              // Last resort: amount stays 0
              amount = 0;
            }
          }

          json << "{"
               << R"("txid":")" << epee::string_tools::pod_to_hex(p.first)
               << R"(",)"
               << R"("payment_id":")"
               << epee::string_tools::pod_to_hex(pd.m_payment_id) << R"(",)"
               << R"("amount":)" << amount << ","
               << R"("asset_type":")" << asset_type << R"(",)"
               << R"("fee":)" << fee << ","
               << R"("block_height":)" << pd.m_block_height << ","
               << R"("unlock_time":)" << pd.m_unlock_time << ","
               << R"("timestamp":)" << pd.m_timestamp << ","
               << R"("type":"out",)"
               << R"("tx_type":)" << static_cast<int>(pd.m_tx.type) << ","
               << R"("subaddr_account":)" << pd.m_subaddr_account << "}";
        }

        // v5.36.0: Add synthetic STAKE outgoing entries
        // These are STAKE transactions detected via change outputs that
        // weren't recorded in confirmed_transfer_details during scan
        for (const auto &stake : synthetic_stakes) {
          // Don't double-count if already in out_payments
          if (known_out_txids.find(stake.txid) != known_out_txids.end())
            continue;

          if (!first)
            json << ",";
          first = false;

          json << "{"
               << R"("txid":")" << epee::string_tools::pod_to_hex(stake.txid)
               << R"(",)"
               << R"("payment_id":"",)"
               << R"("amount":)" << stake.amount_burnt << ","
               << R"("asset_type":"SAL",)"
               << R"("fee":0,)"
               << R"("block_height":)" << stake.block_height << ","
               << R"("unlock_time":)" << stake.unlock_time << ","
               << R"("timestamp":)" << stake.timestamp << ","
               << R"("type":"out",)"
               << R"("tx_type":)" << stake.tx_type << ","
               << R"("subaddr_account":0})";
        }

        json << "]";
      }

      // Pending/Unconfirmed outgoing
      if (include_pending) {
        if (!first_category)
          json << ",";
        first_category = false;
        json << R"("pending":[)";

        bool first = true;
        for (const auto &p : pending_payments) {
          if (!first)
            json << ",";
          first = false;

          const auto &pd = p.second;

          // Get the asset type for this transaction
          std::string asset_type = pd.m_tx.source_asset_type;

          // Safe calculation to prevent uint64 underflow
          uint64_t amount_in = pd.m_amount_in;
          uint64_t amount_out = pd.m_amount_out;
          uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change;

          // Calculate fee (SAL: fee = amount_in - amount_out)
          uint64_t fee = 0;
          if (amount_in >= amount_out) {
            fee = amount_in - amount_out;
          }

          // Calculate amount based on asset type
          uint64_t amount = 0;

          if (asset_type != "SAL") {
            // For non-SAL transfers (e.g., SAL1):
            // When m_dests is populated (wallet created tx): sum destination
            // amounts When m_dests is empty (scanned tx from another wallet):
            //   m_amount_in = total source asset spent
            //   m_change = source asset change received
            //   So: amount sent = m_amount_in - m_change
            if (!pd.m_dests.empty()) {
              for (const auto &dest : pd.m_dests) {
                amount += dest.amount;
              }
            } else if (amount_in >= change) {
              // Scanned transaction - amount_in and change are in source asset
              amount = amount_in - change;
            }
          } else {
            // For SAL transfers: amount = amount_in - change - fee
            if (amount_in >= change + fee) {
              amount = amount_in - change - fee;
            } else if (amount_out > change) {
              amount = amount_out - change;
            }
          }

          const char *state_str = "pending";
          if (pd.m_state ==
              tools::wallet2::unconfirmed_transfer_details::failed) {
            state_str = "failed";
          } else if (pd.m_state ==
                     tools::wallet2::unconfirmed_transfer_details::
                         pending_in_pool) {
            state_str = "pool";
          }

          json << "{"
               << R"("txid":")" << epee::string_tools::pod_to_hex(p.first)
               << R"(",)"
               << R"("payment_id":")"
               << epee::string_tools::pod_to_hex(pd.m_payment_id) << R"(",)"
               << R"("amount":)" << amount << ","
               << R"("asset_type":")" << asset_type << R"(",)"
               << R"("fee":)" << fee << ","
               << R"("timestamp":)" << pd.m_timestamp << ","
               << R"("state":")" << state_str << R"(",)"
               << R"("type":"pending",)"
               << R"("tx_type":)" << static_cast<int>(pd.m_tx.type) << ","
               << R"("subaddr_account":)" << pd.m_subaddr_account << "}";
        }
        json << "]";
      }

      json << "}";
      return json.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      return std::string(R"({"error":")") + e.what() + R"("})";
    }
  }

  // ========================================================================
  // Transaction Creation (Phase 6 - Step 3)
  // ========================================================================

  // Create a transaction and return the signed blob as JSON
  // CRITICAL: Amounts are passed as STRINGS to avoid JavaScript double
  // precision loss JavaScript double only has 53-bit integer precision, but
  // Salvium amounts are 64-bit
  //
  // Prerequisites before calling this function:
  // 1. JS must fetch decoy outputs from daemon via /get_outs.bin
  // 2. JS must call inject_decoy_outputs(binaryData) to cache them
  // 3. JS must fetch output distribution via /get_output_distribution.bin
  // (optional but recommended)
  // 4. JS must call inject_output_distribution(binaryData) to cache it
  //
  // Returns JSON:
  // Success:
  // {"status":"success","transactions":[{"tx_blob":"hex...","tx_key":"hex...","fee":1234567,"amount":100000000}]}
  // Error:   {"status":"error","error":"error message"}
  std::string create_transaction_json(
      const std::string &dest_address_str,
      const std::string
          &amount_str, // Amount as STRING to avoid precision loss!
      double mixin_count_d, double priority_d) {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      // Parse amount safely from string (avoids JavaScript double precision
      // loss)
      uint64_t amount = std::stoull(amount_str);
      uint32_t mixin_count = static_cast<uint32_t>(mixin_count_d);
      uint32_t priority = static_cast<uint32_t>(priority_d);

      // WORKAROUND: If the base_fee for the requested priority is 0,
      // bump up to a priority that has a valid fee. This can happen when
      // the RPC cache doesn't have proper fee estimates for all priorities.
      if (m_wallet->get_base_fee(priority) == 0) {
        for (uint32_t p = priority + 1; p <= 4; ++p) {
          if (m_wallet->get_base_fee(p) > 0) {
            priority = p;
            break;
          }
        }
        // If still 0, try to set a reasonable default (this shouldn't happen)
        if (m_wallet->get_base_fee(priority) == 0) {
          priority =
              2; // Fall back to priority 2 which typically has valid fees
        }
      }

      // Check if wallet has any balance first (sum both SAL and SAL1)
      uint64_t balance = m_wallet->balance(0, "SAL", false) +
                         m_wallet->balance(0, "SAL1", false);
      uint64_t unlocked = m_wallet->unlocked_balance(0, "SAL", false) +
                          m_wallet->unlocked_balance(0, "SAL1", false);

      if (balance == 0) {
        return R"({"status":"error","error":"Wallet has no balance. Need to sync first."})";
      }

      if (unlocked == 0) {
        return R"({"status":"error","error":"No unlocked balance. Funds may still be locked."})";
      }

      if (amount > unlocked) {
        std::ostringstream err;
        err << R"({"status":"error","error":"Insufficient unlocked balance. Requested: )"
            << amount << ", available: " << unlocked << R"("})";
        return err.str();
      }

      // Parse destination address
      cryptonote::address_parse_info info;
      if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(),
                                                    dest_address_str)) {
        return R"({"status":"error","error":"Invalid destination address"})";
      }

      // Setup destination entry
      std::vector<cryptonote::tx_destination_entry> dsts;
      cryptonote::tx_destination_entry dst;
      dst.amount = amount;
      dst.addr = info.address;
      dst.is_subaddress = info.is_subaddress;
      dst.is_integrated = info.has_payment_id;

      // Smart Asset Selection: Check which asset type has enough funds
      uint64_t unlocked_sal = m_wallet->unlocked_balance(0, "SAL", false);
      uint64_t unlocked_sal1 = m_wallet->unlocked_balance(0, "SAL1", false);

      std::string asset_type;
      if (unlocked_sal1 >= amount) {
        asset_type = "SAL1";
      } else if (unlocked_sal >= amount) {
        asset_type = "SAL";
      } else {
        // Default to HF version if neither is sufficient
        const bool is_carrot_hf = m_wallet->get_current_hard_fork() >= 10;
        asset_type = is_carrot_hf ? "SAL1" : "SAL";
      }

      dst.asset_type = asset_type;
      dsts.push_back(dst);

      // Extra field for payment ID if integrated address
      std::vector<uint8_t> extra;
      if (info.has_payment_id) {
        // Add encrypted payment ID to extra
        std::string extra_nonce;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce,
                                                               info.payment_id);
        if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
          return R"({"status":"error","error":"Failed to add payment ID to extra"})";
        }
      }

      // DEBUG: Log pre-TX state
      std_cerr << "[WASM DEBUG] About to call create_transactions_2:"
               << std::endl;
      std_cerr << "  dsts.size()=" << dsts.size() << std::endl;
      std_cerr << "  asset_type=" << asset_type << std::endl;
      std_cerr << "  mixin_count=" << mixin_count << std::endl;
      std_cerr << "  priority=" << priority << std::endl;
      std_cerr << "  extra.size()=" << extra.size() << std::endl;
      std_cerr << "  m_daemon_address="
               << (m_wallet->get_daemon_address().empty()
                       ? "(empty)"
                       : m_wallet->get_daemon_address())
               << std::endl;

      // Create transaction using wallet2's create_transactions_2
      // Parameters:
      // - dsts: destinations
      // - source_asset: SAL or SAL1 based on hardfork
      // - dest_asset: SAL or SAL1 based on hardfork
      // - tx_type: TRANSFER (standard transfer)
      // - fake_outs_count: mixin count (ring size - 1)
      // - unlock_time: 0 (no time lock)
      // - priority: user-specified (0-3)
      // - extra: payment ID if any
      // - subaddr_account: 0 (main account)
      // - subaddr_indices: empty set (use any)
      std::vector<tools::wallet2::pending_tx> ptx_vector =
          m_wallet->create_transactions_2(
              dsts,
              asset_type, // source_asset
              asset_type, // dest_asset
              cryptonote::transaction_type::TRANSFER, mixin_count,
              0, // unlock_time
              priority, extra,
              0, // subaddr_account
              {} // subaddr_indices (empty = use any)
          );

      std_cerr << "[WASM DEBUG] create_transactions_2 returned "
               << ptx_vector.size() << " transactions" << std::endl;

      if (ptx_vector.empty()) {
        return R"({"status":"error","error":"No transactions created"})";
      }

      // Build JSON response with transaction blobs
      std::ostringstream json;
      json << R"({"status":"success","transactions":[)";

      bool first = true;
      for (const auto &ptx : ptx_vector) {
        if (!first)
          json << ",";
        first = false;

        // Convert the signed TX to a hex blob
        std::string tx_blob = epee::string_tools::buff_to_hex_nodelimer(
            cryptonote::tx_to_blob(ptx.tx));

        // Get the Tx Key (needed to prove payment later)
        // Note: tx_key is crypto::secret_key (mlocked), use key_to_hex helper
        std::string tx_key = key_to_hex((const unsigned char *)&ptx.tx_key);

        // Get tx hash
        crypto::hash tx_hash;
        cryptonote::get_transaction_hash(ptx.tx, tx_hash);
        std::string tx_hash_str = epee::string_tools::pod_to_hex(tx_hash);

        json << "{"
             << R"("tx_blob":")" << tx_blob << R"(",)"
             << R"("tx_key":")" << tx_key << R"(",)"
             << R"("tx_hash":")" << tx_hash_str << R"(",)"
             << R"("fee":)" << ptx.fee << ","
             << R"("dust":)" << ptx.dust << ","
             << R"("amount":)" << amount << "}";
      }

      json << "]}";
      return json.str();

    } catch (const tools::error::not_enough_money &e) {
      m_last_error = "Not enough unlocked balance";
      return R"({"status":"error","error":"Not enough unlocked balance. Wallet may need to sync first."})";
    } catch (const tools::error::not_enough_unlocked_money &e) {
      m_last_error = "Not enough unlocked balance";
      return R"({"status":"error","error":"Not enough unlocked balance. Wait for funds to unlock."})";
    } catch (const tools::error::tx_not_possible &e) {
      m_last_error = "Transaction not possible";
      return R"({"status":"error","error":"Transaction not possible with current inputs. Need decoy outputs?"})";
    } catch (const tools::error::no_connection_to_daemon &e) {
      // This error means wallet2 tried to make an RPC call that wasn't cached
      std::string error_details = e.to_string();
      m_last_error = "no connection to daemon";
      // Escape quotes in error message
      size_t pos = 0;
      while ((pos = error_details.find('"', pos)) != std::string::npos) {
        error_details.replace(pos, 1, "'");
        pos += 1;
      }
      std::ostringstream err;
      err << R"({"status":"error","error":"no connection to daemon: )"
          << error_details << R"("})";
      return err.str();
    } catch (const std::exception &e) {
      m_last_error = e.what() ? e.what() : "Unknown error";
      // Escape any quotes in error message
      std::string error_msg = m_last_error;
      size_t pos = 0;
      while ((pos = error_msg.find('"', pos)) != std::string::npos) {
        error_msg.replace(pos, 1, "\\\"");
        pos += 2;
      }
      std::ostringstream err;
      err << R"({"status":"error","error":")" << error_msg << R"("})";
      return err.str();
    } catch (...) {
      m_last_error = "Unknown exception during transaction creation";
      return R"({"status":"error","error":"Unknown exception during transaction creation"})";
    }
  }

  // ========================================================================
  // STAKE Transaction Creation
  // ========================================================================
  // Creates a STAKE transaction to lock SAL/SAL1 for yield rewards
  // The stake returns to the wallet's own address after STAKE_LOCK_PERIOD
  // (21600 blocks, ~30 days)
  //
  // Parameters:
  // - amount_str: Amount to stake (atomic units as STRING for precision)
  // - mixin_count_d: Ring size minus 1 (typically 15)
  // - priority_d: Fee priority (0-3)
  //
  // Returns JSON:
  // Success:
  // {"status":"success","transactions":[{"tx_blob":"hex...","tx_hash":"hex...","fee":1234567,"stake_amount":100000000}]}
  // Error: {"status":"error","error":"error message"}
  std::string create_stake_transaction_json(const std::string &amount_str,
                                            double mixin_count_d,
                                            double priority_d) {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      // Parse amount safely from string (avoids JavaScript double precision
      // loss)
      uint64_t amount = std::stoull(amount_str);
      uint32_t mixin_count = static_cast<uint32_t>(mixin_count_d);
      uint32_t priority = static_cast<uint32_t>(priority_d);

      // WORKAROUND: If the base_fee for the requested priority is 0,
      // bump up to a priority that has a valid fee.
      if (m_wallet->get_base_fee(priority) == 0) {
        for (uint32_t p = priority + 1; p <= 4; ++p) {
          if (m_wallet->get_base_fee(p) > 0) {
            priority = p;
            break;
          }
        }
        if (m_wallet->get_base_fee(priority) == 0) {
          priority = 2;
        }
      }

      // Determine asset type based on hardfork (SAL1 for Carrot, SAL otherwise)
      // NOTE: wallet2.cpp now normalizes all post-fork outputs to SAL1 during scanning
      const bool is_carrot_hf = m_wallet->get_current_hard_fork() >= 10;
      std::string asset_type = is_carrot_hf ? "SAL1" : "SAL";

      // Check balance
      uint64_t unlocked = m_wallet->unlocked_balance(0, asset_type, false);

      // Also check SAL if SAL1 is empty (wallet needs rescan for normalization fix)
      uint64_t unlocked_other = 0;
      if (is_carrot_hf && unlocked == 0) {
        unlocked_other = m_wallet->unlocked_balance(0, "SAL", false);
        if (unlocked_other > 0) {
          std::ostringstream err;
          err << R"({"status":"error","error":"Wallet needs rescan. Funds ()"
              << unlocked_other << R"() are indexed under old asset type. Please restore wallet from seed."})";
          return err.str();
        }
      }

      if (unlocked == 0) {
        return R"({"status":"error","error":"No unlocked balance. Funds may still be locked."})";
      }

      if (amount > unlocked) {
        std::ostringstream err;
        err << R"({"status":"error","error":"Insufficient unlocked balance. Requested: )"
            << amount << ", available: " << unlocked << R"("})";
        return err.str();
      }

      // Get wallet's own address for stake return
      // Use Carrot or PreCarrot derive type based on hardfork
      carrot::AddressDeriveType derive_type =
          is_carrot_hf ? carrot::AddressDeriveType::Carrot
                       : carrot::AddressDeriveType::PreCarrot;

      std::string own_address = m_wallet->get_subaddress_as_str(
          {{0, 0}, derive_type, false}); // Main account, index 0

      // Parse own address to get address_parse_info
      cryptonote::address_parse_info info;
      if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(),
                                                    own_address)) {
        return R"({"status":"error","error":"Failed to parse wallet's own address"})";
      }

      // Setup destination entry for stake return
      std::vector<cryptonote::tx_destination_entry> dsts;
      cryptonote::tx_destination_entry dst;
      dst.amount = amount;
      dst.addr = info.address;
      dst.is_subaddress = info.is_subaddress;
      dst.is_integrated = false;
      dst.asset_type = asset_type;
      dsts.push_back(dst);

      // Empty extra for stake transactions
      std::vector<uint8_t> extra;

      // DEBUG: Log pre-TX state
      std_cerr << "[WASM DEBUG] About to call create_transactions_2 for STAKE:"
               << std::endl;
      std_cerr << "  amount=" << amount << std::endl;
      std_cerr << "  asset_type=" << asset_type << std::endl;
      std_cerr << "  own_address=" << own_address << std::endl;
      std_cerr << "  mixin_count=" << mixin_count << std::endl;
      std_cerr << "  priority=" << priority << std::endl;

      // Create STAKE transaction using wallet2's create_transactions_2
      std::vector<tools::wallet2::pending_tx> ptx_vector =
          m_wallet->create_transactions_2(
              dsts,
              asset_type, // source_asset
              asset_type, // dest_asset
              cryptonote::transaction_type::STAKE, // TX TYPE = STAKE
              mixin_count,
              0, // unlock_time (stake lock is handled by protocol)
              priority, extra,
              0, // subaddr_account
              {} // subaddr_indices (empty = use any)
          );

      std_cerr << "[WASM DEBUG] create_transactions_2 STAKE returned "
               << ptx_vector.size() << " transactions" << std::endl;

      if (ptx_vector.empty()) {
        return R"({"status":"error","error":"No stake transactions created"})";
      }

      // Build JSON response with transaction blobs
      std::ostringstream json;
      json << R"({"status":"success","transactions":[)";

      bool first = true;
      for (const auto &ptx : ptx_vector) {
        if (!first)
          json << ",";
        first = false;

        // Convert the signed TX to a hex blob
        std::string tx_blob = epee::string_tools::buff_to_hex_nodelimer(
            cryptonote::tx_to_blob(ptx.tx));

        // Get the Tx Key
        std::string tx_key = key_to_hex((const unsigned char *)&ptx.tx_key);

        // Get tx hash
        crypto::hash tx_hash;
        cryptonote::get_transaction_hash(ptx.tx, tx_hash);
        std::string tx_hash_str = epee::string_tools::pod_to_hex(tx_hash);

        json << "{"
             << R"("tx_blob":")" << tx_blob << R"(",)"
             << R"("tx_key":")" << tx_key << R"(",)"
             << R"("tx_hash":")" << tx_hash_str << R"(",)"
             << R"("fee":)" << ptx.fee << ","
             << R"("stake_amount":)" << amount << "}";
      }

      json << "]}";
      return json.str();

    } catch (const tools::error::not_enough_money &e) {
      m_last_error = "Not enough unlocked balance";
      return R"({"status":"error","error":"Not enough unlocked balance. Wallet may need to sync first."})";
    } catch (const tools::error::not_enough_unlocked_money &e) {
      m_last_error = "Not enough unlocked balance";
      return R"({"status":"error","error":"Not enough unlocked balance. Wait for funds to unlock."})";
    } catch (const tools::error::tx_not_possible &e) {
      m_last_error = "Transaction not possible";
      return R"({"status":"error","error":"Transaction not possible with current inputs. Need decoy outputs?"})";
    } catch (const tools::error::no_connection_to_daemon &e) {
      std::string error_details = e.to_string();
      m_last_error = "no connection to daemon";
      size_t pos = 0;
      while ((pos = error_details.find('"', pos)) != std::string::npos) {
        error_details.replace(pos, 1, "'");
        pos += 1;
      }
      std::ostringstream err;
      err << R"({"status":"error","error":"no connection to daemon: )"
          << error_details << R"("})";
      return err.str();
    } catch (const std::exception &e) {
      m_last_error = e.what() ? e.what() : "Unknown error";
      std::string error_msg = m_last_error;
      size_t pos = 0;
      while ((pos = error_msg.find('"', pos)) != std::string::npos) {
        error_msg.replace(pos, 1, "\\\"");
        pos += 2;
      }
      std::ostringstream err;
      err << R"({"status":"error","error":")" << error_msg << R"("})";
      return err.str();
    } catch (...) {
      m_last_error = "Unknown exception during stake transaction creation";
      return R"({"status":"error","error":"Unknown exception during stake transaction creation"})";
    }
  }

  // ========================================================================
  // RETURN TRANSACTION - Return funds to original sender
  // ========================================================================
  // Creates a RETURN transaction that sends funds back to the sender of
  // the original transaction. This is used when you want to refund someone
  // who sent you funds.
  //
  // Parameters:
  //   txid: The transaction hash (64 hex chars) of the incoming transaction to return
  //
  // Returns JSON:
  // Success: {"status":"success","transactions":[{"tx_blob":"...","tx_key":"...","tx_hash":"...","fee":123,"return_amount":456},...]}
  // Error: {"status":"error","error":"message"}
  // ========================================================================
  std::string create_return_transaction_json(const std::string &txid) {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      if (txid.empty() || txid.length() != 64) {
        return R"({"status":"error","error":"Invalid txid. Must be 64 hex characters."})";
      }

      // Convert txid string to crypto::hash
      crypto::hash target_txid;
      if (!epee::string_tools::hex_to_pod(txid, target_txid)) {
        return R"({"status":"error","error":"Invalid txid format. Must be valid hex."})";
      }

      // Find all transfer indices that belong to this txid
      std::vector<size_t> transfer_indices;
      size_t num_transfers = m_wallet->get_num_transfer_details();

      std_cerr << "[WASM DEBUG] Searching " << num_transfers << " transfers for txid " << txid << std::endl;

      for (size_t i = 0; i < num_transfers; ++i) {
        const auto& td = m_wallet->get_transfer_details(i);
        if (td.m_txid == target_txid) {
          // Check if this output is unspent and unlocked
          if (!td.m_spent && !td.m_frozen && m_wallet->is_transfer_unlocked(td)) {
            transfer_indices.push_back(i);
            std_cerr << "[WASM DEBUG] Found matching transfer at index " << i
                     << ", amount=" << td.amount() << std::endl;
          } else {
            std_cerr << "[WASM DEBUG] Skipping transfer at index " << i
                     << " (spent=" << td.m_spent
                     << ", frozen=" << td.m_frozen
                     << ", unlocked=" << m_wallet->is_transfer_unlocked(td) << ")" << std::endl;
          }
        }
      }

      if (transfer_indices.empty()) {
        return R"({"status":"error","error":"No returnable outputs found for this transaction. The funds may be spent, locked, or not yet confirmed."})";
      }

      if (transfer_indices.size() > 15) {
        return R"({"status":"error","error":"Too many outputs in this transaction. Maximum is 15."})";
      }

      // Calculate total amount being returned (for response)
      uint64_t total_return_amount = 0;
      for (size_t idx : transfer_indices) {
        const auto& td = m_wallet->get_transfer_details(idx);
        total_return_amount += td.amount();
      }

      // DEBUG: Log pre-TX state
      std_cerr << "[WASM DEBUG] About to call create_transactions_return:" << std::endl;
      std_cerr << "  transfer_indices=[";
      for (size_t i = 0; i < transfer_indices.size(); ++i) {
        if (i > 0) std_cerr << ",";
        std_cerr << transfer_indices[i];
      }
      std_cerr << "]" << std::endl;
      std_cerr << "  total_return_amount=" << total_return_amount << std::endl;

      // Create RETURN transaction using wallet2's create_transactions_return
      std::vector<tools::wallet2::pending_tx> ptx_vector =
          m_wallet->create_transactions_return(transfer_indices);

      std_cerr << "[WASM DEBUG] create_transactions_return returned "
               << ptx_vector.size() << " transactions" << std::endl;

      if (ptx_vector.empty()) {
        return R"({"status":"error","error":"No return transactions created"})";
      }

      // Build JSON response with transaction blobs
      std::ostringstream json;
      json << R"({"status":"success","transactions":[)";

      bool first = true;
      for (const auto &ptx : ptx_vector) {
        if (!first)
          json << ",";
        first = false;

        // Convert the signed TX to a hex blob
        std::string tx_blob = epee::string_tools::buff_to_hex_nodelimer(
            cryptonote::tx_to_blob(ptx.tx));

        // Get the Tx Key
        std::string tx_key = key_to_hex((const unsigned char *)&ptx.tx_key);

        // Get tx hash
        crypto::hash tx_hash;
        cryptonote::get_transaction_hash(ptx.tx, tx_hash);
        std::string tx_hash_str = epee::string_tools::pod_to_hex(tx_hash);

        json << "{"
             << R"("tx_blob":")" << tx_blob << R"(",)"
             << R"("tx_key":")" << tx_key << R"(",)"
             << R"("tx_hash":")" << tx_hash_str << R"(",)"
             << R"("fee":)" << ptx.fee << ","
             << R"("return_amount":)" << total_return_amount << "}";
      }

      json << "]}";
      return json.str();

    } catch (const tools::error::not_enough_money &e) {
      m_last_error = "Not enough unlocked balance";
      return R"({"status":"error","error":"Not enough unlocked balance for return transaction."})";
    } catch (const tools::error::not_enough_unlocked_money &e) {
      m_last_error = "Not enough unlocked balance";
      return R"({"status":"error","error":"Not enough unlocked balance. Wait for funds to unlock."})";
    } catch (const tools::error::tx_not_possible &e) {
      m_last_error = "Transaction not possible";
      return R"({"status":"error","error":"Return transaction not possible with current inputs."})";
    } catch (const tools::error::no_connection_to_daemon &e) {
      std::string error_details = e.to_string();
      m_last_error = "no connection to daemon";
      size_t pos = 0;
      while ((pos = error_details.find('"', pos)) != std::string::npos) {
        error_details.replace(pos, 1, "'");
        pos += 1;
      }
      std::ostringstream err;
      err << R"({"status":"error","error":"no connection to daemon: )"
          << error_details << R"("})";
      return err.str();
    } catch (const std::exception &e) {
      m_last_error = e.what() ? e.what() : "Unknown error";
      std::string error_msg = m_last_error;
      size_t pos = 0;
      while ((pos = error_msg.find('"', pos)) != std::string::npos) {
        error_msg.replace(pos, 1, "\\\"");
        pos += 2;
      }
      std::ostringstream err;
      err << R"({"status":"error","error":")" << error_msg << R"("})";
      return err.str();
    } catch (...) {
      m_last_error = "Unknown exception during return transaction creation";
      return R"({"status":"error","error":"Unknown exception during return transaction creation"})";
    }
  }

  // ========================================================================
  // SWEEP ALL Transaction Creation
  // ========================================================================
  // Creates a transaction that sweeps ALL unlocked funds to a destination address.
  // This is useful for emptying a wallet or consolidating all outputs.
  //
  // Parameters:
  // - dest_address_str: Destination address (standard or integrated)
  // - mixin_count_d: Ring size minus 1 (typically 15)
  // - priority_d: Fee priority (0-3)
  //
  // Returns JSON:
  // Success:
  // {"status":"success","transactions":[{"tx_blob":"hex...","tx_hash":"hex...","tx_key":"hex...","fee":1234567,"amount":100000000}],"total_amount":123456789,"total_fee":12345}
  // Error: {"status":"error","error":"error message"}
  std::string create_sweep_all_transaction_json(
      const std::string &dest_address_str,
      double mixin_count_d, double priority_d) {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      uint32_t mixin_count = static_cast<uint32_t>(mixin_count_d);
      uint32_t priority = static_cast<uint32_t>(priority_d);

      // WORKAROUND: If the base_fee for the requested priority is 0,
      // bump up to a priority that has a valid fee.
      if (m_wallet->get_base_fee(priority) == 0) {
        for (uint32_t p = priority + 1; p <= 4; ++p) {
          if (m_wallet->get_base_fee(p) > 0) {
            priority = p;
            break;
          }
        }
        if (m_wallet->get_base_fee(priority) == 0) {
          priority = 2;
        }
      }

      // Check if wallet has any balance (sum both SAL and SAL1)
      uint64_t balance = m_wallet->balance(0, "SAL", false) +
                         m_wallet->balance(0, "SAL1", false);
      uint64_t unlocked = m_wallet->unlocked_balance(0, "SAL", false) +
                          m_wallet->unlocked_balance(0, "SAL1", false);

      if (balance == 0) {
        return R"({"status":"error","error":"Wallet has no balance. Need to sync first."})";
      }

      if (unlocked == 0) {
        return R"({"status":"error","error":"No unlocked balance. Funds may still be locked."})";
      }

      // Parse destination address
      cryptonote::address_parse_info info;
      if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(),
                                                    dest_address_str)) {
        return R"({"status":"error","error":"Invalid destination address"})";
      }

      // Extra field for payment ID if integrated address
      std::vector<uint8_t> extra;
      if (info.has_payment_id) {
        std::string extra_nonce;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce,
                                                               info.payment_id);
        if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
          return R"({"status":"error","error":"Failed to add payment ID to extra"})";
        }
      }

      // Determine asset type based on hardfork (SAL1 for Carrot, SAL otherwise)
      const bool is_carrot_hf = m_wallet->get_current_hard_fork() >= 10;
      std::string asset_type = is_carrot_hf ? "SAL1" : "SAL";

      // Check if this asset type has balance, otherwise try the other
      uint64_t asset_unlocked = m_wallet->unlocked_balance(0, asset_type, false);
      if (asset_unlocked == 0) {
        // Try the other asset type
        asset_type = (asset_type == "SAL1") ? "SAL" : "SAL1";
        asset_unlocked = m_wallet->unlocked_balance(0, asset_type, false);
        if (asset_unlocked == 0) {
          return R"({"status":"error","error":"No unlocked balance in any asset type"})";
        }
      }

      std_cerr << "[WASM DEBUG] About to call create_transactions_all (sweep_all):"
               << std::endl;
      std_cerr << "  asset_type=" << asset_type << std::endl;
      std_cerr << "  mixin_count=" << mixin_count << std::endl;
      std_cerr << "  priority=" << priority << std::endl;
      std_cerr << "  dest_address=" << dest_address_str << std::endl;

      // Create sweep_all transaction using wallet2's create_transactions_all
      // Parameters:
      // - below: 0 (sweep ALL outputs regardless of size)
      // - tx_type: TRANSFER
      // - asset_type: SAL or SAL1 based on hardfork
      // - address: destination address
      // - is_subaddress: from address parsing
      // - outputs: 1 (single output per tx)
      // - fake_outs_count: mixin count (ring size - 1)
      // - unlock_time: 0 (no time lock)
      // - priority: user-specified (0-3)
      // - extra: payment ID if any
      // - subaddr_account: 0 (main account)
      // - subaddr_indices: empty set (use any subaddress)
      std::vector<tools::wallet2::pending_tx> ptx_vector =
          m_wallet->create_transactions_all(
              0, // below = 0 means sweep ALL outputs
              cryptonote::transaction_type::TRANSFER,
              asset_type,
              info.address,
              info.is_subaddress,
              1, // outputs per tx
              mixin_count,
              0, // unlock_time
              priority,
              extra,
              0, // subaddr_account
              {} // subaddr_indices (empty = use any)
          );

      std_cerr << "[WASM DEBUG] create_transactions_all returned "
               << ptx_vector.size() << " transactions" << std::endl;

      if (ptx_vector.empty()) {
        return R"({"status":"error","error":"No transactions created"})";
      }

      // Build JSON response with transaction blobs
      std::ostringstream json;
      json << R"({"status":"success","transactions":[)";

      uint64_t total_amount = 0;
      uint64_t total_fee = 0;

      bool first = true;
      for (const auto &ptx : ptx_vector) {
        if (!first)
          json << ",";
        first = false;

        // Convert the signed TX to a hex blob
        std::string tx_blob = epee::string_tools::buff_to_hex_nodelimer(
            cryptonote::tx_to_blob(ptx.tx));

        // Get the Tx Key
        std::string tx_key = key_to_hex((const unsigned char *)&ptx.tx_key);

        // Get tx hash
        crypto::hash tx_hash;
        cryptonote::get_transaction_hash(ptx.tx, tx_hash);
        std::string tx_hash_str = epee::string_tools::pod_to_hex(tx_hash);

        // Calculate amount from outputs (for sweep_all, amount varies per tx)
        uint64_t tx_amount = 0;
        for (const auto &dest : ptx.dests) {
          tx_amount += dest.amount;
        }

        total_amount += tx_amount;
        total_fee += ptx.fee;

        json << "{"
             << R"("tx_blob":")" << tx_blob << R"(",)"
             << R"("tx_key":")" << tx_key << R"(",)"
             << R"("tx_hash":")" << tx_hash_str << R"(",)"
             << R"("fee":)" << ptx.fee << ","
             << R"("dust":)" << ptx.dust << ","
             << R"("amount":)" << tx_amount << "}";
      }

      json << "],"
           << R"("total_amount":)" << total_amount << ","
           << R"("total_fee":)" << total_fee << "}";
      return json.str();

    } catch (const tools::error::not_enough_money &e) {
      m_last_error = "Not enough unlocked balance";
      return R"({"status":"error","error":"Not enough unlocked balance. Wallet may need to sync first."})";
    } catch (const tools::error::not_enough_unlocked_money &e) {
      m_last_error = "Not enough unlocked balance";
      return R"({"status":"error","error":"Not enough unlocked balance. Wait for funds to unlock."})";
    } catch (const tools::error::tx_not_possible &e) {
      m_last_error = "Transaction not possible";
      return R"({"status":"error","error":"Transaction not possible with current inputs. Need decoy outputs?"})";
    } catch (const tools::error::no_connection_to_daemon &e) {
      std::string error_details = e.to_string();
      m_last_error = "no connection to daemon";
      size_t pos = 0;
      while ((pos = error_details.find('"', pos)) != std::string::npos) {
        error_details.replace(pos, 1, "'");
        pos += 1;
      }
      std::ostringstream err;
      err << R"({"status":"error","error":"no connection to daemon: )"
          << error_details << R"("})";
      return err.str();
    } catch (const std::exception &e) {
      m_last_error = e.what() ? e.what() : "Unknown error";
      std::string error_msg = m_last_error;
      size_t pos = 0;
      while ((pos = error_msg.find('"', pos)) != std::string::npos) {
        error_msg.replace(pos, 1, "\\\"");
        pos += 2;
      }
      std::ostringstream err;
      err << R"({"status":"error","error":")" << error_msg << R"("})";
      return err.str();
    } catch (...) {
      m_last_error = "Unknown exception during sweep_all transaction creation";
      return R"({"status":"error","error":"Unknown exception during sweep_all transaction creation"})";
    }
  }

  // ========================================================================
  // SPLIT TRANSACTION ARCHITECTURE - Phase 1: Prepare
  // ========================================================================
  // Selects inputs, calculates fee, and determines decoy requirements.
  // Does NOT sign the transaction - that happens in complete_transaction_json.
  //
  // This function will attempt to create a transaction. When it fails due to
  // missing decoys (cache miss), it captures:
  //   1. The exact get_outs request (what outputs the wallet needs)
  //   2. The selected input transfers (which of our outputs will be spent)
  //
  // Returns JSON:
  // Success: {
  //   "status": "prepared",
  //   "uuid": "unique-id-for-this-preparation",
  //   "inputs_selected": [{"index": 0, "amount": "1000000000", "global_index":
  //   12345}, ...], "estimated_fee": "1234567", "decoy_request":
  //   "base64-encoded-binary-request", "asset_type": "SAL1"
  // }
  // Error: {"status":"error","error":"message"}
  //
  // After receiving this response, JavaScript should:
  // 1. Decode the decoy_request and send it to the daemon's /get_outs.bin
  // endpoint
  // 2. Call inject_decoy_outputs_from_json() with the daemon's response
  // 3. Call complete_transaction_json() with the same uuid
  std::string prepare_transaction_json(const std::string &dest_address_str,
                                       const std::string &amount_str,
                                       double mixin_count_d,
                                       double priority_d) {

    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      // Invalidate any previous preparation
      m_prepared_tx.valid = false;

      // Clear any pending get_outs request from previous attempts
      wasm_http_clear_pending_get_outs_request();

      // Parse parameters
      uint64_t amount = std::stoull(amount_str);
      uint32_t mixin_count = static_cast<uint32_t>(mixin_count_d);
      uint32_t priority = static_cast<uint32_t>(priority_d);

      // WORKAROUND: If the base_fee for the requested priority is 0,
      // bump up to a priority that has a valid fee.
      if (m_wallet->get_base_fee(priority) == 0) {
        for (uint32_t p = priority + 1; p <= 4; ++p) {
          if (m_wallet->get_base_fee(p) > 0) {
            priority = p;
            break;
          }
        }
      }

      // Validate destination address
      cryptonote::address_parse_info info;
      if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(),
                                                    dest_address_str)) {
        return R"({"status":"error","error":"Invalid destination address"})";
      }

      // Check balance
      uint64_t unlocked_sal = m_wallet->unlocked_balance(0, "SAL", false);
      uint64_t unlocked_sal1 = m_wallet->unlocked_balance(0, "SAL1", false);

      std::string asset_type;
      if (unlocked_sal1 >= amount) {
        asset_type = "SAL1";
      } else if (unlocked_sal >= amount) {
        asset_type = "SAL";
      } else {
        std::ostringstream err;
        err << R"({"status":"error","error":"Insufficient unlocked balance. SAL: )"
            << unlocked_sal << ", SAL1: " << unlocked_sal1
            << ", needed: " << amount << R"("})";
        return err.str();
      }

      // Build destination
      std::vector<cryptonote::tx_destination_entry> dsts;
      cryptonote::tx_destination_entry dst;
      dst.amount = amount;
      dst.addr = info.address;
      dst.is_subaddress = info.is_subaddress;
      dst.is_integrated = info.has_payment_id;
      dst.asset_type = asset_type;
      dsts.push_back(dst);

      // Build extra (payment ID if integrated address)
      std::vector<uint8_t> extra;
      if (info.has_payment_id) {
        std::string extra_nonce;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce,
                                                               info.payment_id);
        cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
      }

      // Attempt to create transaction - this will fail on cache miss
      // but will capture the get_outs request
      try {
        std::vector<tools::wallet2::pending_tx> ptx_vector =
            m_wallet->create_transactions_2(
                dsts, asset_type, asset_type,
                cryptonote::transaction_type::TRANSFER, mixin_count, 0,
                priority, extra, 0, {});

        // If we get here, transaction was created successfully!
        // This means decoys were already cached. We can return the signed tx
        // directly. But for the split architecture, we still save state and
        // return "prepared" so the caller can call complete_transaction_json if
        // they want.

        // Actually, if this succeeds, there's no need for the split flow.
        // Let's return the actual transaction data instead.
        if (!ptx_vector.empty()) {
          std::ostringstream json;
          json
              << R"({"status":"ready","message":"Decoys already cached, transaction ready","transactions":[)";

          bool first = true;
          for (const auto &ptx : ptx_vector) {
            if (!first)
              json << ",";
            first = false;

            std::string tx_blob = epee::string_tools::buff_to_hex_nodelimer(
                cryptonote::tx_to_blob(ptx.tx));
            std::string tx_key = key_to_hex((const unsigned char *)&ptx.tx_key);
            crypto::hash tx_hash;
            cryptonote::get_transaction_hash(ptx.tx, tx_hash);
            std::string tx_hash_str = epee::string_tools::pod_to_hex(tx_hash);

            json << "{"
                 << R"("tx_blob":")" << tx_blob << R"(",)"
                 << R"("tx_key":")" << tx_key << R"(",)"
                 << R"("tx_hash":")" << tx_hash_str << R"(",)"
                 << R"("fee":)" << ptx.fee << ","
                 << R"("amount":)" << amount << "}";
          }
          json << "]}";
          return json.str();
        }

      } catch (const tools::error::no_connection_to_daemon &e) {
        // Expected! This means get_outs cache miss occurred.
        // The request has been captured in the pending queue.
      } catch (const tools::error::not_enough_money &e) {
        return R"({"status":"error","error":"Not enough money"})";
      } catch (const tools::error::not_enough_unlocked_money &e) {
        return R"({"status":"error","error":"Not enough unlocked money"})";
      } catch (const tools::error::tx_not_possible &e) {
        return R"({"status":"error","error":"Transaction not possible with current inputs"})";
      }

      // Check if we captured a get_outs request
      if (!wasm_http_has_pending_get_outs_request()) {
        return R"({"status":"error","error":"No decoy request captured - unexpected state"})";
      }

      // Get the request body
      const char *base64_request =
          wasm_http_get_pending_get_outs_request_base64();
      if (!base64_request || strlen(base64_request) == 0) {
        return R"({"status":"error","error":"Failed to get decoy request body"})";
      }

      // Decode the request to find selected transfers
      std::string decoded_request =
          epee::string_encoding::base64_decode(base64_request);
      std::vector<size_t> selected_transfers =
          find_selected_transfers_from_request(decoded_request, asset_type);

      // Note: if selected_transfers is empty, we can still proceed but won't
      // freeze inputs

      // Estimate fee (rough estimate)
      uint64_t base_fee = m_wallet->get_base_fee(priority);
      uint64_t estimated_fee = base_fee * 2000; // ~2KB transaction

      // Generate UUID for this preparation
      std::string uuid = generate_tx_uuid();

      // Store preparation state
      m_prepared_tx.valid = true;
      m_prepared_tx.uuid = uuid;
      m_prepared_tx.selected_transfers = selected_transfers;
      m_prepared_tx.dest_address = dest_address_str;
      m_prepared_tx.amount = amount;
      m_prepared_tx.mixin_count = mixin_count;
      m_prepared_tx.priority = priority;
      m_prepared_tx.asset_type = asset_type;
      m_prepared_tx.extra = extra;
      m_prepared_tx.estimated_fee = estimated_fee;

      // Build response JSON
      std::ostringstream json;
      json << R"({"status":"prepared",)"
           << R"("uuid":")" << uuid << R"(",)"
           << R"("asset_type":")" << asset_type << R"(",)"
           << R"("amount":")" << amount << R"(",)"
           << R"("estimated_fee":")" << estimated_fee << R"(",)"
           << R"("decoy_request":")" << base64_request << R"(",)"
           << R"("inputs_selected":[)";

      bool first = true;
      for (size_t idx : selected_transfers) {
        if (!first)
          json << ",";
        first = false;
        const auto &td = m_wallet->m_transfers[idx];
        json << "{"
             << R"("index":)" << idx << ","
             << R"("amount":")" << td.amount() << R"(",)"
             << R"("global_index":)" << td.m_global_output_index << "}";
      }
      json << "]}";
      return json.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      std::ostringstream err;
      err << R"({"status":"error","error":")" << e.what() << R"("})";
      return err.str();
    }
  }

  // ========================================================================
  // SPLIT TRANSACTION ARCHITECTURE - Phase 2: Complete
  // ========================================================================
  // Signs the transaction using previously prepared data and cached decoys.
  //
  // Prerequisites:
  // 1. prepare_transaction_json() was called and returned status="prepared"
  // 2. JavaScript fetched decoys from daemon using the decoy_request
  // 3. JavaScript called inject_decoy_outputs_from_json() with the response
  //
  // The uuid parameter must match the one returned by prepare_transaction_json.
  //
  // Returns JSON:
  // Success: {
  //   "status": "success",
  //   "transactions": [{
  //     "tx_blob": "hex...",
  //     "tx_key": "hex...",
  //     "tx_hash": "hex...",
  //     "fee": 1234567,
  //     "amount": 100000000
  //   }]
  // }
  // Error: {"status":"error","error":"message"}
  std::string complete_transaction_json(const std::string &uuid) {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      // Validate preparation state
      if (!m_prepared_tx.valid) {
        return R"({"status":"error","error":"No prepared transaction. Call prepare_transaction_json first."})";
      }

      if (m_prepared_tx.uuid != uuid) {
        std::ostringstream err;
        err << R"({"status":"error","error":"UUID mismatch. Expected: )"
            << m_prepared_tx.uuid << ", got: " << uuid << R"("})";
        return err.str();
      }

      // Strategy: Freeze all transfers EXCEPT the selected ones
      // This forces create_transactions_2 to use exactly those inputs
      std::vector<size_t> frozen_indices;

      if (!m_prepared_tx.selected_transfers.empty()) {
        std::unordered_set<size_t> selected_set(
            m_prepared_tx.selected_transfers.begin(),
            m_prepared_tx.selected_transfers.end());

        for (size_t i = 0; i < m_wallet->m_transfers.size(); ++i) {
          auto &td = m_wallet->m_transfers[i];
          if (td.asset_type != m_prepared_tx.asset_type)
            continue;
          if (td.m_spent)
            continue;
          if (td.m_frozen)
            continue; // Already frozen, skip

          if (selected_set.find(i) == selected_set.end()) {
            // Not in selected set - freeze it
            m_wallet->freeze(i);
            frozen_indices.push_back(i);
          }
        }
      }

      // Build destination from stored state
      cryptonote::address_parse_info info;
      if (!cryptonote::get_account_address_from_str(
              info, m_wallet->nettype(), m_prepared_tx.dest_address)) {
        // Thaw before returning error
        for (size_t idx : frozen_indices) {
          m_wallet->thaw(idx);
        }
        return R"({"status":"error","error":"Invalid stored destination address"})";
      }

      std::vector<cryptonote::tx_destination_entry> dsts;
      cryptonote::tx_destination_entry dst;
      dst.amount = m_prepared_tx.amount;
      dst.addr = info.address;
      dst.is_subaddress = info.is_subaddress;
      dst.is_integrated = info.has_payment_id;
      dst.asset_type = m_prepared_tx.asset_type;
      dsts.push_back(dst);

      std::string result;
      try {
        // Now create the transaction - should succeed with cached decoys
        std::vector<tools::wallet2::pending_tx> ptx_vector =
            m_wallet->create_transactions_2(
                dsts, m_prepared_tx.asset_type, m_prepared_tx.asset_type,
                cryptonote::transaction_type::TRANSFER,
                m_prepared_tx.mixin_count,
                0, // unlock_time
                m_prepared_tx.priority, m_prepared_tx.extra,
                0, // subaddr_account
                {} // subaddr_indices
            );

        // Thaw all frozen transfers
        for (size_t idx : frozen_indices) {
          m_wallet->thaw(idx);
        }

        if (ptx_vector.empty()) {
          m_prepared_tx.valid = false;
          return R"({"status":"error","error":"No transactions created"})";
        }

        // Build success response
        std::ostringstream json;
        json << R"({"status":"success","transactions":[)";

        bool first = true;
        for (const auto &ptx : ptx_vector) {
          if (!first)
            json << ",";
          first = false;

          std::string tx_blob = epee::string_tools::buff_to_hex_nodelimer(
              cryptonote::tx_to_blob(ptx.tx));
          std::string tx_key = key_to_hex((const unsigned char *)&ptx.tx_key);
          crypto::hash tx_hash;
          cryptonote::get_transaction_hash(ptx.tx, tx_hash);
          std::string tx_hash_str = epee::string_tools::pod_to_hex(tx_hash);

          json << "{"
               << R"("tx_blob":")" << tx_blob << R"(",)"
               << R"("tx_key":")" << tx_key << R"(",)"
               << R"("tx_hash":")" << tx_hash_str << R"(",)"
               << R"("fee":)" << ptx.fee << ","
               << R"("dust":)" << ptx.dust << ","
               << R"("amount":)" << m_prepared_tx.amount << "}";
        }
        json << "]}";

        result = json.str();

        // Invalidate preparation state after successful completion
        m_prepared_tx.valid = false;

      } catch (const tools::error::no_connection_to_daemon &e) {
        // Thaw before returning error
        for (size_t idx : frozen_indices) {
          m_wallet->thaw(idx);
        }
        m_prepared_tx.valid = false;
        return R"({"status":"error","error":"Decoys still not cached. Did you call inject_decoy_outputs?"})";

      } catch (const tools::error::not_enough_money &e) {
        for (size_t idx : frozen_indices) {
          m_wallet->thaw(idx);
        }
        m_prepared_tx.valid = false;
        return R"({"status":"error","error":"Not enough money"})";

      } catch (const tools::error::not_enough_unlocked_money &e) {
        for (size_t idx : frozen_indices) {
          m_wallet->thaw(idx);
        }
        m_prepared_tx.valid = false;
        return R"({"status":"error","error":"Not enough unlocked money"})";

      } catch (const tools::error::tx_not_possible &e) {
        for (size_t idx : frozen_indices) {
          m_wallet->thaw(idx);
        }
        m_prepared_tx.valid = false;
        return R"({"status":"error","error":"Transaction not possible"})";
      }

      return result;

    } catch (const std::exception &e) {
      m_prepared_tx.valid = false;
      m_last_error = e.what();
      std::ostringstream err;
      err << R"({"status":"error","error":")" << e.what() << R"("})";
      return err.str();
    }
  }

  // ========================================================================
  // SPLIT TRANSACTION ARCHITECTURE - Utility: Clear Prepared State
  // ========================================================================
  // Cancels any pending prepared transaction.
  void clear_prepared_transaction() {
    m_prepared_tx.valid = false;
    m_prepared_tx.selected_transfers.clear();
  }

  // ========================================================================
  // SPLIT TRANSACTION ARCHITECTURE - Utility: Get Prepared State Info
  // ========================================================================
  // Returns JSON with info about any pending prepared transaction.
  std::string get_prepared_transaction_info() {
    if (!m_prepared_tx.valid) {
      return R"({"status":"none"})";
    }

    std::ostringstream json;
    json << R"({"status":"pending",)"
         << R"("uuid":")" << m_prepared_tx.uuid << R"(",)"
         << R"("asset_type":")" << m_prepared_tx.asset_type << R"(",)"
         << R"("amount":")" << m_prepared_tx.amount << R"(",)"
         << R"("estimated_fee":")" << m_prepared_tx.estimated_fee << R"(",)"
         << R"("inputs_count":)" << m_prepared_tx.selected_transfers.size()
         << "}";
    return json.str();
  }

  // Estimate transaction fee without creating the transaction
  // Returns JSON: {"status":"success","fee":1234567,"fee_per_byte":123}
  // Or:           {"status":"error","error":"message"}
  std::string estimate_fee_json(const std::string &amount_str,
                                double mixin_count_d, double priority_d) {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      uint64_t amount = std::stoull(amount_str);
      uint32_t priority = static_cast<uint32_t>(priority_d);

      // Get fee estimation from wallet
      uint64_t base_fee = m_wallet->get_base_fee(priority);
      uint64_t fee_quantization_mask = m_wallet->get_fee_quantization_mask();

      // Rough estimate: ~2KB transaction with typical ring size
      uint64_t estimated_size = 2000; // bytes
      uint64_t estimated_fee = base_fee * estimated_size;

      // Apply quantization
      if (fee_quantization_mask > 0) {
        estimated_fee = (estimated_fee + fee_quantization_mask - 1) /
                        fee_quantization_mask * fee_quantization_mask;
      }

      std::ostringstream json;
      json << R"({"status":"success",)"
           << R"("estimated_fee":)" << estimated_fee << ","
           << R"("base_fee":)" << base_fee << ","
           << R"("priority":)" << priority << "}";

      return json.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      std::ostringstream err;
      err << R"({"status":"error","error":")" << e.what() << R"("})";
      return err.str();
    }
  }

  // ========================================================================
  // OUTPUT EXPORT/IMPORT - For persisting wallet state across page refreshes
  // NOTE: We removed the assert(false) in wallet2.cpp::import_outputs to make
  // this work.
  // ========================================================================

  // Export all wallet outputs to hex string for storage in localStorage
  // This allows restoring spendable outputs after page refresh
  // Returns JSON: {"status":"success","outputs_hex":"...", "count": N}
  std::string export_outputs_hex() {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      // Export all outputs using wallet2's standard export
      std::string outputs_str = m_wallet->export_outputs_to_str(true /* all */);
      std::string outputs_hex =
          epee::string_tools::buff_to_hex_nodelimer(outputs_str);

      // Get count for diagnostic
      auto outputs_tuple = m_wallet->export_outputs(true);
      size_t count = std::get<2>(outputs_tuple).size();

      std::ostringstream json;
      json << R"({"status":"success",)"
           << R"("outputs_hex":")" << outputs_hex << R"(",)"
           << R"("count":)" << count << "}";

      fprintf(
          stderr,
          "[WASM] export_outputs_hex: exported %zu outputs (%zu bytes hex)\n",
          count, outputs_hex.size());
      return json.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      std::ostringstream err;
      err << R"({"status":"error","error":")" << e.what() << R"("})";
      return err.str();
    }
  }

  // Import wallet outputs from hex string (from localStorage)
  // This restores spendable outputs after page refresh
  // Returns JSON: {"status":"success","num_imported": N}
  std::string import_outputs_hex(const std::string &outputs_hex) {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      if (outputs_hex.empty()) {
        return R"({"status":"success","num_imported":0})";
      }

      // Convert hex to binary
      std::string outputs_str;
      if (!epee::string_tools::parse_hexstr_to_binbuff(outputs_hex,
                                                       outputs_str)) {
        return R"({"status":"error","error":"Invalid hex string"})";
      }

      fprintf(stderr,
              "[WASM] import_outputs_hex: attempting import (%zu bytes)...\n",
              outputs_str.size());

      // Use wallet2's standard import (with assert(false) removed)
      size_t num_imported = m_wallet->import_outputs_from_str(outputs_str);

      fprintf(stderr, "[WASM] import_outputs_hex: imported %zu outputs\n",
              num_imported);

      std::ostringstream json;
      json << R"({"status":"success",)"
           << R"("num_imported":)" << num_imported << "}";
      return json.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      fprintf(stderr, "[WASM] import_outputs_hex failed: %s\n", e.what());
      std::ostringstream err;
      err << R"({"status":"error","error":")" << e.what() << R"("})";
      return err.str();
    }
  }

  // ========================================================================
  // FULL WALLET CACHE EXPORT/IMPORT
  // Unlike export_outputs which uses a minimal format (losing m_tx data),
  // these functions serialize the FULL wallet state using the native
  // serialization machinery. This preserves everything including:
  // - Full m_tx in each transfer_details (needed for get_public_key())
  // - Key images
  // - Transaction history
  // - All wallet metadata
  // ========================================================================

  // Export full wallet cache to hex string
  // This uses wallet2's native serialization (without encryption - we let JS
  // handle that) Returns JSON: {"status":"success","cache_hex":"...",
  // "transfers":N, "bytes":N}
  std::string export_wallet_cache_hex() {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      // Use wallet2's get_cache_file_data() which serializes EVERYTHING
      auto cache_opt = m_wallet->get_cache_file_data();
      if (!cache_opt) {
        return R"({"status":"error","error":"Failed to get cache file data"})";
      }

      // The cache_file_data contains encrypted data + IV
      // Serialize the whole thing as binary using binary_archive
      // Note: need non-const copy for serialization
      tools::wallet2::cache_file_data cache_data = cache_opt.get();

      std::ostringstream oss;
      binary_archive<true> oar(oss);
      bool serialize_ok = ::serialization::serialize(oar, cache_data);
      if (!serialize_ok) {
        return R"({"status":"error","error":"Failed to serialize cache data"})";
      }
      std::string binary_data = oss.str();

      // Convert to hex for storage
      std::string cache_hex =
          epee::string_tools::buff_to_hex_nodelimer(binary_data);

      size_t num_transfers = m_wallet->get_num_transfer_details();

      fprintf(stderr,
              "[WASM] export_wallet_cache_hex: exported %zu transfers, %zu "
              "bytes -> %zu hex chars\n",
              num_transfers, binary_data.size(), cache_hex.size());

      std::ostringstream json;
      json << R"({"status":"success",)"
           << R"("cache_hex":")" << cache_hex << R"(",)"
           << R"("transfers":)" << num_transfers << ","
           << R"("bytes":)" << binary_data.size() << "}";
      return json.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      fprintf(stderr, "[WASM] export_wallet_cache_hex failed: %s\n", e.what());
      std::ostringstream err;
      err << R"({"status":"error","error":")" << e.what() << R"("})";
      return err.str();
    }
  }

  // Import full wallet cache from hex string
  // This restores the complete wallet state including all transfer_details with
  // m_tx Returns JSON: {"status":"success","transfers":N}
  std::string import_wallet_cache_hex(const std::string &cache_hex) {
    if (!m_initialized) {
      return R"({"status":"error","error":"Wallet not initialized"})";
    }

    try {
      if (cache_hex.empty()) {
        return R"({"status":"success","transfers":0,"message":"Empty cache"})";
      }

      // Convert hex to binary
      std::string binary_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(cache_hex,
                                                       binary_data)) {
        return R"({"status":"error","error":"Invalid hex string"})";
      }

      fprintf(stderr, "[WASM] import_wallet_cache_hex: parsing %zu bytes...\n",
              binary_data.size());

      // Parse the cache_file_data structure using binary_archive
      tools::wallet2::cache_file_data cache_data;
      binary_archive<false> ar_parse{epee::strspan<std::uint8_t>(binary_data)};
      bool parse_ok = ::serialization::serialize(ar_parse, cache_data);
      if (!parse_ok || !::serialization::check_stream_state(ar_parse)) {
        return R"({"status":"error","error":"Failed to parse cache data structure"})";
      }

      fprintf(stderr,
              "[WASM] import_wallet_cache_hex: decrypting cache (%zu bytes, iv "
              "present)...\n",
              cache_data.cache_data.size());

      // Decrypt the cache using wallet's cache key
      std::string decrypted;
      decrypted.resize(cache_data.cache_data.size());

      // Get the cache key from wallet (derived from password/keys)
      crypto::chacha_key cache_key = m_wallet->get_cache_key();

      crypto::chacha20(cache_data.cache_data.data(),
                       cache_data.cache_data.size(), cache_key, cache_data.iv,
                       &decrypted[0]);

      // Deserialize the wallet state
      fprintf(
          stderr,
          "[WASM] import_wallet_cache_hex: deserializing wallet state...\n");

      binary_archive<false> ar{epee::strspan<std::uint8_t>(decrypted)};
      bool loaded = ::serialization::serialize(ar, *m_wallet);
      if (!loaded || !::serialization::check_stream_state(ar)) {
        // Try with varint bug compatibility
        binary_archive<false> ar2{epee::strspan<std::uint8_t>(decrypted)};
        ar2.enable_varint_bug_backward_compatibility();
        loaded = ::serialization::serialize(ar2, *m_wallet);
        if (!loaded || !::serialization::check_stream_state(ar2)) {
          return R"({"status":"error","error":"Failed to deserialize wallet cache"})";
        }
      }

      size_t num_transfers = m_wallet->get_num_transfer_details();

      fprintf(stderr,
              "[WASM] import_wallet_cache_hex: restored %zu transfers\n",
              num_transfers);

      std::ostringstream json;
      json << R"({"status":"success",)"
           << R"("transfers":)" << num_transfers << "}";
      return json.str();

    } catch (const std::exception &e) {
      m_last_error = e.what();
      fprintf(stderr, "[WASM] import_wallet_cache_hex failed: %s\n", e.what());
      std::ostringstream err;
      err << R"({"status":"error","error":")" << e.what() << R"("})";
      return err.str();
    }
  }

  // ========================================================================
  // MANUAL AUDIT TRANSACTION PARSER
  // AUDIT transactions contain salvium_input_data_t which has type mismatches
  // between native (64-bit size_t) and WASM32. This function manually parses
  // the critical fields we need for scanning.
  // ========================================================================
  bool parse_audit_tx_manually(const std::string &tx_blob,
                               cryptonote::transaction &tx,
                               crypto::hash &tx_hash) {
    try {
      // First, get tx hash from blob
      crypto::cn_fast_hash(tx_blob.data(), tx_blob.size(), tx_hash);

      // Standard parsing attempt removed to force manual parsing logic
      // when this function is called explicitly.

      const uint8_t *data = reinterpret_cast<const uint8_t *>(tx_blob.data());
      size_t size = tx_blob.size();
      size_t offset = 0;

      // Helper to read varint
      auto read_varint = [&]() -> uint64_t {
        uint64_t result = 0;
        int shift = 0;
        while (offset < size) {
          uint8_t byte = data[offset++];
          result |= (uint64_t)(byte & 0x7F) << shift;
          if ((byte & 0x80) == 0)
            break;
          shift += 7;
        }
        return result;
      };

      // Helper to read string (varint length + bytes)
      auto read_string = [&]() {
        uint64_t str_len = read_varint();
        if (str_len > 0) {
          if (offset + str_len <= size) {
            offset += str_len; // Skip the string bytes
          } else {
            offset = size; // Clamp to end to trigger error if needed
          }
        }
      };

      // Parse transaction prefix
      tx.version = read_varint();     // Usually 2, 3, or 4 (Carrot)
      tx.unlock_time = read_varint(); // Usually 0

      // Parse vin (inputs) - READ ONLY, just skip to reach footer
      uint64_t vin_count = read_varint();
      // [DEBUG_FIX] NOT resizing tx.vin - keeping standard parser data
      for (uint64_t i = 0; i < vin_count; i++) {
        uint8_t input_type = data[offset++];
        if (input_type == 0x02) { // txin_to_key
          // Skip amount
          read_varint();

          // CRITICAL FIX: Read asset_type string (skip it)
          uint64_t str_len = read_varint();
          if (str_len > 0) {
            if (offset + str_len <= size) {
              offset += str_len;
            } else {
              offset = size;
            }
          }

          // Skip key_offsets
          uint64_t mixin = read_varint();
          for (uint64_t j = 0; j < mixin; j++) {
            read_varint();
          }
          // Skip key image (32 bytes)
          if (offset + 32 <= size) {
            offset += 32;
          }
          // [DEBUG_FIX] NOT assigning to tx.vin[i] - keeping standard parser
          // data
        } else if (input_type == 0xff) {
          // Coinbase/Gen input. Not needed for return_address.
          // Silently fail/return to reduce log noise.
          return false;
        } else {
          // Unknown input type, parsing failed
          return false;
        }
      }

      // Parse vout (outputs) - READ ONLY, just skip to reach footer
      uint64_t vout_count = read_varint();
      // [DEBUG_FIX] NOT resizing tx.vout - keeping standard parser data
      for (uint64_t i = 0; i < vout_count; i++) {
        read_varint(); // Skip amount

        uint8_t output_type = data[offset++];
        if (output_type == 0x02) { // txout_to_key
          // Skip key (32 bytes)
          if (offset + 32 <= size) {
            offset += 32;
          }
          // Skip asset_type and unlock_time
          read_string();
          read_varint();
          // [DEBUG_FIX] NOT assigning to tx.vout[i].target
        } else if (output_type == 0x03) { // txout_to_tagged_key
          // Skip key (32 bytes)
          if (offset + 32 <= size) {
            offset += 32;
          }
          // Skip asset_type, unlock_time, view_tag
          read_string();
          read_varint();
          if (offset + 1 <= size) {
            offset += 1;
          }
          // [DEBUG_FIX] NOT assigning to tx.vout[i].target
        } else if (output_type == 0x04) { // txout_to_carrot_v1
          // Fields: key(32), asset_type(string), view_tag(3), anchor(16)

          // 1. Key (32 bytes)
          if (offset + 32 <= size) {
            offset += 32;
          }

          // 2. Asset Type (string)
          read_string();

          // 3. View Tag (3 bytes) - defined in carrot_core/core_types.h
          if (offset + 3 <= size) {
            offset += 3;
          }

          // 4. Encrypted Janus Anchor (16 bytes)
          if (offset + 16 <= size) {
            offset += 16;
          }

          // Note: We don't store this in tx.vout target variant because
          // we are only parsing manually to reach the footer (return_address).

        } else {
          // Unknown output type
          return false;
        }
      }

      // Parse extra - READ ONLY, just skip
      uint64_t extra_size = read_varint();
      // [DEBUG_FIX] NOT resizing tx.extra - keeping standard parser data
      if (offset + extra_size <= size) {
        offset += extra_size;
      }

      // CRITICAL FIX: tx_type is a varint AFTER extra
      uint64_t tx_type_val = read_varint();
      // FIX: Assign type to tx so it's available after parsing
      tx.type = static_cast<cryptonote::transaction_type>(tx_type_val);

      // Parse AUDIT/STAKE transaction fields using the PARSED tx_type_val
      // (NOT tx.type, which may be 0 if tx is a fresh temporary object)
      if (tx_type_val ==
              static_cast<uint64_t>(cryptonote::transaction_type::AUDIT) ||
          tx_type_val ==
              static_cast<uint64_t>(cryptonote::transaction_type::STAKE)) {

        // amount_burnt (varint) - PUBLIC field
        tx.amount_burnt = read_varint();

        // CRITICAL FIX: Compare version for Protocol TX Data vs Legacy Fields
        // TRANSACTION_VERSION_CARROT is 4
        if (tx.version >= 4) {
          // Parse protocol_tx_data
          // Fields: version(varint), return_address(32), return_pubkey(32), ...

          read_varint(); // protocol_version

          // Read return_address
          if (offset + 32 <= size) {
            memcpy(&tx.return_address, data + offset, 32);
            offset += 32;
          }
          // We can stop here! We have what we need.
          return true;
        } else {
          // Legacy (Pre-Carrot) Structure
          // Fields: return_address(32), return_pubkey(32), ...

          if (offset + 32 <= size) {
            memcpy(&tx.return_address, data + offset, 32);
            offset += 32;
          }
          // We can stop here as well.
          return true;
        }
      }
      return true;
    } catch (...) {
      return false;
    }
  }

  // ========================================================================
  // EXTRACT SALVIUM_DATA.SPEND_PUBKEY FROM RAW TRANSACTION BLOB
  // This function scans the raw transaction blob to find and extract the
  // spend_pubkey from salvium_data. Used to fix corrupted parsing due to
  // WASM32/64 type mismatches in salvium_input_data_t.
  // ========================================================================
  bool extract_salvium_data_spend_pubkey(const std::string &tx_blob,
                                         crypto::public_key &spend_pubkey) {
    try {
      const uint8_t *data = reinterpret_cast<const uint8_t *>(tx_blob.data());
      size_t size = tx_blob.size();
      size_t offset = 0;

      // Helper to read varint with bounds checking
      auto read_varint = [&]() -> uint64_t {
        uint64_t result = 0;
        int shift = 0;
        while (offset < size &&
               shift < 63) { // Add shift limit to prevent infinite loop
          uint8_t byte = data[offset++];
          result |= (uint64_t)(byte & 0x7F) << shift;
          if ((byte & 0x80) == 0)
            break;
          shift += 7;
        }
        return result;
      };

      // Helper to read string (varint length + bytes) - used for asset_type
      auto read_string = [&]() {
        uint64_t str_len = read_varint();
        if (str_len > 0 && offset + str_len <= size) {
          offset += str_len; // Skip the string bytes
        }
      };

      // Skip transaction prefix:
      // version (varint)
      read_varint();
      // unlock_time (varint)
      read_varint();

      // Skip vin (inputs)
      // Salvium txin_to_key format: amount(varint), asset_type(string),
      // key_offsets(vector), k_image(32 bytes)
      uint64_t vin_count = read_varint();
      for (uint64_t i = 0; i < vin_count; i++) {
        if (offset >= size)
          return false;
        uint8_t input_type = data[offset++];
        if (input_type == 0x02) { // txin_to_key
          read_varint();          // amount
          read_string(); // asset_type (e.g., "SAL1") - THIS WAS MISSING!
          uint64_t mixin = read_varint(); // key_offsets count
          for (uint64_t j = 0; j < mixin; j++) {
            read_varint(); // key_offset
          }
          if (offset + 32 > size)
            return false;
          offset += 32; // key_image (k_image)
        } else {
          return false; // Unknown input type
        }
      }

      // Skip vout (outputs)
      // Salvium output formats include asset_type and unlock_time fields
      uint64_t vout_count = read_varint();
      for (uint64_t i = 0; i < vout_count; i++) {
        read_varint(); // amount
        if (offset >= size)
          return false;
        uint8_t output_type = data[offset++];
        if (output_type == 0x02) { // txout_to_key
          if (offset + 32 > size)
            return false;
          offset += 32;                   // key
          read_string();                  // asset_type
          read_varint();                  // unlock_time
        } else if (output_type == 0x03) { // txout_to_tagged_key
          if (offset + 32 > size)
            return false;
          offset += 32;                   // key
          read_string();                  // asset_type
          read_varint();                  // unlock_time
          offset += 1;                    // view_tag
        } else if (output_type == 0x04) { // txout_to_carrot_v1
          if (offset + 32 > size)
            return false;
          offset += 32;  // key
          read_string(); // asset_type
          offset += 1;   // view_tag
          offset += 16;  // encrypted_janus_anchor
                         // (carrot::encrypted_janus_anchor_t is 16 bytes)
        } else {
          return false; // Unknown output type
        }
      }

      // Skip extra
      uint64_t extra_size = read_varint();
      offset += extra_size;

      // Read tx_type (varint) - CRITICAL FIX: tx_type is AFTER extra, not RCT
      // type!
      uint64_t tx_type = read_varint();

      // For AUDIT transactions (type 8), we need to skip more prefix fields
      // before RCT
      if (tx_type == 8) {        // AUDIT
        read_varint();           // amount_burnt
        offset += 32;            // return_address (crypto::public_key)
        offset += 32;            // return_pubkey (crypto::public_key)
        read_string();           // source_asset_type ("SAL")
        read_string();           // destination_asset_type ("SAL")
        read_varint();           // amount_slippage_limit
      } else if (tx_type == 6) { // STAKE
        read_varint();           // amount_burnt
        // STAKE with CARROT uses protocol_tx_data, without uses
        // return_address/return_pubkey For now, skip return_address and
        // return_pubkey
        offset += 32;  // return_address
        offset += 32;  // return_pubkey
        read_string(); // source_asset_type
        read_string(); // destination_asset_type
        read_varint(); // amount_slippage_limit
      }

      // Now we're at rct_signatures
      // Skip RCT type (1 byte)
      offset += 1;

      // Skip txnFee (varint)
      read_varint();

      // Read salvium_data_type (varint)
      uint64_t salvium_data_type = read_varint();

      // Skip pr_proof (96 bytes)
      offset += 96;

      // Skip sa_proof (96 bytes)
      offset += 96;

      // SalviumZeroAudit = 1
      if (salvium_data_type == 1) {
        // Skip cz_proof (96 bytes)
        offset += 96;

        // Skip input_verification_data
        uint64_t ivd_count = read_varint();
        for (uint64_t i = 0; i < ivd_count; i++) {
          offset += 32;                         // aR
          read_varint();                        // amount
          read_varint();                        // i
          uint64_t origin_type = read_varint(); // origin_tx_type
          if (origin_type != 0) {               // not UNSET
            offset += 32;                       // aR_stake
            read_varint();                      // i_stake
          }
        }

        // Read spend_pubkey (32 bytes)
        if (offset + 32 <= size) {
          memcpy(&spend_pubkey, data + offset, 32);
          return true;
        }
      }

      return false;
    } catch (...) {
      return false;
    }
  }

  // ========================================================================
  // SPARSE TRANSACTION INGESTION
  inline static constexpr const char *SPARSE_GUARDRAILS_BUILD =
      "BUILD_2026_01_09_PRODUCTION_DEBUG_DISABLED";
  //
  // Supported formats:
  // - v2: [TxCount:4] + per tx:
  //     [GlobalIndex:4][BlockHeight:4][OutputIndexCount:2][OutputIndices:4*count][TxSize:4][TxBlob]
  // - v3: [Magic:4='SPR3'][TxCount:4] + per tx:
  //     [GlobalIndex:4][BlockHeight:4][TxHash:32][OutputIndexCount:2][OutputIndices:4*count][TxSize:4][TxBlob]
  //
  // CRITICAL: For STAKE/AUDIT and PROTOCOL transactions to be correctly
  // detected, transactions MUST be processed in blockchain height order.
  // STAKE/AUDIT tx change outputs create entries in the subaddress map that
  // PROTOCOL returns depend on.
  // ========================================================================
  std::string ingest_sparse_transactions(uintptr_t ptr, size_t size,
                                         double height_d, bool skip_prefilter) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    // Immediate build verification - if caller passes size=1 and data[0]==0x42,
    // return the build ID to confirm which WASM is running
    if (size == 1) {
      const uint8_t *probe = reinterpret_cast<const uint8_t *>(ptr);
      if (probe && probe[0] == 0x42) {
        return std::string(R"({"success":true,"build_id":")") +
               SPARSE_GUARDRAILS_BUILD + R"("})";
      }
    }

    // Outer try-catch to capture bad_array_new_length BEFORE inner try block
    int trace_step = 0; // Track where error occurs (accessible in catch)
    try {

    try {
      // STEP TRACING: Track exactly where bad_array_new_length occurs
      auto trace_error = [&](const std::string &msg) -> std::string {
        std::ostringstream oss;
        oss << R"({"success":false,"error":")" << msg << R"(","trace_step":)"
            << trace_step << R"(,"build_id":")" << SPARSE_GUARDRAILS_BUILD
            << R"("})";
        return oss.str();
      };

      trace_step = 1; // Entry
      uint64_t default_height = static_cast<uint64_t>(height_d);
      const uint8_t *data = reinterpret_cast<const uint8_t *>(ptr);

      if (size < 4) {
        return R"({"success":false,"error":"Sparse data too small"})";
      }

      trace_step = 2; // Before wallet_tx_count
      // Build a set of existing transaction hashes for O(1) duplicate checking
      // OPTIMIZATION v4.3.0: Use cached existing_txs set with incremental
      // updates Only rebuild if wallet TX count changed (indicating new TXs
      // were added)
      size_t wallet_tx_count = m_wallet->get_num_transfer_details();
      
      // SANITY CHECK: Prevent cascade failures from corrupted wallet state
      // A wallet with >1M transfers is unrealistic and indicates corruption
      const size_t MAX_SANE_TRANSFER_COUNT = 1000000;
      if (wallet_tx_count > MAX_SANE_TRANSFER_COUNT) {
        std::ostringstream err;
        err << R"({"success":false,"error":"wallet_tx_count_insane: )" << wallet_tx_count
            << R"(","trace_step":)" << trace_step
            << R"(,"build_id":")" << SPARSE_GUARDRAILS_BUILD << R"("})";
        return err.str();
      }
      
      trace_step = 3; // Before cache rebuild check
      if (wallet_tx_count != m_existing_txs_cache_size) {
        trace_step = 31; // Inside cache rebuild
        // Rebuild cache - only happens when new TXs are added
        m_existing_txs_cache.clear();
        trace_step = 32;
        m_existing_txs_cache.reserve(wallet_tx_count);
        trace_step = 33;
        for (size_t i = 0; i < wallet_tx_count; ++i) {
          const auto &td = m_wallet->get_transfer_details(i);
          m_existing_txs_cache.insert(td.m_txid);
        }
        trace_step = 34;
        m_existing_txs_cache_size = wallet_tx_count;
      }

      trace_step = 4; // After cache, before SPR parsing

      // Use reference to cached set (non-const to avoid build error with
      // unordered_set::find)
      auto &existing_txs = m_existing_txs_cache;

      trace_step = 5; // Before SPR version detection

      // Read transaction count + detect sparse format version
      uint32_t tx_count = 0;
      size_t offset = 0;
      size_t begin_offset = 0;
      const char *spr_magic = "SPRX";
      bool has_tx_hash_field = false;
      bool has_asset_indices_field = false;
      bool has_timestamp_field = false;
      bool has_block_version_field = false;


      // Safety rails: corrupted sparse framing or version mismatches can cause
      // huge allocations (bad_array_new_length) on wasm32.
      const uint32_t MAX_SPARSE_TX_COUNT = 20000;
      const uint16_t MAX_SPARSE_INDEX_COUNT = 4096;
      const uint32_t MAX_SPARSE_TX_BLOB_SIZE = 2 * 1024 * 1024; // 2MB

      auto sparse_error = [&](const std::string &msg, size_t fail_offset,
                              uint32_t tx_index, uint64_t v1 = 0,
                              uint64_t v2 = 0) -> std::string {
        std::ostringstream oss;
        oss << "{\"success\":false,\"error\":\"" << msg << "\"";
        oss << ",\"spr\":\"" << std::string(spr_magic, 4) << "\"";
        oss << ",\"size\":" << size;
        oss << ",\"offset\":" << fail_offset;
        oss << ",\"tx_index\":" << tx_index;
        oss << ",\"tx_count\":" << tx_count;
        if (v1 != 0) {
          oss << ",\"v1\":" << v1;
        }
        if (v2 != 0) {
          oss << ",\"v2\":" << v2;
        }
        oss << "}";
        return oss.str();
      };


       if (size >= 8 && memcmp(data, "SPR6", 4) == 0) {
         // v6: [SPR6][TxCount] - includes timestamp and version
         spr_magic = "SPR6";
         memcpy(&tx_count, data + 4, 4);
         offset = 8;
         begin_offset = offset;
         has_tx_hash_field = true;
         has_asset_indices_field = true;
         has_timestamp_field = true;
         has_block_version_field = true;
       } else if (size >= 8 && memcmp(data, "SPR5", 4) == 0) {
         // v5: [SPR5][TxCount] - includes timestamp
         spr_magic = "SPR5";
         memcpy(&tx_count, data + 4, 4);
         offset = 8;
         begin_offset = offset;
         has_tx_hash_field = true;
         has_asset_indices_field = true;
         has_timestamp_field = true;
       } else if (size >= 8 && memcmp(data, "SPR4", 4) == 0) {
         // v4: [SPR4][TxCount]
         spr_magic = "SPR4";
         memcpy(&tx_count, data + 4, 4);
         offset = 8;
         begin_offset = offset;
         has_tx_hash_field = true;
         has_asset_indices_field = true;
       } else if (size >= 8 && memcmp(data, "SPR3", 4) == 0) {
         // v3: [SPR3][TxCount]
         spr_magic = "SPR3";
         memcpy(&tx_count, data + 4, 4);
         offset = 8;
         begin_offset = offset;
         has_tx_hash_field = true;
       } else {
         // v2: [TxCount]
         spr_magic = "SPR2";
         memcpy(&tx_count, data, 4);
         offset = 4;
         begin_offset = offset;
       }


       if (tx_count > MAX_SPARSE_TX_COUNT) {
         return sparse_error("Sparse tx_count too large", offset, 0, tx_count);
       }

      trace_step = 6; // After SPR header parsed, tx_count validated

      // Debug logging removed for performance - was slowing down wallet scans
      // Keys logging disabled to reduce console spam

      // ================================================================
      // PHASE 1: Parse all transactions and collect metadata
      // We need to sort by block height before processing to ensure
      // STAKE/AUDIT outputs are added to subaddress map before PROTOCOL
      // returns that depend on them.
      // ================================================================
      struct TxEntry {
        uint32_t global_index;
        uint64_t block_height;
        uint64_t timestamp;    // Unix timestamp from block header (SPR5)
        uint8_t block_version; // Block major version (SPR6)
        crypto::hash tx_hash;
        bool has_tx_hash;
        std::vector<uint64_t> output_indices;
        std::vector<uint64_t> asset_indices;
        std::string tx_blob;
        size_t original_order;
      };

      trace_step = 7; // Before tx_entries.reserve(tx_count)
      std::vector<TxEntry> tx_entries;
      tx_entries.reserve(tx_count);
      trace_step = 8; // After tx_entries.reserve - starting tx parsing loop

      const size_t min_record_header =
          has_timestamp_field
              ? (has_block_version_field ? (4 + 4 + 8 + 1 + 32 + 2)
                                         : (4 + 4 + 8 + 32 + 2))
              : (has_tx_hash_field ? (4 + 4 + 32 + 2) : (4 + 4 + 2));
      for (uint32_t i = 0; i < tx_count && offset + min_record_header <= size;
           i++) {
        TxEntry entry;
        entry.original_order = i;
        entry.tx_hash = crypto::null_hash;
        entry.has_tx_hash = false;
        entry.timestamp = 0;
        entry.block_version = 0;

        // Read global index
        memcpy(&entry.global_index, data + offset, 4);
        offset += 4;

        // Read block height
        uint32_t block_height32;
        memcpy(&block_height32, data + offset, 4);
        offset += 4;
        entry.block_height =
            block_height32 > 0 ? block_height32 : default_height;

         // v5: Timestamp (8 bytes)
         if (has_timestamp_field) {
           if (offset + 8 > size) {
             return sparse_error("Sparse truncated timestamp", offset, i);
           }
           memcpy(&entry.timestamp, data + offset, 8);
           offset += 8;
         }


         // v6: BlockVersion (1 byte)
         if (has_block_version_field) {
           if (offset + 1 > size) {
             return sparse_error("Sparse truncated block_version", offset, i);
           }
           memcpy(&entry.block_version, data + offset, 1);
           offset += 1;
         }


        // v3/v4/v5: TxHash (32 bytes) - currently unused here, but must be
        // skipped
         if (has_tx_hash_field) {
           if (offset + 32 > size) {
             return sparse_error("Sparse truncated tx_hash", offset, i);
           }
           memcpy(&entry.tx_hash, data + offset, 32);
           entry.has_tx_hash = true;
           offset += 32;
         }


        // Read output index count
        uint16_t idx_count;
        memcpy(&idx_count, data + offset, 2);
        offset += 2;

         if (idx_count > MAX_SPARSE_INDEX_COUNT) {
           return sparse_error("Sparse idx_count too large", offset, i,
                               idx_count);
         }
         if (offset + static_cast<size_t>(idx_count) * 4 > size) {
           return sparse_error("Sparse output_indices truncated", offset, i,
                               idx_count);
         }


        // Read output indices
        entry.output_indices.reserve(idx_count);
        for (uint16_t j = 0; j < idx_count && offset + 4 <= size; j++) {
          uint32_t idx32;
          memcpy(&idx32, data + offset, 4);
          offset += 4;
          entry.output_indices.push_back(static_cast<uint64_t>(idx32));
        }

         // v4: Read asset index count + indices
         if (has_asset_indices_field) {
           if (offset + 2 > size) {
             return sparse_error("Sparse truncated asset_count", offset, i);
           }
           uint16_t asset_count;
           memcpy(&asset_count, data + offset, 2);
           offset += 2;


           if (asset_count > MAX_SPARSE_INDEX_COUNT) {
             return sparse_error("Sparse asset_count too large", offset, i,
                                 asset_count);
           }
           if (offset + static_cast<size_t>(asset_count) * 4 > size) {
             return sparse_error("Sparse asset_indices truncated", offset, i,
                                 asset_count);
           }


          entry.asset_indices.reserve(asset_count);
          for (uint16_t j = 0; j < asset_count && offset + 4 <= size; j++) {
            uint32_t idx32;
            memcpy(&idx32, data + offset, 4);
            offset += 4;
            entry.asset_indices.push_back(static_cast<uint64_t>(idx32));
          }
        } else {
          // v2/v3: no asset index list provided; treat as same as output
          // indices
          entry.asset_indices = entry.output_indices;
        }

         // Read transaction size
         if (offset + 4 > size) {
           return sparse_error("Sparse truncated tx_size", offset, i);
         }
         uint32_t tx_size;
         memcpy(&tx_size, data + offset, 4);
         offset += 4;


         if (tx_size > MAX_SPARSE_TX_BLOB_SIZE) {
           return sparse_error("Sparse tx_size too large", offset, i, tx_size);
         }


         if (offset + tx_size > size) {
           return sparse_error("Sparse truncated tx_blob", offset, i, tx_size);
         }


        // Store tx blob
        entry.tx_blob.assign(reinterpret_cast<const char *>(data + offset),
                             tx_size);
        offset += tx_size;

        tx_entries.push_back(std::move(entry));
      }

      trace_step = 9; // After tx parsing loop, before sort

      // Sort by block height to ensure proper processing order
      // STAKE/AUDIT outputs must be processed before their PROTOCOL returns
      // OPTIMIZATION A2: Check if already sorted before sorting (server sends
      // chunks in order)
      auto sort_comparator = [](const TxEntry &a, const TxEntry &b) {
        if (a.block_height != b.block_height)
          return a.block_height < b.block_height;
        return a.original_order <
               b.original_order; // Preserve original order within same block
      };

      bool already_sorted =
          std::is_sorted(tx_entries.begin(), tx_entries.end(), sort_comparator);
      if (!already_sorted) {
        std::sort(tx_entries.begin(), tx_entries.end(), sort_comparator);
      }

      trace_step = 10; // After sort, before Phase 1.5

      // ================================================================
      // PHASE 1.5: BATCH DERIVATION PRE-FILTER (NEW OPTIMIZATION)
      // Parse all TXs, batch compute derivations, quick-scan to identify
      // matches. Only TXs that pass this check get full
      // process_new_transaction. This reduces expensive crypto from 28K TXs to
      // ~3K (89% reduction!).
      // ================================================================

      // Structure to hold parsed TX data for two-pass processing
      struct ParsedTx {
        cryptonote::transaction tx;
        crypto::hash tx_hash;
        bool parse_success;
        bool passes_quick_scan; // Does this TX contain outputs for us?
        crypto::public_key main_tx_pubkey;
        std::vector<crypto::public_key> additional_pubkeys;
      };

      trace_step = 11; // Before parsed_txs allocation (tx_entries.size() elements)
      std::vector<ParsedTx> parsed_txs(tx_entries.size());
      trace_step = 12; // After parsed_txs allocation

      // Collect all main TX pubkeys for batch derivation
      trace_step = 13; // Before all_main_pubkeys.reserve
      std::vector<crypto::public_key> all_main_pubkeys;
      all_main_pubkeys.reserve(tx_entries.size());
      trace_step = 14; // After all_main_pubkeys.reserve, before PASS 1 loop

      // PASS 1: Parse all transactions and collect pubkeys
      size_t parse_success_count = 0;
      for (size_t i = 0; i < tx_entries.size(); i++) {
        const TxEntry &entry = tx_entries[i];
        auto &ptx = parsed_txs[i];
        ptx.passes_quick_scan = false;

        // Parse transaction blob
        bool used_fallback = false;
        try {
          ptx.parse_success = cryptonote::parse_and_validate_tx_from_blob(
              entry.tx_blob, ptx.tx, ptx.tx_hash);
        } catch (const std::exception &e) {
          // Some tx types / malformed blobs can trigger
          // std::length_error("vector") or similar during parsing. Do not crash
          // sparse ingest; fall back to the AUDIT parsers below.
          ptx.parse_success = false;
          if (m_last_error.empty()) {
            m_last_error =
                std::string("parse_and_validate_tx_from_blob: ") + e.what();
          }
        } catch (...) {
          ptx.parse_success = false;
          if (m_last_error.empty()) {
            m_last_error = "parse_and_validate_tx_from_blob: unknown exception";
          }
        }

        // Fallback for AUDIT transactions
        if (!ptx.parse_success) {
          used_fallback = true;
          ptx.parse_success =
              parse_audit_tx_manually(entry.tx_blob, ptx.tx, ptx.tx_hash);
        } else {
          // Standard parsing succeeded.
          // For STAKE and AUDIT transactions, we MUST try manual parsing
          // to populate 'return_address' which is not handled by the standard
          // parser.
          if (ptx.tx.type == cryptonote::transaction_type::STAKE ||
              ptx.tx.type == cryptonote::transaction_type::AUDIT) {

            // Attempt manual parsing into a TEMPORARY transaction object
            // We use the "Merge" strategy: Keep the robust standard-parsed tx
            // for inputs/outputs/RCT, and only backfill the missing
            // return_address/amount_burnt from the manual parser.
            cryptonote::transaction tx_manual;
            crypto::hash hash_manual;

            if (parse_audit_tx_manually(entry.tx_blob, tx_manual,
                                        hash_manual)) {
              // Manual parse SUCCESS.
              // Backfill critical fields into the standard transaction
              ptx.tx.return_address = tx_manual.return_address;
              ptx.tx.amount_burnt = tx_manual.amount_burnt;

              // Also backfill return_pubkey if it was found
              if (tx_manual.return_pubkey != crypto::null_pkey) {
                ptx.tx.return_pubkey = tx_manual.return_pubkey;
              }

              std::cout
                  << "[DEBUG_FIX] Manual parse SUCCESS. Merged return_address="
                  << key_to_hex(reinterpret_cast<const unsigned char *>(
                         &ptx.tx.return_address))
                  << " into tx " << ptx.tx_hash << "." << std::endl;
            }
          }
        }
        if (!ptx.parse_success) {
          used_fallback = true;
          ptx.parse_success =
              parse_audit_tx_manually(entry.tx_blob, ptx.tx, ptx.tx_hash);
        }

        // Some AUDIT tx blobs still fail full parsing due to WASM32
        // serialization edge-cases. As a last resort, use the minimal AUDIT
        // parser (prefix + RCT outPk) and then compute tx_hash from the parsed
        // tx object.
        if (!ptx.parse_success) {
          if (parse_audit_tx_minimal(entry.tx_blob, ptx.tx)) {
            cryptonote::get_transaction_hash(ptx.tx, ptx.tx_hash);
            ptx.parse_success = true;
          }
        }

        // CRITICAL: If sparse data includes a canonical tx hash (SPR3/SPR4),
        // treat it as authoritative. Manual/minimal AUDIT parsing can produce
        // a tx object that is insufficient to recompute the canonical txid,
        // leading to txid mismatches and "missing" transactions.
        if (entry.has_tx_hash && entry.tx_hash != crypto::null_hash) {
          if (ptx.parse_success) {
            ptx.tx_hash = entry.tx_hash;
          }
        }

        if (ptx.parse_success) {
          parse_success_count++;

          // DEBUG: Log STAKE transaction parsing details (DISABLED for
          // production) if (ptx.tx.type == cryptonote::transaction_type::STAKE)
          // {
          //   std::cout << "[STAKE TX PARSE] height=" << entry.block_height
          //             << " return_address="
          //             << key_to_hex(reinterpret_cast<const unsigned char *>(
          //                    &ptx.tx.return_address))
          //             << " protocol_tx_data.return_address="
          //             << key_to_hex(reinterpret_cast<const unsigned char *>(
          //                    &ptx.tx.protocol_tx_data.return_address))
          //             << " amount_burnt=" << ptx.tx.amount_burnt
          //             << " used_fallback=" << used_fallback << std::endl;
          // }

          // Handle AUDIT/STAKE salvium_data extraction
          if (ptx.tx.type == cryptonote::transaction_type::AUDIT ||
              ptx.tx.type == cryptonote::transaction_type::STAKE) {
            crypto::public_key extracted_spend_pubkey;
            if (extract_salvium_data_spend_pubkey(entry.tx_blob,
                                                  extracted_spend_pubkey)) {
              ptx.tx.rct_signatures.salvium_data.spend_pubkey =
                  extracted_spend_pubkey;
              ptx.tx.rct_signatures.salvium_data.salvium_data_type =
                  rct::SalviumZeroAudit;
            }
          }

          // Extract TX pubkeys for batch derivation
          ptx.main_tx_pubkey = cryptonote::get_tx_pub_key_from_extra(ptx.tx);
          ptx.additional_pubkeys =
              cryptonote::get_additional_tx_pub_keys_from_extra(ptx.tx);

          all_main_pubkeys.push_back(ptx.main_tx_pubkey);
        } else {
          // Push null key for failed parses to keep indices aligned
          all_main_pubkeys.push_back(crypto::null_pkey);
        }
      }

      trace_step = 15; // After PASS 1 loop, before batch derivation allocation

      // BATCH DERIVATION: Compute all main derivations in one call
      std::vector<crypto::key_derivation> all_main_derivations(
          all_main_pubkeys.size());
      trace_step = 16; // After all_main_derivations allocation

      const crypto::secret_key &view_secret =
          m_wallet->get_account().get_keys().m_view_secret_key;

      trace_step = 17; // Before fast_batch_key_derivations call
      int batch_success = fast_batch_key_derivations(
          reinterpret_cast<unsigned char *>(all_main_derivations.data()),
          reinterpret_cast<const unsigned char *>(all_main_pubkeys.data()),
          reinterpret_cast<const unsigned char *>(&view_secret),
          static_cast<int>(all_main_pubkeys.size()));
      trace_step = 18; // After batch derivation, before PASS 2 quick-scan loop

      // PASS 2: Quick-scan each TX with pre-computed derivations to identify
      // matches
      size_t quick_match_count = 0;
      for (size_t i = 0; i < parsed_txs.size(); i++) {
        auto &ptx = parsed_txs[i];
        if (!ptx.parse_success)
          continue;

        // Check if already seen (duplicate)
        if (existing_txs.find(ptx.tx_hash) != existing_txs.end()) {
          continue;
        }

        // DISABLED OPTIMIZATION: Always process all transactions fully.
        // The batch derivation (Phase 1.5) fails for Carrot (X25519)
        // transactions because fast_batch_key_derivations is Ed25519-only. This
        // caused missed transactions and masked the Phase 3b crash.
        ptx.passes_quick_scan = true;
        quick_match_count++;
        continue;

        if (ptx.tx.type == cryptonote::transaction_type::AUDIT ||
            ptx.tx.type == cryptonote::transaction_type::STAKE ||
            ptx.tx.type == cryptonote::transaction_type::PROTOCOL) {
          ptx.passes_quick_scan = true;
          quick_match_count++;
          continue;
        }

        // Use pre-computed derivation for quick scan
        const crypto::key_derivation &main_deriv = all_main_derivations[i];

        // Parse TX extra for scan
        std::vector<crypto::public_key> main_pubkeys = {ptx.main_tx_pubkey};
        cryptonote::blobdata tx_extra_nonce;
        std::vector<crypto::public_key> additional_pubkeys_parsed;
        tools::wallet::parse_tx_extra_for_scanning(
            ptx.tx.extra, ptx.tx.vout.size(), main_pubkeys,
            additional_pubkeys_parsed, tx_extra_nonce);

        // Compute additional derivations if needed (less common, can't batch
        // easily)
        std::vector<crypto::key_derivation> additional_derivations;
        if (!additional_pubkeys_parsed.empty()) {
          additional_derivations.resize(additional_pubkeys_parsed.size());
          for (size_t j = 0; j < additional_pubkeys_parsed.size(); j++) {
            crypto::generate_key_derivation(additional_pubkeys_parsed[j],
                                            view_secret,
                                            additional_derivations[j]);
          }
        }

        // Prepare scan result buffer
        std::vector<
            std::optional<tools::wallet::enote_view_incoming_scan_info_t>>
            scan_results(ptx.tx.vout.size());

        // Quick-scan with pre-computed derivations
        std::vector<crypto::key_derivation> main_derivs_vec = {main_deriv};
        tools::wallet::view_incoming_scan_transaction(
            ptx.tx, epee::to_span(main_pubkeys),
            epee::to_span(additional_pubkeys_parsed), tx_extra_nonce,
            epee::to_span(main_derivs_vec),
            epee::to_span(additional_derivations), m_wallet->get_account(),
            epee::to_mut_span(scan_results));

        // Check if any output matched
        for (const auto &result : scan_results) {
          if (result.has_value()) {
            ptx.passes_quick_scan = true;
            quick_match_count++;
            break;
          }
        }
      }

      // Prefilter stats logging disabled to reduce console spam
      // (Was: printf("[BATCH PREFILTER] Parsed: %zu/%zu...")

      trace_step = 19; // After PASS 2 quick-scan, before Phase 2 setup

      // ================================================================
      // PHASE 2: Process ONLY matched transactions (full processing)
      // ================================================================

      uint64_t balance_before = m_wallet->balance(0, "SAL", false) +
                                m_wallet->balance(0, "SAL1", false);
      trace_step = 20; // After balance check, setting up counters
      uint32_t txs_processed = 0;
      uint32_t txs_matched = 0;
      uint32_t txs_parse_failed = 0;
      uint32_t txs_exception = 0;
      uint32_t txs_prescan_match_but_not_added = 0; // GHOST MATCHES
      uint32_t txs_reprocessed =
          0; // Transactions successfully matched on second pass
      uint32_t txs_skipped_by_prefilter =
          0; // NEW: Count TXs skipped by batch prefilter
      uint32_t outputs_marked_spent_total =
          0; // v5.22.0: Total outputs marked as spent during ingest
      std::string first_tx_hash_hex;
      std::string first_tx_pubkey_hex;
      uint32_t first_tx_outputs = 0;
      uint32_t first_tx_indices = 0;
      std::string ghost_tx_hashes; // First few ghost tx hashes for debug

      // Track stake heights for return block prediction
      // Stake returns happen at stake_height + 21601 (STAKE_LOCK_PERIOD + 1)
      // The +1 is because blockchain.cpp uses: matured_height = height -
      // stake_lock_period - 1
      std::vector<uint64_t> stake_heights;

      // Track audit heights for return block prediction
      // Audit returns happen at audit_height + 7201 (AUDIT_LOCK_PERIOD + 1)
      // This is 1/3 of the stake lock period (~1 week vs ~1 month)
      std::vector<uint64_t> audit_heights;

      // Keep track of ghost transactions for potential reprocessing
      std::vector<size_t> ghost_tx_indices;

      trace_step = 21; // Before Phase 2 processing loop

      // SAFETY: Verify tx_entries doesn't have corrupted size
      if (tx_entries.size() > MAX_SPARSE_TX_COUNT) {
        std::ostringstream err;
        err << R"({"success":false,"error":"tx_entries_size_insane: )" << tx_entries.size()
            << R"(","trace_step":)" << trace_step
            << R"(,"build_id":")" << SPARSE_GUARDRAILS_BUILD << R"("})";
        return err.str();
      }

      trace_step = 22; // Entering Phase 2 loop

      // Process only transactions that passed quick-scan
      for (size_t i = 0; i < tx_entries.size(); i++) {
        trace_step = 200 + static_cast<int>(i % 100); // Track iteration start (200+i)
        DEBUG_LOG("[INGEST DEBUG] Starting iteration %zu/%zu\n", i + 1,
                  tx_entries.size());

        // OPTIMIZATION: Skip TXs that didn't pass batch pre-filter
        const auto &ptx = parsed_txs[i];
        trace_step = 300 + static_cast<int>(i % 100); // After ptx access (300+i)
        if (!ptx.parse_success) {
          txs_parse_failed++;
          txs_processed++;
          continue;
        }
        if (!ptx.passes_quick_scan && !skip_prefilter) {
          // TX doesn't contain any outputs for us - skip expensive processing
          txs_skipped_by_prefilter++;
          txs_processed++;
          continue;
        }

        trace_step = 400 + static_cast<int>(i % 100); // Before entry access (400+i)
        // Use already-parsed TX data (no need to re-parse!)
        const TxEntry &entry = tx_entries[i];
        trace_step = 500 + static_cast<int>(i % 100); // After entry access (500+i)
        uint64_t block_height = entry.block_height;
        const std::vector<uint64_t> &output_indices = entry.output_indices;
        const cryptonote::transaction &tx = ptx.tx;
        const crypto::hash &tx_hash = ptx.tx_hash;
        bool parse_success = true; // Already verified in pre-filter

        // NOTE: AUDIT/STAKE salvium_data extraction is now done in pre-filter
        // pass

        if (parse_success) {
          DEBUG_LOG("[INGEST DEBUG] Parse success, checking tx type=%d "
                    "vout.size=%zu\n",
                    (int)tx.type, tx.vout.size());

          // DUPLICATE CHECK: If we already have this transaction, skip it to
          // prevent double-counting This is critical because
          // process_new_transaction might not deduplicate correctly if called
          // multiple times for the same tx (e.g. during re-scans)
          DEBUG_LOG("[INGEST DEBUG] Checking duplicate...\n");

          if (existing_txs.find(tx_hash) != existing_txs.end()) {
            // Skip processing but count as processed
            DEBUG_LOG("[INGEST DEBUG] Skipping duplicate tx\n");

            txs_processed++;
            continue;
          }
          DEBUG_LOG("[INGEST DEBUG] Not duplicate, continuing...\n");

          // Capture first tx info for diagnostics
          if (txs_processed == 0) {
            first_tx_hash_hex =
                key_to_hex(reinterpret_cast<const unsigned char *>(&tx_hash));
            crypto::public_key tx_pub =
                cryptonote::get_tx_pub_key_from_extra(tx);
            first_tx_pubkey_hex =
                key_to_hex(reinterpret_cast<const unsigned char *>(&tx_pub));
            first_tx_outputs = tx.vout.size();
            first_tx_indices = output_indices.size();
          }

          DEBUG_LOG(
              "[INGEST DEBUG] About to check is_carrot_transaction_v1...\n");

          // CARROT DEBUG: Check if this is a Carrot transaction
          bool is_carrot_tx = carrot::is_carrot_transaction_v1(tx);

          DEBUG_LOG("[INGEST DEBUG] is_carrot_tx=%d\n", is_carrot_tx);

          static int carrot_debug_count = 0;
          if (is_carrot_tx && carrot_debug_count < 3) {
            carrot_debug_count++;
            DEBUG_LOG(
                "[CARROT INGEST DEBUG #%d] height=%lu hash=%s\n",
                carrot_debug_count, (unsigned long)block_height,
                key_to_hex(reinterpret_cast<const unsigned char *>(&tx_hash))
                    .c_str());
            DEBUG_LOG("  outputs=%zu indices=%zu\n", tx.vout.size(),
                      output_indices.size());

            // Check the account's Carrot keys
            const auto &keys = m_wallet->get_account().get_keys();
            DEBUG_LOG("  k_view_incoming: %s\n",
                      key_to_hex(reinterpret_cast<const unsigned char *>(
                                     &keys.k_view_incoming))
                          .c_str());
            DEBUG_LOG("  m_view_secret_key: %s\n",
                      key_to_hex(reinterpret_cast<const unsigned char *>(
                                     &keys.m_view_secret_key))
                          .c_str());
            DEBUG_LOG(
                "  carrot_address_spend: %s\n",
                key_to_hex(
                    reinterpret_cast<const unsigned char *>(
                        &keys.m_carrot_account_address.m_spend_public_key))
                    .c_str());

            // Check if output is carrot_v1 type
            if (!tx.vout.empty()) {
              const auto &target = tx.vout[0].target;
              if (target.type() == typeid(cryptonote::txout_to_carrot_v1)) {
                const auto &carrot_out =
                    boost::get<cryptonote::txout_to_carrot_v1>(target);
                DEBUG_LOG(
                    "  output[0] is carrot_v1: key=%s view_tag=%02x%02x%02x\n",
                    key_to_hex(reinterpret_cast<const unsigned char *>(
                                   &carrot_out.key))
                        .c_str(),
                    carrot_out.view_tag.bytes[0], carrot_out.view_tag.bytes[1],
                    carrot_out.view_tag.bytes[2]);
              }
            }

            // Manually call view_incoming_scan_transaction and check results
            auto scan_results = tools::wallet::view_incoming_scan_transaction(
                tx, m_wallet->get_account());
            int matches_found = 0;
            for (size_t oi = 0; oi < scan_results.size(); oi++) {
              if (scan_results[oi].has_value()) {
                matches_found++;
                DEBUG_LOG("  OUTPUT %zu MATCHED! amount=%llu is_carrot=%d\n",
                          oi, (unsigned long long)scan_results[oi]->amount,
                          scan_results[oi]->is_carrot);
              }
            }
            DEBUG_LOG("  scan_results: %d/%zu outputs matched\n", matches_found,
                      scan_results.size());
          }

          // Process the transaction WITH output indices and asset-type output
          // indices
          const std::vector<uint64_t> &asset_indices = entry.asset_indices;

          // DIAGNOSTIC: Check if output indices vector size matches tx outputs
          bool indices_match = (output_indices.size() == tx.vout.size());

          // DEBUG: Log ALL transactions at height 154820 (the missing AUDIT tx
          // height)
          if (block_height == 154820) {
            std::string tx_hash_hex =
                key_to_hex(reinterpret_cast<const unsigned char *>(&tx_hash));
            DEBUG_LOG("[DEBUG 154820] Processing tx: hash=%s type=%d "
                      "rct_type=%d salvium_data_type=%d\n",
                      tx_hash_hex.c_str(), (int)tx.type,
                      (int)tx.rct_signatures.type,
                      (int)tx.rct_signatures.salvium_data.salvium_data_type);

            // Log spend_pubkey if present
            if (tx.rct_signatures.salvium_data.salvium_data_type ==
                rct::SalviumZeroAudit) {
              DEBUG_LOG(
                  "[DEBUG 154820] salvium_data.spend_pubkey=%s\n",
                  key_to_hex(reinterpret_cast<const unsigned char *>(
                                 &tx.rct_signatures.salvium_data.spend_pubkey))
                      .c_str());
            }

            // Log wallet's main spend key for comparison
            const auto &keys = m_wallet->get_account().get_keys();
            DEBUG_LOG(
                "[DEBUG 154820] "
                "wallet.m_account_address.m_spend_public_key=%s\n",
                key_to_hex(reinterpret_cast<const unsigned char *>(
                               &keys.m_account_address.m_spend_public_key))
                    .c_str());
          }

          // ================================================================
          // FIX FOR AUDIT/STAKE TRANSACTIONS:
          // These transactions create P_change outputs with a derived
          // spend_pubkey that is stored in salvium_data.spend_pubkey. We need
          // to add this key to the subaddress map BEFORE scanning so the output
          // can be detected.
          //
          // CRITICAL FIX v3.3.11: For AUDIT returns at maturity, the
          // protocol_tx output uses tx.return_address as the output key (NOT
          // spend_pubkey). We must ALSO add return_address to subaddress map
          // for returns to work!
          // - spend_pubkey: Used for the P_change output in the original AUDIT
          // tx
          // - return_address: Used for the return output in protocol_tx at
          // maturity
          // ================================================================
          bool added_audit_spend_key = false;
          bool added_audit_return_address = false;
          bool added_stake_return_address = false;
          crypto::public_key audit_spend_pubkey{};
          crypto::public_key audit_return_address{};
          crypto::public_key stake_return_address{};

          auto &account = m_wallet->get_account();
          const auto &subaddr_map = account.get_subaddress_map_cn();

          // ================================================================
          // STAKE TRANSACTION FIX (v5.8.0 + v5.16.0):
          // IMPORTANT: Do NOT add return_address to subaddress map BEFORE
          // processing the STAKE tx! If we do, the stake output will be
          // detected as "received by us" because the output key is derived
          // from return_address. This causes:
          //   self_received = stake_amount
          //   m_change = stake_amount
          //   amount = amount_in - change = 0 (WRONG!)
          //
          // Instead, we add return_address AFTER processing (see below)
          // so it's available for the PROTOCOL return tx at maturity.
          //
          // v5.16.0 FIX: Pre-Carrot STAKE txs use tx.return_address (set by
          // manual parsing). Post-Carrot STAKE txs use
          // tx.protocol_tx_data.return_address. We must check BOTH since manual
          // parsing sets tx.return_address.
          // ================================================================
          if (tx.type == cryptonote::transaction_type::STAKE) {
            // Try tx.return_address first (pre-Carrot / manual parsing)
            if (tx.return_address != crypto::null_pkey) {
              stake_return_address = tx.return_address;
            }
            // Fall back to protocol_tx_data.return_address (post-Carrot)
            else if (tx.protocol_tx_data.return_address != crypto::null_pkey) {
              stake_return_address = tx.protocol_tx_data.return_address;
            }
            // IMPORTANT: Do NOT add return_address to the subaddress map here.
            // We only add it AFTER processing, and only if the tx actually
            // matched this wallet (see post-processing block guarded by
            // this_tx_matched).
          }

          // ================================================================
          // AUDIT TRANSACTION FIX:
          // AUDIT transactions (type 8) use salvium_data.spend_pubkey for
          // the P_change output, and tx.return_address for the return output.
          // ================================================================
          if (tx.type == cryptonote::transaction_type::AUDIT) {
            // Check if this transaction has salvium_data with spend_pubkey
            // salvium_data_type == 1 (SalviumZeroAudit) means it has
            // spend_pubkey
            if (tx.rct_signatures.salvium_data.salvium_data_type ==
                rct::SalviumZeroAudit) {
              audit_spend_pubkey = tx.rct_signatures.salvium_data.spend_pubkey;

              // Check if this spend_pubkey is NOT already in the subaddress map
              if (subaddr_map.find(audit_spend_pubkey) == subaddr_map.end()) {
                // Add to subaddress map with index {0,0} and
                // is_return_spend_key=true This mimics what the CLI wallet does
                // in scanning_tools.cpp line 246
                carrot::subaddress_index_extended subaddr_idx{
                    .index = {0, 0},
                    .derive_type = carrot::AddressDeriveType::PreCarrot,
                    .is_return_spend_key = true};
                account.insert_subaddresses(
                    {{audit_spend_pubkey, subaddr_idx}});
                added_audit_spend_key = true;

                // Debug logging for first few AUDIT transactions
                static int audit_debug_count = 0;
                if (audit_debug_count < 10) {
                  audit_debug_count++;
                  DEBUG_LOG("[AUDIT FIX] Added spend_pubkey to subaddress map: "
                            "height=%lu spend_pubkey=%s\n",
                            (unsigned long)block_height,
                            key_to_hex(reinterpret_cast<const unsigned char *>(
                                           &audit_spend_pubkey))
                                .c_str());
                }
              }

              // Also add tx.return_address for AUDIT return outputs
              // The protocol_tx at maturity uses return_address as output key
              audit_return_address = tx.return_address;
              if (audit_return_address != crypto::null_pkey &&
                  subaddr_map.find(audit_return_address) == subaddr_map.end()) {
                carrot::subaddress_index_extended return_idx{
                    .index = {0, 0},
                    .derive_type = carrot::AddressDeriveType::PreCarrot,
                    .is_return_spend_key = true};
                account.insert_subaddresses(
                    {{audit_return_address, return_idx}});
                added_audit_return_address = true;

                static int return_debug_count = 0;
                if (return_debug_count < 10) {
                  return_debug_count++;
                  DEBUG_LOG("[AUDIT RETURN FIX] Added return_address to "
                            "subaddress map: height=%lu return_address=%s\n",
                            (unsigned long)block_height,
                            key_to_hex(reinterpret_cast<const unsigned char *>(
                                           &audit_return_address))
                                .c_str());
                }
              }
            }
          }

          // NOTE: Pre-scan diagnostic REMOVED for performance (v4.3.0)
          // Previously called view_incoming_scan_transaction here which doubled
          // crypto work process_new_transaction already does the scan
          // internally

          // DEBUG: Log transaction being processed (without expensive pre-scan)
          std::string tx_hash_hex =
              key_to_hex(reinterpret_cast<const unsigned char *>(&tx_hash));
          DEBUG_LOG("[INGEST DEBUG] Processing tx %zu/%zu: height=%lu type=%d "
                    "outputs=%zu hash=%s\n",
                    i + 1, tx_entries.size(), (unsigned long)block_height,
                    (int)tx.type, tx.vout.size(),
                    tx_hash_hex.substr(0, 16).c_str());

          // Fix v5.31.6: Check output_indices size mismatch
          const size_t expected_size = tx.vout.size();
          if (output_indices.size() != expected_size) {
            txs_processed++;
            continue; // Skip without error
          }

          // v5.35.9 FIX: Re-enable transfers_before check to fix inflation bug
          // The "hang" was from get_num_transfer_details(), not from size()
          // access Use m_transfers.size() directly which is safe
          size_t transfers_before = m_wallet->m_transfers.size();
          bool this_tx_matched =
              false; // v5.35.9: Declared outside try for scope
          DEBUG_LOG("[INGEST DEBUG] transfers_before=%zu\n", transfers_before);

          try {
            DEBUG_LOG("[INGEST DEBUG] About to call process_new_transaction "
                      "for tx %zu\n",
                      i + 1);

            // fallback asset indices logic
            const std::vector<uint64_t> *p_asset_indices = &asset_indices;
            std::vector<uint64_t> fallback_asset_indices;
            if (asset_indices.size() != expected_size) {
              fallback_asset_indices = output_indices;
              p_asset_indices = &fallback_asset_indices;
            }

            // Heuristic for legacy SPR data (version 0)
            uint8_t effective_block_version = entry.block_version;
            if (effective_block_version == 0) {
              // Carrot height is 342784
              if (block_height >= 342784) {
                effective_block_version = 16;
              } else {
                effective_block_version = 12;
              }
            }

            DEBUG_LOG(
                "[CRASH_HUNT] Calling process_new_transaction for tx %zu at "
                "height %llu hash=%s\n",
                i, (unsigned long long)block_height,
                key_to_hex(reinterpret_cast<const unsigned char *>(&tx_hash))
                    .c_str());

            trace_step = 600 + static_cast<int>(i % 100); // Before process_new_transaction (600+i)
            m_wallet->process_new_transaction(
                tx_hash, tx, output_indices, *p_asset_indices, block_height,
                effective_block_version, // block_version (heuristic or SPR6)
                entry.timestamp,         // timestamp from SPR5
                false,                   // miner_tx
                false,                   // pool
                false,                   // double_spend_seen
                true // ignore_callbacks - MUST be true in WASM to prevent
                     // callback trap (SPR6 Timestamp Fix Verified)
            );
            trace_step = 700 + static_cast<int>(i % 100); // After process_new_transaction (700+i)

            DEBUG_LOG("[CRASH_HUNT] process_new_transaction returned success "
                      "for tx %zu\n",
                      i);

            // CACHE TIMESTAMP: Store timestamp for export (since
            // transfer_details drops it)
            if (entry.timestamp > 0) {
              m_tx_timestamps[tx_hash] = entry.timestamp;
            }
            trace_step = 710 + static_cast<int>(i % 100); // After timestamp cache (710+i)

            // v5.35.9 FIX: Actually check if transfers increased (fixes
            // inflation bug!) Previously assumed all view-tag-matched txs were
            // ours, but view tags have ~1/256 false positive rate. Non-owner
            // STAKE txs were adding their return_address to subaddress map,
            // causing PROTOCOL returns to match incorrectly.
            size_t transfers_after = m_wallet->m_transfers.size();
            trace_step = 720 + static_cast<int>(i % 100); // After transfers_after (720+i)
            this_tx_matched = transfers_after >
                              transfers_before; // Assignment, not declaration

            DEBUG_LOG("[INGEST DEBUG] process_new_transaction returned for tx "
                      "%zu (transfers %zu->%zu, matched=%s)\n",
                      i + 1, transfers_before, transfers_after,
                      this_tx_matched ? "YES" : "NO");

            trace_step = 730 + static_cast<int>(i % 100); // Before matched handling (730+i)
            if (this_tx_matched) {
              txs_matched++;
              existing_txs.insert(tx_hash); // Add to set to prevent duplicates
                                            // within this batch
              trace_step = 740 + static_cast<int>(i % 100); // After existing_txs.insert (740+i)

              // Track STAKE transaction heights for return block prediction
              // Stake returns happen at stake_height + 21601 (STAKE_LOCK_PERIOD
              // + 1)
              if (tx.type == cryptonote::transaction_type::STAKE) {
                stake_heights.push_back(block_height);
              }
              trace_step = 750 + static_cast<int>(i % 100); // After stake_heights (750+i)

              // Track AUDIT transaction heights for return block prediction
              // Audit returns happen at audit_height + 7201 (AUDIT_LOCK_PERIOD
              // + 1)
              if (tx.type == cryptonote::transaction_type::AUDIT) {
                audit_heights.push_back(block_height);
              }
              trace_step = 760 + static_cast<int>(i % 100); // After audit_heights (760+i)
            }
            // NOTE: Ghost match tracking removed (v4.3.0) - no longer have
            // prescan diagnostic
          } catch (const std::exception &e) {
            txs_exception++;
            // Store first exception message for diagnostics
            if (txs_exception == 1) {
              std::ostringstream err;
              err << "process_new_transaction: " << e.what()
                  << " (height=" << (unsigned long)block_height
                  << ", type=" << (int)tx.type
                  << ", vout=" << (unsigned long)tx.vout.size()
                  << ", indices=" << (unsigned long)output_indices.size()
                  << ", txid="
                  << key_to_hex(
                         reinterpret_cast<const unsigned char *>(&tx_hash))
                  << ")";
              m_last_error = err.str();
            }
          } catch (...) {
            txs_exception++;
            if (txs_exception == 1) {
              std::ostringstream err;
              err << "process_new_transaction: unknown exception"
                  << " (height=" << (unsigned long)block_height
                  << ", type=" << (int)tx.type
                  << ", vout=" << (unsigned long)tx.vout.size()
                  << ", indices=" << (unsigned long)output_indices.size()
                  << ", txid="
                  << key_to_hex(
                         reinterpret_cast<const unsigned char *>(&tx_hash))
                  << ")";
              m_last_error = err.str();
            }
          }

          trace_step = 800 + static_cast<int>(i % 100); // After try-catch block (800+i)
          // ================================================================
          // v5.22.0 FIX: Mark spent outputs during ingest
          // CRITICAL: After processing outputs, check if this tx SPENDS any
          // of our outputs by matching input key images against m_key_images.
          // This is essential for fresh scans where we don't have prior tx
          // records - without this, change outputs show as incoming!
          //
          // NOTE: Transactions MUST be processed in chronological order for
          // spent detection to work. The output's key_image must be in
          // m_key_images before the spending tx is processed.
          //
          // v5.36.0 FIX: Wrapped in try-catch and added safety checks to
          // prevent bad_array_new_length crash on malformed tx.vin
          //
          // v5.48.0: RE-ENABLED - was disabled in v5.36.3 for debug
          // ================================================================
          try {
            trace_step = 810 + static_cast<int>(i % 100); // Enter spent detection block
            
            // FIX_DEBUG: Trace spent detection for STAKE transactions
            bool is_stake = (tx.type == cryptonote::transaction_type::STAKE);
            
            // v5.36.0 SAFETY: Check tx.vin.size() sanity before iterating
            // Malformed transactions could have corrupted vin causing bad_array_new_length
            const size_t vin_size = tx.vin.size();
            if (vin_size > 10000) {
              // Sanity check - no legitimate tx should have >10k inputs
              DEBUG_LOG("[SPENT_DETECT] SKIP: tx.vin.size()=%zu exceeds sanity limit\n", vin_size);
            } else {
              trace_step = 820 + static_cast<int>(i % 100); // vin_size validated
              
              if (is_stake) {
                DEBUG_LOG(
                    "[FIX_DEBUG] Checking inputs for STAKE tx %s "
                    "(vin_size=%zu)\n",
                    key_to_hex(reinterpret_cast<const unsigned char *>(&tx_hash))
                        .c_str(),
                    vin_size);
              }

              trace_step = 830 + static_cast<int>(i % 100); // Before vin loop
              size_t vin_idx = 0;
              for (const auto &in : tx.vin) {
                trace_step = 840 + static_cast<int>(i % 100); // Inside vin loop
                
                // v5.36.0 SAFETY: Validate variant type before accessing
                if (in.empty()) {
                  vin_idx++;
                  continue;  // Skip empty variants
                }
                
                trace_step = 841 + static_cast<int>(i % 100); // After empty check
                
                if (in.type() != typeid(cryptonote::txin_to_key)) {
                  if (is_stake)
                    DEBUG_LOG("[FIX_DEBUG] Input skipped (not txin_to_key)\n");
                  vin_idx++;
                  continue;
                }

                trace_step = 842 + static_cast<int>(i % 100); // Before boost::get
                
                // v5.36.0 SAFETY: Use boost::get with pointer form first to validate
                const cryptonote::txin_to_key *p_in_to_key =
                    boost::get<cryptonote::txin_to_key>(&in);
                if (!p_in_to_key) {
                  // Type check passed but get failed - corrupted data
                  DEBUG_LOG("[SPENT_DETECT] WARNING: boost::get returned null for vin[%zu]\n", vin_idx);
                  vin_idx++;
                  continue;
                }
                const cryptonote::txin_to_key &in_to_key = *p_in_to_key;

                trace_step = 843 + static_cast<int>(i % 100); // After boost::get

                if (is_stake) {
                  DEBUG_LOG("[FIX_DEBUG] Input Key Image: %s\n",
                            key_to_hex(reinterpret_cast<const unsigned char *>(
                                           &in_to_key.k_image))
                                .c_str());
                }

                trace_step = 844 + static_cast<int>(i % 100); // Before m_key_images.find
                
                auto ki_it = m_wallet->m_key_images.find(in_to_key.k_image);
                
                trace_step = 845 + static_cast<int>(i % 100); // After m_key_images.find
                
                if (ki_it != m_wallet->m_key_images.end()) {
                  // FIX v5.31.4: Bounds check to prevent WASM crash
                  size_t transfer_idx = ki_it->second;

                  if (is_stake) {
                    DEBUG_LOG("[FIX_DEBUG] Match FOUND in m_key_images! "
                              "TransferIdx=%zu\n",
                              transfer_idx);
                  }

                  trace_step = 846 + static_cast<int>(i % 100); // Before transfers access
                  
                  if (transfer_idx < m_wallet->m_transfers.size()) {
                    auto &spent_td = m_wallet->m_transfers[transfer_idx];
                    if (!spent_td.m_spent) {
                      spent_td.m_spent = true;
                      spent_td.m_spent_height = block_height;
                      outputs_marked_spent_total++;
                      if (is_stake)
                        DEBUG_LOG("[FIX_DEBUG] Marked transfer %zu as SPENT\n",
                                  transfer_idx);
                    } else {
                      if (is_stake)
                        DEBUG_LOG("[FIX_DEBUG] Transfer %zu ALREADY spent\n",
                                  transfer_idx);
                    }
                  }
                  trace_step = 847 + static_cast<int>(i % 100); // After transfers access
                } else {
                  if (is_stake) {
                    DEBUG_LOG("[FIX_DEBUG] Match NOT FOUND in m_key_images. This "
                              "input will NOT be marked spent.\n");
                  }
                }
                vin_idx++;
              }
              trace_step = 850 + static_cast<int>(i % 100); // After vin loop complete
            }
          } catch (const std::exception &e) {
            // v5.36.0: Log and continue instead of crashing
            DEBUG_LOG("[SPENT_DETECT] Exception in spent detection for tx %zu: %s\n", i, e.what());
          } catch (...) {
            DEBUG_LOG("[SPENT_DETECT] Unknown exception in spent detection for tx %zu\n", i);
          }
          trace_step = 860 + static_cast<int>(i % 100); // After spent detection block

          // ================================================================
          // STAKE return_address insertion (AFTER processing) - v5.8.0
          // Now that the STAKE tx has been processed, add return_address
          // to subaddress map so future PROTOCOL return tx can be detected.
          // This MUST happen AFTER processing to avoid detecting the stake
          // output as "received by us" which would cause amount=0.
          //
          // v5.35.9 FIX: CRITICAL - Only add return_address if tx ACTUALLY
          // matched (added outputs to our wallet). Previously this ran for
          // ALL STAKE txs that passed view tag filtering, causing non-owner
          // STAKE return_addresses to pollute our subaddress map. This caused
          // PROTOCOL returns at those heights to incorrectly match!
          // ================================================================
          if (this_tx_matched &&
              tx.type == cryptonote::transaction_type::STAKE &&
              stake_return_address != crypto::null_pkey) {
            const auto &subaddr_map_after = account.get_subaddress_map_cn();
            if (subaddr_map_after.find(stake_return_address) ==
                subaddr_map_after.end()) {
              carrot::subaddress_index_extended return_idx{
                  .index = {0, 0},
                  .derive_type = carrot::AddressDeriveType::PreCarrot,
                  .is_return_spend_key = true};
              account.insert_subaddresses({{stake_return_address, return_idx}});
              added_stake_return_address = true;

              static int stake_return_debug_count = 0;
              if (stake_return_debug_count < 10) {
                stake_return_debug_count++;
                DEBUG_LOG("[STAKE RETURN FIX v5.35.9] Added "
                          "protocol_tx_data.return_address to "
                          "subaddress map (tx MATCHED): height=%lu "
                          "return_address=%s\n",
                          (unsigned long)block_height,
                          key_to_hex(reinterpret_cast<const unsigned char *>(
                                         &stake_return_address))
                              .c_str());
              }
            }
          }

          txs_processed++;
          DEBUG_LOG(
              "[INGEST DEBUG] Loop iteration %zu complete, txs_processed=%u\n",
              i + 1, txs_processed);
        } else {
          txs_parse_failed++;
          DEBUG_LOG("[INGEST DEBUG] Parse failed for tx %zu\n", i + 1);
        }

        DEBUG_LOG("[INGEST DEBUG] End of iteration %zu, continuing to next\n",
                  i + 1);
      }

      // ================================================================
      // PHASE 3: Reprocess ghost transactions
      // After processing all transactions, the subaddress map should be
      // populated with P_change values. Try ghost transactions again.
      // ================================================================
      if (!ghost_tx_indices.empty()) {
        for (size_t ghost_i : ghost_tx_indices) {
          const TxEntry &entry = tx_entries[ghost_i];

          cryptonote::transaction tx;
          crypto::hash tx_hash;

          bool ok = false;
          try {
            ok = cryptonote::parse_and_validate_tx_from_blob(entry.tx_blob, tx,
                                                             tx_hash);
          } catch (...) {
            ok = false;
          }
          if (!ok) {
            continue; // Already failed parsing, skip
          }

          // Skip if already processed (somehow got added on first pass after
          // ghost detection)
          if (existing_txs.find(tx_hash) != existing_txs.end()) {
            continue;
          }

          // Try again with updated subaddress map
          auto prescan_results = tools::wallet::view_incoming_scan_transaction(
              tx, m_wallet->get_account());
          int prescan_matches = 0;
          for (size_t pi = 0; pi < prescan_results.size(); pi++) {
            if (prescan_results[pi].has_value())
              prescan_matches++;
          }

          if (prescan_matches == 0) {
            continue; // Still no matches, skip
          }

          // uint64_t transfers_before = m_wallet->get_num_transfer_details();

          try {
            m_wallet->process_new_transaction(
                tx_hash, tx, entry.output_indices, entry.asset_indices,
                entry.block_height,
                0, // block_version
                0, // timestamp (unknown for ghost tx reprocess)
                false, false, false, true);

            // uint64_t transfers_after = m_wallet->get_num_transfer_details();
            if (true) {
              txs_reprocessed++;
              txs_matched++;                     // Count as matched now
              txs_prescan_match_but_not_added--; // No longer a ghost
              existing_txs.insert(tx_hash);
            }
          } catch (...) {
            // Silent fail on reprocess
          }
        }
      }

      // ================================================================
      // PHASE 4: POST-PROCESSING SPENT DETECTION (v5.36.0 / v5.36.1 OPT)
      // ================================================================
      // The inline spent detection during Phase 2 can miss spends when:
      // - Transactions are processed out of height order
      // - Key images weren't in m_key_images yet when spending tx processed
      //
      // This pass ensures ALL outputs that are spent by ANY transaction
      // in our m_transfers get marked as spent. This is critical for
      // correct balance calculation.
      //
      // v5.36.1 OPTIMIZATION: Changed from O(n??) to O(n) using hashmap.
      // Build a map of all key images spent by our transactions ONCE,
      // then do a single pass to mark spent outputs.
      // For ~3000 transfers, this reduces ~9M iterations to ~6K.
      //
      // v5.48.0: RE-ENABLED - was disabled in v5.36.3 for debug
      // ================================================================
      trace_step = 900; // Entering post-processing spent detection
      {
        size_t post_marked_spent = 0;
        const size_t transfer_count = m_wallet->m_transfers.size();
        trace_step = 901; // Got transfer count
        
        // v5.36.2 SAFETY: Sanity check transfer_count before using it
        // If m_transfers is corrupted, size() could return garbage
        if (transfer_count > 1000000) {
          // Corrupted - skip post-processing entirely
          DEBUG_LOG("[SPENT_DETECT] SKIP post-processing: transfer_count=%zu exceeds sanity limit\n", transfer_count);
        } else {
          trace_step = 902; // transfer_count validated

          // Step 1: Build map of key_image -> (spending_tx_index, block_height)
          // This is O(n * avg_inputs_per_tx) ??? O(n)
          std::unordered_map<crypto::key_image, std::pair<size_t, uint64_t>>
              spending_tx_map;
          
          // v5.36.2: Only reserve if transfer_count is reasonable
          if (transfer_count < 100000) {
            spending_tx_map.reserve(transfer_count * 2); // Assume ~2 inputs avg
          }
          trace_step = 903; // Reserved map

        // v5.36.1 FIX: Wrap in try-catch and use safe boost::get
        for (size_t j = 0; j < transfer_count; ++j) {
          trace_step = 910 + static_cast<int>(j % 100); // Post-process iteration j
          try {
            const auto &other_td = m_wallet->m_transfers[j];
            const uint64_t spend_height = other_td.m_block_height;
            
            // Safety check for vin size
            if (other_td.m_tx.vin.size() > 10000) continue;

            for (const auto &in : other_td.m_tx.vin) {
              if (in.empty()) continue;
              if (in.type() != typeid(cryptonote::txin_to_key))
                continue;
              // Use safe pointer form of boost::get
              const auto *p_txin = boost::get<cryptonote::txin_to_key>(&in);
              if (!p_txin) continue;
              const auto &txin = *p_txin;
              // Store the earliest spending tx for each key image
              auto it = spending_tx_map.find(txin.k_image);
              if (it == spending_tx_map.end() ||
                  spend_height < it->second.second) {
                spending_tx_map[txin.k_image] = {j, spend_height};
              }
            }
          } catch (...) {
            // Skip problematic transfers
            continue;
          }
        }
        trace_step = 920; // After Step 1 loop

          // Step 2: Single O(n) pass to mark spent outputs
          for (size_t i = 0; i < transfer_count; ++i) {
            auto &td = m_wallet->m_transfers[i];
            if (td.m_spent)
              continue; // Already marked
            if (!td.m_key_image_known)
              continue; // Can't detect without key image

            auto it = spending_tx_map.find(td.m_key_image);
            if (it != spending_tx_map.end()) {
              // Verify the spending tx is at a higher height than our output
              if (it->second.second > td.m_block_height) {
                td.m_spent = true;
                td.m_spent_height = it->second.second;
                post_marked_spent++;
              }
            }
          }
          trace_step = 930; // After Step 2 loop

          outputs_marked_spent_total += post_marked_spent;
        } // end else (transfer_count sanity check)
      }
      trace_step = 940; // After post-processing block

      uint64_t balance_after = m_wallet->balance(0, "SAL", false) +
                               m_wallet->balance(0, "SAL1", false);

      // v5.36.4 SANITY CHECK: Verify wallet state is not corrupted BEFORE returning success
      // This helps isolate whether corruption happens during chunk processing or between chunks
      trace_step = 950;
      size_t final_transfer_count = m_wallet->get_num_transfer_details();
      if (final_transfer_count > MAX_SANE_TRANSFER_COUNT) {
        std::ostringstream err;
        err << R"({"success":false,"error":"post_chunk_corruption: )" << final_transfer_count
            << R"(","trace_step":)" << trace_step
            << R"(,"build_id":")" << SPARSE_GUARDRAILS_BUILD << R"("})";
        return err.str();
      }
      trace_step = 951;

      // DIAGNOSTIC: Get subaddress map sizes for debugging
      size_t wallet_subaddr_map_size = m_wallet->m_subaddresses.size();
      size_t account_subaddr_map_size =
          m_wallet->get_account().get_subaddress_map_cn().size();

      // Build stake_heights JSON array for return block prediction
      std::string stake_heights_json = "[";
      for (size_t i = 0; i < stake_heights.size(); i++) {
        if (i > 0)
          stake_heights_json += ",";
        stake_heights_json += std::to_string(stake_heights[i]);
      }
      stake_heights_json += "]";

      // Build audit_heights JSON array for return block prediction
      std::string audit_heights_json = "[";
      for (size_t i = 0; i < audit_heights.size(); i++) {
        if (i > 0)
          audit_heights_json += ",";
        audit_heights_json += std::to_string(audit_heights[i]);
      }
      audit_heights_json += "]";

      std::ostringstream oss;
      oss << "{"
          << "\"success\":true,"
          << "\"tx_count\":" << tx_count << ","
          << "\"tx_entries_parsed\":" << tx_entries.size() << ","
          << "\"txs_processed\":" << txs_processed << ","
          << "\"txs_matched\":" << txs_matched << ","
          << "\"outputs_marked_spent\":" << outputs_marked_spent_total << ","
          << "\"txs_skipped_by_prefilter\":" << txs_skipped_by_prefilter << ","
          << "\"quick_match_count\":" << quick_match_count << ","
          << "\"txs_reprocessed\":" << txs_reprocessed << ","
          << "\"txs_parse_failed\":" << txs_parse_failed << ","
          << "\"txs_exception\":" << txs_exception << ","
          << "\"txs_ghost_match\":" << txs_prescan_match_but_not_added << ","
          << "\"ghost_tx_hashes\":[" << ghost_tx_hashes << "],"
          << "\"stake_heights\":" << stake_heights_json << ","
          << "\"audit_heights\":" << audit_heights_json << ","
          << "\"first_tx_hash\":\"" << first_tx_hash_hex << "\","
          << "\"first_tx_pubkey\":\"" << first_tx_pubkey_hex << "\","
          << "\"first_tx_outputs\":" << first_tx_outputs << ","
          << "\"first_tx_indices\":" << first_tx_indices << ","
          << "\"balance_before\":\"" << balance_before << "\","
          << "\"balance_after\":\"" << balance_after << "\","
          << "\"balance_change\":\""
          << (balance_after >= balance_before
                  ? std::to_string(balance_after - balance_before)
                  : "-" + std::to_string(balance_before - balance_after))
          << "\","
          << "\"m_key_images_size\":" << m_wallet->m_key_images.size() << ","
          << "\"m_transfers_size\":" << m_wallet->m_transfers.size() << ","
          << "\"wallet_subaddr_map\":" << wallet_subaddr_map_size << ","
          << "\"account_subaddr_map\":" << account_subaddr_map_size << ","
          << "\"last_error\":\"" << m_last_error << "\","
          << "\"build_id\":\"" << SPARSE_GUARDRAILS_BUILD << "\""
          << "}";

      return oss.str();
    } catch (const std::exception &e) {
      m_last_error = e.what();
      std::ostringstream err;
      err << R"({"success":false,"error":")" << e.what()
          << R"(","trace_step":)" << trace_step
          << R"(,"build_id":")" << SPARSE_GUARDRAILS_BUILD << R"("})";
      return err.str();
    }

    } catch (const std::exception &outer_e) {
      // Outer catch for bad_array_new_length or other allocation failures
      std::ostringstream err;
      err << R"({"success":false,"error":"outer_catch: )" << outer_e.what()
          << R"(","trace_step":)" << trace_step
          << R"(,"build_id":")" << SPARSE_GUARDRAILS_BUILD << R"("})";
      return err.str();
    } catch (...) {
      // Catch-all for non-std exceptions
      std::ostringstream err;
      err << R"({"success":false,"error":"outer_catch_unknown","trace_step":)"
          << trace_step << R"(,"build_id":")" << SPARSE_GUARDRAILS_BUILD
          << R"("})";
      return err.str();
    }
  }

  // ========================================================================
  // DEBUG: Test scanning a single transaction to understand why outputs
  // aren't being detected. This function provides detailed tracing.
  // NOW CARROT-AWARE: Uses correct view key for Carrot vs legacy transactions
  // ========================================================================
  std::string debug_scan_transaction(uintptr_t tx_blob_ptr, size_t tx_blob_size,
                                     double height_d) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    try {
      std::ostringstream oss;
      oss << "{";

      // Report donna64 version for debugging
      int donna64_ver = donna64_get_version();
      oss << "\"donna64_version\":\"0x" << std::hex << donna64_ver << std::dec
          << "\",";

      uint64_t height = static_cast<uint64_t>(height_d);
      const uint8_t *data = reinterpret_cast<const uint8_t *>(tx_blob_ptr);
      std::string tx_blob(reinterpret_cast<const char *>(data), tx_blob_size);

      // Parse transaction
      cryptonote::transaction tx;
      crypto::hash tx_hash;
      if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash)) {
        return R"({"success":false,"error":"Failed to parse transaction"})";
      }

      oss << "\"tx_hash\":\"" << epee::string_tools::pod_to_hex(tx_hash)
          << "\",";
      oss << "\"tx_version\":" << tx.version << ",";
      oss << "\"tx_type\":" << static_cast<int>(tx.type) << ",";
      oss << "\"num_outputs\":" << tx.vout.size() << ",";

      // Get tx pubkey
      crypto::public_key tx_pub = cryptonote::get_tx_pub_key_from_extra(tx);
      oss << "\"tx_pubkey\":\"" << epee::string_tools::pod_to_hex(tx_pub)
          << "\",";

      // Check if Carrot (by checking output type - Carrot uses
      // txout_to_carrot_v1)
      bool is_carrot =
          !tx.vout.empty() &&
          tx.vout[0].target.type() == typeid(cryptonote::txout_to_carrot_v1);
      oss << "\"is_carrot\":" << (is_carrot ? "true" : "false") << ",";

      // Get wallet's keys - show BOTH legacy and Carrot
      const auto &keys = m_wallet->get_account().get_keys();
      oss << "\"wallet_view_pub\":\""
          << epee::string_tools::pod_to_hex(
                 keys.m_account_address.m_view_public_key)
          << "\",";
      oss << "\"wallet_spend_pub\":\""
          << epee::string_tools::pod_to_hex(
                 keys.m_account_address.m_spend_public_key)
          << "\",";
      oss << "\"carrot_spend_pub\":\""
          << epee::string_tools::pod_to_hex(
                 keys.m_carrot_account_address.m_spend_public_key)
          << "\",";
      oss << "\"carrot_main_spend_pub\":\""
          << epee::string_tools::pod_to_hex(
                 keys.m_carrot_main_address.m_spend_public_key)
          << "\",";

      // Compute key derivation with the CORRECT view key
      // For Carrot: use k_view_incoming
      // For Pre-Carrot: use m_view_secret_key
      crypto::key_derivation derivation;
      bool deriv_ok;
      std::string deriv_key_type;
      if (is_carrot) {
        deriv_ok = crypto::generate_key_derivation(tx_pub, keys.k_view_incoming,
                                                   derivation);
        deriv_key_type = "k_view_incoming";
      } else {
        deriv_ok = crypto::generate_key_derivation(
            tx_pub, keys.m_view_secret_key, derivation);
        deriv_key_type = "m_view_secret_key";
      }
      oss << "\"derivation_key_type\":\"" << deriv_key_type << "\",";
      oss << "\"derivation_ok\":" << (deriv_ok ? "true" : "false") << ",";
      if (deriv_ok) {
        oss << "\"derivation_crypto\":\""
            << epee::string_tools::pod_to_hex(derivation) << "\",";
      }

      // ALSO compute derivation using hwdev (what the actual scan uses)
      crypto::key_derivation derivation_hwdev;
      hw::device &hwdev = m_wallet->get_account().get_keys().get_device();
      bool deriv_hwdev_ok;
      if (is_carrot) {
        deriv_hwdev_ok = hwdev.generate_key_derivation(
            tx_pub, keys.k_view_incoming, derivation_hwdev);
      } else {
        deriv_hwdev_ok = hwdev.generate_key_derivation(
            tx_pub, keys.m_view_secret_key, derivation_hwdev);
      }
      oss << "\"derivation_hwdev_ok\":" << (deriv_hwdev_ok ? "true" : "false")
          << ",";
      if (deriv_hwdev_ok) {
        oss << "\"derivation_hwdev\":\""
            << epee::string_tools::pod_to_hex(derivation_hwdev) << "\",";
      }
      oss << "\"derivations_match\":"
          << (deriv_ok && deriv_hwdev_ok && derivation == derivation_hwdev
                  ? "true"
                  : "false")
          << ",";

      // ALSO compute derivation by calling donna64 DIRECTLY
      // This tells us if hwdev is actually using donna64 or something else
      crypto::key_derivation derivation_donna64_direct;
      bool deriv_donna64_ok;
      if (is_carrot) {
        deriv_donna64_ok =
            donna64_generate_key_derivation(
                reinterpret_cast<unsigned char *>(&derivation_donna64_direct),
                reinterpret_cast<const unsigned char *>(&tx_pub),
                reinterpret_cast<const unsigned char *>(
                    &keys.k_view_incoming)) == 0;
      } else {
        deriv_donna64_ok =
            donna64_generate_key_derivation(
                reinterpret_cast<unsigned char *>(&derivation_donna64_direct),
                reinterpret_cast<const unsigned char *>(&tx_pub),
                reinterpret_cast<const unsigned char *>(
                    &keys.m_view_secret_key)) == 0;
      }
      oss << "\"derivation_donna64_direct_ok\":"
          << (deriv_donna64_ok ? "true" : "false") << ",";
      if (deriv_donna64_ok) {
        oss << "\"derivation_donna64_direct\":\""
            << epee::string_tools::pod_to_hex(derivation_donna64_direct)
            << "\",";
      }
      // Check which paths match
      oss << "\"hwdev_matches_donna64\":"
          << (deriv_hwdev_ok && deriv_donna64_ok &&
                      derivation_hwdev == derivation_donna64_direct
                  ? "true"
                  : "false")
          << ",";
      oss << "\"ref10_matches_donna64\":"
          << (deriv_ok && deriv_donna64_ok &&
                      derivation == derivation_donna64_direct
                  ? "true"
                  : "false")
          << ",";

      // Use the ACTUAL wallet scanning mechanism - this is what
      // process_new_transaction uses! This will tell us definitively if wallet2
      // finds the outputs
      std::vector<std::optional<tools::wallet::enote_view_incoming_scan_info_t>>
          scan_results;
      try {
        scan_results = tools::wallet::view_incoming_scan_transaction(
            tx, m_wallet->get_account());
      } catch (const std::exception &e) {
        oss << "\"scan_error\":\"" << e.what() << "\",";
      }

      // Check each output
      oss << "\"outputs\":[";
      for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (i > 0)
          oss << ",";
        oss << "{";
        oss << "\"index\":" << i << ",";

        // Get output key
        crypto::public_key out_key;
        if (!cryptonote::get_output_public_key(tx.vout[i], out_key)) {
          oss << "\"error\":\"no output key\"}";
          continue;
        }
        oss << "\"out_key\":\"" << epee::string_tools::pod_to_hex(out_key)
            << "\",";

        // Get view tag if present
        auto view_tag_opt = cryptonote::get_output_view_tag(tx.vout[i]);
        if (view_tag_opt) {
          oss << "\"view_tag\":" << static_cast<int>(view_tag_opt->data) << ",";
        }

        // Check wallet scan result for this output
        if (i < scan_results.size() && scan_results[i].has_value()) {
          const auto &info = scan_results[i].value();
          oss << "\"wallet_scan_matched\":true,";
          oss << "\"amount\":\"" << info.amount << "\",";
          if (info.subaddr_index.has_value()) {
            oss << "\"subaddr_major\":" << info.subaddr_index->index.major
                << ",";
            oss << "\"subaddr_minor\":" << info.subaddr_index->index.minor
                << ",";
          }
          oss << "\"is_carrot_output\":" << (info.is_carrot ? "true" : "false");
        } else {
          oss << "\"wallet_scan_matched\":false";

          // If wallet scan didn't find it, also try legacy derivation for
          // comparison Use BOTH derivations to see which one works
          if (deriv_ok) {
            crypto::public_key derived_spend_key_crypto;
            hw::device &hwdev_check =
                m_wallet->get_account().get_keys().get_device();
            if (hwdev_check.derive_subaddress_public_key(
                    out_key, derivation, i, derived_spend_key_crypto)) {
              oss << ",\"derived_spend_key_crypto\":\""
                  << epee::string_tools::pod_to_hex(derived_spend_key_crypto)
                  << "\"";

              // Check if this key is in the legacy subaddress map
              const auto &subaddr_map =
                  m_wallet->get_account().get_subaddress_map_cn();
              auto found_crypto = subaddr_map.find(derived_spend_key_crypto);
              oss << ",\"in_legacy_subaddr_map_crypto\":"
                  << (found_crypto != subaddr_map.end() ? "true" : "false");
            }
          }

          // Also try with hwdev derivation
          if (deriv_hwdev_ok) {
            crypto::public_key derived_spend_key_hwdev;
            hw::device &hwdev_check =
                m_wallet->get_account().get_keys().get_device();
            if (hwdev_check.derive_subaddress_public_key(
                    out_key, derivation_hwdev, i, derived_spend_key_hwdev)) {
              oss << ",\"derived_spend_key_hwdev\":\""
                  << epee::string_tools::pod_to_hex(derived_spend_key_hwdev)
                  << "\"";

              // Check if this key is in the legacy subaddress map
              const auto &subaddr_map =
                  m_wallet->get_account().get_subaddress_map_cn();
              auto found_hwdev = subaddr_map.find(derived_spend_key_hwdev);
              oss << ",\"in_legacy_subaddr_map_hwdev\":"
                  << (found_hwdev != subaddr_map.end() ? "true" : "false");
            }
          }
        }

        oss << "}";
      }
      oss << "],";

      // Show subaddress map sizes (both legacy and extended)
      const auto &subaddr_map_cn =
          m_wallet->get_account().get_subaddress_map_cn();
      const auto &subaddr_map_ext =
          m_wallet->get_account().get_subaddress_map_ref();
      oss << "\"subaddr_map_cn_size\":" << subaddr_map_cn.size() << ",";
      oss << "\"subaddr_map_ext_size\":" << subaddr_map_ext.size() << ",";

      // Show first few keys from extended subaddress map (includes derive type)
      oss << "\"subaddr_map_sample\":[";
      int count = 0;
      for (const auto &entry : subaddr_map_ext) {
        if (count >= 3)
          break;
        if (count > 0)
          oss << ",";
        oss << "{\"key\":\"" << epee::string_tools::pod_to_hex(entry.first)
            << "\",";
        oss << "\"major\":" << entry.second.index.major << ",";
        oss << "\"minor\":" << entry.second.index.minor << ",";
        oss << "\"derive_type\":" << static_cast<int>(entry.second.derive_type)
            << "}";
        count++;
      }
      oss << "],";

      oss << "\"success\":true}";
      return oss.str();

    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    }
  }

  // ========================================================================
  // GET LOCKED COINS INFO - Debug function for protocol_tx troubleshooting
  // Returns the current m_locked_coins map state for debugging staking issues
  // ========================================================================
  std::string get_locked_coins_info() {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }

    try {
      std::ostringstream oss;

      // =====================================================================
      // PART 1: Direct access to m_locked_coins (the actual active stakes)
      // This is what balance() uses to add locked stake amounts
      // =====================================================================
      oss << "{\"m_locked_coins\":[";
      uint64_t total_locked = 0;
      bool first = true;
      for (const auto &lc : m_wallet->m_locked_coins) {
        if (!first)
          oss << ",";
        first = false;
        oss << "{\"key\":\"" << epee::string_tools::pod_to_hex(lc.first) << "\""
            << ",\"index_major\":" << lc.second.m_index_major
            << ",\"amount\":" << lc.second.m_amount << ",\"asset_type\":\""
            << lc.second.m_asset_type << "\"}";
        total_locked += lc.second.m_amount;
      }
      oss << "],\"m_locked_coins_count\":" << m_wallet->m_locked_coins.size()
          << ",\"m_locked_coins_total\":" << total_locked;

      // =====================================================================
      // PART 2: Scan transfer_details for STAKE type outputs (change outputs)
      // =====================================================================
      size_t stake_change_count = 0;
      uint64_t stake_change_total = 0;

      const size_t transfer_count = m_wallet->get_num_transfer_details();
      oss << ",\"stake_change_outputs\":[";
      first = true;

      for (size_t i = 0; i < transfer_count; ++i) {
        const auto &td = m_wallet->get_transfer_details(i);

        // Check if this is from a STAKE transaction (change output)
        if (td.m_tx.type == cryptonote::transaction_type::STAKE) {
          if (!first)
            oss << ",";
          first = false;
          stake_change_count++;
          stake_change_total += td.m_amount;

          oss << "{\"idx\":" << i << ",\"txid\":\""
              << epee::string_tools::pod_to_hex(td.m_txid) << "\""
              << ",\"amount\":" << td.m_amount
              << ",\"amount_burnt\":" << td.m_tx.amount_burnt
              << ",\"spent\":" << (td.m_spent ? "true" : "false")
              << ",\"height\":" << td.m_block_height << ",\"asset\":\""
              << td.asset_type << "\"}";
        }
      }
      oss << "],\"stake_change_count\":" << stake_change_count
          << ",\"stake_change_total\":" << stake_change_total;

      // =====================================================================
      // PART 3: Protocol returns (PROTOCOL type = stake returns)
      // =====================================================================
      size_t protocol_count = 0;
      uint64_t protocol_total = 0;
      oss << ",\"protocol_returns\":[";
      first = true;

      for (size_t i = 0; i < transfer_count; ++i) {
        const auto &td = m_wallet->get_transfer_details(i);
        if (td.m_tx.type == cryptonote::transaction_type::PROTOCOL) {
          if (!first)
            oss << ",";
          first = false;
          protocol_count++;
          protocol_total += td.m_amount;

          oss << "{\"idx\":" << i << ",\"txid\":\""
              << epee::string_tools::pod_to_hex(td.m_txid) << "\""
              << ",\"amount\":" << td.m_amount
              << ",\"spent\":" << (td.m_spent ? "true" : "false")
              << ",\"height\":" << td.m_block_height
              << ",\"origin_idx\":" << td.m_td_origin_idx << "}";
        }
      }
      oss << "],\"protocol_return_count\":" << protocol_count
          << ",\"protocol_return_total\":" << protocol_total;

      // =====================================================================
      // PART 4: Balance summary
      // =====================================================================
      uint64_t bal = m_wallet->balance(0, "SAL", false) +
                     m_wallet->balance(0, "SAL1", false);
      uint64_t unlocked = m_wallet->unlocked_balance(0, "SAL", false) +
                          m_wallet->unlocked_balance(0, "SAL1", false);
      oss << ",\"balance\":" << bal << ",\"unlocked_balance\":" << unlocked
          << ",\"locked_via_m_locked_coins\":" << (bal - unlocked)
          << ",\"total_transfers\":" << transfer_count << ",\"success\":true}";

      return oss.str();

    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    }
  }

  // ========================================================================
  // DEBUG: Transfer VIN inspection
  // Returns JSON array of transfer details including vin.size() for debugging
  // ========================================================================
  std::string debug_transfer_vin() {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }
    try {
      const size_t transfer_count = m_wallet->get_num_transfer_details();
      std::ostringstream oss;
      oss << "{\"success\":true,\"transfer_count\":" << transfer_count
          << ",\"m_key_images_size\":" << m_wallet->m_key_images.size();

      // Show all key images we have in the map
      oss << ",\"all_key_images\":[";
      bool first_ki = true;
      for (const auto &kv : m_wallet->m_key_images) {
        if (!first_ki)
          oss << ",";
        first_ki = false;
        oss << "{\"ki\":\""
            << epee::string_tools::pod_to_hex(kv.first).substr(0, 16) << "...\""
            << ",\"td_idx\":" << kv.second << "}";
      }
      oss << "],\"transfers\":[";

      bool first = true;
      for (size_t i = 0; i < transfer_count && i < 20; ++i) {
        const auto &td = m_wallet->get_transfer_details(i);
        if (!first)
          oss << ",";
        first = false;

        oss << "{\"idx\":" << i << ",\"height\":" << td.m_block_height
            << ",\"txid\":\""
            << epee::string_tools::pod_to_hex(td.m_txid).substr(0, 16)
            << "...\""
            << ",\"type\":" << static_cast<int>(td.m_tx.type)
            << ",\"vin_size\":" << td.m_tx.vin.size()
            << ",\"vout_size\":" << td.m_tx.vout.size()
            << ",\"spent\":" << (td.m_spent ? "true" : "false")
            << ",\"spent_height\":" << td.m_spent_height
            << ",\"key_image_known\":"
            << (td.m_key_image_known ? "true" : "false")
            << ",\"origin_idx\":" << td.m_td_origin_idx
            << ",\"amount\":" << td.m_amount;

        // Show OUR key image for this transfer
        oss << ",\"our_ki\":\""
            << epee::string_tools::pod_to_hex(td.m_key_image).substr(0, 16)
            << "...\"";

        // Check if key_image is in m_key_images
        bool ki_in_map = m_wallet->m_key_images.find(td.m_key_image) !=
                         m_wallet->m_key_images.end();
        oss << ",\"ki_in_map\":" << (ki_in_map ? "true" : "false");

        // If vin has entries, show first key_image
        if (!td.m_tx.vin.empty() &&
            td.m_tx.vin[0].type() == typeid(cryptonote::txin_to_key)) {
          const auto &txin =
              boost::get<cryptonote::txin_to_key>(td.m_tx.vin[0]);
          oss << ",\"input0_ki\":\""
              << epee::string_tools::pod_to_hex(txin.k_image).substr(0, 16)
              << "...\"";
          bool in0_in_map = m_wallet->m_key_images.find(txin.k_image) !=
                            m_wallet->m_key_images.end();
          oss << ",\"input0_ki_in_map\":" << (in0_in_map ? "true" : "false");
        }

        oss << "}";
      }
      oss << "]}";
      return oss.str();
    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    }
  }

  // ========================================================================
  // DEBUG: Diagnose "no input candidates" issue
  // Shows m_transfers_indices and spendability of each transfer
  // ========================================================================
  std::string debug_input_candidates() {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }
    try {
      std::ostringstream oss;
      oss << "{\"success\":true";

      // Show m_transfers_indices map
      oss << ",\"transfers_indices\":{";
      bool first_asset = true;
      for (const auto &kv : m_wallet->m_transfers_indices) {
        if (!first_asset)
          oss << ",";
        first_asset = false;
        oss << "\"" << kv.first << "\":" << kv.second.size();
      }
      oss << "}";

      // Get current height for unlock checking
      uint64_t current_height = m_wallet->get_blockchain_current_height();
      oss << ",\"current_height\":" << current_height;

      // Count ALL transfers first
      size_t total = m_wallet->m_transfers.size();
      size_t sal_count = 0, sal1_count = 0;
      size_t sal_spendable = 0, sal1_spendable = 0;
      size_t spent_count = 0, frozen_count = 0, locked_count = 0;
      size_t no_key_image = 0, partial_key_image = 0;
      size_t sal1_account0 = 0, sal1_account0_spendable = 0;

      for (size_t i = 0; i < total; ++i) {
        const auto &td = m_wallet->m_transfers[i];
        bool is_sal1 = (td.asset_type == "SAL1");
        bool is_spent = td.m_spent;
        bool is_frozen = td.m_frozen;
        bool is_unlocked = m_wallet->is_transfer_unlocked(td);
        bool has_key_image = td.m_key_image_known;
        bool partial_ki = td.m_key_image_partial;
        bool spendable = !is_spent && !is_frozen && is_unlocked &&
                         has_key_image && !partial_ki;
        bool is_account0 = (td.m_subaddr_index.major == 0);

        if (is_sal1) {
          sal1_count++;
          if (spendable)
            sal1_spendable++;
          if (is_account0) {
            sal1_account0++;
            if (spendable)
              sal1_account0_spendable++;
          }
        } else {
          sal_count++;
          if (spendable)
            sal_spendable++;
        }
        if (is_spent)
          spent_count++;
        if (is_frozen)
          frozen_count++;
        if (!is_unlocked)
          locked_count++;
        if (!has_key_image)
          no_key_image++;
        if (partial_ki)
          partial_key_image++;
      }

      // Show first 15 SAL transfers and first 15 SAL1 transfers
      oss << ",\"transfers\":[";
      bool first = true;
      size_t sal_shown = 0, sal1_shown = 0;
      for (size_t i = 0; i < total && (sal_shown < 15 || sal1_shown < 15);
           ++i) {
        const auto &td = m_wallet->m_transfers[i];
        bool is_sal1 = (td.asset_type == "SAL1");
        if (is_sal1 && sal1_shown >= 15)
          continue;
        if (!is_sal1 && sal_shown >= 15)
          continue;
        if (is_sal1)
          sal1_shown++;
        else
          sal_shown++;

        if (!first)
          oss << ",";
        first = false;

        bool is_spent = td.m_spent;
        bool is_frozen = td.m_frozen;
        bool is_unlocked = m_wallet->is_transfer_unlocked(td);
        bool has_key_image = td.m_key_image_known;
        bool partial_ki = td.m_key_image_partial;
        bool spendable = !is_spent && !is_frozen && is_unlocked &&
                         has_key_image && !partial_ki;

        oss << "{\"idx\":" << i << ",\"asset\":\"" << td.asset_type << "\""
            << ",\"amount\":" << td.amount()
            << ",\"height\":" << td.m_block_height
            << ",\"global_idx\":" << td.m_global_output_index
            << ",\"subaddr_major\":" << td.m_subaddr_index.major
            << ",\"subaddr_minor\":" << td.m_subaddr_index.minor
            << ",\"spent\":" << (is_spent ? "true" : "false")
            << ",\"frozen\":" << (is_frozen ? "true" : "false")
            << ",\"unlocked\":" << (is_unlocked ? "true" : "false")
            << ",\"ki_known\":" << (has_key_image ? "true" : "false")
            << ",\"ki_partial\":" << (partial_ki ? "true" : "false")
            << ",\"spendable\":" << (spendable ? "true" : "false")
            << ",\"unlock_time\":" << td.m_tx.unlock_time << "}";
      }
      oss << "]";

      // Check what balance_per_subaddress returns (this populates
      // subaddr_indices)
      auto sal1_balance_per_subaddr =
          m_wallet->balance_per_subaddress(0, "SAL1", false);
      auto sal_balance_per_subaddr =
          m_wallet->balance_per_subaddress(0, "SAL", false);

      // Summary
      oss << ",\"summary\":{"
          << "\"total\":" << total << ",\"sal_count\":" << sal_count
          << ",\"sal1_count\":" << sal1_count
          << ",\"sal_spendable\":" << sal_spendable
          << ",\"sal1_spendable\":" << sal1_spendable
          << ",\"sal1_account0\":" << sal1_account0
          << ",\"sal1_account0_spendable\":" << sal1_account0_spendable
          << ",\"spent\":" << spent_count << ",\"frozen\":" << frozen_count
          << ",\"locked\":" << locked_count
          << ",\"no_key_image\":" << no_key_image
          << ",\"partial_key_image\":" << partial_key_image
          << ",\"sal1_subaddr_count\":" << sal1_balance_per_subaddr.size()
          << ",\"sal_subaddr_count\":" << sal_balance_per_subaddr.size() << "}";

      oss << "}";
      return oss.str();
    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    }
  }

  // ========================================================================
  // DEBUG: Simulate exact input selection logic from tx_builder.cpp
  // This mirrors is_transfer_usable_for_input_selection EXACTLY
  // ========================================================================
  std::string debug_tx_input_selection(uint32_t from_account) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }
    try {
      std::ostringstream oss;
      oss << "{\"success\":true";

      // Get EXACTLY what tx_builder uses
      uint64_t current_chain_height = m_wallet->get_blockchain_current_height();
      uint64_t top_block_index =
          (current_chain_height > 0) ? current_chain_height - 1 : 0;
      uint64_t ignore_above = m_wallet->ignore_outputs_above();
      uint64_t ignore_below = m_wallet->ignore_outputs_below();

      oss << ",\"current_chain_height\":" << current_chain_height
          << ",\"top_block_index\":" << top_block_index
          << ",\"from_account\":" << from_account
          << ",\"ignore_above\":" << ignore_above
          << ",\"ignore_below\":" << ignore_below;

      // Mimic tx_builder.cpp: get_transfers copies m_transfers
      size_t total = m_wallet->m_transfers.size();
      oss << ",\"total_transfers\":" << total;

      // Count by exact tx_builder logic
      size_t sal1_total = 0, sal1_usable = 0;
      size_t rejected_spent = 0, rejected_no_ki = 0, rejected_partial = 0;
      size_t rejected_frozen = 0, rejected_locked = 0, rejected_account = 0;
      size_t rejected_amt = 0, rejected_not_v10 = 0;

      // Sample of first 10 rejections for each reason
      std::vector<std::string> sample_rejections;

      for (size_t i = 0; i < total; ++i) {
        const auto &td = m_wallet->m_transfers[i];

        bool is_v10 = (td.asset_type == "SAL1");
        if (!is_v10)
          continue; // Only count SAL1
        sal1_total++;

        // EXACT logic from tx_builder.cpp
        // is_transfer_usable_for_input_selection
        size_t blocks_locked_for = CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE; // 10
        if (td.m_tx.type == cryptonote::transaction_type::MINER ||
            td.m_tx.type == cryptonote::transaction_type::PROTOCOL)
          blocks_locked_for = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; // 60

        bool is_spent = td.m_spent;
        bool ki_known = td.m_key_image_known;
        bool ki_partial = td.m_key_image_partial;
        bool frozen = td.m_frozen;
        bool height_unlocked =
            (top_block_index >= td.m_block_height + blocks_locked_for);
        bool acct_match = (td.m_subaddr_index.major == from_account);
        bool subaddr_match = true; // Empty subaddresses = match all
        bool amt_ok =
            (td.amount() >= ignore_below && td.amount() <= ignore_above);

        bool result = !is_spent && ki_known && !ki_partial && !frozen &&
                      height_unlocked && acct_match && subaddr_match &&
                      amt_ok && is_v10;

        if (result) {
          sal1_usable++;
        } else {
          // Track rejection reason
          if (is_spent)
            rejected_spent++;
          else if (!ki_known)
            rejected_no_ki++;
          else if (ki_partial)
            rejected_partial++;
          else if (frozen)
            rejected_frozen++;
          else if (!height_unlocked)
            rejected_locked++;
          else if (!acct_match)
            rejected_account++;
          else if (!amt_ok)
            rejected_amt++;

          // Sample first few rejections with details
          if (sample_rejections.size() < 10) {
            std::ostringstream rej;
            rej << "{\"idx\":" << i << ",\"height\":" << td.m_block_height
                << ",\"amount\":" << td.amount()
                << ",\"tx_type\":" << static_cast<int>(td.m_tx.type)
                << ",\"blocks_locked_for\":" << blocks_locked_for
                << ",\"unlock_at\":" << (td.m_block_height + blocks_locked_for)
                << ",\"is_spent\":" << (is_spent ? "true" : "false")
                << ",\"ki_known\":" << (ki_known ? "true" : "false")
                << ",\"ki_partial\":" << (ki_partial ? "true" : "false")
                << ",\"frozen\":" << (frozen ? "true" : "false")
                << ",\"height_unlocked\":"
                << (height_unlocked ? "true" : "false")
                << ",\"acct_match\":" << (acct_match ? "true" : "false")
                << ",\"amt_ok\":" << (amt_ok ? "true" : "false")
                << ",\"subaddr_major\":" << td.m_subaddr_index.major << "}";
            sample_rejections.push_back(rej.str());
          }
        }
      }

      oss << ",\"sal1_total\":" << sal1_total
          << ",\"sal1_usable\":" << sal1_usable
          << ",\"rejected_spent\":" << rejected_spent
          << ",\"rejected_no_ki\":" << rejected_no_ki
          << ",\"rejected_partial\":" << rejected_partial
          << ",\"rejected_frozen\":" << rejected_frozen
          << ",\"rejected_locked\":" << rejected_locked
          << ",\"rejected_account\":" << rejected_account
          << ",\"rejected_amt\":" << rejected_amt;

      // Show sample rejections
      oss << ",\"sample_rejections\":[";
      for (size_t i = 0; i < sample_rejections.size(); ++i) {
        if (i > 0)
          oss << ",";
        oss << sample_rejections[i];
      }
      oss << "]";

      oss << "}";
      return oss.str();
    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    }
  }

  // ========================================================================
  // DEBUG: Trace entire create_transaction path
  // This simulates create_transaction_json and reports detailed diagnostics
  // ========================================================================
  std::string debug_create_tx_path(const std::string &dest_address_str,
                                   const std::string &amount_str) {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }
    try {
      std::ostringstream oss;
      oss << "{\"success\":true";

      // Parse amount
      uint64_t amount = std::stoull(amount_str);
      oss << ",\"amount\":" << amount;

      // Get HF version
      uint8_t hf_version = m_wallet->get_current_hard_fork();
      oss << ",\"hf_version\":" << (int)hf_version;
      oss << ",\"is_carrot_hf\":" << (hf_version >= 10 ? "true" : "false");

      // Parse destination address
      cryptonote::address_parse_info info;
      bool addr_valid = cryptonote::get_account_address_from_str(
          info, m_wallet->nettype(), dest_address_str);
      oss << ",\"address_valid\":" << (addr_valid ? "true" : "false");

      if (addr_valid) {
        oss << ",\"is_subaddress\":" << (info.is_subaddress ? "true" : "false");
        oss << ",\"has_payment_id\":"
            << (info.has_payment_id ? "true" : "false");
        oss << ",\"addr_is_carrot\":"
            << (info.address.m_is_carrot ? "true" : "false");

        // Check if address type matches HF
        bool addr_hf_match = (hf_version >= 10 && info.address.m_is_carrot) ||
                             (hf_version < 10 && !info.address.m_is_carrot);
        oss << ",\"addr_hf_match\":" << (addr_hf_match ? "true" : "false");
      }

      // Get balances
      uint64_t unlocked_sal = m_wallet->unlocked_balance(0, "SAL", false);
      uint64_t unlocked_sal1 = m_wallet->unlocked_balance(0, "SAL1", false);
      oss << ",\"unlocked_sal\":" << unlocked_sal;
      oss << ",\"unlocked_sal1\":" << unlocked_sal1;

      // Determine asset type
      std::string asset_type;
      if (unlocked_sal1 >= amount) {
        asset_type = "SAL1";
      } else if (unlocked_sal >= amount) {
        asset_type = "SAL";
      } else {
        asset_type = (hf_version >= 10) ? "SAL1" : "SAL";
      }
      oss << ",\"asset_type\":\"" << asset_type << "\"";

      // Get transfer counts
      tools::wallet2::transfer_container transfers;
      m_wallet->get_transfers(transfers);
      oss << ",\"total_transfers\":" << transfers.size();

      // Count SAL1 transfers specifically
      size_t sal1_count = 0;
      for (const auto &td : transfers) {
        if (td.asset_type == "SAL1")
          sal1_count++;
      }
      oss << ",\"sal1_transfers\":" << sal1_count;

      // Try to create transaction and catch specific error
      if (addr_valid) {
        oss << ",\"tx_attempt\":{";
        try {
          std::vector<cryptonote::tx_destination_entry> dsts;
          cryptonote::tx_destination_entry dst;
          dst.amount = amount;
          dst.addr = info.address;
          dst.is_subaddress = info.is_subaddress;
          dst.is_integrated = info.has_payment_id;
          dst.asset_type = asset_type;
          dsts.push_back(dst);

          std::vector<uint8_t> extra;

          // Find a valid priority with non-zero base_fee
          uint32_t priority = 1;
          if (m_wallet->get_base_fee(priority) == 0) {
            for (uint32_t p = 2; p <= 4; ++p) {
              if (m_wallet->get_base_fee(p) > 0) {
                priority = p;
                break;
              }
            }
          }
          oss << "\"priority_used\":" << priority << ",";

          // This will throw with the exact error
          auto ptx_vector = m_wallet->create_transactions_2(
              dsts, asset_type, asset_type,
              cryptonote::transaction_type::TRANSFER,
              15, // mixin
              0,  // unlock_time
              priority, extra, 0, {});

          oss << "\"result\":\"success\",\"tx_count\":" << ptx_vector.size();
        } catch (const std::exception &e) {
          std::string err = e.what();
          // Escape quotes
          size_t pos = 0;
          while ((pos = err.find('"', pos)) != std::string::npos) {
            err.replace(pos, 1, "'");
            pos += 1;
          }
          oss << "\"result\":\"error\",\"error\":\"" << err << "\"";
        }
        oss << "}";
      }

      oss << "}";
      return oss.str();
    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    }
  }

  // ========================================================================
  // DEBUG: Check fee calculation parameters
  // This helps diagnose "fee not monotonically increasing" errors
  // ========================================================================
  std::string debug_fee_params() {
    if (!m_initialized) {
      return R"({"success":false,"error":"Wallet not initialized"})";
    }
    try {
      std::ostringstream oss;
      oss << "{\"success\":true";

      // Get base fee for different priorities
      for (uint32_t priority = 0; priority <= 4; ++priority) {
        uint64_t base_fee = m_wallet->get_base_fee(priority);
        oss << ",\"base_fee_priority_" << priority << "\":" << base_fee;
      }

      // Get fee quantization mask
      uint64_t fee_quantization_mask = m_wallet->get_fee_quantization_mask();
      oss << ",\"fee_quantization_mask\":" << fee_quantization_mask;

      // Simulate fee calculation like tx_proposal_utils.cpp does
      // Use typical values: 2 outputs (destination + change), 100 byte extra
      uint64_t base_fee = m_wallet->get_base_fee(1); // priority 1
      size_t num_outs = 2;
      size_t tx_extra_size = 100;

      oss << ",\"simulated_fees\":[";
      bool first = true;
      for (size_t num_ins = 1; num_ins <= 8; ++num_ins) {
        if (!first)
          oss << ",";
        first = false;

        // Estimate weight (simplified version)
        // From tx_proposal_utils.h estimate_tx_weigh_carrot
        size_t weight = num_ins * 1000 + num_outs * 500 + tx_extra_size;

        // Calculate fee
        uint64_t fee = weight * base_fee;
        uint64_t quantized_fee = (fee + fee_quantization_mask - 1) /
                                 fee_quantization_mask * fee_quantization_mask;

        oss << "{\"inputs\":" << num_ins << ",\"weight\":" << weight
            << ",\"raw_fee\":" << fee << ",\"quantized_fee\":" << quantized_fee
            << "}";
      }
      oss << "]";

      oss << "}";
      return oss.str();
    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    }
  }

  // ========================================================================
  // COMPREHENSIVE DERIVATION COMPARISON
  // Compares ref10 vs donna64 with detailed intermediate values
  // ========================================================================
  std::string compare_derivation_methods(const std::string &tx_pub_hex,
                                         const std::string &view_sec_hex) {
    std::ostringstream oss;
    oss << "{";

    try {
      unsigned char tx_pub[32];
      unsigned char view_sec[32];

      // Parse hex inputs
      if (tx_pub_hex.length() != 64 || view_sec_hex.length() != 64) {
        return R"({"error":"tx_pub and view_sec must be 64 hex characters"})";
      }

      for (int i = 0; i < 32; i++) {
        tx_pub[i] = std::stoi(tx_pub_hex.substr(i * 2, 2), nullptr, 16);
        view_sec[i] = std::stoi(view_sec_hex.substr(i * 2, 2), nullptr, 16);
      }

      // Report donna64 version
      int ver = donna64_get_version();
      oss << "\"donna64_version\":\"0x" << std::hex << ver << std::dec << "\",";

      // METHOD 1: ref10 (crypto::generate_key_derivation)
      crypto::public_key crypto_pub;
      crypto::secret_key crypto_sec;
      crypto::key_derivation derivation_ref10;
      memcpy(&crypto_pub, tx_pub, 32);
      memcpy(&crypto_sec, view_sec, 32);

      bool ref10_ok = crypto::generate_key_derivation(crypto_pub, crypto_sec,
                                                      derivation_ref10);
      oss << "\"ref10_ok\":" << (ref10_ok ? "true" : "false") << ",";
      if (ref10_ok) {
        oss << "\"derivation_ref10\":\""
            << epee::string_tools::pod_to_hex(derivation_ref10) << "\",";
      }

      // METHOD 2: donna64 direct call
      unsigned char derivation_donna64[32];
      int donna64_ret =
          donna64_generate_key_derivation(derivation_donna64, tx_pub, view_sec);
      bool donna64_ok = (donna64_ret == 0);
      oss << "\"donna64_ok\":" << (donna64_ok ? "true" : "false") << ",";
      if (donna64_ok) {
        oss << "\"derivation_donna64\":\"" << key_to_hex(derivation_donna64)
            << "\",";
      }

      // Compare
      if (ref10_ok && donna64_ok) {
        bool match = (memcmp(&derivation_ref10, derivation_donna64, 32) == 0);
        oss << "\"match\":" << (match ? "true" : "false") << ",";

        if (!match) {
          // Find first differing byte
          int first_diff = -1;
          for (int i = 0; i < 32; i++) {
            if (reinterpret_cast<unsigned char *>(&derivation_ref10)[i] !=
                derivation_donna64[i]) {
              first_diff = i;
              break;
            }
          }
          oss << "\"first_diff_byte\":" << first_diff << ",";
        }
      }

      // Run donna64 field tests
      extern int donna64_test_field_ops(void);
      int field_test = donna64_test_field_ops();
      oss << "\"donna64_field_test\":" << field_test << ",";

      // Run donna64 point roundtrip test
      extern int donna64_test_point_roundtrip(const unsigned char *,
                                              unsigned char *);
      unsigned char roundtrip_out[32];
      int roundtrip_ret = donna64_test_point_roundtrip(tx_pub, roundtrip_out);
      oss << "\"donna64_roundtrip_ok\":"
          << (roundtrip_ret == 0 ? "true" : "false") << ",";
      if (roundtrip_ret == 0) {
        bool roundtrip_match = (memcmp(tx_pub, roundtrip_out, 32) == 0);
        oss << "\"roundtrip_match\":" << (roundtrip_match ? "true" : "false")
            << ",";
        if (!roundtrip_match) {
          oss << "\"roundtrip_out\":\"" << key_to_hex(roundtrip_out) << "\",";
        }
      }

      oss << "\"success\":true}";
      return oss.str();

    } catch (const std::exception &e) {
      return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
    }
  }
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string validate_address(const std::string &address) {
  try {
    cryptonote::address_parse_info info;
    if (cryptonote::get_account_address_from_str(info, cryptonote::MAINNET,
                                                 address)) {
      return info.is_subaddress ? "subaddress" : "standard";
    }
    return "invalid";
  } catch (...) {
    return "error";
  }
}

std::string get_version() {
  std::string version = "SalviumWallet WASM v" + std::string(WASM_VERSION);

  // Add SIMD status
#ifdef __wasm_simd128__
  version += " [SIMD:ON]";
#else
  version += " [SIMD:OFF]";
#endif

  // Add optimization level
#ifdef NDEBUG
  version += " [Release]";
#else
  version += " [Debug]";
#endif

  return version;
}

// Returns the sparse guardrails build ID for verification
std::string get_sparse_build_id() {
  return WasmWallet::SPARSE_GUARDRAILS_BUILD;
}

// ============================================================================
// HTTP Cache Functions (from http_client_stubs.cpp)
// For injecting pre-fetched decoy outputs before transaction creation
// ============================================================================
extern "C" {
void wasm_http_inject_binary_response(const char *path, const char *data,
                                      size_t data_len);
void wasm_http_inject_json_response(const char *path, const char *json_data);
void wasm_http_clear_cache();
bool wasm_http_has_cached_response(const char *path);
// Functions for two-phase transaction creation
bool wasm_http_has_pending_get_outs_request();
const char *wasm_http_get_pending_get_outs_request_base64();
void wasm_http_clear_pending_get_outs_request();
// Per-index output cache functions
// NOTE: cache_index is asset_type_output_index (from request), output_id is
// global_output_index
// asset_type distinguishes same indices across different asset types (SAL vs
// SAL1)
void wasm_http_add_output_to_cache(const char *asset_type, uint64_t cache_index,
                                   const char *key, size_t key_len,
                                   const char *mask, size_t mask_len,
                                   bool unlocked, uint64_t height,
                                   const char *txid, size_t txid_len,
                                   uint64_t output_id);
size_t wasm_http_get_cached_output_count();
}

// Wrapper for injecting decoy outputs (binary data for /get_outs.bin)
void inject_decoy_outputs(const std::string &data) {
  fprintf(stderr, "[WASM] inject_decoy_outputs() called with %zu bytes\n",
          data.size());
  if (data.size() > 0) {
    fprintf(stderr, "[WASM]   First 16 bytes: ");
    for (size_t i = 0; i < std::min((size_t)16, data.size()); i++) {
      fprintf(stderr, "%02x ", (unsigned char)data[i]);
    }
    fprintf(stderr, "\n");
  }
  wasm_http_inject_binary_response("/get_outs.bin", data.data(), data.size());
  fprintf(stderr, "[WASM] inject_decoy_outputs() complete - cached under "
                  "'/get_outs.bin'\n");
}

// Wrapper for injecting base64 encoded decoy outputs (fixes binary corruption
// issue)
void inject_decoy_outputs_base64(const std::string &base64_data) {
  // epee::string_encoding::base64_decode returns the string directly
  std::string decoded_data = epee::string_encoding::base64_decode(base64_data);

  fprintf(stderr,
          "[WASM] inject_decoy_outputs_base64: Decoded %zu bytes from %zu "
          "base64 chars\n",
          decoded_data.size(), base64_data.size());

  // Call the original function with decoded data
  inject_decoy_outputs(decoded_data);
}

// Wrapper for injecting output distribution data
void inject_output_distribution(const std::string &data) {
  wasm_http_inject_binary_response("/get_output_distribution.bin", data.data(),
                                   data.size());
}

// ============================================================================
// inject_output_distribution_from_json - Parse JSON distribution, construct
// binary response. This fixes the issue where wallet2 expects binary epee but
// we only have JSON from the daemon's JSON-RPC endpoint.
// ============================================================================
// JSON format expected from JavaScript (JSON-RPC response wrapper):
// {
//   "jsonrpc": "2.0",
//   "id": "0",
//   "result": {
//     "status": "OK",
//     "distributions": [
//       {
//         "amount": 0,
//         "start_height": 0,
//         "distribution": [1, 2, 5, 10, ...],  // cumulative counts per block
//         "base": 0,
//         "num_spendable_global_outs": 2217659
//       }
//     ]
//   }
// }
bool inject_output_distribution_from_json(const std::string &json_data) {
  fprintf(stderr,
          "[WASM] inject_output_distribution_from_json: Received %zu bytes\n",
          json_data.size());

  if (json_data.empty()) {
    fprintf(stderr,
            "[WASM ERROR] inject_output_distribution_from_json: Empty JSON\n");
    return false;
  }

  // Parse JSON using rapidjson
  rapidjson::Document doc;
  doc.Parse(json_data.c_str());

  if (doc.HasParseError()) {
    fprintf(stderr,
            "[WASM ERROR] inject_output_distribution_from_json: JSON parse "
            "error at %zu\n",
            doc.GetErrorOffset());
    return false;
  }

  if (!doc.IsObject()) {
    fprintf(stderr,
            "[WASM ERROR] inject_output_distribution_from_json: Root is not "
            "object\n");
    return false;
  }

  // Navigate to result.distributions (JSON-RPC wrapper)
  const rapidjson::Value *result = &doc;
  if (doc.HasMember("result") && doc["result"].IsObject()) {
    result = &doc["result"];
  }

  if (!result->HasMember("distributions") ||
      !(*result)["distributions"].IsArray()) {
    fprintf(stderr,
            "[WASM ERROR] inject_output_distribution_from_json: Missing "
            "'distributions' array\n");
    return false;
  }

  const rapidjson::Value &distributions = (*result)["distributions"];
  if (distributions.Size() == 0) {
    fprintf(stderr, "[WASM ERROR] inject_output_distribution_from_json: Empty "
                    "distributions array\n");
    return false;
  }

  // Construct the response struct
  cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response resp;
  resp.status = "OK";
  resp.distributions.reserve(distributions.Size());

  for (rapidjson::SizeType i = 0; i < distributions.Size(); i++) {
    const rapidjson::Value &dist = distributions[i];
    cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::distribution entry;

    // amount (should be 0 for RCT outputs)
    entry.amount = dist.HasMember("amount") && dist["amount"].IsUint64()
                       ? dist["amount"].GetUint64()
                       : 0;

    // start_height
    entry.data.start_height =
        dist.HasMember("start_height") && dist["start_height"].IsUint64()
            ? dist["start_height"].GetUint64()
            : 0;

    // base
    entry.data.base = dist.HasMember("base") && dist["base"].IsUint64()
                          ? dist["base"].GetUint64()
                          : 0;

    // num_spendable_global_outs - CRITICAL for valid index range
    entry.data.num_spendable_global_outs =
        dist.HasMember("num_spendable_global_outs") &&
                dist["num_spendable_global_outs"].IsUint64()
            ? dist["num_spendable_global_outs"].GetUint64()
            : 0;

    // distribution array - the cumulative output counts per block
    // distribution array - parsed into temp vector for compression
    std::vector<uint64_t> temp_dist;

    // Check if daemon returned pre-compressed data (binary string)
    if (dist.HasMember("compressed_data") &&
        dist["compressed_data"].IsString()) {
      // Daemon already compressed - pass through directly
      const char *compressed = dist["compressed_data"].GetString();
      size_t compressed_len = dist["compressed_data"].GetStringLength();
      entry.compressed_data.assign(compressed, compressed_len);
      entry.binary = true;
      entry.compress = true;
      fprintf(stderr,
              "[WASM] inject_output_distribution_from_json: Using "
              "pre-compressed data (%zu bytes)\n",
              compressed_len);
    } else {
      // Look for distribution array - check both nested (data.distribution) and
      // top-level
      const rapidjson::Value *dist_array_ptr = nullptr;

      // First check nested: dist.data.distribution (server format)
      if (dist.HasMember("data") && dist["data"].IsObject()) {
        const rapidjson::Value &data_obj = dist["data"];
        if (data_obj.HasMember("distribution") &&
            data_obj["distribution"].IsArray()) {
          dist_array_ptr = &data_obj["distribution"];
          fprintf(stderr, "[WASM] inject_output_distribution_from_json: Found "
                          "distribution in data.distribution\n");
        }
      }

      // Fall back to top-level: dist.distribution
      if (!dist_array_ptr && dist.HasMember("distribution") &&
          dist["distribution"].IsArray()) {
        dist_array_ptr = &dist["distribution"];
        fprintf(stderr, "[WASM] inject_output_distribution_from_json: Found "
                        "distribution at top level\n");
      }

      if (dist_array_ptr) {
        const rapidjson::Value &dist_array = *dist_array_ptr;
        fprintf(stderr,
                "[WASM] inject_output_distribution_from_json: Parsing "
                "distribution array with %u entries\n",
                dist_array.Size());
        temp_dist.reserve(dist_array.Size());
        for (rapidjson::SizeType j = 0; j < dist_array.Size(); j++) {
          if (dist_array[j].IsUint64()) {
            temp_dist.push_back(dist_array[j].GetUint64());
          } else if (dist_array[j].IsInt64()) {
            temp_dist.push_back(
                static_cast<uint64_t>(dist_array[j].GetInt64()));
          } else if (dist_array[j].IsUint()) {
            temp_dist.push_back(static_cast<uint64_t>(dist_array[j].GetUint()));
          } else if (dist_array[j].IsInt()) {
            temp_dist.push_back(static_cast<uint64_t>(dist_array[j].GetInt()));
          } else if (dist_array[j].IsNumber()) {
            // Fallback for any numeric type
            temp_dist.push_back(
                static_cast<uint64_t>(dist_array[j].GetDouble()));
          }
        }
      } else {
        // No distribution data found - log available fields for debugging
        fprintf(stderr, "[WASM ERROR] inject_output_distribution_from_json: No "
                        "'distribution' or 'compressed_data' found!\n");
        fprintf(stderr, "[WASM DEBUG] Available fields in dist object:\n");
        for (rapidjson::Value::ConstMemberIterator it = dist.MemberBegin();
             it != dist.MemberEnd(); ++it) {
          fprintf(stderr, "[WASM DEBUG]   - '%s' (type=%d)\n",
                  it->name.GetString(), it->value.GetType());
        }
      }
      fprintf(stderr,
              "[WASM] inject_output_distribution_from_json: Parsed %zu values "
              "from distribution array\n",
              temp_dist.size());

      // IMPORTANT: The daemon returns CUMULATIVE data (each value is total
      // outputs up to that block) But wallet2::get_rct_distribution() expects
      // NON-CUMULATIVE (per-block) data and applies its own cumulative
      // conversion (lines 5021-5023). We MUST convert cumulative ??? per-block
      // here to avoid double conversion.
      if (!temp_dist.empty() && temp_dist.size() > 1) {
        fprintf(stderr,
                "[WASM] Converting cumulative???per-block: "
                "before=[%lu,%lu,%lu,...,%lu,%lu]\n",
                (unsigned long)temp_dist[0],
                temp_dist.size() > 1 ? (unsigned long)temp_dist[1] : 0,
                temp_dist.size() > 2 ? (unsigned long)temp_dist[2] : 0,
                temp_dist.size() > 1
                    ? (unsigned long)temp_dist[temp_dist.size() - 2]
                    : 0,
                (unsigned long)temp_dist.back());

        // Convert cumulative to per-block (work backwards to avoid overwriting)
        for (size_t i = temp_dist.size() - 1; i > 0; --i) {
          temp_dist[i] = temp_dist[i] - temp_dist[i - 1];
        }
        // First value stays the same (outputs in block 0)

        fprintf(stderr,
                "[WASM] Converting cumulative???per-block: "
                "after=[%lu,%lu,%lu,...,%lu,%lu]\n",
                (unsigned long)temp_dist[0],
                temp_dist.size() > 1 ? (unsigned long)temp_dist[1] : 0,
                temp_dist.size() > 2 ? (unsigned long)temp_dist[2] : 0,
                temp_dist.size() > 1
                    ? (unsigned long)temp_dist[temp_dist.size() - 2]
                    : 0,
                (unsigned long)temp_dist.back());
      }

      // Populate data.distribution with per-block values
      // wallet2::get_rct_distribution will apply cumulative conversion
      if (!temp_dist.empty()) {
        entry.data.distribution = std::move(temp_dist);
        entry.binary = true;
        entry.compress = true;
        fprintf(
            stderr,
            "[WASM] inject_output_distribution_from_json: Stored %zu values "
            "in data.distribution (wallet2 will apply cumulative conversion)\n",
            entry.data.distribution.size());
      }
    }

    fprintf(stderr,
            "[WASM] inject_output_distribution_from_json: Distribution %zu: "
            "amount=%lu, start_height=%lu, compressed_size=%zu, "
            "num_spendable_global_outs=%lu\n",
            (size_t)i, (unsigned long)entry.amount,
            (unsigned long)entry.data.start_height,
            entry.compressed_data.size(),
            (unsigned long)entry.data.num_spendable_global_outs);

    resp.distributions.push_back(entry);
  }

  fprintf(stderr,
          "[WASM] inject_output_distribution_from_json: Parsed %zu "
          "distributions\n",
          resp.distributions.size());

  // Serialize the response struct to binary using epee
  epee::byte_slice binary_data;
  if (!epee::serialization::store_t_to_binary(resp, binary_data)) {
    fprintf(stderr, "[WASM ERROR] inject_output_distribution_from_json: Failed "
                    "to serialize to binary\n");
    return false;
  }

  fprintf(stderr,
          "[WASM] inject_output_distribution_from_json: Serialized to %zu "
          "bytes binary\n",
          binary_data.size());

  // VALIDATION: Try to deserialize what we just serialized to verify format
  // Use same limits as invoke_http_bin: max_entries=65536, max_depth=16,
  // max_blob=512MB
  static constexpr epee::serialization::portable_storage::limits_t http_limits =
      {65536, 16, 512 * 1024 * 1024};
  cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response verify_resp;
  bool deserialize_ok = epee::serialization::load_t_from_binary(
      verify_resp,
      epee::span<const uint8_t>(
          reinterpret_cast<const uint8_t *>(binary_data.data()),
          binary_data.size()),
      &http_limits);

  if (!deserialize_ok) {
    fprintf(stderr, "[WASM ERROR] inject_output_distribution_from_json: "
                    "VALIDATION FAILED - could not deserialize with limits!\n");
    return false;
  }

  fprintf(stderr,
          "[WASM] inject_output_distribution_from_json: VALIDATION OK - "
          "deserialized %zu distributions, status='%s'\n",
          verify_resp.distributions.size(), verify_resp.status.c_str());

  if (verify_resp.distributions.size() > 0) {
    auto &d = verify_resp.distributions[0];
    fprintf(stderr,
            "[WASM] inject_output_distribution_from_json: VALIDATION - "
            "amount=%lu, start_height=%lu, dist_size=%zu, "
            "num_spendable=%lu, binary=%d, compress=%d\n",
            (unsigned long)d.amount, (unsigned long)d.data.start_height,
            d.data.distribution.size(),
            (unsigned long)d.data.num_spendable_global_outs, (int)d.binary,
            (int)d.compress);

    // Log first few and last distribution values for debugging
    if (d.data.distribution.size() > 10) {
      fprintf(
          stderr,
          "[WASM] DIST VALUES: first=[%lu, %lu, %lu, %lu, %lu] "
          "last=[%lu, %lu, %lu, %lu, %lu]\n",
          (unsigned long)d.data.distribution[0],
          (unsigned long)d.data.distribution[1],
          (unsigned long)d.data.distribution[2],
          (unsigned long)d.data.distribution[3],
          (unsigned long)d.data.distribution[4],
          (unsigned long)d.data.distribution[d.data.distribution.size() - 5],
          (unsigned long)d.data.distribution[d.data.distribution.size() - 4],
          (unsigned long)d.data.distribution[d.data.distribution.size() - 3],
          (unsigned long)d.data.distribution[d.data.distribution.size() - 2],
          (unsigned long)d.data.distribution[d.data.distribution.size() - 1]);
    }
  }

  // Inject the binary data into the HTTP cache
  wasm_http_inject_binary_response(
      "/get_output_distribution.bin",
      reinterpret_cast<const char *>(binary_data.data()), binary_data.size());

  fprintf(stderr, "[WASM] inject_output_distribution_from_json: Complete - "
                  "cached under '/get_output_distribution.bin'\n");
  return true;
}

// ============================================================================
// inject_decoy_outputs_from_json - Parse JSON outputs, construct binary
// response This bypasses epee deserialization issues with daemon's binary
// format
// ============================================================================
// JSON format expected from JavaScript:
// {
//   "status": "OK",
//   "outs": [
//     {"key": "hex...", "mask": "hex...", "unlocked": true, "height": 12345,
//     "txid": "hex...", "output_id": 0},
//     ...
//   ]
// }
bool inject_decoy_outputs_from_json(const std::string &json_data) {
  fprintf(stderr, "[WASM] inject_decoy_outputs_from_json: Received %zu bytes\n",
          json_data.size());

  if (json_data.empty()) {
    fprintf(stderr,
            "[WASM ERROR] inject_decoy_outputs_from_json: Empty JSON\n");
    return false;
  }

  // Parse JSON using rapidjson
  rapidjson::Document doc;
  doc.Parse(json_data.c_str());

  if (doc.HasParseError()) {
    fprintf(stderr,
            "[WASM ERROR] inject_decoy_outputs_from_json: JSON parse error at "
            "%zu\n",
            doc.GetErrorOffset());
    return false;
  }

  if (!doc.IsObject()) {
    fprintf(
        stderr,
        "[WASM ERROR] inject_decoy_outputs_from_json: Root is not object\n");
    return false;
  }

  // Construct the response struct
  cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response resp;
  resp.status = "OK";

  // Parse asset_type from JSON (CRITICAL for correct cache keying)
  // This distinguishes outputs for SAL vs SAL1 etc
  std::string asset_type = "SAL1"; // Default fallback
  if (doc.HasMember("asset_type") && doc["asset_type"].IsString()) {
    asset_type = doc["asset_type"].GetString();
    fprintf(stderr, "[WASM] inject_decoy_outputs_from_json: asset_type='%s'\n",
            asset_type.c_str());
  } else {
    fprintf(stderr, "[WASM WARNING] inject_decoy_outputs_from_json: No "
                    "asset_type in JSON, defaulting to 'SAL1'\n");
  }

  if (!doc.HasMember("outs") || !doc["outs"].IsArray()) {
    fprintf(
        stderr,
        "[WASM ERROR] inject_decoy_outputs_from_json: Missing 'outs' array\n");
    return false;
  }

  // Parse sequences if present (for server-side forced decoys)
  // NOTE: Forced decoys disabled due to index out of bounds crash.
  // The per-index cache + retry mechanism will be used instead.
  if (doc.HasMember("sequences") && doc["sequences"].IsArray()) {
    const rapidjson::Value &sequences = doc["sequences"];
    size_t total_decoys = 0;

    for (rapidjson::SizeType i = 0; i < sequences.Size(); i++) {
      const rapidjson::Value &seq = sequences[i];
      if (seq.IsArray()) {
        total_decoys += seq.Size();
      }
    }

    fprintf(stderr,
            "[WASM] inject_decoy_outputs_from_json: Parsed %zu sequences with "
            "%zu total decoys (forced decoys DISABLED)\n",
            sequences.Size(), total_decoys);
  }

  const rapidjson::Value &outs = doc["outs"];
  resp.outs.reserve(outs.Size());

  for (rapidjson::SizeType i = 0; i < outs.Size(); i++) {
    const rapidjson::Value &out = outs[i];
    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::outkey entry;

    // Parse key (hex string -> crypto::public_key)
    if (out.HasMember("key") && out["key"].IsString()) {
      std::string key_hex = out["key"].GetString();
      if (!epee::string_tools::hex_to_pod(key_hex, entry.key)) {
        fprintf(stderr,
                "[WASM WARN] inject_decoy_outputs_from_json: Failed to parse "
                "key %zu\n",
                i);
      }
    }

    // Parse mask (hex string -> rct::key)
    if (out.HasMember("mask") && out["mask"].IsString()) {
      std::string mask_hex = out["mask"].GetString();
      if (!epee::string_tools::hex_to_pod(mask_hex, entry.mask)) {
        fprintf(stderr,
                "[WASM WARN] inject_decoy_outputs_from_json: Failed to parse "
                "mask %zu\n",
                i);
      }
    }

    // Parse unlocked
    entry.unlocked = out.HasMember("unlocked") && out["unlocked"].IsBool()
                         ? out["unlocked"].GetBool()
                         : true;

    // Parse height
    entry.height = out.HasMember("height") && out["height"].IsUint64()
                       ? out["height"].GetUint64()
                       : 0;

    // Parse txid (hex string -> crypto::hash)
    if (out.HasMember("txid") && out["txid"].IsString()) {
      std::string txid_hex = out["txid"].GetString();
      if (!epee::string_tools::hex_to_pod(txid_hex, entry.txid)) {
        // txid might be empty if get_txid=false
      }
    }

    // Parse output_id (global_output_index from daemon response)
    // FIX: Use IsNumber() instead of IsUint64() - RapidJSON returns
    // IsUint64()=false for numbers under 2^31
    uint64_t output_id = 0;
    bool has_output_id = false;
    if (out.HasMember("output_id") && out["output_id"].IsNumber()) {
      output_id = out["output_id"].GetUint64();
      has_output_id = true;
    }
    entry.output_id = output_id;

    // Parse cache_index (asset_type_output_index from request)
    // This is what wallet2 uses to request outputs (from "index" field)
    // FIX: Use IsNumber() instead of IsUint64() - RapidJSON returns
    // IsUint64()=false for numbers under 2^31
    uint64_t cache_index = 0;
    if (out.HasMember("index") && out["index"].IsNumber()) {
      cache_index = out["index"].GetUint64();
    } else if (out.HasMember("global_index") &&
               out["global_index"].IsNumber()) {
      cache_index = out["global_index"].GetUint64();
    }

    // Store in per-index cache (enables dynamic response building)
    // Key: cache_index (asset_type_output_index from request)
    // Value: includes output_id (global_output_index for wallet2 verification)
    if (cache_index > 0 ||
        (out.HasMember("index") || out.HasMember("global_index"))) {
      // v5.40.9: Log ALL caching operations, especially missing output_ids
      if (!has_output_id) {
        fprintf(stderr,
                "[WASM WARNING] Caching output %zu at cache_index %llu but "
                "output_id IS MISSING! This will cause real output not found "
                "errors!\n",
                i, (unsigned long long)cache_index);
      } else if (i < 5 || cache_index == 1929837 || cache_index == 1105498) {
        // v5.40.20: Also log index 1105498 which has key_match=0 issue
        const unsigned char *key_bytes =
            reinterpret_cast<const unsigned char *>(&entry.key);
        fprintf(stderr,
                "[WASM] inject_decoy_outputs_from_json: Caching output %zu at "
                "cache_index %llu (output_id=%llu)\n",
                i, (unsigned long long)cache_index,
                (unsigned long long)output_id);
        fprintf(stderr, "[WASM]   Key[0:8]: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3],
                key_bytes[4], key_bytes[5], key_bytes[6], key_bytes[7]);
      }

      // Get binary key/mask/txid for cache storage
      std::string key_bin(reinterpret_cast<const char *>(&entry.key),
                          sizeof(entry.key));
      std::string mask_bin(reinterpret_cast<const char *>(&entry.mask),
                           sizeof(entry.mask));
      std::string txid_bin(reinterpret_cast<const char *>(&entry.txid),
                           sizeof(entry.txid));

      wasm_http_add_output_to_cache(
          asset_type.c_str(), cache_index, key_bin.data(), key_bin.size(),
          mask_bin.data(), mask_bin.size(), entry.unlocked, entry.height,
          txid_bin.data(), txid_bin.size(), output_id);
    }

    resp.outs.push_back(entry);
  }

  fprintf(stderr,
          "[WASM] inject_decoy_outputs_from_json: Parsed %zu outputs, cached "
          "%zu total\n",
          resp.outs.size(), wasm_http_get_cached_output_count());

  // Serialize the response struct to binary using epee
  epee::byte_slice binary_data;
  if (!epee::serialization::store_t_to_binary(resp, binary_data)) {
    fprintf(stderr, "[WASM ERROR] inject_decoy_outputs_from_json: Failed to "
                    "serialize to binary\n");
    return false;
  }

  fprintf(
      stderr,
      "[WASM] inject_decoy_outputs_from_json: Serialized to %zu bytes binary\n",
      binary_data.size());

  // Inject the binary data into the HTTP cache
  // Use simple path since RNG restore doesn't produce deterministic decoys.
  // The cache fallback will find this when wallet requests with different hash.
  const char *cache_key = "/get_outs.bin";
  fprintf(stderr,
          "[WASM] inject_decoy_outputs_from_json: Using cache key '%s'\n",
          cache_key);

  wasm_http_inject_binary_response(
      cache_key, reinterpret_cast<const char *>(binary_data.data()),
      binary_data.size());

  fprintf(stderr,
          "[WASM] inject_decoy_outputs_from_json: Complete - cached "
          "under '%s'\n",
          cache_key);
  return true;
}

// Clear all cached HTTP responses
void clear_http_cache() { wasm_http_clear_cache(); }

// Check if decoy outputs are cached (useful before transaction creation)
bool has_decoy_outputs() {
  return wasm_http_has_cached_response("/get_outs.bin");
}

// Check if there's a pending get_outs request (cache miss occurred)
// Used for two-phase transaction creation:
// 1. First TX attempt fails, but captures which outputs the wallet requested
// 2. JS calls this to check if there's a pending request
// 3. JS fetches those exact outputs and injects them
// 4. Second TX attempt succeeds
bool has_pending_get_outs_request() {
  return wasm_http_has_pending_get_outs_request();
}

// Get the pending get_outs request body as base64
// JS can decode this to extract the output indices the wallet needs
std::string get_pending_get_outs_request() {
  const char *base64 = wasm_http_get_pending_get_outs_request_base64();
  return base64 ? std::string(base64) : "";
}

// Clear the pending get_outs request
void clear_pending_get_outs_request() {
  wasm_http_clear_pending_get_outs_request();
}

// Inject decoy outputs from JSON (for JavaScript-friendly API)
// JavaScript calls this with JSON data from /get_outs endpoint
// We store it as a JSON response that wallet2 can use
// Returns true if injection succeeded
bool inject_decoy_outputs_json(const std::string &json_data) {
  if (json_data.empty()) {
    return false;
  }

  // Store the JSON data for later use by create_transaction
  // wallet2's get_outs() uses HTTP client which we intercept
  // For JSON path, use /get_outs (not .bin)
  wasm_http_inject_json_response("/get_outs", json_data.c_str());

  // Also store under .bin path in case wallet2 uses that
  // The data is stored as-is (JSON), wallet2 will handle parsing
  wasm_http_inject_json_response("/get_outs.bin", json_data.c_str());

  return true;
}

// Inject /json_rpc response with method-based caching
// Example: inject_json_rpc_response("hard_fork_info", jsonResponse)
// This allows multiple RPC methods to be cached separately
void inject_json_rpc_response(const std::string &method,
                              const std::string &json_response) {
  std::string key = "/json_rpc:" + method; // e.g., "/json_rpc:hard_fork_info"
  fprintf(stderr,
          "[WASM] inject_json_rpc_response() method='%s' size=%zu bytes\n",
          method.c_str(), json_response.size());
  if (json_response.size() > 0 && json_response.size() < 200) {
    fprintf(stderr, "[WASM]   Content: %s\n", json_response.c_str());
  }
  wasm_http_inject_json_response(key.c_str(), json_response.c_str());
  fprintf(stderr,
          "[WASM] inject_json_rpc_response() complete - cached under '%s'\n",
          key.c_str());
}

// Set the blockchain height for WASM for unlock time calculation
// This is needed after import when m_blockchain is empty
// Call this with the height from get_info before sending transactions
// Note: Using double for JS compatibility (converts to uint64_t)
void set_blockchain_height(double height_d) {
  uint64_t height = static_cast<uint64_t>(height_d);
  fprintf(stderr, "[WASM] set_blockchain_height(%llu)\n",
          (unsigned long long)height);
  if (g_wallet_instance) {
    g_wallet_instance->m_node_rpc_proxy.set_height(height);
    fprintf(stderr, "[WASM] set_blockchain_height complete\n");
  } else {
    fprintf(stderr, "[WASM] set_blockchain_height failed - no wallet\n");
  }
}

// ============================================================================
// Direct RPC cache population (bypasses HTTP layer format issues)
// These functions set data directly in wallet2's NodeRPCProxy cache
// ============================================================================

// Inject fee estimate data directly into RPC cache
// Parameters: fee (base fee), fees_json (JSON array of fee tiers),
// quantization_mask
void inject_fee_estimate(double fee_d, const std::string &fees_json,
                         double quantization_mask_d) {
  fprintf(stderr, "[WASM] inject_fee_estimate() fee=%f, fees_json=%s\n", fee_d,
          fees_json.c_str());

  if (!g_wallet_instance) {
    fprintf(stderr, "[WASM] inject_fee_estimate failed - no wallet\n");
    return;
  }

  uint64_t fee = static_cast<uint64_t>(fee_d);
  uint64_t quantization_mask = static_cast<uint64_t>(quantization_mask_d);

  // Parse fees from JSON array string like "[360,720,1080,1440]"
  std::vector<uint64_t> fees;
  try {
    // Simple JSON array parsing
    std::string trimmed = fees_json;
    // Remove whitespace and brackets
    size_t start = trimmed.find('[');
    size_t end = trimmed.rfind(']');
    if (start != std::string::npos && end != std::string::npos && end > start) {
      std::string inner = trimmed.substr(start + 1, end - start - 1);
      // Split by comma
      std::stringstream ss(inner);
      std::string token;
      while (std::getline(ss, token, ',')) {
        // Trim whitespace
        size_t first = token.find_first_not_of(" \t\n\r");
        size_t last = token.find_last_not_of(" \t\n\r");
        if (first != std::string::npos && last != std::string::npos) {
          std::string num = token.substr(first, last - first + 1);
          if (!num.empty()) {
            fees.push_back(static_cast<uint64_t>(std::stod(num)));
          }
        }
      }
    }
  } catch (...) {
    fprintf(stderr, "[WASM] inject_fee_estimate failed to parse fees JSON\n");
    // Use default single fee
    fees.push_back(fee);
  }

  if (fees.empty()) {
    fees.push_back(fee);
  }

  fprintf(stderr, "[WASM] inject_fee_estimate parsed %zu fees\n", fees.size());
  g_wallet_instance->m_node_rpc_proxy.set_cached_fee_estimate(
      fee, fees, quantization_mask);
  fprintf(stderr, "[WASM] inject_fee_estimate complete\n");
}

// Inject hardfork info directly into RPC cache
// Parameters: version (hardfork version), earliest_height (activation height)
void inject_hardfork_info(uint8_t version, double earliest_height_d) {
  fprintf(stderr, "[WASM] inject_hardfork_info() version=%u, height=%f\n",
          (unsigned)version, earliest_height_d);

  if (!g_wallet_instance) {
    fprintf(stderr, "[WASM] inject_hardfork_info failed - no wallet\n");
    return;
  }

  uint64_t earliest_height = static_cast<uint64_t>(earliest_height_d);
  g_wallet_instance->m_node_rpc_proxy.set_cached_hardfork_info(version,
                                                               earliest_height);
  fprintf(stderr, "[WASM] inject_hardfork_info complete\n");
}

// Inject RPC version directly into cache
void inject_rpc_version(uint32_t version) {
  fprintf(stderr, "[WASM] inject_rpc_version() version=%u\n", version);

  if (!g_wallet_instance) {
    fprintf(stderr, "[WASM] inject_rpc_version failed - no wallet\n");
    return;
  }

  g_wallet_instance->m_node_rpc_proxy.set_cached_rpc_version(version);
  fprintf(stderr, "[WASM] inject_rpc_version complete\n");
}

// Inject target height and block weight limit
void inject_daemon_info(double height_d, double target_height_d,
                        double block_weight_limit_d) {
  fprintf(stderr,
          "[WASM] inject_daemon_info() height=%f, target=%f, weight_limit=%f\n",
          height_d, target_height_d, block_weight_limit_d);

  if (!g_wallet_instance) {
    fprintf(stderr, "[WASM] inject_daemon_info failed - no wallet\n");
    return;
  }

  uint64_t height = static_cast<uint64_t>(height_d);
  uint64_t target_height = static_cast<uint64_t>(target_height_d);
  uint64_t block_weight_limit = static_cast<uint64_t>(block_weight_limit_d);

  auto &proxy = g_wallet_instance->m_node_rpc_proxy;

  // CRITICAL: Set offline = false on BOTH NodeRPCProxy AND wallet2
  // These are separate flags that both need to be false for RPC calls to work
  proxy.set_offline(false);
  g_wallet_instance->m_offline = false; // wallet2's own offline flag

  proxy.set_height(height);
  proxy.set_cached_target_height(target_height);
  proxy.set_cached_block_weight_limit(block_weight_limit);
  fprintf(stderr, "[WASM] inject_daemon_info complete "
                  "(wallet2.m_offline=false, proxy.m_offline=false)\n");
}

// ============================================================================
// Block scanning injection functions
// These allow JavaScript to inject block data for wallet refresh/sync
// ============================================================================

// Wrapper for injecting block data (binary data for /getblocks.bin)
void inject_blocks_response(const std::string &data) {
  wasm_http_inject_binary_response("/getblocks.bin", data.data(), data.size());
}

// Wrapper for injecting block hashes (binary data for /gethashes.bin)
void inject_hashes_response(const std::string &data) {
  wasm_http_inject_binary_response("/gethashes.bin", data.data(), data.size());
}

// Check if blocks are cached
bool has_blocks_cached() {
  return wasm_http_has_cached_response("/getblocks.bin");
}

// Standalone test for epee portable_storage parsing (no wallet2 dependency)
// This isolates whether the crash is in epee or wallet2
std::string test_epee_parse(const std::string &binary_data) {
  std::ostringstream result;
  result << "{";

  // Basic validation
  if (binary_data.empty()) {
    result << "\"success\":false,\"error\":\"Empty data\"}";
    return result.str();
  }

  result << "\"data_size\":" << binary_data.size() << ",";

  // Check header bytes
  const unsigned char *data =
      reinterpret_cast<const unsigned char *>(binary_data.data());
  result << "\"first_8_hex\":\"";
  for (int i = 0; i < 8 && i < (int)binary_data.size(); i++) {
    if (i > 0)
      result << " ";
    result << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
  }
  result << std::dec << "\",";

  // Validate epee signature
  bool has_epee_sig =
      (binary_data.size() >= 8 && data[0] == 0x01 && data[1] == 0x11 &&
       data[2] == 0x01 && data[3] == 0x01 && data[4] == 0x01 &&
       data[5] == 0x01 && data[6] == 0x02 && data[7] == 0x01);
  result << "\"has_epee_signature\":" << (has_epee_sig ? "true" : "false")
         << ",";

  if (!has_epee_sig) {
    result << "\"success\":false,\"error\":\"Invalid epee signature\"}";
    return result.str();
  }

  // Try portable_storage parsing directly (step 1)
  result << "\"parse_test\":\"starting\",";
  try {
    epee::serialization::portable_storage ps;
    epee::span<const uint8_t> span_data(
        reinterpret_cast<const uint8_t *>(binary_data.data()),
        binary_data.size());

    bool ps_ok = ps.load_from_binary(span_data);
    result << "\"portable_storage_ok\":" << (ps_ok ? "true" : "false") << ",";

    if (!ps_ok) {
      result << "\"success\":false,\"error\":\"portable_storage.load_from_"
                "binary failed\"}";
      return result.str();
    }

    // Try to read the status field
    std::string status_str;
    if (ps.get_value("status", status_str, nullptr)) {
      result << "\"status\":\"" << status_str << "\",";
    } else {
      result << "\"status\":\"(not found)\",";
    }

    // Try to read start_height
    uint64_t start_height = 0;
    if (ps.get_value("start_height", start_height, nullptr)) {
      result << "\"start_height\":" << start_height << ",";
    } else {
      result << "\"start_height\":\"(not found)\",";
    }

    // Try to read current_height
    uint64_t current_height = 0;
    if (ps.get_value("current_height", current_height, nullptr)) {
      result << "\"current_height\":" << current_height << ",";
    }

    result << "\"success\":true}";
    return result.str();

  } catch (const std::exception &e) {
    result << "\"success\":false,\"error\":\"Exception: " << e.what() << "\"}";
    return result.str();
  } catch (...) {
    result << "\"success\":false,\"error\":\"Unknown exception\"}";
    return result.str();
  }
}

// Test loading the full COMMAND_RPC_GET_BLOCKS_FAST::response
std::string test_getblocks_parse(const std::string &binary_data) {
  std::ostringstream result;
  result << "{";

  if (binary_data.size() < 10) {
    result << "\"success\":false,\"error\":\"Data too small\"}";
    return result.str();
  }

  result << "\"data_size\":" << binary_data.size() << ",";

  try {
    // Parse as the actual RPC response type
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;

    bool parse_ok = epee::serialization::load_t_from_binary(res, binary_data);
    result << "\"parse_ok\":" << (parse_ok ? "true" : "false") << ",";

    if (!parse_ok) {
      result << "\"success\":false,\"error\":\"load_t_from_binary returned "
                "false\"}";
      return result.str();
    }

    result << "\"status\":\"" << res.status << "\",";
    result << "\"start_height\":" << res.start_height << ",";
    result << "\"current_height\":" << res.current_height << ",";
    result << "\"blocks_count\":" << res.blocks.size() << ",";
    result << "\"output_indices_count\":" << res.output_indices.size() << ",";
    result << "\"success\":true}";
    return result.str();

  } catch (const std::exception &e) {
    result << "\"success\":false,\"exception\":\"" << e.what() << "\"}";
    return result.str();
  } catch (...) {
    result << "\"success\":false,\"exception\":\"unknown\"}";
    return result.str();
  }
}

bool test_crypto() {
  try {
    // Test random number generation
    crypto::secret_key test_key;
    crypto::random32_unbiased((unsigned char *)test_key.data);

    // Test key derivation
    crypto::public_key pub;
    crypto::secret_key_to_public_key(test_key, pub);

    return true;
  } catch (...) {
    return false;
  }
}

/**
 * benchmark_key_derivation - Measure performance of generate_key_derivation
 *
 * This tests the donna64-optimized key derivation. Expected:
 * - With donna64: ~0.5ms per derivation (~2000/sec)
 * - With ref10: ~7ms per derivation (~140/sec)
 *
 * @param iterations Number of derivations to perform
 * @return JSON with timing results
 */
std::string benchmark_key_derivation(int iterations) {
  try {
    // Fixed test vectors
    crypto::public_key tx_pub;
    crypto::secret_key view_sec;
    crypto::key_derivation derivation;

    // Initialize with deterministic test values
    memset(&tx_pub, 0x42, sizeof(tx_pub)); // Some non-zero value
    memset(&view_sec, 0x01, sizeof(view_sec));

    // Make view_sec a valid scalar (clear bits as needed)
    view_sec.data[0] &= 0xF8;
    view_sec.data[31] &= 0x7F;
    view_sec.data[31] |= 0x40;

    auto start = std::chrono::high_resolution_clock::now();

    int success_count = 0;
    for (int i = 0; i < iterations; i++) {
      // Vary tx_pub slightly each iteration (to avoid caching)
      tx_pub.data[0] = (unsigned char)(i & 0xFF);
      tx_pub.data[1] = (unsigned char)((i >> 8) & 0xFF);

      if (crypto::generate_key_derivation(tx_pub, view_sec, derivation)) {
        success_count++;
      }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    double avg_us = (elapsed_ms * 1000.0) / iterations;
    int per_second = static_cast<int>((iterations / elapsed_ms) * 1000.0);

    std::ostringstream oss;
    oss << "{"
        << "\"iterations\":" << iterations << ","
        << "\"success_count\":" << success_count << ","
        << "\"total_ms\":" << elapsed_ms << ","
        << "\"avg_microseconds\":" << avg_us << ","
        << "\"derivations_per_second\":" << per_second << ","
        << "\"version\":\"" << WASM_VERSION << "\""
        << "}";
    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\"}";
  }
}

/**
 * compare_ref10_donna64 - Comprehensive comparison of ref10 vs donna64
 * derivation
 *
 * This function calls BOTH implementations with the SAME inputs and compares:
 * 1. ref10 (crypto::generate_key_derivation) - the reference implementation
 * 2. donna64 (donna64_generate_key_derivation_debug) - with intermediate
 * capture
 *
 * Use this to diagnose WHY donna64 produces different results than ref10.
 * The debug version captures intermediate values at every step.
 *
 * Usage:
 * compare_ref10_donna64("e3e1e35258e9d38e42d6776546f54d51fb2b5c3328de93ace255a8365f583b09",
 *                               "3e704615a5df83b56371d5c7058e1416b846734e81a5732b3bf5913e53103209")
 *
 * NOTE: The donna64 debug functions use hardcoded test vectors internally!
 * The tx_pub_hex and view_sec_hex parameters are used for ref10 comparison
 * only. For full debug tracing, we call donna64_debug_full_trace() which uses:
 *   tx_pub:   e3e1e35258e9d38e42d6776546f54d51fb2b5c3328de93ace255a8365f583b09
 *   view_sec: 3e704615a5df83b56371d5c7058e1416b846734e81a5732b3bf5913e53103209
 *
 * Returns JSON with all intermediate values and comparison results.
 */
std::string compare_ref10_donna64(const std::string &tx_pub_hex,
                                  const std::string &view_sec_hex) {
  std::ostringstream oss;
  oss << "{";

  try {
    // Parse inputs
    if (tx_pub_hex.length() != 64 || view_sec_hex.length() != 64) {
      oss << "\"error\":\"tx_pub_hex and view_sec_hex must be 64 character hex "
             "strings\"}";
      return oss.str();
    }

    unsigned char tx_pub[32], view_sec[32];
    for (int i = 0; i < 32; i++) {
      tx_pub[i] = (unsigned char)strtol(tx_pub_hex.substr(i * 2, 2).c_str(),
                                        nullptr, 16);
      view_sec[i] = (unsigned char)strtol(view_sec_hex.substr(i * 2, 2).c_str(),
                                          nullptr, 16);
    }

    // Output inputs for verification
    oss << "\"tx_pub_input\":\"" << tx_pub_hex << "\",";
    oss << "\"view_sec_input\":\"" << view_sec_hex << "\",";

    // ====================================================================
    // REF10: crypto::generate_key_derivation (using provided inputs)
    // ====================================================================
    crypto::public_key crypto_pub;
    crypto::secret_key crypto_sec;
    crypto::key_derivation derivation_ref10;
    memcpy(&crypto_pub, tx_pub, 32);
    memcpy(&crypto_sec, view_sec, 32);

    bool ref10_ok = crypto::generate_key_derivation(crypto_pub, crypto_sec,
                                                    derivation_ref10);
    oss << "\"ref10_success\":" << (ref10_ok ? "true" : "false") << ",";
    if (ref10_ok) {
      oss << "\"ref10_derivation\":\""
          << epee::string_tools::pod_to_hex(derivation_ref10) << "\",";
    }

    // ====================================================================
    // DONNA64 DIRECT: donna64_generate_key_derivation (using provided inputs)
    // ====================================================================
    unsigned char derivation_donna64[32];
    int donna64_direct_result =
        donna64_generate_key_derivation(derivation_donna64, tx_pub, view_sec);
    bool donna64_direct_ok = (donna64_direct_result == 0);

    oss << "\"donna64_direct_success\":"
        << (donna64_direct_ok ? "true" : "false") << ",";
    oss << "\"donna64_direct_result_code\":" << donna64_direct_result << ",";
    if (donna64_direct_ok) {
      oss << "\"donna64_direct_derivation\":\""
          << key_to_hex(derivation_donna64) << "\",";
    }

    // ====================================================================
    // COMPARISON (ref10 vs donna64 direct)
    // ====================================================================
    bool direct_match =
        ref10_ok && donna64_direct_ok &&
        (memcmp(&derivation_ref10, derivation_donna64, 32) == 0);
    oss << "\"direct_derivations_match\":" << (direct_match ? "true" : "false")
        << ",";

    if (!direct_match && ref10_ok && donna64_direct_ok) {
      int first_diff = -1;
      for (int i = 0; i < 32; i++) {
        if (((unsigned char *)&derivation_ref10)[i] != derivation_donna64[i]) {
          first_diff = i;
          break;
        }
      }
      oss << "\"first_diff_byte\":" << first_diff << ",";
    }

    // ====================================================================
    // DONNA64 DEBUG TRACE (uses HARDCODED test vectors internally!)
    // This captures intermediate values at every step of the computation
    // ====================================================================
    int debug_trace_result = donna64_debug_full_trace();
    // Returns: 100=success, 0-31=first mismatch byte, -1=decompress fail,
    // -2=scalarmult fail

    oss << "\"donna64_debug_trace\":{";
    oss << "\"result_code\":" << debug_trace_result << ",";
    oss << "\"status\":\"";
    if (debug_trace_result == 100)
      oss << "SUCCESS - matches expected";
    else if (debug_trace_result >= 0 && debug_trace_result <= 31)
      oss << "MISMATCH at byte " << debug_trace_result;
    else if (debug_trace_result == -1)
      oss << "DECOMPRESS_FAILED";
    else if (debug_trace_result == -2)
      oss << "SCALARMULT_FAILED";
    else
      oss << "UNKNOWN_ERROR";
    oss << "\",";

    // Debug flags
    int flags = donna64_debug_get_flags();
    oss << "\"decompress_ok\":" << (flags & 1 ? "true" : "false") << ",";
    oss << "\"scalarmult_ok\":" << ((flags >> 1) & 1 ? "true" : "false") << ",";

    // Decompressed point P (from debug trace)
    oss << "\"point_P\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_point_P(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Precomputed 1P
    oss << "\"precomp_1P\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_precomp_1P(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Precomputed 2P
    oss << "\"precomp_2P\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_precomp_2P(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Precomputed 8P
    oss << "\"precomp_8P\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_precomp_8P(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Scalar decomposition e[64]
    oss << "\"scalar_e\":[";
    for (int i = 0; i < 64; i++) {
      if (i > 0)
        oss << ",";
      oss << donna64_debug_get_scalar_e(i);
    }
    oss << "],";

    // Point after first iteration (i=63)
    oss << "\"iter0\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_iter0(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Point after second iteration (i=62) - THIS IS WHERE DIVERGENCE HAPPENS
    oss << "\"iter1\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_iter1(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Point after third iteration (i=61)
    oss << "\"iter2\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_iter2(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Point after midpoint iteration (i=31)
    oss << "\"iter32\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_iter32(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // 16P state in iteration 62 (after 4 doublings, BEFORE add)
    oss << "\"iter62_16P\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_iter62_16P(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Point after scalar multiplication (before cofactor)
    oss << "\"after_scalarmult\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_after_scalarmult(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Final result
    oss << "\"final_result\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_byte(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\"";

    oss << "},"; // end donna64_debug_trace

    // ====================================================================
    // HWDEV PATH (the actual path Phase 2 scan uses)
    // ====================================================================
    oss << "\"hwdev_comparison\":{";
    crypto::key_derivation derivation_hwdev;
    hw::device &hwdev = hw::get_device("default");
    bool hwdev_ok =
        hwdev.generate_key_derivation(crypto_pub, crypto_sec, derivation_hwdev);
    oss << "\"hwdev_success\":" << (hwdev_ok ? "true" : "false") << ",";
    if (hwdev_ok) {
      oss << "\"hwdev_derivation\":\""
          << epee::string_tools::pod_to_hex(derivation_hwdev) << "\",";
    }
    bool hwdev_matches_ref10 =
        hwdev_ok && ref10_ok &&
        (memcmp(&derivation_hwdev, &derivation_ref10, 32) == 0);
    bool hwdev_matches_donna64 =
        hwdev_ok && donna64_direct_ok &&
        (memcmp(&derivation_hwdev, derivation_donna64, 32) == 0);
    oss << "\"hwdev_matches_ref10\":"
        << (hwdev_matches_ref10 ? "true" : "false") << ",";
    oss << "\"hwdev_matches_donna64\":"
        << (hwdev_matches_donna64 ? "true" : "false");
    oss << "},";

    // ====================================================================
    // VERSION INFO
    // ====================================================================
    int donna64_ver = donna64_get_version();
    oss << "\"versions\":{";
    oss << "\"donna64\":\"0x" << std::hex << donna64_ver << std::dec << "\",";
    oss << "\"wasm\":\"" << WASM_VERSION << "\"";
    oss << "},";

    // ====================================================================
    // REF10 DEBUG TRACE - Compute 9P and 16P using ref10 for comparison
    // ====================================================================
    oss << "\"ref10_debug_trace\":{";
    {
      // Decompress tx_pub using ref10
      ge_p3 P;
      if (ge_frombytes_vartime(&P, tx_pub) == 0) {
        oss << "\"decompress_ok\":true,";

        // Compute 16P using ref10: double P 4 times
        ge_p2 p2;
        ge_p1p1 t1;
        ge_p3_to_p2(&p2, &P); // Convert P3 -> P2

        // Double 4 times: P -> 2P -> 4P -> 8P -> 16P
        ge_p2_dbl(&t1, &p2);
        ge_p1p1_to_p2(&p2, &t1);
        ge_p2_dbl(&t1, &p2);
        ge_p1p1_to_p2(&p2, &t1);
        ge_p2_dbl(&t1, &p2);
        ge_p1p1_to_p2(&p2, &t1);
        ge_p2_dbl(&t1, &p2);
        ge_p1p1_to_p2(&p2, &t1);

        // Output ref10 16P
        unsigned char ref10_16P[32];
        ge_tobytes(ref10_16P, &p2);
        oss << "\"ref10_16P\":\"";
        for (int i = 0; i < 32; i++) {
          oss << std::hex << std::setfill('0') << std::setw(2)
              << (int)ref10_16P[i];
        }
        oss << std::dec << "\",";

        // Compute 9P using ref10: scalar multiply P by 9
        unsigned char scalar_9[32] = {0};
        scalar_9[0] = 9; // scalar = 9 (little endian)
        ge_p2 nine_P;
        ge_scalarmult(&nine_P, scalar_9, &P);

        // Output ref10 9P
        unsigned char ref10_9P[32];
        ge_tobytes(ref10_9P, &nine_P);
        oss << "\"ref10_9P\":\"";
        for (int i = 0; i < 32; i++) {
          oss << std::hex << std::setfill('0') << std::setw(2)
              << (int)ref10_9P[i];
        }
        oss << std::dec << "\",";

        // Also compute 7P using ref10
        unsigned char scalar_7[32] = {0};
        scalar_7[0] = 7;
        ge_p2 seven_P;
        ge_scalarmult(&seven_P, scalar_7, &P);

        unsigned char ref10_7P[32];
        ge_tobytes(ref10_7P, &seven_P);
        oss << "\"ref10_7P\":\"";
        for (int i = 0; i < 32; i++) {
          oss << std::hex << std::setfill('0') << std::setw(2)
              << (int)ref10_7P[i];
        }
        oss << std::dec << "\",";

        // Compute 16P - 7P = 9P using ref10 subtraction
        // First convert 16P to p3 for subtraction
        ge_p2_dbl(&t1, &p2); // Actually we need to redo 16P ending in p3
        // Let's just verify: does donna64 iter1 == ref10 9P?
        oss << "\"donna64_iter1_matches_ref10_9P\":";
        unsigned char donna64_iter1[32];
        for (int i = 0; i < 32; i++) {
          donna64_iter1[i] = (unsigned char)donna64_debug_get_iter1(i);
        }
        oss << (memcmp(donna64_iter1, ref10_9P, 32) == 0 ? "true" : "false")
            << ",";

        // Also check if donna64 iter62_16P matches ref10 16P
        oss << "\"donna64_iter62_16P_matches_ref10_16P\":";
        unsigned char donna64_16P[32];
        for (int i = 0; i < 32; i++) {
          donna64_16P[i] = (unsigned char)donna64_debug_get_iter62_16P(i);
        }
        oss << (memcmp(donna64_16P, ref10_16P, 32) == 0 ? "true" : "false")
            << ",";

        // CRITICAL: Compare scalar*P (before cofactor) between donna64 and
        // ref10 ref10: ge_scalarmult returns scalar*P in P2 form
        ge_p2 ref10_scalarmult_result;
        ge_scalarmult(&ref10_scalarmult_result, view_sec, &P);
        unsigned char ref10_after_scalarmult[32];
        ge_tobytes(ref10_after_scalarmult, &ref10_scalarmult_result);

        oss << "\"ref10_after_scalarmult\":\"";
        for (int i = 0; i < 32; i++) {
          oss << std::hex << std::setfill('0') << std::setw(2)
              << (int)ref10_after_scalarmult[i];
        }
        oss << std::dec << "\",";

        // Compare donna64 after_scalarmult with ref10
        oss << "\"donna64_after_scalarmult_matches_ref10\":";
        unsigned char donna64_after_scalarmult[32];
        for (int i = 0; i < 32; i++) {
          donna64_after_scalarmult[i] =
              (unsigned char)donna64_debug_get_after_scalarmult(i);
        }
        oss << (memcmp(donna64_after_scalarmult, ref10_after_scalarmult, 32) ==
                        0
                    ? "true"
                    : "false");
      } else {
        oss << "\"decompress_ok\":false";
      }
    }
    oss << "},";

    // ====================================================================
    // SUMMARY
    // ====================================================================
    oss << "\"summary\":{";
    oss << "\"ref10_correct\":" << (ref10_ok ? "true" : "false") << ",";
    oss << "\"donna64_matches_ref10\":" << (direct_match ? "true" : "false")
        << ",";
    oss << "\"hwdev_uses_donna64\":"
        << (hwdev_matches_donna64 ? "true" : "false") << ",";
    oss << "\"hwdev_uses_ref10\":" << (hwdev_matches_ref10 ? "true" : "false")
        << ",";
    oss << "\"donna64_debug_passed\":"
        << (debug_trace_result == 100 ? "true" : "false");
    oss << "}";

    oss << "}"; // end root

  } catch (const std::exception &e) {
    oss << "\"error\":\"" << e.what() << "\"}";
  }

  return oss.str();
}

/**
 * debug_iteration_by_iteration - COMPREHENSIVE per-iteration comparison
 *
 * This function dumps ALL 64 donna64 iteration states and compares with ref10
 * final result. Since we can't easily step through ref10's internal iterations,
 * we output all donna64 states so we can identify the exact iteration where
 * divergence starts.
 *
 * Returns JSON with:
 * - all_iterations[]: Array of 64 donna64 states (32 bytes each as hex)
 * - ref10_final: ref10's final scalar*P result
 * - donna64_final: donna64's final scalar*P result
 * - first_diff_from_final: First iteration where donna64 differs from its final
 * state
 */
std::string debug_iteration_by_iteration() {
  std::ostringstream oss;
  oss << "{";

  try {
    // Hardcoded test vectors (same as donna64_debug_full_trace)
    unsigned char tx_pub[32] = {0xe3, 0xe1, 0xe3, 0x52, 0x58, 0xe9, 0xd3, 0x8e,
                                0x42, 0xd6, 0x77, 0x65, 0x46, 0xf5, 0x4d, 0x51,
                                0xfb, 0x2b, 0x5c, 0x33, 0x28, 0xde, 0x93, 0xac,
                                0xe2, 0x55, 0xa8, 0x36, 0x5f, 0x58, 0x3b, 0x09};
    unsigned char view_sec[32] = {
        0x3e, 0x70, 0x46, 0x15, 0xa5, 0xdf, 0x83, 0xb5, 0x63, 0x71, 0xd5,
        0xc7, 0x05, 0x8e, 0x14, 0x16, 0xb8, 0x46, 0x73, 0x4e, 0x81, 0xa5,
        0x73, 0x2b, 0x3b, 0xf5, 0x91, 0x3e, 0x53, 0x10, 0x32, 0x09};

    // Scalar decomposition (for reference)
    signed char e[64];
    int carry = 0, carry2;
    for (int i = 0; i < 31; i++) {
      carry += view_sec[i];
      carry2 = (carry + 8) >> 4;
      e[2 * i] = carry - (carry2 << 4);
      carry = (carry2 + 8) >> 4;
      e[2 * i + 1] = carry2 - (carry << 4);
    }
    carry += view_sec[31];
    carry2 = (carry + 8) >> 4;
    e[62] = carry - (carry2 << 4);
    e[63] = carry2;

    oss << "\"scalar_e\":[";
    for (int i = 0; i < 64; i++) {
      oss << (int)e[i];
      if (i < 63)
        oss << ",";
    }
    oss << "],";

    // Run donna64 debug trace to fill all buffers
    int donna64_result = donna64_debug_full_trace();
    oss << "\"donna64_debug_result\":" << donna64_result << ",";

    // Get ref10 final result for comparison
    ge_p3 P_ref10;
    if (ge_frombytes_vartime(&P_ref10, tx_pub) != 0) {
      oss << "\"error\":\"ref10 decompress failed\"}";
      return oss.str();
    }
    ge_p2 ref10_scalarmult_result;
    ge_scalarmult(&ref10_scalarmult_result, view_sec, &P_ref10);
    unsigned char ref10_after_scalarmult[32];
    ge_tobytes(ref10_after_scalarmult, &ref10_scalarmult_result);

    oss << "\"ref10_after_scalarmult\":\"";
    for (int j = 0; j < 32; j++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (int)ref10_after_scalarmult[j];
    }
    oss << std::dec << "\",";

    // Get donna64 final after_scalarmult
    unsigned char donna64_after_scalarmult[32];
    for (int j = 0; j < 32; j++) {
      donna64_after_scalarmult[j] =
          (unsigned char)donna64_debug_get_after_scalarmult(j);
    }

    oss << "\"donna64_after_scalarmult\":\"";
    for (int j = 0; j < 32; j++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (int)donna64_after_scalarmult[j];
    }
    oss << std::dec << "\",";

    oss << "\"scalarmult_match\":"
        << (memcmp(ref10_after_scalarmult, donna64_after_scalarmult, 32) == 0
                ? "true"
                : "false")
        << ",";

    // Output ALL 64 donna64 iteration states
    // iter_num 0 = state after i=63 (first iteration)
    // iter_num 63 = state after i=0 (last iteration, same as after_scalarmult)
    oss << "\"donna64_all_iterations\":[";
    for (int iter_num = 0; iter_num < 64; iter_num++) {
      if (iter_num > 0)
        oss << ",";
      oss << "{\"iter_num\":" << iter_num << ",\"loop_i\":" << (63 - iter_num)
          << ",\"e_i\":" << (int)e[63 - iter_num] << ",\"state\":\"";
      for (int b = 0; b < 32; b++) {
        int byte_val = donna64_debug_get_all_iter(iter_num, b);
        oss << std::hex << std::setfill('0') << std::setw(2)
            << (byte_val & 0xFF);
      }
      oss << std::dec << "\"}";
    }
    oss << "],";

    // Find first iteration where donna64 state matches ref10 final (working
    // backwards) This helps identify when the computation "becomes correct" if
    // read in reverse
    int last_matching_iter = -1;
    for (int iter_num = 63; iter_num >= 0; iter_num--) {
      unsigned char iter_state[32];
      for (int b = 0; b < 32; b++) {
        iter_state[b] = (unsigned char)donna64_debug_get_all_iter(iter_num, b);
      }
      if (memcmp(iter_state, donna64_after_scalarmult, 32) == 0) {
        last_matching_iter = iter_num;
        break;
      }
    }
    oss << "\"last_iter_matching_final\":" << last_matching_iter << ",";

    // Also compute ref10 partial results at key points for comparison
    // We can use scalar multiplication with truncated scalars to get
    // intermediate states Compute ref10 result after just iteration 63 (scalar
    // = e[63] * 16^63) This is complex, so let's just compare specific known
    // good points

    // Check if donna64 iter0 (after i=63) matches P (since e[63]=1, result
    // should be 1*P = P)
    unsigned char donna64_iter0[32];
    for (int b = 0; b < 32; b++) {
      donna64_iter0[b] = (unsigned char)donna64_debug_get_all_iter(0, b);
    }
    oss << "\"donna64_iter0_is_P\":"
        << (memcmp(donna64_iter0, tx_pub, 32) == 0 ? "true" : "false") << ",";

    // Quick sanity check: iter63 should equal after_scalarmult
    unsigned char donna64_iter63[32];
    for (int b = 0; b < 32; b++) {
      donna64_iter63[b] = (unsigned char)donna64_debug_get_all_iter(63, b);
    }
    oss << "\"donna64_iter63_equals_after_scalarmult\":"
        << (memcmp(donna64_iter63, donna64_after_scalarmult, 32) == 0
                ? "true"
                : "false");

    oss << "}";

  } catch (const std::exception &ex) {
    oss << "\"error\":\"" << ex.what() << "\"}";
  }

  return oss.str();
}

/**
 * diagnose_crypto_speed - Compare ref10 vs donna64 key derivation speed
 *
 * This is the CRITICAL diagnostic that proves whether donna64 is actually
 * being used by wallet scanning. It tests BOTH code paths:
 *
 * TEST 1: crypto::generate_key_derivation - The path wallet2 uses (ref10)
 * TEST 2: donna64_generate_key_derivation - Direct donna64 call
 *
 * Expected results:
 * - If donna64 is NOT hooked up: Test 1 ~7ms, Test 2 ~0.5ms  (14:1 ratio)
 * - If donna64 IS hooked up:     Test 1 ~0.5ms, Test 2 ~0.5ms (1:1 ratio)
 */
std::string diagnose_crypto_speed(int iterations) {
  using namespace std::chrono;

  // Test vectors - same as benchmark_key_derivation
  unsigned char tx_pub[32];
  unsigned char view_sec[32];
  unsigned char derivation[32];
  crypto::key_derivation crypto_derivation;

  // Initialize deterministic test values
  memset(tx_pub, 0x42, sizeof(tx_pub));
  memset(view_sec, 0x01, sizeof(view_sec));

  // Make view_sec a valid scalar
  view_sec[0] &= 0xF8;
  view_sec[31] &= 0x7F;
  view_sec[31] |= 0x40;

  // Copy to crypto types for ref10 test
  crypto::public_key crypto_pub;
  crypto::secret_key crypto_sec;
  memcpy(&crypto_pub, tx_pub, 32);
  memcpy(&crypto_sec, view_sec, 32);

  // ========================================================================
  // TEST 1: crypto::generate_key_derivation (ref10 path - what wallet2 uses)
  // ========================================================================
  auto ref10_start = high_resolution_clock::now();
  int ref10_success = 0;

  for (int i = 0; i < iterations; i++) {
    // Vary input to prevent caching
    crypto_pub.data[0] = (unsigned char)(i & 0xFF);
    crypto_pub.data[1] = (unsigned char)((i >> 8) & 0xFF);

    if (crypto::generate_key_derivation(crypto_pub, crypto_sec,
                                        crypto_derivation)) {
      ref10_success++;
    }
  }

  auto ref10_end = high_resolution_clock::now();
  double ref10_ms =
      duration<double, std::milli>(ref10_end - ref10_start).count();

  // ========================================================================
  // TEST 2: donna64_generate_key_derivation (direct donna64 call)
  // ========================================================================
  auto donna64_start = high_resolution_clock::now();
  int donna64_success = 0;

  for (int i = 0; i < iterations; i++) {
    // Vary input to prevent caching
    tx_pub[0] = (unsigned char)(i & 0xFF);
    tx_pub[1] = (unsigned char)((i >> 8) & 0xFF);

    if (donna64_generate_key_derivation(derivation, tx_pub, view_sec) == 0) {
      donna64_success++;
    }
  }

  auto donna64_end = high_resolution_clock::now();
  double donna64_ms =
      duration<double, std::milli>(donna64_end - donna64_start).count();

  // ========================================================================
  // Calculate metrics
  // ========================================================================
  double ref10_us_per_op = (ref10_ms * 1000.0) / iterations;
  double donna64_us_per_op = (donna64_ms * 1000.0) / iterations;
  double speedup_ratio = ref10_ms / donna64_ms;

  // Diagnose what's happening
  std::string diagnosis;
  if (speedup_ratio > 5.0) {
    // Large ratio = ref10 is slow, donna64 is fast = donna64 NOT hooked up
    diagnosis = "SLOW - ref10 in use, donna64 NOT hooked to wallet scanning";
  } else if (speedup_ratio > 1.5) {
    diagnosis = "PARTIAL - some speedup, but not full donna64 integration";
  } else {
    diagnosis = "FAST - donna64 is hooked up correctly!";
  }

  std::ostringstream oss;
  oss << std::fixed << std::setprecision(3);
  oss << "{"
      << "\"iterations\":" << iterations << ","
      << "\"ref10_path\":{"
      << "\"name\":\"crypto::generate_key_derivation\","
      << "\"total_ms\":" << ref10_ms << ","
      << "\"us_per_op\":" << ref10_us_per_op << ","
      << "\"success\":" << ref10_success << "},"
      << "\"donna64_direct\":{"
      << "\"name\":\"donna64_generate_key_derivation\","
      << "\"total_ms\":" << donna64_ms << ","
      << "\"us_per_op\":" << donna64_us_per_op << ","
      << "\"success\":" << donna64_success << "},"
      << "\"speedup_ratio\":" << speedup_ratio << ","
      << "\"diagnosis\":\"" << diagnosis << "\","
      << "\"version\":\"" << WASM_VERSION << "\""
      << "}";

  return oss.str();
}

/**
 * donna64_direct_benchmark - Benchmark donna64 directly without any C++ wrapper
 *
 * Calls the C function donna64_benchmark() which runs purely in C.
 * This gives the absolute best-case performance of donna64.
 */
std::string donna64_direct_benchmark(int iterations) {
  using namespace std::chrono;

  auto start = high_resolution_clock::now();
  int success = donna64_benchmark(iterations);
  auto end = high_resolution_clock::now();

  double elapsed_ms = duration<double, std::milli>(end - start).count();
  double us_per_op = (elapsed_ms * 1000.0) / iterations;
  int per_second = static_cast<int>((iterations / elapsed_ms) * 1000.0);

  std::ostringstream oss;
  oss << std::fixed << std::setprecision(3);
  oss << "{"
      << "\"iterations\":" << iterations << ","
      << "\"success_count\":" << success << ","
      << "\"total_ms\":" << elapsed_ms << ","
      << "\"us_per_op\":" << us_per_op << ","
      << "\"derivations_per_second\":" << per_second << ","
      << "\"implementation\":\"donna64_benchmark (pure C)\","
      << "\"version\":\"" << WASM_VERSION << "\""
      << "}";

  return oss.str();
}

// ============================================================================
// VIEW TAG COMPUTATION - For JavaScript pre-filtering optimization
// ============================================================================

/**
 * compute_view_tag - Compute expected view tag for JavaScript pre-filtering
 *
 * This function enables the following optimization:
 * 1. JavaScript fetches minimal JSON data from /api/scan-data (tx_pub_keys,
 * view_tags, output_keys)
 * 2. For each output, JavaScript calls compute_view_tag(tx_pub_key,
 * output_index)
 * 3. If computed_view_tag != received_view_tag, output is NOT ours (99.6% case)
 * 4. Only outputs with matching view tags need full ECDH verification
 *
 * This bypasses the slow epee deserialization entirely for 99.6% of outputs.
 *
 * Algorithm (from crypto.cpp):
 * 1. derivation = tx_pub_key * view_secret_key (ECDH - donna64 optimized)
 * 2. buffer = "view_tag" || derivation || varint(output_index)
 * 3. hash = cn_fast_hash(buffer)
 * 4. view_tag = hash[0] (first byte)
 *
 * @param tx_pub_key_hex 64-char hex string of transaction public key
 * @param output_index Output index within the transaction
 * @param view_secret_key_hex 64-char hex string of wallet's view secret key
 * @return JSON with view_tag (as integer 0-255) and timing, or error
 */
std::string compute_view_tag(const std::string &tx_pub_key_hex,
                             int output_index,
                             const std::string &view_secret_key_hex) {
  try {
    // Validate inputs
    if (tx_pub_key_hex.length() != 64) {
      return "{\"error\":\"tx_pub_key must be 64 hex chars\"}";
    }
    if (view_secret_key_hex.length() != 64) {
      return "{\"error\":\"view_secret_key must be 64 hex chars\"}";
    }
    if (output_index < 0) {
      return "{\"error\":\"output_index must be >= 0\"}";
    }

    // Parse hex strings to bytes
    unsigned char tx_pub[32];
    unsigned char view_sec[32];

    if (!epee::string_tools::hex_to_pod(tx_pub_key_hex, tx_pub)) {
      return "{\"error\":\"invalid tx_pub_key hex\"}";
    }
    if (!epee::string_tools::hex_to_pod(view_secret_key_hex, view_sec)) {
      return "{\"error\":\"invalid view_secret_key hex\"}";
    }

    auto start = std::chrono::high_resolution_clock::now();

    // Compute derivation using donna64 (matches hwdev.generate_key_derivation)
    crypto::key_derivation crypto_derivation;

    if (donna64_generate_key_derivation(
            reinterpret_cast<unsigned char *>(&crypto_derivation), tx_pub,
            view_sec) != 0) {
      return "{\"error\":\"key derivation failed\"}";
    }

    unsigned char derivation[32];
    memcpy(derivation, &crypto_derivation, 32);

// Step 2-4: Compute view tag (from crypto.cpp derive_view_tag)
// Buffer: "view_tag" (8 bytes) || derivation (32 bytes) || varint(output_index)
#pragma pack(push, 1)
    struct {
      char salt[8];
      unsigned char derivation[32];
      char output_index_varint[10]; // max varint size for size_t
    } buf;
#pragma pack(pop)

    memcpy(buf.salt, "view_tag", 8);
    memcpy(buf.derivation, derivation, 32);

    // Encode output_index as varint
    char *end = buf.output_index_varint;
    tools::write_varint(end, static_cast<size_t>(output_index));

    size_t buf_len = 8 + 32 + (end - buf.output_index_varint);

    // Hash and take first byte
    crypto::hash view_tag_full;
    crypto::cn_fast_hash(&buf, buf_len, view_tag_full);

    unsigned char view_tag = view_tag_full.data[0];

    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_us =
        std::chrono::duration<double, std::micro>(end_time - start).count();

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3);
    oss << "{"
        << "\"view_tag\":" << static_cast<int>(view_tag) << ","
        << "\"view_tag_hex\":\"" << std::hex << std::setw(2)
        << std::setfill('0') << static_cast<int>(view_tag) << std::dec << "\","
        << "\"elapsed_us\":" << elapsed_us << ","
        << "\"success\":true"
        << "}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"error\":\"unknown exception\"}";
  }
}

/**
 * compute_view_tags_batch - Compute view tags for multiple outputs efficiently
 *
 * Batch version for processing many outputs at once. This is even more
 * efficient because we can reuse the derivation for multiple outputs in the
 * same transaction.
 *
 * @param tx_pub_key_hex Transaction public key (64 hex chars)
 * @param output_indices_json JSON array of output indices, e.g. "[0,1,2,3]"
 * @param view_secret_key_hex Wallet's view secret key (64 hex chars)
 * @return JSON with array of view tags
 */
std::string compute_view_tags_batch(const std::string &tx_pub_key_hex,
                                    const std::string &output_indices_json,
                                    const std::string &view_secret_key_hex) {
  try {
    // Validate inputs
    if (tx_pub_key_hex.length() != 64 || view_secret_key_hex.length() != 64) {
      return "{\"error\":\"keys must be 64 hex chars\"}";
    }

    // Parse hex strings
    unsigned char tx_pub[32];
    unsigned char view_sec[32];

    if (!epee::string_tools::hex_to_pod(tx_pub_key_hex, tx_pub)) {
      return "{\"error\":\"invalid tx_pub_key hex\"}";
    }
    if (!epee::string_tools::hex_to_pod(view_secret_key_hex, view_sec)) {
      return "{\"error\":\"invalid view_secret_key hex\"}";
    }

    // Parse output indices (simple JSON array parsing)
    std::vector<int> output_indices;
    std::string indices_str = output_indices_json;
    // Remove [ and ]
    size_t start_pos = indices_str.find('[');
    size_t end_pos = indices_str.find(']');
    if (start_pos == std::string::npos || end_pos == std::string::npos) {
      return "{\"error\":\"invalid output_indices JSON array\"}";
    }
    indices_str = indices_str.substr(start_pos + 1, end_pos - start_pos - 1);

    // Parse comma-separated numbers
    std::istringstream iss(indices_str);
    std::string token;
    while (std::getline(iss, token, ',')) {
      // Trim whitespace
      size_t first = token.find_first_not_of(" \t");
      size_t last = token.find_last_not_of(" \t");
      if (first != std::string::npos) {
        token = token.substr(first, last - first + 1);
        output_indices.push_back(std::stoi(token));
      }
    }

    if (output_indices.empty()) {
      return "{\"error\":\"no output indices provided\"}";
    }

    auto start = std::chrono::high_resolution_clock::now();

    // Compute derivation ONCE using donna64 (matches
    // hwdev.generate_key_derivation)
    crypto::key_derivation crypto_derivation;

    if (donna64_generate_key_derivation(
            reinterpret_cast<unsigned char *>(&crypto_derivation), tx_pub,
            view_sec) != 0) {
      return "{\"error\":\"key derivation failed\"}";
    }

    unsigned char derivation[32];
    memcpy(derivation, &crypto_derivation, 32);

    // Compute view tags for all indices
    std::vector<int> view_tags;
    view_tags.reserve(output_indices.size());

    for (int idx : output_indices) {
// Buffer for this index
#pragma pack(push, 1)
      struct {
        char salt[8];
        unsigned char derivation[32];
        char output_index_varint[10];
      } buf;
#pragma pack(pop)

      memcpy(buf.salt, "view_tag", 8);
      memcpy(buf.derivation, derivation, 32);

      char *end = buf.output_index_varint;
      tools::write_varint(end, static_cast<size_t>(idx));

      size_t buf_len = 8 + 32 + (end - buf.output_index_varint);

      crypto::hash view_tag_full;
      crypto::cn_fast_hash(&buf, buf_len, view_tag_full);

      view_tags.push_back(static_cast<int>(view_tag_full.data[0]));
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_us =
        std::chrono::duration<double, std::micro>(end_time - start).count();

    // Build result JSON
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3);
    oss << "{\"view_tags\":[";
    for (size_t i = 0; i < view_tags.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << view_tags[i];
    }
    oss << "],\"count\":" << view_tags.size()
        << ",\"elapsed_us\":" << elapsed_us
        << ",\"us_per_tag\":" << (elapsed_us / view_tags.size())
        << ",\"success\":true}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"error\":\"unknown exception\"}";
  }
}

// ============================================================================
// DEBUG: Derive subaddress public key from components (no wallet needed)
// This computes: derived_spend_key = out_key - H(derivation || output_index) *
// G Then compares to a known spend pubkey to determine if output is ours
// ============================================================================
std::string debug_derive_subaddress_public_key(const std::string &tx_pub_hex,
                                               const std::string &view_sec_hex,
                                               const std::string &out_key_hex,
                                               int output_index) {
  try {
    // Parse tx public key
    crypto::public_key tx_pub;
    if (tx_pub_hex.length() != 64 ||
        !epee::string_tools::hex_to_pod(tx_pub_hex, tx_pub)) {
      return "{\"error\":\"invalid tx_pub hex\"}";
    }

    // Parse view secret key
    crypto::secret_key view_sec;
    if (view_sec_hex.length() != 64 ||
        !epee::string_tools::hex_to_pod(view_sec_hex, view_sec)) {
      return "{\"error\":\"invalid view_sec hex\"}";
    }

    // Parse output public key
    crypto::public_key out_key;
    if (out_key_hex.length() != 64 ||
        !epee::string_tools::hex_to_pod(out_key_hex, out_key)) {
      return "{\"error\":\"invalid out_key hex\"}";
    }

    std::ostringstream oss;
    oss << "{";

    // Step 1: Compute key derivation using BOTH crypto:: (ref10) and donna64
    crypto::key_derivation derivation_ref10;
    bool deriv_ref10_ok =
        crypto::generate_key_derivation(tx_pub, view_sec, derivation_ref10);

    crypto::key_derivation derivation_donna64;
    bool deriv_donna64_ok =
        donna64_generate_key_derivation(
            reinterpret_cast<unsigned char *>(&derivation_donna64),
            reinterpret_cast<const unsigned char *>(&tx_pub),
            reinterpret_cast<const unsigned char *>(&view_sec)) == 0;

    oss << "\"derivation_ref10_ok\":" << (deriv_ref10_ok ? "true" : "false")
        << ",";
    if (deriv_ref10_ok) {
      oss << "\"derivation_ref10\":\""
          << epee::string_tools::pod_to_hex(derivation_ref10) << "\",";
    }

    oss << "\"derivation_donna64_ok\":" << (deriv_donna64_ok ? "true" : "false")
        << ",";
    if (deriv_donna64_ok) {
      oss << "\"derivation_donna64\":\""
          << epee::string_tools::pod_to_hex(derivation_donna64) << "\",";
    }

    oss << "\"derivations_match\":"
        << (deriv_ref10_ok && deriv_donna64_ok &&
                    derivation_ref10 == derivation_donna64
                ? "true"
                : "false")
        << ",";

    // Step 2: Compute derive_subaddress_public_key using device (which uses
    // donna64 via ops.h) Formula: derived_spend_key = out_key - H(derivation ||
    // output_index) * G
    hw::device &hwdev = hw::get_device("default");

    // Use ref10 derivation
    crypto::public_key derived_spend_key_ref10;
    bool derive_ref10_ok = false;
    if (deriv_ref10_ok) {
      derive_ref10_ok = hwdev.derive_subaddress_public_key(
          out_key, derivation_ref10, output_index, derived_spend_key_ref10);
    }

    // Use donna64 derivation
    crypto::public_key derived_spend_key_donna64;
    bool derive_donna64_ok = false;
    if (deriv_donna64_ok) {
      derive_donna64_ok = hwdev.derive_subaddress_public_key(
          out_key, derivation_donna64, output_index, derived_spend_key_donna64);
    }

    oss << "\"derive_ref10_ok\":" << (derive_ref10_ok ? "true" : "false")
        << ",";
    if (derive_ref10_ok) {
      oss << "\"derived_spend_key_ref10\":\""
          << epee::string_tools::pod_to_hex(derived_spend_key_ref10) << "\",";
    }

    oss << "\"derive_donna64_ok\":" << (derive_donna64_ok ? "true" : "false")
        << ",";
    if (derive_donna64_ok) {
      oss << "\"derived_spend_key_donna64\":\""
          << epee::string_tools::pod_to_hex(derived_spend_key_donna64) << "\",";
    }

    oss << "\"derived_spend_keys_match\":"
        << (derive_ref10_ok && derive_donna64_ok &&
                    derived_spend_key_ref10 == derived_spend_key_donna64
                ? "true"
                : "false")
        << ",";

    // Step 3: Compute view tag using both derivations for comparison
    auto compute_view_tag =
        [output_index](const crypto::key_derivation &deriv) -> uint8_t {
#pragma pack(push, 1)
      struct {
        char salt[8];
        unsigned char derivation[32];
        char output_index_varint[10];
      } buf;
#pragma pack(pop)

      memcpy(buf.salt, "view_tag", 8);
      memcpy(buf.derivation, &deriv, 32);

      char *varint_end = buf.output_index_varint;
      tools::write_varint(varint_end, static_cast<size_t>(output_index));
      size_t buf_len = 8 + 32 + (varint_end - buf.output_index_varint);

      crypto::hash view_tag_hash;
      crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);
      return view_tag_hash.data[0];
    };

    if (deriv_ref10_ok) {
      uint8_t tag_ref10 = compute_view_tag(derivation_ref10);
      oss << "\"view_tag_ref10\":" << static_cast<int>(tag_ref10) << ",";
      oss << "\"view_tag_ref10_hex\":\"" << std::hex << std::setfill('0')
          << std::setw(2) << static_cast<int>(tag_ref10) << std::dec << "\",";
    }

    if (deriv_donna64_ok) {
      uint8_t tag_donna64 = compute_view_tag(derivation_donna64);
      oss << "\"view_tag_donna64\":" << static_cast<int>(tag_donna64) << ",";
      oss << "\"view_tag_donna64_hex\":\"" << std::hex << std::setfill('0')
          << std::setw(2) << static_cast<int>(tag_donna64) << std::dec << "\",";
    }

    oss << "\"output_index\":" << output_index << ",";
    oss << "\"success\":true}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\",\"success\":false}";
  }
}

// ============================================================================
// COMPACT SCAN PROTOCOL (CSP) - ZERO-COPY BINARY SCANNING
// ============================================================================
// This function processes flat binary CSP data using pointer arithmetic only.
// NO ALLOCATIONS, NO PARSING - just pointer walking and donna64 math.
//
// CSP Binary Format:
// [Header: 12 bytes]
//   - Magic: 4 bytes = "CSP\x01"
//   - StartHeight: 4 bytes (uint32 LE)
//   - TxCount: 4 bytes (uint32 LE)
// [Transactions: variable]
//   - TxPubKey: 32 bytes
//   - OutputCount: 2 bytes (uint16 LE)
//   For each output:
//   - OutputPubKey: 32 bytes
//   - ViewTag: 1 byte
//
// Returns JSON with matching outputs (sparse - only matches)
// Target: 30s epee parsing ??? <100ms pointer walk
// ============================================================================

/**
 * debug_csp_find_tx - Find a specific transaction in CSP buffer and check view
 * tag
 *
 * This is a diagnostic function to understand why scanning might miss a known
 * transaction. SUPPORTS CSP v1, v2, and v3 formats.
 *
 * @param csp_ptr Pointer to CSP buffer in WASM heap
 * @param csp_size Size of CSP buffer in bytes
 * @param tx_pubkey_hex Transaction public key to search for (64 hex chars)
 * @param view_secret_key_hex Wallet's view secret key (64 hex chars)
 * @return JSON with diagnostic info about the transaction if found
 */
std::string debug_csp_find_tx(uintptr_t csp_ptr, size_t csp_size,
                              const std::string &tx_pubkey_hex,
                              const std::string &view_secret_key_hex) {
  try {
    // Validate inputs
    if (csp_ptr == 0 || csp_size < 12) {
      return "{\"error\":\"invalid CSP buffer\"}";
    }
    if (tx_pubkey_hex.length() != 64) {
      return "{\"error\":\"tx_pubkey must be 64 hex chars\"}";
    }
    if (view_secret_key_hex.length() != 64) {
      return "{\"error\":\"view_secret_key must be 64 hex chars\"}";
    }

    // Parse target tx_pubkey
    unsigned char target_tx_pub[32];
    if (!epee::string_tools::hex_to_pod(tx_pubkey_hex, target_tx_pub)) {
      return "{\"error\":\"invalid tx_pubkey hex\"}";
    }

    // Parse view secret key
    unsigned char view_sec[32];
    if (!epee::string_tools::hex_to_pod(view_secret_key_hex, view_sec)) {
      return "{\"error\":\"invalid view_secret_key hex\"}";
    }

    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(csp_ptr);
    const uint8_t *end = ptr + csp_size;

    // Validate magic and detect version
    if (ptr[0] != 'C' || ptr[1] != 'S' || ptr[2] != 'P') {
      return "{\"error\":\"invalid CSP magic\"}";
    }

    uint8_t csp_version = ptr[3];
    if (csp_version != 0x01 && csp_version != 0x02 && csp_version != 0x03) {
      return "{\"error\":\"unsupported CSP version " +
             std::to_string(csp_version) + "\"}";
    }

    uint32_t start_height =
        ptr[4] | (ptr[5] << 8) | (ptr[6] << 16) | (ptr[7] << 24);
    uint32_t tx_count =
        ptr[8] | (ptr[9] << 8) | (ptr[10] << 16) | (ptr[11] << 24);
    ptr += 12;

    // Search for target tx
    bool found = false;
    uint32_t found_tx_idx = 0;
    uint16_t found_output_count = 0;
    uint32_t found_block_height = 0;
    bool deriv_ok = false;
    crypto::key_derivation derivation;
    std::vector<std::tuple<uint16_t, uint8_t, uint8_t, bool, uint8_t, bool>>
        output_results; // idx, stored, computed, match, output_type,
                        // has_additional

    for (uint32_t tx_idx = 0; tx_idx < tx_count && ptr < end; tx_idx++) {
      if (ptr + 32 > end)
        break;
      const unsigned char *tx_pub = ptr;
      ptr += 32;

      // CSP v2/v3: Read block height
      uint32_t block_height = 0;
      if (csp_version >= 0x02) {
        if (ptr + 4 > end)
          break;
        block_height = ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
        ptr += 4;
      }

      if (ptr + 2 > end)
        break;
      uint16_t output_count = ptr[0] | (ptr[1] << 8);
      ptr += 2;

      if (memcmp(tx_pub, target_tx_pub, 32) == 0) {
        found = true;
        found_tx_idx = tx_idx;
        found_output_count = output_count;
        found_block_height = block_height;

        // Compute derivation using donna64 (matches
        // hwdev.generate_key_derivation)
        deriv_ok = donna64_generate_key_derivation(
                       reinterpret_cast<unsigned char *>(&derivation), tx_pub,
                       view_sec) == 0;

        if (deriv_ok) {
          // Process each output
          for (uint16_t out_idx = 0; out_idx < output_count && ptr < end;
               out_idx++) {
            if (ptr + 32 > end)
              break;
            const unsigned char *output_pub = ptr;
            ptr += 32;

            uint8_t output_type = 0;
            uint8_t stored_view_tag = 0;
            bool has_additional_pubkey = false;
            crypto::key_derivation output_derivation =
                derivation; // Default to main derivation

            if (csp_version == 0x01) {
              // CSP v1: 1 byte view tag only
              if (ptr + 1 > end)
                break;
              stored_view_tag = *ptr++;
              output_type = (stored_view_tag == 0) ? 0 : 1;
            } else {
              // CSP v2/v3: 1 byte output_type + 4 bytes view_tag
              if (ptr + 5 > end)
                break;
              output_type = *ptr++;
              stored_view_tag = *ptr++; // First byte of view tag
              ptr += 3;                 // Skip remaining view tag bytes

              // CSP v3: Check for additional pubkey (used for subaddress
              // outputs)
              if (csp_version == 0x03 && ptr < end) {
                uint8_t has_additional = *ptr++;
                if (has_additional) {
                  has_additional_pubkey = true;
                  if (ptr + 32 <= end) {
                    const unsigned char *additional_pubkey = ptr;
                    ptr += 32;

                    // Compute derivation using additional pubkey for subaddress
                    // outputs This is CRITICAL for correct view tag
                    // computation!
                    donna64_generate_key_derivation(
                        reinterpret_cast<unsigned char *>(&output_derivation),
                        additional_pubkey, view_sec);
                  }
                }
              }
            }

// Compute expected view tag using per-output derivation
#pragma pack(push, 1)
            struct {
              char salt[8];
              unsigned char derivation[32];
              char output_index_varint[10];
            } buf;
#pragma pack(pop)

            memcpy(buf.salt, "view_tag", 8);
            memcpy(buf.derivation, &output_derivation,
                   32); // Use per-output derivation!

            char *varint_end = buf.output_index_varint;
            tools::write_varint(varint_end, static_cast<size_t>(out_idx));
            size_t buf_len = 8 + 32 + (varint_end - buf.output_index_varint);

            crypto::hash view_tag_hash;
            crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);
            uint8_t computed_view_tag = view_tag_hash.data[0];

            // For output_type 0 (no viewtag), stored_view_tag=0 should match
            // anything
            bool match = (output_type == 0 && stored_view_tag == 0) ||
                         (stored_view_tag == computed_view_tag);

            output_results.push_back(
                std::make_tuple(out_idx, stored_view_tag, computed_view_tag,
                                match, output_type, has_additional_pubkey));
          }
        } else {
          // Skip outputs if derivation failed
          for (uint16_t out_idx = 0; out_idx < output_count && ptr < end;
               out_idx++) {
            ptr += 32; // output_pub
            if (csp_version == 0x01) {
              ptr += 1; // view_tag
            } else {
              ptr += 5; // output_type + view_tag
              if (csp_version == 0x03 && ptr < end) {
                uint8_t has_additional = *ptr++;
                if (has_additional)
                  ptr += 32;
              }
            }
          }
        }

        break;
      } else {
        // Skip outputs
        for (uint16_t out_idx = 0; out_idx < output_count && ptr < end;
             out_idx++) {
          ptr += 32; // output_pub
          if (csp_version == 0x01) {
            ptr += 1; // view_tag
          } else {
            ptr += 5; // output_type + view_tag
            if (csp_version == 0x03 && ptr < end) {
              uint8_t has_additional = *ptr++;
              if (has_additional)
                ptr += 32;
            }
          }
        }
      }
    }

    // Build JSON response
    std::ostringstream oss;
    oss << "{\"csp_version\":" << static_cast<int>(csp_version) << ","
        << "\"csp_start_height\":" << start_height << ","
        << "\"csp_tx_count\":" << tx_count << ",";

    if (found) {
      oss << "\"found\":true,"
          << "\"tx_index\":" << found_tx_idx << ","
          << "\"block_height\":" << found_block_height << ","
          << "\"output_count\":" << found_output_count << ","
          << "\"derivation_ok\":" << (deriv_ok ? "true" : "false") << ",";

      if (deriv_ok) {
        oss << "\"derivation\":\""
            << key_to_hex(reinterpret_cast<const unsigned char *>(&derivation))
            << "\","
            << "\"outputs\":[";

        for (size_t i = 0; i < output_results.size(); i++) {
          if (i > 0)
            oss << ",";
          oss << "{\"idx\":" << std::get<0>(output_results[i])
              << ",\"output_type\":"
              << static_cast<int>(std::get<4>(output_results[i]))
              << ",\"has_additional\":"
              << (std::get<5>(output_results[i]) ? "true" : "false")
              << ",\"stored_tag\":"
              << static_cast<int>(std::get<1>(output_results[i]))
              << ",\"computed_tag\":"
              << static_cast<int>(std::get<2>(output_results[i]))
              << ",\"match\":"
              << (std::get<3>(output_results[i]) ? "true" : "false") << "}";
        }
        oss << "],";
      }
    } else {
      oss << "\"found\":false,";
    }

    oss << "\"success\":true}";
    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"error\":\"unknown exception\"}";
  }
}

/**
 * debug_parse_tx_blob - Parse a transaction blob and extract
 * hash/pubkey/view_tags
 *
 * Used for debugging TXI data to verify transaction identity.
 *
 * @param tx_blob_ptr Pointer to transaction blob in WASM heap
 * @param tx_blob_size Size of transaction blob in bytes
 * @return JSON with tx_hash, tx_pubkey, output_count, output_view_tags
 */
std::string debug_parse_tx_blob(uintptr_t tx_blob_ptr, size_t tx_blob_size) {
  try {
    if (tx_blob_ptr == 0 || tx_blob_size == 0) {
      return "{\"success\":false,\"error\":\"invalid blob\"}";
    }

    const uint8_t *data = reinterpret_cast<const uint8_t *>(tx_blob_ptr);
    std::string tx_blob(reinterpret_cast<const char *>(data), tx_blob_size);

    cryptonote::transaction tx;
    crypto::hash tx_hash;

    // Try standard parsing
    bool parse_success =
        cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash);

    if (!parse_success) {
      // Standard parsing failed - this is expected for AUDIT transactions
      // The wallet's ingest_sparse_transactions uses parse_audit_tx_manually as
      // fallback For this debug endpoint, just report the failure with guidance

      // Check if it looks like an AUDIT tx (type byte at offset 2 or 3 should
      // be 8 or 0x08 in hex)
      std::string msg = "failed to parse tx blob (standard parser)";
      if (tx_blob_size > 10) {
        // Type is typically at byte 2 or 3 depending on version encoding
        uint8_t type_byte = 0;
        if (static_cast<uint8_t>(tx_blob[0]) == 2) {
          // Version 2 encoding - check possible type positions
          type_byte = static_cast<uint8_t>(
              tx_blob[2]); // After version + unlock_time varint start
        }
        if (type_byte == 0x08 ||
            type_byte == 0x17) { // 0x08=AUDIT raw, 0x17=23 which includes type
          msg = "failed to parse tx blob (standard parser). This appears to be "
                "an AUDIT tx - wallet uses manual parser fallback for these.";
        }
      }
      return "{\"success\":false,\"error\":\"" + msg + "\"}";
    }

    crypto::public_key tx_pubkey = cryptonote::get_tx_pub_key_from_extra(tx);

    // Extract view tags from outputs
    std::vector<int> view_tags;
    for (const auto &out : tx.vout) {
      uint8_t view_tag = 0;
      if (auto *tagged_ptr =
              boost::get<cryptonote::txout_to_tagged_key>(&out.target)) {
        view_tag = tagged_ptr->view_tag.data;
      } else if (auto *carrot_ptr =
                     boost::get<cryptonote::txout_to_carrot_v1>(&out.target)) {
        view_tag = carrot_ptr->view_tag.bytes[0];
      }
      view_tags.push_back(view_tag);
    }

    std::ostringstream oss;
    oss << "{\"success\":true,"
        << "\"tx_hash\":\"" << epee::string_tools::pod_to_hex(tx_hash) << "\","
        << "\"tx_pubkey\":\"" << epee::string_tools::pod_to_hex(tx_pubkey)
        << "\","
        << "\"tx_type\":" << (int)tx.type << ","
        << "\"tx_type_name\":\""
        << (tx.type == cryptonote::transaction_type::AUDIT      ? "AUDIT"
            : tx.type == cryptonote::transaction_type::STAKE    ? "STAKE"
            : tx.type == cryptonote::transaction_type::PROTOCOL ? "PROTOCOL"
            : tx.type == cryptonote::transaction_type::TRANSFER ? "TRANSFER"
            : tx.type == cryptonote::transaction_type::MINER    ? "MINER"
                                                                : "UNKNOWN")
        << "\","
        << "\"rct_type\":" << (int)tx.rct_signatures.type << ","
        << "\"salvium_data_type\":"
        << (int)tx.rct_signatures.salvium_data.salvium_data_type << ",";

    // Include salvium_data.spend_pubkey if present (for AUDIT/STAKE
    // transactions)
    if (tx.rct_signatures.salvium_data.salvium_data_type ==
        rct::SalviumZeroAudit) {
      oss << "\"salvium_data_spend_pubkey\":\""
          << epee::string_tools::pod_to_hex(
                 tx.rct_signatures.salvium_data.spend_pubkey)
          << "\",";
    } else {
      oss << "\"salvium_data_spend_pubkey\":null,";
    }

    oss << "\"output_count\":" << tx.vout.size() << ","
        << "\"output_view_tags\":[";

    for (size_t i = 0; i < view_tags.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << view_tags[i];
    }
    oss << "]}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"success\":false,\"error\":\"unknown exception\"}";
  }
}

/**
 * debug_parse_audit_tx - Parse AUDIT tx using manual parser and show
 * return_address
 *
 * This specifically tests parse_audit_tx_manually to verify it correctly
 * extracts return_address from AUDIT transactions.
 *
 * @param tx_blob_ptr Pointer to transaction blob in WASM heap
 * @param tx_blob_size Size of transaction blob in bytes
 * @return JSON with return_address, spend_pubkey, etc.
 */
std::string debug_parse_audit_tx(uintptr_t tx_blob_ptr, size_t tx_blob_size) {
  try {
    if (tx_blob_ptr == 0 || tx_blob_size == 0) {
      return "{\"success\":false,\"error\":\"invalid blob\"}";
    }

    const uint8_t *data = reinterpret_cast<const uint8_t *>(tx_blob_ptr);
    std::string tx_blob(reinterpret_cast<const char *>(data), tx_blob_size);

    cryptonote::transaction tx;
    crypto::hash tx_hash;

    // Use the manual AUDIT parser that we fixed in v5.3.1
    // This function is defined in WasmWallet class but we have a standalone
    // version
    bool parse_success = false;

    // Direct manual parsing like ingest_sparse_transactions does
    // Re-implement the parsing here for debug purposes
    size_t offset = 0;
    const size_t size = tx_blob_size;

    auto read_varint = [&]() -> uint64_t {
      uint64_t val = 0;
      uint8_t shift = 0;
      while (offset < size) {
        uint8_t byte = data[offset++];
        val |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0)
          break;
        shift += 7;
      }
      return val;
    };

    // Parse version
    tx.version = read_varint();
    tx.unlock_time = read_varint();

    // Parse vin (inputs)
    uint64_t vin_count = read_varint();
    tx.vin.resize(vin_count);
    for (size_t i = 0; i < vin_count; i++) {
      uint8_t input_type = data[offset++];
      if (input_type == 0x02) { // txin_to_key
        cryptonote::txin_to_key in;
        in.amount = read_varint();
        uint64_t key_offset_count = read_varint();
        in.key_offsets.resize(key_offset_count);
        for (size_t j = 0; j < key_offset_count; j++) {
          in.key_offsets[j] = read_varint();
        }
        if (offset + 32 <= size) {
          memcpy(&in.k_image, data + offset, 32);
          offset += 32;
        }
        tx.vin[i] = in;
      }
    }

    // Parse vout (outputs)
    uint64_t vout_count = read_varint();
    tx.vout.resize(vout_count);
    for (size_t i = 0; i < vout_count; i++) {
      tx.vout[i].amount = read_varint();
      uint8_t output_type = data[offset++];
      if (output_type == 0x03) { // txout_to_tagged_key
        cryptonote::txout_to_tagged_key out;
        memcpy(&out.key, data + offset, 32);
        offset += 32;
        out.view_tag.data = data[offset++];
        memcpy(out.asset_type.data(), data + offset, 8);
        offset += 8;
        tx.vout[i].target = out;
      } else if (output_type == 0x02) { // txout_to_key
        cryptonote::txout_to_key out;
        memcpy(&out.key, data + offset, 32);
        offset += 32;
        tx.vout[i].target = out;
      }
    }

    // Parse extra
    uint64_t extra_size = read_varint();
    tx.extra.resize(extra_size);
    memcpy(tx.extra.data(), data + offset, extra_size);
    offset += extra_size;

    // Parse tx type
    uint64_t tx_type_val = read_varint();
    tx.type = static_cast<cryptonote::transaction_type>(tx_type_val);

    auto read_string = [&]() {
      uint64_t str_len = read_varint();
      if (str_len > 0 && offset + str_len <= size) {
        offset += str_len;
      }
    };

    // Parse AUDIT prefix fields
    if (tx.type == cryptonote::transaction_type::AUDIT) {
      tx.amount_burnt = read_varint();

      if (offset + 32 <= size) {
        memcpy(&tx.return_address, data + offset, 32);
        offset += 32;
      }

      if (offset + 32 <= size) {
        memcpy(&tx.return_pubkey, data + offset, 32);
        offset += 32;
      }

      read_string(); // source_asset_type
      read_string(); // destination_asset_type
      tx.amount_slippage_limit = read_varint();

      // Parse RCT type
      tx.rct_signatures.type = data[offset++];

      // Parse salvium_data
      read_varint(); // txnFee
      uint64_t salvium_data_type = read_varint();
      tx.rct_signatures.salvium_data.salvium_data_type =
          static_cast<rct::SalviumDataType>(salvium_data_type);

      // Skip proofs
      offset += 96; // pr_proof
      offset += 96; // sa_proof

      if (salvium_data_type == rct::SalviumZeroAudit) {
        offset += 96; // cz_proof

        uint64_t ivd_count = read_varint();
        for (uint64_t i = 0; i < ivd_count; i++) {
          offset += 32;  // aR
          read_varint(); // amount
          read_varint(); // i
          uint64_t origin_type = read_varint();
          if (origin_type != 0) {
            offset += 32;  // aR_stake
            read_varint(); // i_stake
          }
        }

        // Parse spend_pubkey
        if (offset + 32 <= size) {
          memcpy(&tx.rct_signatures.salvium_data.spend_pubkey, data + offset,
                 32);
          offset += 32;
        }
      }

      parse_success = true;
    }

    // Compute tx_hash
    crypto::cn_fast_hash(tx_blob.data(), tx_blob.size(), tx_hash);

    // Build JSON response
    std::ostringstream oss;
    oss << "{\"success\":" << (parse_success ? "true" : "false") << ",";
    oss << "\"tx_hash\":\"" << epee::string_tools::pod_to_hex(tx_hash) << "\",";
    oss << "\"tx_type\":" << (int)tx.type << ",";
    oss << "\"tx_type_name\":\""
        << (tx.type == cryptonote::transaction_type::AUDIT      ? "AUDIT"
            : tx.type == cryptonote::transaction_type::STAKE    ? "STAKE"
            : tx.type == cryptonote::transaction_type::PROTOCOL ? "PROTOCOL"
                                                                : "OTHER")
        << "\",";
    oss << "\"amount_burnt\":" << tx.amount_burnt << ",";
    oss << "\"return_address\":\""
        << epee::string_tools::pod_to_hex(tx.return_address) << "\",";
    oss << "\"return_pubkey\":\""
        << epee::string_tools::pod_to_hex(tx.return_pubkey) << "\",";
    oss << "\"salvium_data_type\":"
        << (int)tx.rct_signatures.salvium_data.salvium_data_type << ",";
    oss << "\"salvium_data_spend_pubkey\":\""
        << epee::string_tools::pod_to_hex(
               tx.rct_signatures.salvium_data.spend_pubkey)
        << "\",";
    oss << "\"return_address_is_null\":"
        << (tx.return_address == crypto::null_pkey ? "true" : "false") << ",";
    oss << "\"output_count\":" << tx.vout.size() << "}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"success\":false,\"error\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"success\":false,\"error\":\"unknown exception\"}";
  }
}

// Helper to subtract keys: res = a - b
void sub_keys(const crypto::public_key &a, const crypto::public_key &b,
              crypto::public_key &res) {
  ge_p3 A;
  if (ge_frombytes_vartime(&A, (const unsigned char *)a.data) != 0) {
    memset(&res, 0, 32);
    return;
  }
  ge_p3 B;
  if (ge_frombytes_vartime(&B, (const unsigned char *)b.data) != 0) {
    memset(&res, 0, 32);
    return;
  }
  ge_cached B_cached;
  ge_p3_to_cached(&B_cached, &B);
  ge_p1p1 R;
  ge_sub(&R, &A, &B_cached);
  ge_p2 R_p2;
  ge_p1p1_to_p2(&R_p2, &R);
  ge_tobytes((unsigned char *)res.data, &R_p2);
}

/**
 * debug_carrot_view_tag - Compute Carrot view tag with full debug output
 *
 * This function performs the same computation as scan_csp_batch but outputs
 * all intermediate values for debugging.
 *
 * @param D_e_hex Enote ephemeral pubkey (32 bytes hex) - from tx_pub_key or
 * additional_pubkey
 * @param K_o_hex Onetime address (32 bytes hex) - the output key
 * @param k_vi_hex View-incoming key (32 bytes hex)
 * @param is_coinbase Whether this is a coinbase transaction (affects
 * input_context)
 * @param block_height Block height (for coinbase input_context)
 * @param first_key_image_hex First key image (32 bytes hex, for RingCT
 * input_context)
 * @return JSON with all intermediate values and computed view tag
 */
std::string debug_carrot_view_tag(const std::string &D_e_hex,
                                  const std::string &K_o_hex,
                                  const std::string &k_vi_hex, bool is_coinbase,
                                  uint32_t block_height,
                                  const std::string &first_key_image_hex = "") {
  std::ostringstream oss;
  oss << "{";

  try {
    // Parse D_e (ephemeral pubkey)
    if (D_e_hex.length() != 64) {
      oss << "\"error\":\"D_e must be 64 hex chars\"}";
      return oss.str();
    }
    unsigned char D_e_bytes[32];
    if (!epee::string_tools::hex_to_pod(D_e_hex, D_e_bytes)) {
      oss << "\"error\":\"invalid D_e hex\"}";
      return oss.str();
    }

    // Parse K_o (onetime address)
    if (K_o_hex.length() != 64) {
      oss << "\"error\":\"K_o must be 64 hex chars\"}";
      return oss.str();
    }
    unsigned char K_o_bytes[32];
    if (!epee::string_tools::hex_to_pod(K_o_hex, K_o_bytes)) {
      oss << "\"error\":\"invalid K_o hex\"}";
      return oss.str();
    }

    // Parse k_vi (view-incoming secret key)
    if (k_vi_hex.length() != 64) {
      oss << "\"error\":\"k_vi must be 64 hex chars\"}";
      return oss.str();
    }
    crypto::secret_key k_vi;
    if (!epee::string_tools::hex_to_pod(k_vi_hex, k_vi)) {
      oss << "\"error\":\"invalid k_vi hex\"}";
      return oss.str();
    }

    // Step 1: ECDH to compute s_sr (shared secret)
    // s_sr = k_vi * D_e (X25519 scalar multiplication)
    mx25519_pubkey D_e_mx;
    memcpy(D_e_mx.data, D_e_bytes, 32);

    mx25519_pubkey s_sr;
    bool ecdh_ok = carrot::make_carrot_uncontextualized_shared_key_receiver(
        k_vi, D_e_mx, s_sr);

    std::string s_sr_hex = epee::string_tools::pod_to_hex(s_sr.data);

    if (!ecdh_ok) {
      oss << "\"error\":\"ECDH failed\","
          << "\"inputs\":{\"D_e\":\"" << D_e_hex << "\",\"k_vi\":\"" << k_vi_hex
          << "\"}"
          << "}";
      return oss.str();
    }

    // Step 2: Build input_context
    carrot::input_context_t input_context;
    std::string input_context_type;
    std::string input_context_hex;

    if (is_coinbase) {
      input_context = carrot::make_carrot_input_context_coinbase(block_height);
      input_context_type = "coinbase";
    } else if (first_key_image_hex.length() == 64) {
      crypto::key_image ki;
      if (!epee::string_tools::hex_to_pod(first_key_image_hex, ki)) {
        oss << "\"error\":\"invalid first_key_image hex\"}";
        return oss.str();
      }
      input_context = carrot::make_carrot_input_context(ki);
      input_context_type = "ringct";
    } else {
      oss << "\"error\":\"non-coinbase requires first_key_image\"}";
      return oss.str();
    }

    // Convert input_context to hex (it's a fixed-size structure)
    std::string input_context_bytes(
        reinterpret_cast<const char *>(&input_context), sizeof(input_context));
    input_context_hex =
        epee::string_tools::buff_to_hex_nodelimer(input_context_bytes);

    // Step 3: Compute view tag
    crypto::public_key K_o;
    memcpy(K_o.data, K_o_bytes, 32);

    carrot::view_tag_t view_tag;
    carrot::make_carrot_view_tag(s_sr.data, input_context, K_o, view_tag);

    // Output all values
    oss << "\"success\":true,"
        << "\"inputs\":{"
        << "\"D_e\":\"" << D_e_hex << "\","
        << "\"K_o\":\"" << K_o_hex << "\","
        << "\"k_vi\":\"" << k_vi_hex << "\","
        << "\"is_coinbase\":" << (is_coinbase ? "true" : "false") << ","
        << "\"block_height\":" << block_height << ","
        << "\"first_key_image\":\"" << first_key_image_hex << "\""
        << "},"
        << "\"steps\":{"
        << "\"step1_ecdh\":{\"s_sr\":\"" << s_sr_hex << "\"},"
        << "\"step2_input_context\":{\"type\":\"" << input_context_type
        << "\",\"hex\":\"" << input_context_hex << "\"},"
        << "\"step3_view_tag\":{\"bytes\":[" << (int)view_tag.bytes[0] << ","
        << (int)view_tag.bytes[1] << "," << (int)view_tag.bytes[2] << "]}"
        << "},"
        << "\"computed_view_tag\":[" << (int)view_tag.bytes[0] << ","
        << (int)view_tag.bytes[1] << "," << (int)view_tag.bytes[2] << "]"
        << "}";

  } catch (const std::exception &e) {
    oss << "\"error\":\"" << e.what() << "\"}";
  } catch (...) {
    oss << "\"error\":\"unknown exception\"}";
  }

  return oss.str();
}

/**
 * debug_carrot_internal_view_tag - Compute Carrot INTERNAL enote view tag
 *
 * Internal enotes (change/selfsend) use s_view_balance instead of
 * k_view_incoming for view tag computation: vt = H_3(s_view_balance ||
 * input_context || Ko)
 *
 * @param K_o_hex Onetime address (32 bytes hex) - the output key
 * @param s_view_balance_hex View-balance secret (32 bytes hex)
 * @param first_key_image_hex First key image (32 bytes hex, for RingCT
 * input_context)
 * @return JSON with all intermediate values and computed view tag
 */
std::string
debug_carrot_internal_view_tag(const std::string &K_o_hex,
                               const std::string &s_view_balance_hex,
                               const std::string &first_key_image_hex) {
  std::ostringstream oss;
  oss << "{";

  try {
    // Parse K_o (onetime address)
    if (K_o_hex.length() != 64) {
      oss << "\"error\":\"K_o must be 64 hex chars\"}";
      return oss.str();
    }
    crypto::public_key K_o;
    if (!epee::string_tools::hex_to_pod(K_o_hex, K_o)) {
      oss << "\"error\":\"invalid K_o hex\"}";
      return oss.str();
    }

    // Parse s_view_balance
    if (s_view_balance_hex.length() != 64) {
      oss << "\"error\":\"s_view_balance must be 64 hex chars\"}";
      return oss.str();
    }
    unsigned char s_view_balance[32];
    if (!epee::string_tools::hex_to_pod(s_view_balance_hex, s_view_balance)) {
      oss << "\"error\":\"invalid s_view_balance hex\"}";
      return oss.str();
    }

    // Parse first_key_image for input_context
    if (first_key_image_hex.length() != 64) {
      oss << "\"error\":\"first_key_image must be 64 hex chars\"}";
      return oss.str();
    }
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(first_key_image_hex, ki)) {
      oss << "\"error\":\"invalid first_key_image hex\"}";
      return oss.str();
    }

    // Build input_context from first key image
    carrot::input_context_t input_context =
        carrot::make_carrot_input_context(ki);

    // Convert input_context to hex
    std::string input_context_bytes(
        reinterpret_cast<const char *>(&input_context), sizeof(input_context));
    std::string input_context_hex =
        epee::string_tools::buff_to_hex_nodelimer(input_context_bytes);

    // Compute view tag: H_3(s_view_balance || input_context || Ko)
    carrot::view_tag_t view_tag;
    carrot::make_carrot_view_tag(s_view_balance, input_context, K_o, view_tag);

    // Convert view tag to hex
    char vt_hex[7];
    snprintf(vt_hex, sizeof(vt_hex), "%02x%02x%02x", view_tag.bytes[0],
             view_tag.bytes[1], view_tag.bytes[2]);

    // Output all values
    oss << "\"success\":true,"
        << "\"inputs\":{"
        << "\"K_o\":\"" << K_o_hex << "\","
        << "\"s_view_balance\":\"" << s_view_balance_hex << "\","
        << "\"first_key_image\":\"" << first_key_image_hex << "\""
        << "},"
        << "\"steps\":{"
        << "\"input_context_hex\":\"" << input_context_hex << "\""
        << "},"
        << "\"computed_view_tag\":[" << (int)view_tag.bytes[0] << ","
        << (int)view_tag.bytes[1] << "," << (int)view_tag.bytes[2] << "],"
        << "\"computed_view_tag_hex\":\"" << vt_hex << "\""
        << "}";

  } catch (const std::exception &e) {
    oss << "\"error\":\"" << e.what() << "\"}";
  } catch (...) {
    oss << "\"error\":\"unknown exception\"}";
  }

  return oss.str();
}

/**
 * debug_derive_view_tag - Debug function to compute derivation and view tag
 *
 * @param pubkey_hex Public key to derive from (64 hex chars)
 * @param view_secret_hex View secret key (64 hex chars)
 * @param output_idx Output index for view tag computation
 * @return JSON with derivation and computed view tag
 */
std::string debug_derive_view_tag(const std::string &pubkey_hex,
                                  const std::string &view_secret_hex,
                                  size_t output_idx) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');

  try {
    if (pubkey_hex.length() != 64) {
      return "{\"error\":\"pubkey must be 64 hex chars\"}";
    }
    if (view_secret_hex.length() != 64) {
      return "{\"error\":\"view_secret must be 64 hex chars\"}";
    }

    // Parse pubkey
    unsigned char pubkey[32];
    for (int i = 0; i < 32; i++) {
      pubkey[i] = static_cast<unsigned char>(
          std::stoul(pubkey_hex.substr(i * 2, 2), nullptr, 16));
    }

    // Parse view secret
    unsigned char view_sec[32];
    for (int i = 0; i < 32; i++) {
      view_sec[i] = static_cast<unsigned char>(
          std::stoul(view_secret_hex.substr(i * 2, 2), nullptr, 16));
    }

    // Compute derivation using donna64
    crypto::key_derivation derivation;
    int deriv_result = donna64_generate_key_derivation(
        reinterpret_cast<unsigned char *>(&derivation), pubkey, view_sec);

    oss << "{";
    oss << "\"pubkey\":\"" << pubkey_hex << "\",";
    oss << "\"view_secret\":\"" << view_secret_hex << "\",";
    oss << "\"output_idx\":" << output_idx << ",";
    oss << "\"derivation_ok\":" << (deriv_result == 0 ? "true" : "false")
        << ",";

    // Output derivation as hex
    oss << "\"derivation\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::setw(2)
          << static_cast<int>(
                 reinterpret_cast<unsigned char *>(&derivation)[i]);
    }
    oss << "\",";

    // Compute view tag
    if (deriv_result == 0) {
      // Compute view tag: H("view_tag" || derivation || output_idx)
#pragma pack(push, 1)
      struct {
        char salt[8];
        unsigned char derivation[32];
        char output_index_varint[10];
      } buf;
#pragma pack(pop)

      memcpy(buf.salt, "view_tag", 8);
      memcpy(buf.derivation, &derivation, 32);

      char *varint_end = buf.output_index_varint;
      tools::write_varint(varint_end, output_idx);
      size_t buf_len = 8 + 32 + (varint_end - buf.output_index_varint);

      crypto::hash view_tag_hash;
      crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);
      uint8_t view_tag = view_tag_hash.data[0];

      // Use decimal for view_tag value, hex for view_tag_hex
      oss << "\"view_tag\":" << std::dec << static_cast<int>(view_tag) << ",";
      oss << "\"view_tag_hex\":\"" << std::hex << std::setw(2)
          << static_cast<int>(view_tag) << "\"";
    } else {
      oss << "\"view_tag\":null,\"view_tag_hex\":null";
    }

    oss << "}";
  } catch (const std::exception &e) {
    oss.str("");
    oss << "{\"error\":\"" << e.what() << "\"}";
  }

  return oss.str();
}

/**
 * debug_derive_spend_key - Debug function to derive spend key from output
 *
 * For protocol_tx outputs, this derives what K_spend would be if the output
 * belongs to us. Can be compared against our actual spend pubkey.
 *
 * @param output_key_hex The output's one-time address (Ko, 64 hex chars)
 * @param additional_pubkey_hex The per-output additional pubkey (64 hex chars)
 * @param view_secret_hex View secret key (64 hex chars)
 * @param output_idx Index to use for derivation (0 for protocol_tx)
 * @return JSON with derived spend key
 */
std::string debug_derive_spend_key(const std::string &output_key_hex,
                                   const std::string &additional_pubkey_hex,
                                   const std::string &view_secret_hex,
                                   size_t output_idx) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');

  try {
    if (output_key_hex.length() != 64 || additional_pubkey_hex.length() != 64 ||
        view_secret_hex.length() != 64) {
      return "{\"error\":\"all keys must be 64 hex chars\"}";
    }

    // Parse keys
    crypto::public_key output_key, additional_pubkey;
    crypto::secret_key view_secret;

    if (!epee::string_tools::hex_to_pod(output_key_hex, output_key) ||
        !epee::string_tools::hex_to_pod(additional_pubkey_hex,
                                        additional_pubkey) ||
        !epee::string_tools::hex_to_pod(view_secret_hex, view_secret)) {
      return "{\"error\":\"failed to parse hex keys\"}";
    }

    // Compute derivation: D = 8 * view_secret * additional_pubkey
    crypto::key_derivation derivation;
    bool deriv_ok = crypto::generate_key_derivation(additional_pubkey,
                                                    view_secret, derivation);

    oss << "{";
    oss << "\"output_key\":\"" << output_key_hex << "\",";
    oss << "\"additional_pubkey\":\"" << additional_pubkey_hex << "\",";
    oss << "\"output_idx\":" << std::dec << output_idx << ",";
    oss << "\"derivation_ok\":" << (deriv_ok ? "true" : "false") << ",";

    if (deriv_ok) {
      // Output derivation hex
      oss << "\"derivation\":\"";
      for (int i = 0; i < 32; i++) {
        oss << std::hex << std::setw(2)
            << static_cast<int>(
                   reinterpret_cast<const unsigned char *>(&derivation)[i]);
      }
      oss << "\",";

      // Derive spend key: K_spend = Ko - H(derivation || output_idx) * G
      crypto::public_key derived_spend_key;
      hw::device &hwdev = hw::get_device("default");

      bool derive_ok = hwdev.derive_subaddress_public_key(
          output_key, derivation, output_idx, derived_spend_key);

      oss << "\"derive_ok\":" << (derive_ok ? "true" : "false") << ",";

      if (derive_ok) {
        oss << "\"derived_spend_key\":\"";
        for (int i = 0; i < 32; i++) {
          oss << std::hex << std::setw(2)
              << static_cast<int>(reinterpret_cast<const unsigned char *>(
                     &derived_spend_key)[i]);
        }
        oss << "\",";

        // Check if this equals main spend pubkey (hardcoded for testing)
        const std::string expected_spend =
            "e1ab64dbbae9224a6a71b913ddb26a736b91e4dcd5c98ef163aa3f2966707220";
        crypto::public_key expected_key;
        if (epee::string_tools::hex_to_pod(expected_spend, expected_key)) {
          bool matches = (derived_spend_key == expected_key);
          oss << "\"matches_main_spend\":" << (matches ? "true" : "false");
        } else {
          oss << "\"matches_main_spend\":\"error_parsing_expected\"";
        }
      } else {
        oss << "\"derived_spend_key\":null,\"matches_main_spend\":false";
      }
    } else {
      oss << "\"derivation\":null,\"derive_ok\":false,\"derived_spend_key\":"
             "null,\"matches_main_spend\":false";
    }

    oss << "}";

  } catch (const std::exception &e) {
    oss.str("");
    oss << "{\"error\":\"" << e.what() << "\"}";
  }

  return oss.str();
}

/**
 * scan_csp_batch - Zero-copy CSP buffer scanning
 *
 * @param csp_ptr Pointer to CSP buffer in WASM heap (from
 * allocate_binary_buffer)
 * @param csp_size Size of CSP buffer in bytes
 * @param view_secret_key_hex Wallet's legacy view secret key (64 hex chars)
 * @param k_view_incoming_hex Wallet's Carrot k_view_incoming key (64 hex chars,
 * or empty for legacy-only)
 * @param key_images_hex CSP v6: Comma-separated list of owned key image hashes
 * (64 hex chars each) for spent output detection. Empty string to skip spent
 * detection.
 * @return JSON with matching outputs: {matches: [{tx_idx, out_idx,
 * computed_tag}...], spent: [{tx_idx, block_height, input_idx, key_image}...],
 * stats: {...}}
 *
 * SUPPORTS CSP v1 through v6:
 * - CSP v1 ("CSP\x01"): Legacy 1-byte view tags, 33 bytes per output
 * - CSP v2 ("CSP\x02"): Carrot 3-byte view tags, 37 bytes per output, includes
 * block_height
 * - CSP v3-v5: Enhanced with additional pubkeys and is_coinbase flag
 * - CSP v6 ("CSP\x06"): Adds ALL input key_images for spent output detection
 *
 * NOTE: For Salvium with Carrot transactions, BOTH keys should be provided.
 *       The function will try the legacy key first, then k_view_incoming if no
 * match.
 *
 * v4.2.0-stake-filter: Added stake_return_heights_hex parameter to filter
 * coinbase passthrough. Only coinbase outputs at heights in this set will
 * be passed through (for stake return detection). This eliminates ~65% of
 * false positive coinbase matches that were being sent to Phase 2.
 * Format: comma-separated heights (e.g., "21601,21602,43202")
 */
std::string
scan_csp_batch_impl(uintptr_t csp_ptr, size_t csp_size,
                    const std::string &view_secret_key_hex,
                    const std::string &k_view_incoming_hex,
                    const std::string &s_view_balance_hex,
                    const std::string &key_images_hex = "",
                    const std::string &stake_return_heights_hex = "",
                    const std::string &spend_public_key_hex = "",
                    const std::string &return_addresses_csv = "") {
  auto total_start = std::chrono::high_resolution_clock::now();

  try {
    // Validate inputs
    if (csp_ptr == 0 || csp_size < 12) {
      return "{\"error\":\"invalid CSP buffer\",\"matches\":[],\"spent\":[]}";
    }
    if (view_secret_key_hex.length() != 64) {
      return "{\"error\":\"view_secret_key must be 64 hex "
             "chars\",\"matches\":[],\"spent\":[]}";
    }

    // Parse legacy view secret key
    unsigned char view_sec[32];
    if (!epee::string_tools::hex_to_pod(view_secret_key_hex, view_sec)) {
      return "{\"error\":\"invalid view_secret_key "
             "hex\",\"matches\":[],\"spent\":[]}";
    }

    // Parse Carrot k_view_incoming key (if provided)
    unsigned char k_view_incoming[32] = {0};
    crypto::secret_key carrot_view_secret{};
    bool has_carrot_key = false;
    if (k_view_incoming_hex.length() == 64) {
      if (epee::string_tools::hex_to_pod(k_view_incoming_hex,
                                         k_view_incoming)) {
        has_carrot_key = true;
        memcpy(&carrot_view_secret, k_view_incoming, 32);
      }
    }

    // Parse Carrot s_view_balance secret (if provided) for internal enote tags
    crypto::secret_key carrot_s_view_balance{};
    bool has_carrot_s_view_balance = false;
    if (s_view_balance_hex.length() == 64) {
      unsigned char s_vb[32] = {0};
      if (epee::string_tools::hex_to_pod(s_view_balance_hex, s_vb)) {
        has_carrot_s_view_balance = true;
        memcpy(&carrot_s_view_balance, s_vb, 32);
      }
    }

    // Parse spend public key for ownership verification (Phase 1 Fix)
    crypto::public_key spend_public_key{};
    bool has_spend_key = false;
    if (!spend_public_key_hex.empty()) {
      if (epee::string_tools::hex_to_pod(spend_public_key_hex,
                                         spend_public_key)) {
        has_spend_key = true;
      }
    }

    // CSP v6: Parse key_images for spent detection
    // Format: comma-separated 64-char hex strings (e.g.,
    // "aabb...cc,ddeeff...00")
    std::set<crypto::key_image> owned_key_images;
    if (!key_images_hex.empty()) {
      std::istringstream iss(key_images_hex);
      std::string ki_hex;
      while (std::getline(iss, ki_hex, ',')) {
        if (ki_hex.length() == 64) {
          crypto::key_image ki;
          if (epee::string_tools::hex_to_pod(ki_hex, ki)) {
            owned_key_images.insert(ki);
          }
        }
      }
    }
    bool do_spent_detection = !owned_key_images.empty();

    // v4.2.0: Parse stake return heights for coinbase filtering
    // Format: comma-separated decimal heights (e.g., "21601,21602,43202")
    // If provided, only coinbase outputs at these heights will be passed
    // through
    std::set<uint32_t> stake_return_heights;
    if (!stake_return_heights_hex.empty()) {
      std::istringstream iss(stake_return_heights_hex);
      std::string height_str;
      while (std::getline(iss, height_str, ',')) {
        if (!height_str.empty()) {
          try {
            uint32_t h = static_cast<uint32_t>(std::stoul(height_str));
            stake_return_heights.insert(h);
          } catch (...) {
            // Skip invalid heights
          }
        }
      }
    }
    bool do_stake_filtering = !stake_return_heights.empty();
    size_t coinbase_filtered_by_stake = 0; // Track how many we skipped

    // Parse return addresses for RETURN transaction detection
    // Format: comma-separated 64-char hex public keys (K_r values from
    // return_output_map) When someone sends us a RETURN transaction, the output
    // key will be one of these return addresses. We check output keys directly
    // against this set, bypassing view tag matching (which won't work for return
    // outputs since they use a different key derivation).
    std::set<crypto::public_key> return_addresses;
    if (!return_addresses_csv.empty()) {
      std::istringstream iss(return_addresses_csv);
      std::string pk_hex;
      while (std::getline(iss, pk_hex, ',')) {
        if (pk_hex.length() == 64) {
          crypto::public_key pk;
          if (epee::string_tools::hex_to_pod(pk_hex, pk)) {
            return_addresses.insert(pk);
          }
        }
      }
    }
    bool do_return_address_check = !return_addresses.empty();
    size_t return_address_matches = 0;

    // Get pointer to CSP data
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(csp_ptr);
    const uint8_t *end = ptr + csp_size;

    // ================================================================
    // CORRECT Carrot view tag computation using the actual protocol:
    // For Carrot v1 transactions, tx_pub_key in CSP is actually D_e (enote
    // ephemeral pubkey) which is already in X25519/Montgomery format (NOT
    // Ed25519).
    //
    // Protocol steps:
    // 1. Compute s_sr_unctx via X25519 ECDH: k_view_incoming * D_e
    // 2. Build input_context from coinbase ('C' + height) or RingCT ('R' +
    // key_image)
    // 3. Hash: vt = H_3(s_sr || input_context || Ko)
    // ================================================================

    // We need the current tx_pub_key, block_height, and key_image to compute
    // the view tag These are captured by reference in the lambda
    const unsigned char *current_tx_pub = nullptr;
    uint32_t current_block_height = 0;
    const unsigned char *current_first_key_image =
        nullptr; // CSP v5: For RingCT Carrot

    // Lambda to compute Carrot shared secret for a specific output
    // CRITICAL FIX: For Carrot outputs, D_e in CSP is actually
    // additional_pubkey (per-output), NOT tx_pub_key!
    //
    // Protocol:
    // - Legacy: derivation = H(r * V) where r is from tx_pub_key
    // - Carrot: s_sr = k_view_incoming * D_e where D_e is per-output (in
    // additional_pubkey)
    //
    // The additional_pubkey in CSP contains D_e for Carrot transactions.
    // We MUST use the per-output additional_pubkey, not the transaction's
    // tx_pub_key!
    auto compute_carrot_shared_secret = [&](const unsigned char *D_e_pubkey,
                                            mx25519_pubkey &s_sr_out) -> bool {
      if (!has_carrot_key || D_e_pubkey == nullptr)
        return false;

      // For Carrot outputs, additional_pubkey IS D_e (enote_ephemeral_pubkey)
      // which is ALREADY in X25519 format. No conversion needed!
      mx25519_pubkey D_e;
      memcpy(D_e.data, D_e_pubkey, 32);

      // Use Carrot API for receiver-side ECDH: s_sr = k_view_incoming * D_e
      bool ok = carrot::make_carrot_uncontextualized_shared_key_receiver(
          carrot_view_secret, // k_view_incoming as crypto::secret_key
          D_e,                // D_e (enote_ephemeral_pubkey, already X25519)
          s_sr_out            // Output: s_sr (uncontextualized shared secret)
      );

      return ok;
    };

    // Lambda to compute Carrot view tag using correct protocol
    // CSP v5: Can now filter RingCT outputs using first_key_image
    // CRITICAL: s_sr must be pre-computed using the correct D_e (per-output
    // additional_pubkey)
    auto compute_carrot_view_tag =
        [&](const mx25519_pubkey &s_sr, const unsigned char *onetime_address,
            bool is_coinbase, carrot::view_tag_t &out_tag) -> bool {
      // Build input_context based on transaction type
      carrot::input_context_t input_context;
      if (is_coinbase) {
        // Coinbase: input_context = 'C' || block_height (8 bytes LE)
        input_context =
            carrot::make_carrot_input_context_coinbase(current_block_height);
      } else if (current_first_key_image != nullptr) {
        // CSP v5+: RingCT with first_key_image available
        // input_context = 'R' || first_key_image (32 bytes)
        crypto::key_image ki;
        memcpy(ki.data, current_first_key_image, 32);
        input_context = carrot::make_carrot_input_context(ki);
      } else {
        // CSP v4 or earlier: RingCT but no key_image available
        // Cannot compute view tag - must pass through
        return false;
      }

      // Compute view tag using actual Carrot function
      crypto::public_key Ko;
      memcpy(Ko.data, onetime_address, 32);
      carrot::make_carrot_view_tag(s_sr.data, input_context, Ko, out_tag);

      return true;
    };

    // Detect CSP version from magic header
    if (csp_size < 12 || ptr[0] != 'C' || ptr[1] != 'S' || ptr[2] != 'P') {
      return "{\"error\":\"invalid CSP magic "
             "header\",\"matches\":[],\"spent\":[]}";
    }

    uint8_t csp_version = ptr[3];
    if (csp_version < 0x01 || csp_version > 0x06) {
      return "{\"error\":\"unsupported CSP "
             "version\",\"matches\":[],\"spent\":[]}";
    }

    // Read header
    uint32_t start_height =
        ptr[4] | (ptr[5] << 8) | (ptr[6] << 16) | (ptr[7] << 24);
    uint32_t tx_count =
        ptr[8] | (ptr[9] << 8) | (ptr[10] << 16) | (ptr[11] << 24);
    ptr += 12;

    // Statistics
    size_t total_outputs = 0;
    size_t total_inputs_scanned =
        0; // CSP v6: inputs scanned for spent detection
    size_t spent_outputs_found = 0; // CSP v6: number of our key_images found
    size_t view_tag_matches = 0;
    size_t derivations_computed = 0;
    size_t carrot_outputs_found = 0;
    size_t carrot_matches = 0;
    size_t carrot_coinbase_checked =
        0; // CSP v4+: Coinbase Carrot outputs checked
    size_t carrot_coinbase_matched =
        0; // CSP v4+: Coinbase Carrot outputs that matched
    size_t carrot_ringct_passthrough =
        0; // CSP v4: RingCT Carrot outputs passed through (no key_image)
    size_t carrot_ringct_filtered =
        0; // CSP v5+: RingCT Carrot outputs filtered (has key_image)

    // Matches array (sparse - only store matches)
    // For v2, we include output_type (0=no_tag, 1=tagged_key, 2=carrot_v1)
    // OPTIMIZATION v3.5.12: REMOVED spend_key computation from Phase 1!
    // Phase 1 only needs (tx_idx, out_idx) for Phase 2 to fetch the right TXs.
    // wallet2::process_new_transaction does the full ownership check.
    // This saves ~50% CPU time (2 key derivations + 2 scalar mults per match).
    std::vector<std::tuple<uint32_t, uint16_t, uint8_t, uint8_t>>
        matches; // (tx_idx, out_idx, computed_tag, output_type)

    // CSP v6: Spent outputs array - when our key_images are found in tx inputs
    // (tx_idx, block_height, input_idx, key_image_hex)
    std::vector<std::tuple<uint32_t, uint32_t, uint16_t, std::string>>
        spent_matches;

    // Reserve capacity to avoid reallocations (expect ~0.4% match rate)
    matches.reserve(tx_count * 2 / 256); // ~0.8% headroom

    // Process each transaction using pointer arithmetic
    for (uint32_t tx_idx = 0; tx_idx < tx_count && ptr + 34 <= end; tx_idx++) {
      // Read tx_pub_key (32 bytes) - NO COPY, just pointer
      const unsigned char *tx_pub = ptr;
      ptr += 32;

      // CSP v2+: Read block_height (4 bytes, uint32 LE)
      uint32_t block_height = 0;
      if (csp_version >= 0x02) {
        if (ptr + 4 > end)
          break;
        block_height = ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
        ptr += 4;
      }

      // CSP v4+: Read is_coinbase flag (1 byte)
      // 1 = coinbase (miner_tx/protocol_tx) - can compute Carrot view tag
      // 0 = RingCT (user tx) - needs first_key_image (v5) or passthrough (v4)
      bool is_coinbase = false;
      if (csp_version >= 0x04) {
        if (ptr + 1 > end)
          break;
        is_coinbase = (*ptr != 0);
        ptr += 1;
      }

      // CSP v5: Read first_key_image (32 bytes) for RingCT transactions
      // CSP v6: Read input_count + ALL key_images for spent detection
      // This enables computing Carrot view tags: input_context = 'R' ||
      // first_key_image
      const unsigned char *first_key_image = nullptr;
      if (!is_coinbase) {
        if (csp_version == 0x05) {
          // CSP v5: Only first key_image
          if (ptr + 32 > end)
            break;
          first_key_image = ptr;
          ptr += 32;
        } else if (csp_version >= 0x06) {
          // CSP v6: input_count (2) + all key_images (32 each)
          if (ptr + 2 > end)
            break;
          uint16_t input_count = ptr[0] | (ptr[1] << 8);
          ptr += 2;

          // Check if any input key_image matches our owned key_images
          if (ptr + input_count * 32 > end)
            break;

          for (uint16_t i = 0; i < input_count; i++) {
            const unsigned char *ki_ptr = ptr + i * 32;

            // Use first key_image for Carrot view tag (backward compat with v5)
            if (i == 0) {
              first_key_image = ki_ptr;
            }

            // CSP v6 spent detection: check if this key_image is ours
            if (do_spent_detection) {
              crypto::key_image ki;
              memcpy(ki.data, ki_ptr, 32);
              if (owned_key_images.count(ki) > 0) {
                // Found our key_image! This tx spends one of our outputs
                std::string ki_hex = epee::string_tools::pod_to_hex(ki);
                spent_matches.push_back(
                    std::make_tuple(tx_idx, block_height, i, ki_hex));
                spent_outputs_found++;
              }
            }
            total_inputs_scanned++;
          }

          ptr += input_count * 32; // Skip all key_images
        }
      }

      // Read output_count (2 bytes, uint16 LE)
      if (ptr + 2 > end)
        break;
      uint16_t output_count = ptr[0] | (ptr[1] << 8);
      ptr += 2;

      // Skip if no outputs
      if (output_count == 0)
        continue;

      // ================================================================
      // Set current tx context for Carrot view tag computation
      // ================================================================
      current_tx_pub = tx_pub;
      current_block_height = block_height;
      current_first_key_image =
          first_key_image; // CSP v5+: For RingCT Carrot view tag
      // Note: Carrot shared secret is now computed per-output (using
      // additional_pubkey) so no per-tx reset is needed

      // ================================================================
      // LAZY DERIVATION: Only compute derivation when needed
      // ================================================================

      // Defer derivations - compute on first use
      crypto::key_derivation legacy_derivation, carrot_derivation;
      bool legacy_computed = false, carrot_computed = false;
      bool legacy_ok = false, carrot_ok = false;

      // Helper to compute legacy derivation lazily (Ed25519 scalar mult)
      auto ensure_legacy_derivation = [&]() {
        if (!legacy_computed) {
          legacy_computed = true;
          legacy_ok = donna64_generate_key_derivation(
                          reinterpret_cast<unsigned char *>(&legacy_derivation),
                          tx_pub, view_sec) == 0;
          if (legacy_ok)
            derivations_computed++;
        }
        return legacy_ok;
      };

      // Helper to compute Carrot derivation lazily
      auto ensure_carrot_derivation = [&]() {
        if (!carrot_computed && has_carrot_key) {
          carrot_computed = true;
          carrot_ok = donna64_generate_key_derivation(
                          reinterpret_cast<unsigned char *>(&carrot_derivation),
                          tx_pub, k_view_incoming) == 0;
          if (carrot_ok)
            derivations_computed++;
        }
        return carrot_ok;
      };

      // ================================================================
      // PHASE 1: Parse all outputs and collect additional pubkeys
      // ================================================================
      // FIX v5.1.0: SAL1 SHUFFLE BUG - additional_tx_keys are created
      // pre-shuffle but used post-shuffle, causing view tag / output index
      // mismatch.
      //
      // We need to collect ALL additional pubkeys for the TX, then try ALL
      // combinations of (pubkey, index) to find view tag matches.
      // ================================================================

      struct OutputInfo {
        const unsigned char *output_key;
        uint8_t output_type;
        uint8_t view_tag_bytes[4];
        const unsigned char *additional_pubkey;
      };

      std::vector<OutputInfo> tx_outputs;
      std::vector<const unsigned char *> tx_additional_pubkeys;
      tx_outputs.reserve(output_count);
      tx_additional_pubkeys.reserve(output_count);

      // Helper lambda to compute legacy 1-byte view tag (takes index as param)
      auto compute_legacy_view_tag_at_idx =
          [](const crypto::key_derivation &deriv, size_t idx) -> uint8_t {
#pragma pack(push, 1)
        struct {
          char salt[8];
          unsigned char derivation[32];
          char output_index_varint[10];
        } buf;
#pragma pack(pop)

        memcpy(buf.salt, "view_tag", 8);
        memcpy(buf.derivation, &deriv, 32);

        char *varint_end = buf.output_index_varint;
        tools::write_varint(varint_end, idx);
        size_t buf_len = 8 + 32 + (varint_end - buf.output_index_varint);

        crypto::hash view_tag_hash;
        crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);
        return view_tag_hash.data[0];
      };

      // Parse all outputs first
      for (uint16_t out_idx = 0; out_idx < output_count; out_idx++) {
        // Minimum output size varies by version
        size_t min_output_size = (csp_version >= 0x02) ? 38 : 33;
        if (ptr + min_output_size > end)
          break;

        OutputInfo info;
        info.output_key = ptr;
        ptr += 32;

        info.output_type = 0;
        memset(info.view_tag_bytes, 0, 4);
        info.additional_pubkey = nullptr;

        if (csp_version >= 0x02) {
          info.output_type = *ptr++;
          info.view_tag_bytes[0] = *ptr++;
          info.view_tag_bytes[1] = *ptr++;
          info.view_tag_bytes[2] = *ptr++;
          info.view_tag_bytes[3] = *ptr++;

          if (info.output_type == 2)
            carrot_outputs_found++;

          // CSP v3+: Read additional pubkey if present
          if (csp_version >= 0x03) {
            if (ptr + 1 > end)
              break;
            uint8_t has_additional = *ptr++;
            if (has_additional) {
              if (ptr + 32 > end)
                break;
              info.additional_pubkey = ptr;
              tx_additional_pubkeys.push_back(ptr);
              ptr += 32;
            }
          }
        } else {
          uint8_t stored_tag = *ptr++;
          info.output_type = (stored_tag == 0) ? 0 : 1;
          info.view_tag_bytes[0] = stored_tag;
        }

        tx_outputs.push_back(info);
        total_outputs++;
      }

      // ================================================================
      // PHASE 2: Process outputs and find matches
      // ================================================================
      for (uint16_t out_idx = 0; out_idx < tx_outputs.size(); out_idx++) {
        const auto &output = tx_outputs[out_idx];
        const unsigned char *output_key = output.output_key;
        uint8_t output_type = output.output_type;
        uint8_t view_tag_bytes[4];
        memcpy(view_tag_bytes, output.view_tag_bytes, 4);
        const unsigned char *additional_pubkey = output.additional_pubkey;

        // Wrapper to match old API (uses out_idx from loop)
        auto compute_legacy_view_tag =
            [&compute_legacy_view_tag_at_idx,
             out_idx](const crypto::key_derivation &deriv) -> uint8_t {
          return compute_legacy_view_tag_at_idx(deriv, out_idx);
        };

        bool matched = false;
        uint8_t computed_view_tag = 0;
        // OPTIMIZATION v3.5.12: Removed matching_derivation storage - not
        // needed for Phase 1 Phase 2 fetches full TXs and
        // wallet2::process_new_transaction does ownership check

        // Check if output key matches a known return address (for RETURN tx detection)
        if (do_return_address_check) {
          crypto::public_key output_pk;
          memcpy(output_pk.data, output_key, 32);
          if (return_addresses.count(output_pk) > 0) {
            matched = true;
            return_address_matches++;
          }
        }

        // ================================================================
        // VIEW-TAG-ONLY MATCHING (v6.0.0)
        // ================================================================
        // Phase 1 ONLY computes view tags and compares to stored values.
        // NO ownership verification - Phase 2 handles that correctly
        // via wallet2::process_new_transaction() which uses scanning_tools.
        // This removes ~400 lines of buggy custom ownership logic and
        // ensures 100% parity with CLI wallet transaction detection.
        // ================================================================

        // Skip view tag matching if we already matched via return address check
        if (!matched) {
          if (output_type == 0) {
            // Type-0: No view tag stored
            // Pass through coinbase outputs at stake return heights only
            if (is_coinbase) {
              if (!stake_return_heights.empty()) {
                matched = (stake_return_heights.count(current_block_height) > 0);
              } else {
                matched = true; // No stake filter = pass all coinbase
              }
            }
            // User tx type-0: skip (Phase 2 will catch if truly ours)

          } else if (output_type == 1) {
          // Type-1: Legacy output with 1-byte view tag
          // Compute view tag using available derivations and compare

          // 1) Try additional_pubkey first (most outputs use this)
          if (additional_pubkey) {
            crypto::key_derivation d;
            if (donna64_generate_key_derivation(
                    reinterpret_cast<unsigned char *>(&d), additional_pubkey,
                    view_sec) == 0) {
              derivations_computed++;
              computed_view_tag = compute_legacy_view_tag(d);
              if (computed_view_tag == view_tag_bytes[0]) {
                matched = true;
              }
            }
          }

          // 2) Try main tx_pub_key (for change outputs)
          if (!matched && tx_pub && ensure_legacy_derivation()) {
            computed_view_tag = compute_legacy_view_tag(legacy_derivation);
            if (computed_view_tag == view_tag_bytes[0]) {
              matched = true;
            }
          }

          // 3) Try Carrot k_view_incoming if available (SAL1 edge case)
          if (!matched && has_carrot_key) {
            if (additional_pubkey) {
              crypto::key_derivation d;
              if (donna64_generate_key_derivation(
                      reinterpret_cast<unsigned char *>(&d), additional_pubkey,
                      k_view_incoming) == 0) {
                derivations_computed++;
                computed_view_tag = compute_legacy_view_tag(d);
                if (computed_view_tag == view_tag_bytes[0]) {
                  matched = true;
                }
              }
            }
            if (!matched && tx_pub && ensure_carrot_derivation()) {
              computed_view_tag = compute_legacy_view_tag(carrot_derivation);
              if (computed_view_tag == view_tag_bytes[0]) {
                matched = true;
              }
            }
          }

        } else if (output_type == 2) {
          // Type-2: Carrot output with 3-byte view tag
          const unsigned char *D_e_source =
              additional_pubkey ? additional_pubkey : tx_pub;
          if (D_e_source && has_carrot_key) {
            mx25519_pubkey s_sr;
            if (compute_carrot_shared_secret(D_e_source, s_sr)) {
              carrot::view_tag_t computed_vt{};
              if (compute_carrot_view_tag(s_sr, output_key, is_coinbase,
                                          computed_vt)) {
                derivations_computed++;
                if (computed_vt.bytes[0] == view_tag_bytes[0] &&
                    computed_vt.bytes[1] == view_tag_bytes[1] &&
                    computed_vt.bytes[2] == view_tag_bytes[2]) {
                  matched = true;
                  carrot_matches++;
                }
              } else if (is_coinbase) {
                // Carrot coinbase but view tag computation failed
                if (!stake_return_heights.empty()) {
                  if (stake_return_heights.count(current_block_height) > 0) {
                    matched = true;
                    carrot_matches++;
                  }
                } else {
                  matched = true;
                  carrot_matches++;
                }
              } else {
                // v6.0.1 FIX: RingCT Carrot but view tag computation failed
                // (no first_key_image available in CSP data)
                // Pass through to Phase 2 for full verification via
                // wallet2::process_new_transaction
                matched = true;
                carrot_ringct_passthrough++;
              }
            }
          }
          }
        } // End of if (!matched) - view tag matching

        // Report match
        if (matched) {
          view_tag_matches++;
          // v6.0.0: Simplified - Phase 2 does full ownership verification
          matches.push_back(
              std::make_tuple(tx_idx, out_idx, computed_view_tag, output_type));
        }
      }
    }

    auto total_end = std::chrono::high_resolution_clock::now();
    double total_us =
        std::chrono::duration<double, std::micro>(total_end - total_start)
            .count();

    // Build result JSON
    // v6.0.0: View-tag-only matching - Phase 2 does full ownership verification
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3);
    oss << "{\"matches\":[";
    for (size_t i = 0; i < matches.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << "{\"tx\":" << std::get<0>(matches[i])
          << ",\"out\":" << std::get<1>(matches[i])
          << ",\"tag\":" << static_cast<int>(std::get<2>(matches[i]))
          << ",\"type\":" << static_cast<int>(std::get<3>(matches[i])) << "}";
    }

    // CSP v6: Output spent matches (key_images found in tx inputs)
    // AUTO-APPLY FIX: Directly mark inputs as spent in the global wallet
    // instance This ensures balance is updated even if JS fails to call
    // mark_spent_by_key_images
    if (g_wallet_instance && !spent_matches.empty()) {
      size_t auto_marked = 0;
      for (const auto &match : spent_matches) {
        // match: 0=tx_idx, 1=height, 2=input_idx, 3=key_image_hex
        std::string ki_hex = std::get<3>(match);
        crypto::key_image ki;
        if (epee::string_tools::hex_to_pod(ki_hex, ki)) {
          auto it = g_wallet_instance->m_key_images.find(ki);
          if (it != g_wallet_instance->m_key_images.end()) {
            auto &td = g_wallet_instance->m_transfers[it->second];
            if (!td.m_spent) {
              td.m_spent = true;
              td.m_spent_height = std::get<1>(match);
              auto_marked++;
            }
          }
        }
      }
    }

    oss << "],\"spent\":[";
    for (size_t i = 0; i < spent_matches.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << "{\"tx\":" << std::get<0>(spent_matches[i])
          << ",\"height\":" << std::get<1>(spent_matches[i])
          << ",\"input\":" << std::get<2>(spent_matches[i])
          << ",\"key_image\":\"" << std::get<3>(spent_matches[i]) << "\""
          << "}";
    }

    oss << "],\"stats\":{"
        << "\"csp_version\":" << static_cast<int>(csp_version) << ","
        << "\"start_height\":" << start_height << ","
        << "\"tx_count\":" << tx_count << ","
        << "\"total_outputs\":" << total_outputs << ","
        << "\"total_inputs_scanned\":" << total_inputs_scanned << ","
        << "\"spent_outputs_found\":" << spent_outputs_found << ","
        << "\"owned_key_images_count\":" << owned_key_images.size() << ","
        << "\"carrot_outputs\":" << carrot_outputs_found << ","
        << "\"derivations\":" << derivations_computed << ","
        << "\"view_tag_matches\":" << view_tag_matches << ","
        << "\"return_address_matches\":" << return_address_matches << ","
        << "\"carrot_matches\":" << carrot_matches << ","
        << "\"time_us\":" << total_us << "}}";

    return oss.str();
  } catch (const std::exception &e) {
    return std::string("{\"error\":\"") + e.what() + "\"}";
  }
}

// Wrapper function for embind - embind can't handle default parameters
// v6.0.0: 7-parameter version
std::string scan_csp_batch(uintptr_t csp_ptr, size_t csp_size,
                           const std::string &view_secret_key_hex,
                           const std::string &k_view_incoming_hex,
                           const std::string &s_view_balance_hex,
                           const std::string &key_images_hex,
                           const std::string &spend_public_key_hex) {
  return scan_csp_batch_impl(csp_ptr, csp_size, view_secret_key_hex,
                             k_view_incoming_hex, s_view_balance_hex,
                             key_images_hex, "", spend_public_key_hex);
}

// CSP v6: 5-parameter version with key_images for spent detection
std::string scan_csp_batch_with_spent(uintptr_t csp_ptr, size_t csp_size,
                                      const std::string &view_secret_key_hex,
                                      const std::string &k_view_incoming_hex,
                                      const std::string &s_view_balance_hex,
                                      const std::string &key_images_hex,
                                      const std::string &spend_public_key_hex) {
  return scan_csp_batch_impl(csp_ptr, csp_size, view_secret_key_hex,
                             k_view_incoming_hex, s_view_balance_hex,
                             key_images_hex, "", spend_public_key_hex);
}

// v4.2.0: 6-parameter version with stake return heights for coinbase filtering
std::string scan_csp_batch_with_stake_filter(
    uintptr_t csp_ptr, size_t csp_size, const std::string &view_secret_key_hex,
    const std::string &k_view_incoming_hex, const std::string &key_images_hex,
    const std::string &s_view_balance_hex,
    const std::string &stake_return_heights,
    const std::string &spend_public_key_hex,
    const std::string &return_addresses_csv) {
  return scan_csp_batch_impl(csp_ptr, csp_size, view_secret_key_hex,
                             k_view_incoming_hex, s_view_balance_hex,
                             key_images_hex, stake_return_heights,
                             spend_public_key_hex, return_addresses_csv);
}

/**
 * scan_csp_key_images_only - FAST key-image-only scan for Phase 1b

  crypto::public_key derived_key;
  if (crypto::derive_public_key(carrot_derivation, out_idx, spend_public_key,
                                derived_key) &&
      derived_key == expected_output_key) {
    matched = true;
  }
}
}
}
}
else if (output_type == 1) {
  // Type-1: Has stored view tag - do proper matching
  //
  // CRITICAL FIX v3.5.6: Try BOTH derivation paths
  // ================================================
  // The CLI wallet's is_out_to_acc_precomp tries:
  //   1. Main tx_pub_key derivation
  //   2. additional_derivations[output_index] (if present)
  //
  // When additional pubkeys exist:
  // - Regular outputs use additional_pubkey[output_index]
  // - CHANGE outputs use main tx_pub_key (see device_default.cpp:318)
  //
  // Previous bug: We only tried additional_pubkey when present,
  // missing all change outputs in multi-destination transactions.
  // This caused ~50% of transactions to be missed!
  //
  // OPTIMIZATION v3.5.12: Cache main tx_pub_key derivation
  // per-transaction Strategy: Try additional_pubkey first (most
  // outputs), then fall back to CACHED tx_pub_key derivation (for
  // change outputs)

  crypto::key_derivation derivation;
  bool derivation_matched = false;

  // First, try additional_pubkey if present (for regular outputs)
  if (additional_pubkey) {
    if (donna64_generate_key_derivation(
            reinterpret_cast<unsigned char *>(&derivation), additional_pubkey,
            view_sec) == 0) {
      derivations_computed++;
      computed_view_tag = compute_legacy_view_tag(derivation);

      if (tx_idx % 100 == 0 && out_idx == 0) {
        // debug_log += "Tx " + std::to_string(tx_idx) + " | "; // Too
        // verbose
      }

      if (computed_view_tag == view_tag_bytes[0]) {
        derivation_matched = true;
      }
    }
  }

  // If no match, use CACHED main tx_pub_key derivation (avoid
  // recomputing)
  if (!derivation_matched && tx_pub) {
    ensure_legacy_derivation(); // Uses cached derivation from per-tx
                                // lambda
    if (legacy_ok) {
      bool check_tag = true;
      if (has_spend_key && additional_pubkey) {
        // If we have an additional key, the stored view tag is for
        // it. We cannot check standard derivation against it.
        // Instead, we verify ownership using spend key.
        crypto::public_key derived_key;
        if (crypto::derive_public_key(legacy_derivation, out_idx,
                                      spend_public_key, derived_key)) {
          if (derived_key ==
              *reinterpret_cast<const crypto::public_key *>(output_key)) {
            derivation_matched = true;
            check_tag = false;
          }
        }
      }

      if (check_tag && !derivation_matched) {
        computed_view_tag = compute_legacy_view_tag(legacy_derivation);
        if (computed_view_tag == view_tag_bytes[0]) {
          derivation_matched = true;
        }
      }
    }
  }

  // Fallback 2: Try CARROT derivation using tx_pub_key (SAL1 Fix)
  if (!derivation_matched && tx_pub && has_carrot_key) {
    crypto::key_derivation carrot_derivation;
    if (donna64_generate_key_derivation(
            reinterpret_cast<unsigned char *>(&carrot_derivation), tx_pub,
            k_view_incoming) == 0) {

      bool check_tag = true;
      if (has_spend_key && additional_pubkey) {
        crypto::public_key derived_key;
        if (crypto::derive_public_key(carrot_derivation, out_idx,
                                      spend_public_key, derived_key)) {
          if (derived_key ==
              *reinterpret_cast<const crypto::public_key *>(output_key)) {
            derivation_matched = true;
            check_tag = false;
          }
        }
      }

      if (check_tag && !derivation_matched) {
        // SAL1 Type-1 uses Carrot Secret but Legacy Tag (Index-based)
        computed_view_tag = compute_legacy_view_tag(carrot_derivation);

        if (computed_view_tag == view_tag_bytes[0]) {
          derivation_matched = true;
        }
      }
    }
  }

  // ================================================================
  // SAL1 SHUFFLE FIX v5.1.0: Brute-force (pubkey, index) matching
  // ================================================================
  // additional_tx_keys are created PRE-shuffle but used POST-shuffle
  // during TX construction. This causes view tags to be computed with
  // mismatched (pubkey, index) pairs.
  //
  // Example: Output 0's view tag might have been computed using
  // additional_tx_keys[5] at index 3 (due to shuffle), but the CSP
  // stores additional_tx_pub_keys[0] for output 0.
  //
  // Solution: Try ALL collected additional_pubkeys with ALL indices
  // to find a view tag match. This is O(N??) but necessary.
  // ================================================================
  if (!derivation_matched && !tx_additional_pubkeys.empty()) {
    // Try all (pubkey, index) combinations
    for (size_t pk_idx = 0;
         pk_idx < tx_additional_pubkeys.size() && !derivation_matched;
         pk_idx++) {
      const unsigned char *test_pubkey = tx_additional_pubkeys[pk_idx];
      crypto::key_derivation test_derivation;

      if (donna64_generate_key_derivation(
              reinterpret_cast<unsigned char *>(&test_derivation), test_pubkey,
              view_sec) == 0) {
        derivations_computed++;

        // Try all indices
        for (size_t test_idx = 0;
             test_idx < tx_outputs.size() && !derivation_matched; test_idx++) {
          uint8_t test_tag =
              compute_legacy_view_tag_at_idx(test_derivation, test_idx);
          if (test_tag == view_tag_bytes[0]) {
            derivation_matched = true;
            computed_view_tag = test_tag;
          }
        }
      }
    }

    // Also try with Carrot k_view_incoming key if available
    if (!derivation_matched && has_carrot_key) {
      for (size_t pk_idx = 0;
           pk_idx < tx_additional_pubkeys.size() && !derivation_matched;
           pk_idx++) {
        const unsigned char *test_pubkey = tx_additional_pubkeys[pk_idx];
        crypto::key_derivation test_derivation;

        if (donna64_generate_key_derivation(
                reinterpret_cast<unsigned char *>(&test_derivation),
                test_pubkey, k_view_incoming) == 0) {
          derivations_computed++;

          for (size_t test_idx = 0;
               test_idx < tx_outputs.size() && !derivation_matched;
               test_idx++) {
            uint8_t test_tag =
                compute_legacy_view_tag_at_idx(test_derivation, test_idx);
            if (test_tag == view_tag_bytes[0]) {
              derivation_matched = true;
              computed_view_tag = test_tag;
            }
          }
        }
      }
    }
  }

  if (derivation_matched) {
    matched = true;
    // OPTIMIZATION v3.5.12: Don't store derivation - Phase 2 will
    // recompute
  }
}
}
else if (output_type == 2) {
  // ================================================================
  // CARROT OUTPUT FILTERING - CRITICAL FIX v3.4.1
  // ================================================================
  // The Carrot view tag is: vt = H_3(s_sr || input_context || Ko)
  // where s_sr = ECDH(k_view_incoming, D_e) is INDEPENDENT of
  // input_context
  //
  // KEY INSIGHT: We can ALWAYS compute s_sr from CSP data!
  // The input_context only affects the final hash, not the shared
  // secret.
  //
  // For CSP v3 (no is_coinbase flag), we use coinbase context as a
  // FILTER:
  // - Compute view tag with coinbase context
  // - If it matches: MIGHT be ours (coinbase) or might be RingCT with
  // same s_sr
  // - If it doesn't match: Check if s_sr is valid (ECDH succeeded)
  //   - If ECDH failed: definitely not ours
  //   - If ECDH succeeded but tag doesn't match: could still be RingCT
  //
  // HOWEVER: The probability of a random tag matching is 1/2^24 (3
  // bytes) So we can use coinbase context as a PROBABILISTIC filter
  // even for RingCT!
  //
  // Strategy for ALL Carrot outputs (CSP v3 and v4):
  // 1. Compute shared secret s_sr via ECDH
  // 2. Compute view tag with coinbase context
  // 3. If tag matches: it's ours (either coinbase or RingCT with
  // matching tag)
  // 4. If tag doesn't match: NOT ours (view tag is deterministic for
  // our wallet)
  //
  // This works because: if an output is ours, we WILL compute the
  // correct s_sr, and with the correct s_sr, only one input_context
  // will produce the stored tag. Since we don't know the input_context,
  // we try coinbase - if it matches, great! If not, we need to pass it
  // through... BUT WAIT:
  //
  // ACTUALLY: The view tag in the output was computed by the SENDER
  // with the CORRECT input_context. If we compute with WRONG context,
  // we get WRONG tag. So we CANNOT filter RingCT outputs by coinbase
  // context!
  //
  // FINAL SOLUTION: For CSP v3/v4 without is_coinbase:
  // - Try coinbase context first (covers miner_tx, protocol_tx)
  // - If no match, we MUST pass through to wallet2 for RingCT
  // verification
  // - BUT: First verify ECDH succeeds (if not, definitely not ours)
  //
  // CRITICAL FIX (v3.5.1): D_e source depends on tx structure:
  // - If additional_pubkey present: Use it as D_e (per-output
  // ephemeral)
  // - If NO additional_pubkey: Use tx_pub_key as D_e (SHARED ephemeral)
  //
  // This matches wallet scanning_tools.cpp line 658-660:
  //   enote_ephemeral_pubkeys_pk = main_tx_ephemeral_pubkeys.empty()
  //       ? additional_tx_ephemeral_pubkeys
  //       : main_tx_ephemeral_pubkeys;
  // ================================================================

  if (has_carrot_key) {
    // Determine D_e source: per-output additional_pubkey OR shared
    // tx_pub_key For most Carrot txs, tx_pub_key IS D_e (shared across
    // all outputs)
    const unsigned char *D_e_source =
        additional_pubkey ? additional_pubkey : tx_pub;

    // Step 1: Compute shared secret via ECDH using D_e
    mx25519_pubkey s_sr;
    bool ecdh_ok = compute_carrot_shared_secret(D_e_source, s_sr);

    if (!ecdh_ok) {
      // ECDH failed - this output is definitely not ours
      // (invalid point or key mismatch)
      matched = false;
    } else {
      // ECDH succeeded - we have valid s_sr
      // Step 2: Compute view tag with proper input_context
      // CSP v5: We have first_key_image for RingCT, can filter
      // properly!
      carrot::view_tag_t computed_vt{};
      bool vt_ok =
          compute_carrot_view_tag(s_sr, output_key, is_coinbase, computed_vt);

      if (vt_ok) {
        derivations_computed++;

        if (computed_vt.bytes[0] == view_tag_bytes[0] &&
            computed_vt.bytes[1] == view_tag_bytes[1] &&
            computed_vt.bytes[2] == view_tag_bytes[2]) {
          // View tag MATCHES - this output is ours!
          // CSP v5: Both coinbase and RingCT can be properly verified
          matched = true;
          carrot_matches++;
          if (is_coinbase) {
            carrot_coinbase_matched++;
          } else {
            carrot_ringct_filtered++;
          }
          computed_view_tag = computed_vt.bytes[0];
        } else if (is_coinbase) {
          // CRITICAL FIX v3.5.16: STAKE RETURN outputs in protocol_tx
          // ============================================================
          // View tag doesn't match for coinbase, BUT this could still
          // be a STAKE RETURN output! Stake returns are in protocol_tx
          // (is_coinbase=true) but their view tags were computed with
          // the ORIGINAL STAKE transaction's input_context, NOT the
          // coinbase context we used here.
          //
          // v4.2.0-stake-filter: Only pass through if this height is
          // in stake_return_heights (i.e., a stake return is expected
          // here). This eliminates ~65% of false positive coinbase
          // passthrough.
          // ============================================================
          if (!do_stake_filtering ||
              stake_return_heights.count(current_block_height) > 0) {
            matched = true;
            carrot_matches++;
            carrot_coinbase_checked++; // Track passthrough for stats
            computed_view_tag = view_tag_bytes[0]; // Use stored tag
          } else {
            // Height not in stake return heights - skip this coinbase
            // output
            matched = false;
            coinbase_filtered_by_stake++;
          }
        } else {
          // View tag doesn't match for RingCT.
          // Fallback for INTERNAL enotes (change/selfsend):
          // vt = H_3(s_view_balance || input_context || Ko)
          if (has_carrot_s_view_balance && current_first_key_image != nullptr) {
            carrot::input_context_t input_context;
            crypto::key_image ki;
            memcpy(ki.data, current_first_key_image, 32);
            input_context = carrot::make_carrot_input_context(ki);

            carrot::view_tag_t internal_vt{};
            crypto::public_key Ko;
            memcpy(Ko.data, output_key, 32);
            carrot::make_carrot_view_tag(
                reinterpret_cast<const unsigned char *>(
                    carrot_s_view_balance.data),
                input_context, Ko, internal_vt);

            if (internal_vt.bytes[0] == view_tag_bytes[0] &&
                internal_vt.bytes[1] == view_tag_bytes[1] &&
                internal_vt.bytes[2] == view_tag_bytes[2]) {
              matched = true;
              carrot_matches++;
              carrot_ringct_filtered++;
              computed_view_tag = internal_vt.bytes[0];
            } else {
              matched = false;
            }
          } else {
            // CSP v5: We have proper input_context for RingCT,
            // so non-matching means definitively not ours
            matched = false;
          }
        }
      } else {
        // View tag computation failed
        // This happens for CSP v4 or earlier with RingCT (no
        // first_key_image) In that case we MUST pass through to wallet2
        if (!is_coinbase && current_first_key_image == nullptr) {
          // CSP v4 or earlier RingCT - no key_image, must pass through
          matched = true;
          carrot_matches++;
          carrot_ringct_passthrough++;
          computed_view_tag = view_tag_bytes[0];
        } else if (is_coinbase) {
          // Coinbase output but view tag computation failed
          // v4.2.0-stake-filter: Only pass through at stake return
          // heights
          if (!do_stake_filtering ||
              stake_return_heights.count(current_block_height) > 0) {
            matched = true;
            carrot_matches++;
            carrot_coinbase_checked++;
            computed_view_tag = view_tag_bytes[0];
          } else {
            matched = false;
            coinbase_filtered_by_stake++;
          }
        } else {
          // Some other failure for RingCT - skip this output
          matched = false;
        }
      }
    }
  }
}

// Report match
if (matched) {
  view_tag_matches++;
  // OPTIMIZATION v3.5.12: Skip spend_key computation in Phase 1!
  // Phase 1 only needs tx_idx and out_idx for Phase 2 sparse fetch.
  // wallet2::process_new_transaction handles full ownership
  // verification. This saves ~2 scalar mults + 2 key derivations per
  // match.
  matches.push_back(
      std::make_tuple(tx_idx, out_idx, computed_view_tag, output_type));
}
}
}

auto total_end = std::chrono::high_resolution_clock::now();
double total_us =
    std::chrono::duration<double, std::micro>(total_end - total_start).count();

// Build result JSON
// OPTIMIZATION v3.5.12: Simplified match format (no spend_key computation)
// CSP v6 (4.0.0): Added "spent" array for spent output detection
std::ostringstream oss;
oss << std::fixed << std::setprecision(3);
oss << "{\"matches\":[";
for (size_t i = 0; i < matches.size(); i++) {
  if (i > 0)
    oss << ",";
  // Simplified: only tx/out/tag/type - Phase 2 does full ownership check
  oss << "{\"tx\":" << std::get<0>(matches[i])
      << ",\"out\":" << std::get<1>(matches[i])
      << ",\"tag\":" << static_cast<int>(std::get<2>(matches[i]))
      << ",\"type\":" << static_cast<int>(std::get<3>(matches[i])) << "}";
}

// CSP v6: Output spent matches (our key_images found in tx inputs)
oss << "],\"spent\":[";
for (size_t i = 0; i < spent_matches.size(); i++) {
  if (i > 0)
    oss << ",";
  oss << "{\"tx\":" << std::get<0>(spent_matches[i])
      << ",\"height\":" << std::get<1>(spent_matches[i])
      << ",\"input\":" << std::get<2>(spent_matches[i]) << ",\"key_image\":\""
      << std::get<3>(spent_matches[i]) << "\""
      << "}";
}

oss << "],\"stats\":{"
    << "\"csp_version\":" << static_cast<int>(csp_version) << ","
    << "\"start_height\":" << start_height << ","
    << "\"tx_count\":" << tx_count << ","
    << "\"total_outputs\":" << total_outputs << ","
    << "\"total_inputs_scanned\":" << total_inputs_scanned << ","      // CSP v6
    << "\"spent_outputs_found\":" << spent_outputs_found << ","        // CSP v6
    << "\"owned_key_images_count\":" << owned_key_images.size() << "," // CSP v6
    << "\"carrot_outputs\":" << carrot_outputs_found << ","
    << "\"derivations\":" << derivations_computed << ","
    << "\"view_tag_matches\":" << view_tag_matches << ","
    << "\"carrot_matches\":" << carrot_matches << ","
    << "\"carrot_coinbase_checked\":" << carrot_coinbase_checked << ","
    << "\"carrot_coinbase_matched\":" << carrot_coinbase_matched << ","
    << "\"carrot_ringct_passthrough\":" << carrot_ringct_passthrough << ","
    << "\"carrot_ringct_filtered\":" << carrot_ringct_filtered << ","
    << "\"coinbase_filtered_by_stake\":" << coinbase_filtered_by_stake
    << "," // v4.2.0
    << "\"stake_return_heights_count\":" << stake_return_heights.size()
    << "," // v4.2.0
    << "\"has_carrot_key\":" << (has_carrot_key ? "true" : "false") << ","
    << "\"total_us\":" << total_us << ","
    << "\"us_per_tx\":" << (tx_count > 0 ? total_us / tx_count : 0) << ","
    << "\"us_per_output\":"
    << (total_outputs > 0 ? total_us / total_outputs : 0)
    << "},\"success\":true}";

return oss.str();
}
catch (const std::exception &e) {
  return "{\"error\":\"" + std::string(e.what()) +
         "\",\"matches\":[],\"spent\":[]}";
}
catch (...) {
  return "{\"error\":\"unknown exception\",\"matches\":[],\"spent\":[]}";
}
}

// Wrapper function for embind - embind can't handle default parameters
// 4-parameter version for backward compatibility
std::string scan_csp_batch(uintptr_t csp_ptr, size_t csp_size,
                           const std::string &view_secret_key_hex,
                           const std::string &k_view_incoming_hex,
                           const std::string &s_view_balance_hex,
                           const std::string &key_images_hex,
                           const std::string &spend_public_key_hex) {
  return scan_csp_batch_impl(csp_ptr, csp_size, view_secret_key_hex,
                             k_view_incoming_hex, s_view_balance_hex,
                             key_images_hex, "", spend_public_key_hex);
}

// CSP v6: 5-parameter version with key_images for spent detection
std::string scan_csp_batch_with_spent(uintptr_t csp_ptr, size_t csp_size,
                                      const std::string &view_secret_key_hex,
                                      const std::string &k_view_incoming_hex,
                                      const std::string &s_view_balance_hex,
                                      const std::string &key_images_hex,
                                      const std::string &spend_public_key_hex) {
  return scan_csp_batch_impl(csp_ptr, csp_size, view_secret_key_hex,
                             k_view_incoming_hex, s_view_balance_hex,
                             key_images_hex, "", spend_public_key_hex);
}

// v4.2.0: 6-parameter version with stake return heights for coinbase filtering
// stake_return_heights: comma-separated decimal heights (e.g.,
// "21601,21602,43202") Only coinbase outputs at these heights will be passed
// through for Phase 2 check
std::string scan_csp_batch_with_stake_filter(
    uintptr_t csp_ptr, size_t csp_size, const std::string &view_secret_key_hex,
    const std::string &k_view_incoming_hex, const std::string &key_images_hex,
    const std::string &s_view_balance_hex,
    const std::string &stake_return_heights,
    const std::string &spend_public_key_hex,
    const std::string &return_addresses_csv) {
  return scan_csp_batch_impl(csp_ptr, csp_size, view_secret_key_hex,
                             k_view_incoming_hex, s_view_balance_hex,
                             key_images_hex, stake_return_heights,
                             spend_public_key_hex, return_addresses_csv);
}

/**
 * scan_csp_key_images_only - FAST key-image-only scan for Phase 1b
 *
 * This function is ~10x faster than scan_csp_batch because it:
 * 1. ONLY scans transaction inputs for key images
 * 2. SKIPS all output processing (no derivations, no view tags)
 * 3. Returns ONLY spent output matches
 *
 * Use this for Phase 1b spent detection after Phase 1+2 have already
 * found all incoming outputs and computed their key images.
 *
 * @param csp_ptr Pointer to CSP buffer in WASM heap
 * @param csp_size Size of CSP buffer
 * @param key_images_csv Comma-separated 64-char hex key images (our outputs)
 * @return JSON:
 * {"spent":[{tx_idx,block_height,input_idx,key_image}],"inputs_scanned":N,"spent_found":N}
 */
std::string scan_csp_key_images_only(uintptr_t csp_ptr, size_t csp_size,
                                     const std::string &key_images_csv) {
  auto start_time = std::chrono::high_resolution_clock::now();

  try {
    if (csp_ptr == 0 || csp_size < 12) {
      return "{\"error\":\"invalid CSP buffer\",\"spent\":[]}";
    }

    // Parse key images into a set for O(log n) lookup
    std::set<crypto::key_image> owned_key_images;
    if (!key_images_csv.empty()) {
      std::istringstream iss(key_images_csv);
      std::string ki_hex;
      while (std::getline(iss, ki_hex, ',')) {
        if (ki_hex.length() == 64) {
          crypto::key_image ki;
          if (epee::string_tools::hex_to_pod(ki_hex, ki)) {
            owned_key_images.insert(ki);
          }
        }
      }
    }

    if (owned_key_images.empty()) {
      return "{\"error\":\"no key images provided\",\"spent\":[]}";
    }

    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(csp_ptr);
    const uint8_t *end = ptr + csp_size;

    // Parse CSP header - same format as scan_csp_batch_impl
    // Bytes 0-2: "CSP" magic, Byte 3: version, Bytes 4-7: start_height, Bytes
    // 8-11: tx_count
    if (ptr[0] != 'C' || ptr[1] != 'S' || ptr[2] != 'P') {
      return "{\"error\":\"invalid CSP magic header\",\"spent\":[]}";
    }

    uint8_t csp_version = ptr[3];
    if (csp_version < 6) {
      return "{\"error\":\"CSP v6+ required for key image scan\",\"spent\":[]}";
    }

    // Skip start_height (bytes 4-7) and read tx_count (bytes 8-11)
    uint32_t tx_count =
        ptr[8] | (ptr[9] << 8) | (ptr[10] << 16) | (ptr[11] << 24);
    ptr += 12; // Skip full header

    // Results
    std::vector<std::tuple<uint32_t, uint32_t, uint16_t, std::string>>
        spent_matches;
    size_t inputs_scanned = 0;

    // Process each transaction - ONLY parse inputs, skip outputs entirely
    for (uint32_t tx_idx = 0; tx_idx < tx_count && ptr < end; tx_idx++) {
      // Skip tx_pub_key (32 bytes)
      if (ptr + 32 > end)
        break;
      ptr += 32;

      // Read block_height (4 bytes)
      if (ptr + 4 > end)
        break;
      uint32_t block_height =
          ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
      ptr += 4;

      // Read is_coinbase (1 byte)
      if (ptr + 1 > end)
        break;
      bool is_coinbase = (*ptr != 0);
      ptr += 1;

      // For non-coinbase, read input_count + key_images
      if (!is_coinbase) {
        if (ptr + 2 > end)
          break;
        uint16_t input_count = ptr[0] | (ptr[1] << 8);
        ptr += 2;

        if (ptr + input_count * 32 > end)
          break;

        // Check each input key image against our set
        for (uint16_t i = 0; i < input_count; i++) {
          const uint8_t *ki_ptr = ptr + i * 32;
          crypto::key_image ki;
          memcpy(ki.data, ki_ptr, 32);

          if (owned_key_images.count(ki) > 0) {
            std::string ki_hex = epee::string_tools::pod_to_hex(ki);
            spent_matches.push_back(
                std::make_tuple(tx_idx, block_height, i, ki_hex));
          }
          inputs_scanned++;
        }

        ptr += input_count * 32;
      }

      // Skip output_count (2 bytes) and ALL outputs
      if (ptr + 2 > end)
        break;
      uint16_t output_count = ptr[0] | (ptr[1] << 8);
      ptr += 2;

      // Skip outputs based on CSP version
      for (uint16_t o = 0; o < output_count && ptr < end; o++) {
        // output_type (1 byte)
        if (ptr + 1 > end)
          break;
        uint8_t output_type = *ptr++;

        // output_key (32 bytes)
        if (ptr + 32 > end)
          break;
        ptr += 32;

        // view_tag (1-4 bytes depending on type)
        if (output_type == 0) {
          // Legacy no-tag: no view tag bytes
        } else if (output_type == 1) {
          // Legacy tagged: 1 byte view tag
          if (ptr + 1 > end)
            break;
          ptr += 1;
        } else if (output_type == 2) {
          // Carrot: 4 byte view tag
          if (ptr + 4 > end)
            break;
          ptr += 4;
        }

        // additional_pubkey (32 bytes if present)
        if (output_type == 1 || output_type == 2) {
          if (ptr + 32 > end)
            break;
          ptr += 32;
        }
      }
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::high_resolution_clock::now() - start_time)
                       .count();

    // Build JSON result
    std::ostringstream oss;
    oss << "{\"spent\":[";
    for (size_t i = 0; i < spent_matches.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << "{\"tx_idx\":" << std::get<0>(spent_matches[i])
          << ",\"block_height\":" << std::get<1>(spent_matches[i])
          << ",\"input_idx\":" << std::get<2>(spent_matches[i])
          << ",\"key_image\":\"" << std::get<3>(spent_matches[i]) << "\"}";
    }
    oss << "],\"inputs_scanned\":" << inputs_scanned
        << ",\"spent_found\":" << spent_matches.size()
        << ",\"elapsed_ms\":" << elapsed
        << ",\"key_images_count\":" << owned_key_images.size() << "}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\",\"spent\":[]}";
  } catch (...) {
    return "{\"error\":\"unknown exception\",\"spent\":[]}";
  }
}

/**
 * scan_csp_with_ownership - CSP scanning with FULL ownership verification
 *
 * This function performs view tag matching AND ownership verification by:
 * 1. Parsing the subaddress map CSV (from get_subaddress_spend_keys_csv())
 * 2. For each view tag match, computing derive_subaddress_public_key()
 * 3. Looking up the derived spend key in the subaddress map
 * 4. Only returning outputs that are VERIFIED to belong to the wallet
 *
 * This reduces Phase 1 matches from ~28K (view tag only) to ~3K (verified),
 * cutting Phase 2A fetch time by 89% (128s -> 14s).
 *
 * @param csp_ptr Pointer to CSP buffer in WASM heap
 * @param csp_size Size of CSP buffer
 * @param view_secret_key_hex Legacy view secret key (64 hex)
 * @param k_view_incoming_hex Carrot k_view_incoming key (64 hex, or empty)
 * @param subaddress_map_csv Subaddress map in CSV format:
 * "pubkey:major:minor:derive_type,..."
 * @param stake_return_heights_hex Stake return heights for coinbase filtering
 * @return JSON with verified matches only
 */
static std::string scan_csp_with_ownership_impl(
    uintptr_t csp_ptr, size_t csp_size, const std::string &view_secret_key_hex,
    const std::string &k_view_incoming_hex,
    const std::string &s_view_balance_hex,
    const std::string &subaddress_map_csv, const std::string &key_images_hex,
    const std::string &stake_return_heights_hex,
    const std::string &return_addresses_csv = "") {

  auto total_start = std::chrono::high_resolution_clock::now();

  try {
    // Validate inputs
    if (csp_ptr == 0 || csp_size < 12) {
      return R"({"error":"invalid CSP buffer","matches":[]})";
    }
    if (view_secret_key_hex.length() != 64) {
      return R"({"error":"view_secret_key must be 64 hex chars","matches":[]})";
    }
    if (subaddress_map_csv.empty()) {
      return R"({"error":"subaddress_map_csv is required","matches":[]})";
    }

    // Parse view secret key
    unsigned char view_sec[32];
    if (!epee::string_tools::hex_to_pod(view_secret_key_hex, view_sec)) {
      return R"({"error":"invalid view_secret_key hex","matches":[]})";
    }
    crypto::secret_key view_secret_key;
    memcpy(&view_secret_key, view_sec, 32);

    // Parse Carrot k_view_incoming key if provided
    crypto::secret_key carrot_view_secret{};
    bool has_carrot_key = false;
    unsigned char carrot_view_sec[32] = {0};
    if (k_view_incoming_hex.length() == 64) {
      unsigned char k_view[32];
      if (epee::string_tools::hex_to_pod(k_view_incoming_hex, k_view)) {
        has_carrot_key = true;
        memcpy(&carrot_view_secret, k_view, 32);
        memcpy(carrot_view_sec, k_view, 32);
      }
    }

    // Parse Carrot s_view_balance secret if provided (for internal enotes)
    crypto::secret_key carrot_s_view_balance{};
    bool has_carrot_s_view_balance = false;
    if (s_view_balance_hex.length() == 64) {
      unsigned char s_vb[32];
      if (epee::string_tools::hex_to_pod(s_view_balance_hex, s_vb)) {
        has_carrot_s_view_balance = true;
        memcpy(&carrot_s_view_balance, s_vb, 32);
      }
    }

    // Parse subaddress map CSV: "pubkey:major:minor:derive_type,..."
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index>
        subaddress_map;
    {
      size_t pos = 0;
      size_t count = 0;
      while (pos < subaddress_map_csv.size()) {
        size_t end = subaddress_map_csv.find(',', pos);
        if (end == std::string::npos)
          end = subaddress_map_csv.size();

        std::string entry = subaddress_map_csv.substr(pos, end - pos);
        pos = end + 1;

        // Parse "pubkey:major:minor:derive_type"
        size_t c1 = entry.find(':');
        size_t c2 = (c1 != std::string::npos) ? entry.find(':', c1 + 1)
                                              : std::string::npos;
        size_t c3 = (c2 != std::string::npos) ? entry.find(':', c2 + 1)
                                              : std::string::npos;

        if (c1 == std::string::npos || c2 == std::string::npos)
          continue;

        std::string key_hex = entry.substr(0, c1);
        if (key_hex.length() != 64)
          continue;

        crypto::public_key pkey;
        if (!epee::string_tools::hex_to_pod(key_hex, pkey))
          continue;

        uint32_t major = std::stoul(entry.substr(c1 + 1, c2 - c1 - 1));
        uint32_t minor = std::stoul(entry.substr(
            c2 + 1,
            (c3 != std::string::npos ? c3 - c2 - 1 : std::string::npos)));

        subaddress_map[pkey] = {major, minor};
        count++;
      }

      if (count == 0) {
        return R"({"error":"failed to parse subaddress_map_csv","matches":[]})";
      }
    }

    // Parse stake return heights for coinbase filtering
    std::set<uint32_t> stake_return_heights;
    if (!stake_return_heights_hex.empty()) {
      size_t pos = 0;
      while (pos < stake_return_heights_hex.size()) {
        size_t end = stake_return_heights_hex.find(',', pos);
        if (end == std::string::npos)
          end = stake_return_heights_hex.size();
        std::string h = stake_return_heights_hex.substr(pos, end - pos);
        pos = end + 1;
        if (!h.empty()) {
          stake_return_heights.insert(std::stoul(h));
        }
      }
    }

    // CSP v6: Parse key images CSV for spent detection
    struct key_image_less {
      bool operator()(const crypto::key_image &a,
                      const crypto::key_image &b) const {
        return memcmp(a.data, b.data, 32) < 0;
      }
    };
    std::set<crypto::key_image, key_image_less> key_images;
    if (!key_images_hex.empty()) {
      size_t pos = 0;
      while (pos < key_images_hex.size()) {
        size_t end = key_images_hex.find(',', pos);
        if (end == std::string::npos)
          end = key_images_hex.size();
        std::string h = key_images_hex.substr(pos, end - pos);
        pos = end + 1;
        if (h.empty())
          continue;
        if (h.size() != 64)
          continue;
        crypto::key_image ki;
        if (epee::string_tools::hex_to_pod(h, ki)) {
          key_images.insert(ki);
        }
      }
    }

    // Parse return addresses for RETURN transaction detection
    // Format: comma-separated 64-char hex public keys (K_r values from
    // return_output_map)
    std::set<crypto::public_key> return_addresses;
    if (!return_addresses_csv.empty()) {
      std::istringstream iss(return_addresses_csv);
      std::string pk_hex;
      while (std::getline(iss, pk_hex, ',')) {
        if (pk_hex.length() == 64) {
          crypto::public_key pk;
          if (epee::string_tools::hex_to_pod(pk_hex, pk)) {
            return_addresses.insert(pk);
          }
        }
      }
    }
    bool do_return_address_check = !return_addresses.empty();
    size_t return_address_matches = 0;

    // Parse CSP buffer
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(csp_ptr);
    const uint8_t *end = ptr + csp_size;

    // Verify CSP magic and version
    if (ptr[0] != 'C' || ptr[1] != 'S' || ptr[2] != 'P') {
      return R"({"error":"invalid CSP magic","matches":[]})";
    }
    uint8_t csp_version = ptr[3];
    if (csp_version < 0x01 || csp_version > 0x06) {
      return R"({"error":"unsupported CSP version","matches":[]})";
    }

    uint32_t start_height =
        ptr[4] | (ptr[5] << 8) | (ptr[6] << 16) | (ptr[7] << 24);
    uint32_t tx_count =
        ptr[8] | (ptr[9] << 8) | (ptr[10] << 16) | (ptr[11] << 24);
    ptr += 12;

    // Stats
    size_t total_outputs = 0;
    size_t view_tag_matches = 0;
    size_t ownership_verified = 0;
    size_t coinbase_passthrough = 0;
    size_t total_inputs = 0;

    // Matches: (tx_idx, out_idx, block_height)
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t>> verified_matches;
    verified_matches.reserve(tx_count / 10); // ~10% estimated match rate

    // CSP v6 spent matches: (chunk_tx_idx, block_height, input_idx, key_image)
    std::vector<std::tuple<uint32_t, uint32_t, uint16_t, std::string>>
        spent_matches;

    // Track chunk-relative index for Phase 2 compatibility
    // extract_sparse_txs expects index relative to the start of the 1000-block
    // chunk
    uint32_t current_chunk = 0xFFFFFFFF;
    uint32_t chunk_tx_index = 0;

    // Process transactions
    for (uint32_t tx_idx = 0; tx_idx < tx_count && ptr + 32 <= end; tx_idx++) {
      // Read tx_pub_key
      const unsigned char *tx_pub = ptr;
      ptr += 32;

      // Read block_height (CSP v2+)
      uint32_t block_height = start_height + tx_idx; // Default estimate
      if (csp_version >= 0x02 && ptr + 4 <= end) {
        block_height = ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
        ptr += 4;
      }

      // Update chunk tracking
      uint32_t tx_chunk = block_height / 1000;
      if (tx_chunk != current_chunk) {
        current_chunk = tx_chunk;
        chunk_tx_index = 0;
      }

      // Read is_coinbase (CSP v4+)
      bool is_coinbase = false;
      if (csp_version >= 0x04 && ptr + 1 <= end) {
        is_coinbase = (*ptr != 0);
        ptr++;
      }

      // Read first_key_image for Carrot view tag verification (CSP v5/v6)
      // CSP v6 also contains ALL input key_images for spent detection.
      const unsigned char *first_key_image = nullptr;
      if (csp_version >= 0x06 && !is_coinbase && ptr + 2 <= end) {
        uint16_t input_count = ptr[0] | (ptr[1] << 8);
        ptr += 2;
        total_inputs += input_count;

        if (input_count > 0) {
          if (ptr + 32 <= end) {
            first_key_image = ptr; // Store pointer to first key_image
          }

          // Check ALL key images against our set (spent detection)
          if (!key_images.empty()) {
            if (ptr + (static_cast<size_t>(input_count) * 32) > end)
              break;
            for (uint16_t i = 0; i < input_count; i++) {
              crypto::key_image ki;
              memcpy(ki.data, ptr + (static_cast<size_t>(i) * 32), 32);
              if (key_images.count(ki) > 0) {
                spent_matches.push_back({chunk_tx_index, block_height, i,
                                         epee::string_tools::pod_to_hex(ki)});
              }
            }
          }
        }

        ptr += (static_cast<size_t>(input_count) * 32);
      } else if (csp_version == 0x05 && !is_coinbase && ptr + 32 <= end) {
        first_key_image = ptr; // CSP v5: just first key_image
        // NOTE: CSP v5 does not include all key_images, so spent detection
        // cannot be complete.
        ptr += 32;
      }

      // Read output_count
      if (ptr + 2 > end)
        break;
      uint16_t output_count = ptr[0] | (ptr[1] << 8);
      ptr += 2;

      // Collect all per-output additional pubkeys observed in this tx.
      // Some tx construction paths can mismatch (pubkey, out_idx) pairing;
      // for type-0 outputs (no view tag) we may need to try all pubkeys.
      std::vector<const unsigned char *> tx_additional_pubkeys;
      tx_additional_pubkeys.reserve(output_count);

      // Compute main tx derivation (lazy - only if needed)
      crypto::key_derivation main_derivation;
      bool main_derivation_computed = false;

      // SAL1 edge-case: some outputs use k_view_incoming for derivation.
      // Cache main tx_pub_key derivation for carrot_view_sec separately.
      crypto::key_derivation main_derivation_carrot;
      bool main_carrot_derivation_computed = false;

      // Process each output
      for (uint16_t out_idx = 0; out_idx < output_count && ptr + 38 <= end;
           out_idx++) {
        // Read output_key (32 bytes)
        crypto::public_key output_key;
        memcpy(&output_key, ptr, 32);
        ptr += 32;

        // Read output_type and view_tag
        uint8_t output_type = *ptr++;
        uint8_t view_tag_bytes[4];
        view_tag_bytes[0] = *ptr++;
        view_tag_bytes[1] = *ptr++;
        view_tag_bytes[2] = *ptr++;
        view_tag_bytes[3] = *ptr++;

        // Read additional pubkey if present (CSP v3+)
        const unsigned char *additional_pubkey = nullptr;
        if (csp_version >= 0x03 && ptr + 1 <= end) {
          uint8_t has_additional = *ptr++;
          if (has_additional && ptr + 32 <= end) {
            additional_pubkey = ptr;
            ptr += 32;
          }
        }

        if (additional_pubkey) {
          tx_additional_pubkeys.push_back(additional_pubkey);
        }

        total_outputs++;

        bool verified = false;

        // Check if output key matches a known return address (for RETURN tx detection)
        if (do_return_address_check && return_addresses.count(output_key) > 0) {
          verified = true;
          return_address_matches++;
        }

        // Skip view tag matching if already verified via return address check
        if (!verified) {
        // Type-0 coinbase/protocol outputs have NO view tag.
        // These include miner/protocol payouts ("block unlocked" / yield),
        // which the CLI wallet tracks. We MUST do full derivation + subaddress
        // lookup here, otherwise they are invisible to Phase 1.
        if (output_type == 0) {
          // v5.4.0: CRITICAL FIX for PROTOCOL return outputs!
          // Protocol returns from STAKE/AUDIT txs have their output_key set
          // DIRECTLY to the return_address (no key derivation involved).
          // We must check if output_key itself is in subaddress_map FIRST,
          // before trying derivation. The return_address was added to
          // subaddress_map when we processed the original STAKE/AUDIT tx.
          if (is_coinbase && !stake_return_heights.empty() &&
              stake_return_heights.count(block_height) > 0) {
            // Check if output_key IS a known return_address
            if (subaddress_map.find(output_key) != subaddress_map.end()) {
              ownership_verified++;
              verified = true;
            }
          }

          // Standard derivation check (for miner_tx rewards, etc.)
          if (!verified) {
            crypto::key_derivation derivation;
            bool derivation_ok = false;

            // Try additional pubkey first (subaddress outputs)
            if (additional_pubkey) {
              if (donna64_generate_key_derivation(
                      reinterpret_cast<unsigned char *>(&derivation),
                      additional_pubkey, view_sec) == 0) {
                derivation_ok = true;
              }
            }

            // Fall back to main tx pubkey derivation (primary outputs / change)
            if (!derivation_ok) {
              if (!main_derivation_computed) {
                main_derivation_computed = true;
                donna64_generate_key_derivation(
                    reinterpret_cast<unsigned char *>(&main_derivation), tx_pub,
                    view_sec);
              }
              derivation = main_derivation;
              derivation_ok = true;
            }

            if (derivation_ok) {
              crypto::public_key derived_spend_key;
              hw::get_device("default").derive_subaddress_public_key(
                  output_key, derivation, out_idx, derived_spend_key);

              if (subaddress_map.find(derived_spend_key) !=
                  subaddress_map.end()) {
                ownership_verified++;
                verified = true;
              }
            } else {
              // Fallback: if we can't derive at all (unexpected), only pass
              // through at stake-return heights for coinbase/protocol contexts
              // to avoid reintroducing massive false positives.
              if (is_coinbase && !stake_return_heights.empty() &&
                  stake_return_heights.count(block_height) > 0) {
                coinbase_passthrough++;
                verified = true;
              }
            }
          }

          // SAL1 fallback: try derivation using k_view_incoming if legacy
          // derivation did not verify ownership. This is extremely low risk
          // (derived spend key must still match our subaddress map).
          if (!verified && has_carrot_key) {
            crypto::key_derivation derivation_carrot;
            bool derivation_ok_carrot = false;

            // Try additional pubkey first
            if (additional_pubkey) {
              if (donna64_generate_key_derivation(
                      reinterpret_cast<unsigned char *>(&derivation_carrot),
                      additional_pubkey, carrot_view_sec) == 0) {
                derivation_ok_carrot = true;
              }
            }

            // Fall back to main tx pubkey derivation
            if (!derivation_ok_carrot) {
              if (!main_carrot_derivation_computed) {
                main_carrot_derivation_computed = true;
                donna64_generate_key_derivation(
                    reinterpret_cast<unsigned char *>(&main_derivation_carrot),
                    tx_pub, carrot_view_sec);
              }
              derivation_carrot = main_derivation_carrot;
              derivation_ok_carrot = true;
            }

            if (derivation_ok_carrot) {
              crypto::public_key derived_spend_key_carrot;
              hw::get_device("default").derive_subaddress_public_key(
                  output_key, derivation_carrot, out_idx,
                  derived_spend_key_carrot);

              if (subaddress_map.find(derived_spend_key_carrot) !=
                  subaddress_map.end()) {
                ownership_verified++;
                verified = true;
              }
            }
          }

          // SAL1 shuffle/mismatch edge-case for TYPE-0:
          // If additional pubkeys exist in the tx, the (pubkey, out_idx)
          // pairing can be inconsistent. For untagged outputs we brute-force
          // all observed additional pubkeys. This remains safe because we
          // still require a derived spend key hit in subaddress_map.
          if (!verified && !tx_additional_pubkeys.empty()) {
            for (const unsigned char *test_pubkey : tx_additional_pubkeys) {
              if (verified)
                break;

              // Try legacy view secret
              {
                crypto::key_derivation d;
                if (donna64_generate_key_derivation(
                        reinterpret_cast<unsigned char *>(&d), test_pubkey,
                        view_sec) == 0) {
                  crypto::public_key derived_spend_key;
                  hw::get_device("default").derive_subaddress_public_key(
                      output_key, d, out_idx, derived_spend_key);
                  if (subaddress_map.find(derived_spend_key) !=
                      subaddress_map.end()) {
                    ownership_verified++;
                    verified = true;
                    break;
                  }
                }
              }

              // Try Carrot k_view_incoming (SAL1)
              if (!verified && has_carrot_key) {
                crypto::key_derivation d;
                if (donna64_generate_key_derivation(
                        reinterpret_cast<unsigned char *>(&d), test_pubkey,
                        carrot_view_sec) == 0) {
                  crypto::public_key derived_spend_key;
                  hw::get_device("default").derive_subaddress_public_key(
                      output_key, d, out_idx, derived_spend_key);
                  if (subaddress_map.find(derived_spend_key) !=
                      subaddress_map.end()) {
                    ownership_verified++;
                    verified = true;
                    break;
                  }
                }
              }
            }
          }
        }
        // Type-1 (legacy with view tag): view tag match + ownership check
        else if (output_type == 1) {
          // Compute derivation and check view tag
          crypto::key_derivation derivation;
          bool derivation_ok = false;
          bool tag_matched = false;
          bool ownership_ok = false;

          // Try additional pubkey first (for subaddress outputs)
          if (additional_pubkey) {
            if (donna64_generate_key_derivation(
                    reinterpret_cast<unsigned char *>(&derivation),
                    additional_pubkey, view_sec) == 0) {
              derivation_ok = true;
            }
          }

          // Fall back to main tx pubkey (for change outputs)
          if (!derivation_ok) {
            if (!main_derivation_computed) {
              main_derivation_computed = true;
              donna64_generate_key_derivation(
                  reinterpret_cast<unsigned char *>(&main_derivation), tx_pub,
                  view_sec);
            }
            derivation = main_derivation;
            derivation_ok = true;
          }

          if (derivation_ok) {
            // Compute view tag and check match
            // Use local implementation since cryptonote::derive_view_tag is not
            // available
            uint8_t computed_tag = 0;
            {
              struct {
                char salt[8];
                unsigned char derivation[32];
                char output_index_varint[10];
              } buf;
              memcpy(buf.salt, "view_tag", 8);
              memcpy(buf.derivation, &derivation, 32);
              char *varint_end = buf.output_index_varint;
              tools::write_varint(varint_end, static_cast<size_t>(out_idx));
              size_t buf_len = 8 + 32 + (varint_end - buf.output_index_varint);
              crypto::hash view_tag_hash;
              crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);
              computed_tag = view_tag_hash.data[0];
            }

            if (computed_tag == view_tag_bytes[0]) {
              tag_matched = true;
              view_tag_matches++;

              // OWNERSHIP VERIFICATION: derive_subaddress_public_key
              crypto::public_key derived_spend_key;

              hw::get_device("default").derive_subaddress_public_key(
                  output_key, derivation, out_idx, derived_spend_key);

              // Look up in subaddress map
              if (subaddress_map.find(derived_spend_key) !=
                  subaddress_map.end()) {
                ownership_verified++;
                ownership_ok = true;
                verified = true;
              }

              // IMPORTANT: Change outputs can use tx_pub_key even when
              // additional_pubkey is present. It's possible for the view tag to
              // match using additional_pubkey derivation but the derived spend
              // key is not in the subaddress map. In that case, try the main
              // tx_pub_key derivation for ownership as well.
              if (!ownership_ok && additional_pubkey) {
                if (!main_derivation_computed) {
                  main_derivation_computed = true;
                  donna64_generate_key_derivation(
                      reinterpret_cast<unsigned char *>(&main_derivation),
                      tx_pub, view_sec);
                }

                // Optional safety: verify view tag also matches with main
                // derivation before accepting ownership.
                uint8_t computed_tag_main = 0;
                {
                  struct {
                    char salt[8];
                    unsigned char derivation[32];
                    char output_index_varint[10];
                  } buf;
                  memcpy(buf.salt, "view_tag", 8);
                  memcpy(buf.derivation, &main_derivation, 32);
                  char *varint_end = buf.output_index_varint;
                  tools::write_varint(varint_end, static_cast<size_t>(out_idx));
                  size_t buf_len =
                      8 + 32 + (varint_end - buf.output_index_varint);
                  crypto::hash view_tag_hash;
                  crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);
                  computed_tag_main = view_tag_hash.data[0];
                }

                if (computed_tag_main == view_tag_bytes[0]) {
                  crypto::public_key derived_spend_key_main;
                  hw::get_device("default").derive_subaddress_public_key(
                      output_key, main_derivation, out_idx,
                      derived_spend_key_main);

                  if (subaddress_map.find(derived_spend_key_main) !=
                      subaddress_map.end()) {
                    ownership_verified++;
                    verified = true;
                  }
                }
              }
            }

            // Fallback: If view tag mismatched but we used additional_pubkey,
            // try Main Pubkey derivation directly against the Map (Change
            // Output Fix). Change outputs use tx_pub_key even if
            // additional_pubkey is present.
            if (!tag_matched && additional_pubkey) {
              if (!main_derivation_computed) {
                main_derivation_computed = true;
                donna64_generate_key_derivation(
                    reinterpret_cast<unsigned char *>(&main_derivation), tx_pub,
                    view_sec);
              }

              crypto::public_key derived_spend_key;
              hw::get_device("default").derive_subaddress_public_key(
                  output_key, main_derivation, out_idx, derived_spend_key);

              if (subaddress_map.find(derived_spend_key) !=
                  subaddress_map.end()) {
                // Found it via main derivation!
                ownership_verified++;
                verified = true;
              }
            }
          }

          // SAL1 fallback: some type-1 outputs compute derivation using
          // k_view_incoming but still use legacy (index-based) view tags.
          if (!verified && has_carrot_key) {
            crypto::key_derivation derivation_carrot;
            bool derivation_ok_carrot = false;
            bool tag_matched_carrot = false;
            bool ownership_ok_carrot = false;

            // Try additional pubkey first
            if (additional_pubkey) {
              if (donna64_generate_key_derivation(
                      reinterpret_cast<unsigned char *>(&derivation_carrot),
                      additional_pubkey, carrot_view_sec) == 0) {
                derivation_ok_carrot = true;
              }
            }

            // Fall back to main tx pubkey derivation
            if (!derivation_ok_carrot) {
              if (!main_carrot_derivation_computed) {
                main_carrot_derivation_computed = true;
                donna64_generate_key_derivation(
                    reinterpret_cast<unsigned char *>(&main_derivation_carrot),
                    tx_pub, carrot_view_sec);
              }
              derivation_carrot = main_derivation_carrot;
              derivation_ok_carrot = true;
            }

            if (derivation_ok_carrot) {
              // Compute legacy view tag (index-based) using carrot derivation
              uint8_t computed_tag = 0;
              {
                struct {
                  char salt[8];
                  unsigned char derivation[32];
                  char output_index_varint[10];
                } buf;
                memcpy(buf.salt, "view_tag", 8);
                memcpy(buf.derivation, &derivation_carrot, 32);
                char *varint_end = buf.output_index_varint;
                tools::write_varint(varint_end, static_cast<size_t>(out_idx));
                size_t buf_len =
                    8 + 32 + (varint_end - buf.output_index_varint);
                crypto::hash view_tag_hash;
                crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);
                computed_tag = view_tag_hash.data[0];
              }

              if (computed_tag == view_tag_bytes[0]) {
                tag_matched_carrot = true;
                view_tag_matches++;

                crypto::public_key derived_spend_key;
                hw::get_device("default").derive_subaddress_public_key(
                    output_key, derivation_carrot, out_idx, derived_spend_key);

                if (subaddress_map.find(derived_spend_key) !=
                    subaddress_map.end()) {
                  ownership_verified++;
                  ownership_ok_carrot = true;
                  verified = true;
                }

                // Change-output fix for SAL1 path
                if (!ownership_ok_carrot && additional_pubkey) {
                  if (!main_carrot_derivation_computed) {
                    main_carrot_derivation_computed = true;
                    donna64_generate_key_derivation(
                        reinterpret_cast<unsigned char *>(
                            &main_derivation_carrot),
                        tx_pub, carrot_view_sec);
                  }

                  uint8_t computed_tag_main = 0;
                  {
                    struct {
                      char salt[8];
                      unsigned char derivation[32];
                      char output_index_varint[10];
                    } buf;
                    memcpy(buf.salt, "view_tag", 8);
                    memcpy(buf.derivation, &main_derivation_carrot, 32);
                    char *varint_end = buf.output_index_varint;
                    tools::write_varint(varint_end,
                                        static_cast<size_t>(out_idx));
                    size_t buf_len =
                        8 + 32 + (varint_end - buf.output_index_varint);
                    crypto::hash view_tag_hash;
                    crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);
                    computed_tag_main = view_tag_hash.data[0];
                  }

                  if (computed_tag_main == view_tag_bytes[0]) {
                    crypto::public_key derived_spend_key_main;
                    hw::get_device("default").derive_subaddress_public_key(
                        output_key, main_derivation_carrot, out_idx,
                        derived_spend_key_main);

                    if (subaddress_map.find(derived_spend_key_main) !=
                        subaddress_map.end()) {
                      ownership_verified++;
                      verified = true;
                    }
                  }
                }
              }

              // If tag mismatched but we used additional_pubkey, try main
              // carrot derivation directly against the map (change outputs).
              if (!tag_matched_carrot && additional_pubkey) {
                if (!main_carrot_derivation_computed) {
                  main_carrot_derivation_computed = true;
                  donna64_generate_key_derivation(
                      reinterpret_cast<unsigned char *>(
                          &main_derivation_carrot),
                      tx_pub, carrot_view_sec);
                }

                crypto::public_key derived_spend_key;
                hw::get_device("default").derive_subaddress_public_key(
                    output_key, main_derivation_carrot, out_idx,
                    derived_spend_key);

                if (subaddress_map.find(derived_spend_key) !=
                    subaddress_map.end()) {
                  ownership_verified++;
                  verified = true;
                }
              }
            }
          }
        }
        // Type-2 (Carrot): X25519 ECDH + view tag verification
        else if (output_type == 2 && has_carrot_key) {
          // For Carrot outputs, we need to verify the 3-byte view tag
          // This requires: s_sr = k_view_incoming * D_e (X25519 ECDH)
          // Then compute view_tag from s_sr and compare with CSP view_tag

          // Get ephemeral pubkey (D_e) - for non-coinbase this is
          // additional_pubkey, for coinbase it's the main tx_pubkey
          const unsigned char *D_e =
              additional_pubkey ? additional_pubkey : tx_pub;

          // Compute X25519 shared secret: s_sr = k_view_incoming * D_e
          // IMPORTANT: Use the same receiver-side helper as scan_csp_batch_impl
          // so coinbase/protocol Carrot outputs behave identically.
          mx25519_pubkey s_sr{};
          mx25519_pubkey D_e_mx{};
          memcpy(D_e_mx.data, D_e, 32);
          bool ecdh_ok =
              carrot::make_carrot_uncontextualized_shared_key_receiver(
                  carrot_view_secret, D_e_mx, s_sr);

          if (!ecdh_ok) {
            // ECDH failed -> definitely not ours
            verified = false;
          } else {

            // Build input_context based on transaction type
            carrot::input_context_t input_context;
            bool can_verify = false;

            if (is_coinbase) {
              // Coinbase: input_context = 'C' || block_height (8 bytes LE)
              input_context =
                  carrot::make_carrot_input_context_coinbase(block_height);
              can_verify = true;
            } else if (first_key_image != nullptr) {
              // RingCT with first_key_image available
              crypto::key_image ki;
              memcpy(ki.data, first_key_image, 32);
              input_context = carrot::make_carrot_input_context(ki);
              can_verify = true;
            }
            // If can_verify is false (CSP v4 or earlier), we must pass through

            if (can_verify) {
              crypto::public_key Ko;
              memcpy(Ko.data, &output_key, 32);

              // 1) External Carrot view tag (ECDH-based)
              carrot::view_tag_t computed_tag;
              carrot::make_carrot_view_tag(s_sr.data, input_context, Ko,
                                           computed_tag);

              if (computed_tag.bytes[0] == view_tag_bytes[0] &&
                  computed_tag.bytes[1] == view_tag_bytes[1] &&
                  computed_tag.bytes[2] == view_tag_bytes[2]) {
                ownership_verified++;
                verified = true;
              }

              // 2) Internal Carrot view tag (self-send/change)
              // vt = H_3(s_view_balance || input_context || Ko)
              // Mirror wallet scanning_tools.cpp receiver path: try external
              // first, then internal.
              if (!verified && !is_coinbase && has_carrot_s_view_balance) {
                carrot::view_tag_t internal_tag;
                carrot::make_carrot_view_tag(
                    reinterpret_cast<const unsigned char *>(
                        carrot_s_view_balance.data),
                    input_context, Ko, internal_tag);

                if (internal_tag.bytes[0] == view_tag_bytes[0] &&
                    internal_tag.bytes[1] == view_tag_bytes[1] &&
                    internal_tag.bytes[2] == view_tag_bytes[2]) {
                  ownership_verified++;
                  verified = true;
                }
              }

              if (!verified && is_coinbase) {
                // Carrot coinbase outputs can also be stake returns whose view
                // tag was computed with a DIFFERENT input_context. Mirror
                // scan_csp_batch_impl behavior: pass-through only at stake
                // return heights to avoid false positives.
                if (!stake_return_heights.empty() &&
                    stake_return_heights.count(block_height) > 0) {
                  coinbase_passthrough++;
                  verified = true;
                }
              }
            } else {
              // If we cannot verify input_context (no key_image available), do
              // NOT pass-through non-coinbase Carrot outputs. A non-coinbase
              // tx with no inputs is not verifiable and pass-through causes
              // false positives.
              if (is_coinbase) {
                coinbase_passthrough++;
                verified = true;
              } else {
                verified = false;
              }
            }
          }
        }
        } // End of if (!verified) - view tag matching

        if (verified) {
          verified_matches.push_back({chunk_tx_index, out_idx, block_height});
        }
      }
      chunk_tx_index++;
    }

    auto total_end = std::chrono::high_resolution_clock::now();
    auto total_us = std::chrono::duration_cast<std::chrono::microseconds>(
                        total_end - total_start)
                        .count();

    // Build result JSON
    std::ostringstream oss;
    oss << "{\"matches\":[";
    for (size_t i = 0; i < verified_matches.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << "{\"tx_idx\":" << std::get<0>(verified_matches[i])
          << ",\"out_idx\":" << std::get<1>(verified_matches[i])
          << ",\"block_height\":" << std::get<2>(verified_matches[i]) << "}";
    }
    // CSP v6: Output spent matches (our key_images found in tx inputs)
    oss << "],\"spent\":[";
    for (size_t i = 0; i < spent_matches.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << "{\"tx\":" << std::get<0>(spent_matches[i])
          << ",\"height\":" << std::get<1>(spent_matches[i])
          << ",\"input\":" << std::get<2>(spent_matches[i])
          << ",\"key_image\":\"" << std::get<3>(spent_matches[i]) << "\"}";
    }

    oss << "],\"stats\":{"
        << "\"tx_count\":" << tx_count << ","
        << "\"total_outputs\":" << total_outputs << ","
        << "\"view_tag_matches\":" << view_tag_matches << ","
        << "\"return_address_matches\":" << return_address_matches << ","
        << "\"ownership_verified\":" << ownership_verified << ","
        << "\"coinbase_passthrough\":" << coinbase_passthrough << ","
        << "\"input_count\":" << total_inputs << ","
        << "\"spent_matches\":" << spent_matches.size() << ","
        << "\"subaddress_map_size\":" << subaddress_map.size() << ","
        << "\"total_us\":" << total_us << ","
        << "\"us_per_output\":"
        << (total_outputs > 0 ? total_us / total_outputs : 0) << "}}";

    return oss.str();

  } catch (const std::exception &e) {
    return std::string(R"({"error":")") + e.what() + R"(","matches":[]})";
  } catch (...) {
    return R"({"error":"unknown exception","matches":[]})";
  }
}

// Backward-compatible wrapper (no spent detection)
std::string
scan_csp_with_ownership(uintptr_t csp_ptr, size_t csp_size,
                        const std::string &view_secret_key_hex,
                        const std::string &k_view_incoming_hex,
                        const std::string &s_view_balance_hex,
                        const std::string &subaddress_map_csv,
                        const std::string &stake_return_heights_hex = "",
                        const std::string &return_addresses_csv = "") {
  return scan_csp_with_ownership_impl(
      csp_ptr, csp_size, view_secret_key_hex, k_view_incoming_hex,
      s_view_balance_hex, subaddress_map_csv, "", stake_return_heights_hex,
      return_addresses_csv);
}

// CSP v6: Ownership verification + spent detection
std::string scan_csp_with_ownership_and_spent(
    uintptr_t csp_ptr, size_t csp_size, const std::string &view_secret_key_hex,
    const std::string &k_view_incoming_hex, const std::string &key_images_hex,
    const std::string &s_view_balance_hex,
    const std::string &subaddress_map_csv,
    const std::string &stake_return_heights_hex,
    const std::string &return_addresses_csv = "") {
  return scan_csp_with_ownership_impl(csp_ptr, csp_size, view_secret_key_hex,
                                      k_view_incoming_hex, s_view_balance_hex,
                                      subaddress_map_csv, key_images_hex,
                                      stake_return_heights_hex,
                                      return_addresses_csv);
}
// ============================================================================
// SERVER-SIDE EPEE TO CSP CONVERSION
// ============================================================================
// This function converts raw getblocks.bin (Epee format) to CSP (Compact Scan
// Protocol). It uses Monero's native epee serialization library - the SAME code
// that parses blocks in the C++ wallet. No JS parser needed!
//
// Usage (Node.js backend):
//   const wasmModule = require('./SalviumWallet.js');
//   const ptr = wasmModule._malloc(epeeBuffer.length);
//   wasmModule.HEAPU8.set(epeeBuffer, ptr);
//   const cspResult = wasmModule.convert_epee_to_csp(ptr, epeeBuffer.length,
//   startHeight); wasmModule._free(ptr);
//   // cspResult is a CSP binary buffer (or pointer + size via MemoryView)
//
// This eliminates the need to:
// 1. Parse Epee in JavaScript (impossible/fragile)
// 2. Send huge Epee blobs to client (CSP is 95% smaller)
// 3. Parse Epee in client WASM (slow, memory hungry)
// ============================================================================

/**
 * parse_audit_tx_minimal - Parse AUDIT transactions (type=8) that fail standard
 * parsing
 *
 * AUDIT transactions fail to parse due to WASM32/64-bit size_t serialization
 * mismatch. This function extracts just what we need for wallet scanning:
 * - tx_prefix (with type, extra, vout)
 * - RCT outPk (output commitment masks for view tag calculation)
 *
 * @param tx_blob The raw transaction blob
 * @param tx Output transaction object (populated on success)
 * @return true if minimal parse succeeded
 */
static bool parse_audit_tx_minimal(const std::string &tx_blob,
                                   cryptonote::transaction &tx) {
  try {
    // First, try prefix-only parse
    binary_archive<false> ba_prefix{epee::strspan<std::uint8_t>(tx_blob)};
    if (!::serialization::serialize_noeof(
            ba_prefix, static_cast<cryptonote::transaction_prefix &>(tx))) {
      return false;
    }

    // Check if this is an AUDIT transaction
    if (tx.type != cryptonote::transaction_type::AUDIT) {
      return false; // Not an AUDIT transaction, shouldn't use this fallback
    }

    // Debug: Log what we got from prefix parsing
    static int audit_prefix_debug = 0;
    if (audit_prefix_debug < 3) {
      audit_prefix_debug++;
      crypto::public_key check_pk = cryptonote::get_tx_pub_key_from_extra(tx);
      DEBUG_LOG(
          "[AUDIT PREFIX] type=%d, extra.size=%zu, vout=%zu, "
          "pubkey=%s\n",
          (int)tx.type, tx.extra.size(), tx.vout.size(),
          (check_pk == crypto::null_pkey
               ? "NULL"
               : key_to_hex(reinterpret_cast<const unsigned char *>(&check_pk))
                     .c_str()));
    }

    size_t prefix_bytes_read = ba_prefix.getpos();

    // Now manually parse RCT base to get outPk
    std::string rct_blob(tx_blob.begin() + prefix_bytes_read, tx_blob.end());
    binary_archive<false> ba_rct{epee::strspan<std::uint8_t>(rct_blob)};

    // Read RCT type
    uint8_t rct_type;
    ba_rct.serialize_varint(rct_type);
    tx.rct_signatures.type = rct_type;

    if (rct_type != rct::RCTTypeSalviumZero &&
        rct_type != rct::RCTTypeSalviumOne) {
      return false; // Not a Salvium RCT type
    }

    // Read txnFee
    ba_rct.serialize_varint(tx.rct_signatures.txnFee);

    // Read ecdhInfo (8 bytes per output for Salvium types)
    size_t num_outputs = tx.vout.size();
    tx.rct_signatures.ecdhInfo.resize(num_outputs);
    for (size_t i = 0; i < num_outputs; i++) {
      // For Salvium types, only 8 bytes of amount are stored
      memset(tx.rct_signatures.ecdhInfo[i].amount.bytes, 0, 32);
      ba_rct.serialize_blob(tx.rct_signatures.ecdhInfo[i].amount.bytes, 8);
    }

    // Read outPk (32 bytes per output - the commitment masks we need!)
    tx.rct_signatures.outPk.resize(num_outputs);
    for (size_t i = 0; i < num_outputs; i++) {
      ba_rct.serialize_blob(tx.rct_signatures.outPk[i].mask.bytes, 32);
    }

    // Read p_r (32 bytes)
    ba_rct.serialize_blob(tx.rct_signatures.p_r.bytes, 32);

    // ================================================================
    // Parse salvium_data - CRITICAL for AUDIT transaction handling!
    // salvium_data contains spend_pubkey which is needed for wallet scanning
    // ================================================================

    // Read salvium_data_type (varint)
    ba_rct.serialize_varint(tx.rct_signatures.salvium_data.salvium_data_type);

    // Read pr_proof (zk_proof = R + z1 + z2 = 3*32 = 96 bytes)
    ba_rct.serialize_blob(tx.rct_signatures.salvium_data.pr_proof.R.bytes, 32);
    ba_rct.serialize_blob(tx.rct_signatures.salvium_data.pr_proof.z1.bytes, 32);
    ba_rct.serialize_blob(tx.rct_signatures.salvium_data.pr_proof.z2.bytes, 32);

    // Read sa_proof (same structure - 96 bytes)
    ba_rct.serialize_blob(tx.rct_signatures.salvium_data.sa_proof.R.bytes, 32);
    ba_rct.serialize_blob(tx.rct_signatures.salvium_data.sa_proof.z1.bytes, 32);
    ba_rct.serialize_blob(tx.rct_signatures.salvium_data.sa_proof.z2.bytes, 32);

    // For SalviumZeroAudit (salvium_data_type == 1), also parse:
    // - cz_proof (zk_proof)
    // - input_verification_data (vector)
    // - spend_pubkey (32 bytes) <-- THIS IS WHAT WE NEED!
    // - enc_view_privkey_str (string)
    if (tx.rct_signatures.salvium_data.salvium_data_type ==
        rct::SalviumZeroAudit) {
      // cz_proof (zk_proof = 96 bytes)
      ba_rct.serialize_blob(tx.rct_signatures.salvium_data.cz_proof.R.bytes,
                            32);
      ba_rct.serialize_blob(tx.rct_signatures.salvium_data.cz_proof.z1.bytes,
                            32);
      ba_rct.serialize_blob(tx.rct_signatures.salvium_data.cz_proof.z2.bytes,
                            32);

      // input_verification_data (vector of salvium_input_data_t)
      uint64_t ivd_count = 0;
      ba_rct.serialize_varint(ivd_count);
      tx.rct_signatures.salvium_data.input_verification_data.resize(ivd_count);
      for (size_t i = 0; i < ivd_count; i++) {
        auto &ivd = tx.rct_signatures.salvium_data.input_verification_data[i];
        // salvium_input_data_t serialization order:
        // 1. aR (key_derivation = 32 bytes)
        ba_rct.serialize_blob(ivd.aR.data, 32);
        // 2. amount (varint)
        ba_rct.serialize_varint(ivd.amount);
        // 3. i (varint)
        uint64_t temp_i = 0;
        ba_rct.serialize_varint(temp_i);
        ivd.i = temp_i;
        // 4. origin_tx_type (varint)
        uint64_t temp_origin = 0;
        ba_rct.serialize_varint(temp_origin);
        ivd.origin_tx_type = (uint8_t)temp_origin;
        // 5. If origin_tx_type != UNSET, also parse aR_stake and i_stake
        if (ivd.origin_tx_type != 0) { // UNSET = 0
          ba_rct.serialize_blob(ivd.aR_stake.data, 32);
          uint64_t temp_i_stake = 0;
          ba_rct.serialize_varint(temp_i_stake);
          ivd.i_stake = temp_i_stake;
        }
      }

      // spend_pubkey (32 bytes) - THE KEY WE NEED FOR AUDIT FIX!
      ba_rct.serialize_blob(tx.rct_signatures.salvium_data.spend_pubkey.data,
                            32);

      // enc_view_privkey_str (string)
      uint64_t str_len = 0;
      ba_rct.serialize_varint(str_len);
      if (str_len > 0 && str_len < 1024) {
        tx.rct_signatures.salvium_data.enc_view_privkey_str.resize(str_len);
        ba_rct.serialize_blob(
            (void *)tx.rct_signatures.salvium_data.enc_view_privkey_str.data(),
            str_len);
      }

      // Debug log for AUDIT parsing
      static int audit_parse_count = 0;
      if (audit_parse_count < 5) {
        audit_parse_count++;
        DEBUG_LOG("[AUDIT PARSE] salvium_data_type=%d spend_pubkey=%s "
                  "ivd_count=%lu\n",
                  (int)tx.rct_signatures.salvium_data.salvium_data_type,
                  key_to_hex(reinterpret_cast<const unsigned char *>(
                                 &tx.rct_signatures.salvium_data.spend_pubkey))
                      .c_str(),
                  (unsigned long)ivd_count);
      }
    }

    return ba_rct.good();
  } catch (...) {
    return false;
  }
}

/**
 * convert_epee_to_csp - Server-side Epee to CSP v2 conversion
 *
 * @param epee_ptr Pointer to getblocks.bin response in WASM heap
 * @param epee_size Size of Epee buffer in bytes
 * @param start_height_d Starting block height (for CSP header) - double for JS
 * compatibility
 * @return JSON with CSP buffer info: {ptr, size, tx_count, output_count} or
 * {error}
 *
 * NOW GENERATES CSP v2 FORMAT WITH CARROT SUPPORT:
 * - Output type field (0=no_tag, 1=tagged_key, 2=carrot_v1)
 * - 4-byte view tag field (3 bytes for Carrot, padded with 0x00)
 * - Block height per transaction (for Carrot input_context)
 *
 * NOTE: Caller must free the returned CSP buffer using
 * free_binary_buffer(result.ptr) NOTE: Using double instead of uint64_t for
 * JavaScript/Embind compatibility (JS numbers are doubles)
 */
std::string convert_epee_to_csp(uintptr_t epee_ptr, size_t epee_size,
                                double start_height_d) {
  auto total_start = std::chrono::high_resolution_clock::now();
  uint64_t start_height = static_cast<uint64_t>(start_height_d);

  try {
    if (epee_ptr == 0 || epee_size < 10) {
      return "{\"error\":\"invalid epee buffer\"}";
    }

    // Convert pointer to string (epee uses std::string for binary data)
    const std::string epee_data(reinterpret_cast<const char *>(epee_ptr),
                                epee_size);

    // Parse Epee response using Monero's native serialization
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
    bool parsed = epee::serialization::load_t_from_binary(res, epee_data);

    if (!parsed) {
      return "{\"error\":\"epee parse failed\"}";
    }

    // Pre-calculate CSP v6 buffer size (header + txs)
    // CSP v6: Per output is 32 (key) + 1 (type) + 4 (view_tag) + 1
    // (has_additional) + [32 (additional_pubkey)] = 38-70 bytes Per tx: 32
    // (pubkey) + 4 (block_height) + 1 (is_coinbase) +
    // [2 (input_count) + 32*input_count (key_images) if RingCT] + 2
    // (output_count)
    std::string csp_buffer;
    csp_buffer.reserve(epee_size /
                       2); // CSP v6 larger due to all input key_images

    // Write CSP v6 Header: "CSP\x06" + StartHeight(4) + TxCount(4)
    // CSP v6 adds ALL input key_images for spent output detection
    csp_buffer.append("CSP\x06", 4);

    uint32_t start_h = static_cast<uint32_t>(start_height);
    csp_buffer.append(reinterpret_cast<const char *>(&start_h), 4);

    // Placeholder for TxCount (will overwrite later)
    size_t tx_count_offset = csp_buffer.size();
    uint32_t global_tx_count = 0;
    csp_buffer.append(std::string(4, '\0'));

    uint32_t global_output_count = 0;
    uint32_t global_carrot_count = 0;
    uint32_t global_input_count = 0; // CSP v6: Track total inputs for stats
    uint32_t global_user_tx_count =
        0; // Track user txs separately from miner txs
    uint32_t global_user_tx_parsed = 0; // Track successfully parsed user txs
    uint32_t current_block_height = static_cast<uint32_t>(start_height);

    // Process each block in the response
    for (const auto &block_entry : res.blocks) {
      // Parse block blob to get miner tx
      cryptonote::block blk;
      if (!cryptonote::parse_and_validate_block_from_blob(block_entry.block,
                                                          blk)) {
        current_block_height++;
        continue; // Skip malformed blocks
      }

      // Count user transactions in this block
      global_user_tx_count += block_entry.txs.size();

      // FIX: Use pointers to avoid copying miner/protocol tx which corrupts
      // tx.extra The copy operation on cryptonote::transaction was corrupting
      // the extra field
      struct CspTxRef {
        const cryptonote::transaction *tx;
        bool is_coinbase;
      };
      std::vector<CspTxRef> tx_refs;
      std::vector<cryptonote::transaction> user_txs_storage;
      tx_refs.reserve(2 + block_entry.txs.size());
      user_txs_storage.reserve(block_entry.txs.size());

      // Miner tx - use pointer to original in block (no copy!)
      tx_refs.push_back({&blk.miner_tx, true});

      // Protocol tx if present - use pointer to original in block (no copy!)
      if (blk.protocol_tx.vout.size() > 0) {
        tx_refs.push_back({&blk.protocol_tx, true});
      }

      // Parse user transactions - store then add pointers
      for (const auto &tx_blob_entry : block_entry.txs) {
        cryptonote::transaction tx;
        if (cryptonote::parse_and_validate_tx_from_blob(tx_blob_entry.blob,
                                                        tx)) {
          user_txs_storage.push_back(std::move(tx));
          tx_refs.push_back({&user_txs_storage.back(), false});
          global_user_tx_parsed++;
        } else if (parse_audit_tx_minimal(tx_blob_entry.blob, tx)) {
          user_txs_storage.push_back(std::move(tx));
          tx_refs.push_back({&user_txs_storage.back(), false});
          global_user_tx_parsed++;
        }
      }

      // Extract CSP v5 data from each transaction
      for (const auto &tx_ref : tx_refs) {
        const auto &tx = *tx_ref.tx;
        bool is_coinbase = tx_ref.is_coinbase;

        // Skip if no outputs
        if (tx.vout.empty())
          continue;

        // A. Get tx_pub_key from extra (tag 0x01)
        crypto::public_key tx_pub_key =
            cryptonote::get_tx_pub_key_from_extra(tx);

        // CSP v3: Get additional tx pubkeys for subaddress outputs
        // WORKAROUND: Manual parsing because
        // get_additional_tx_pub_keys_from_extra has a serialization bug that
        // expects a size prefix between tag and data. The correct format is:
        // [0x04 tag][varint count][32-byte pubkeys...]
        std::vector<crypto::public_key> additional_tx_pub_keys;

        // Find tag 0x04 in tx.extra and parse manually
        for (size_t pos = 0; pos < tx.extra.size(); pos++) {
          if (tx.extra[pos] == 0x04) { // TX_EXTRA_TAG_ADDITIONAL_PUBKEYS
            // Read varint count starting at pos+1
            size_t count = 0;
            size_t varint_offset = pos + 1;
            size_t shift = 0;

            while (varint_offset < tx.extra.size()) {
              uint8_t byte = tx.extra[varint_offset++];
              count |= static_cast<size_t>(byte & 0x7F) << shift;
              if ((byte & 0x80) == 0)
                break; // No continuation
              shift += 7;
              if (shift > 63)
                break; // Prevent overflow
            }

            // Validate count (sanity check: max 256 outputs per tx)
            if (count == 0 || count > 256)
              break;

            // Check we have enough bytes for count pubkeys
            size_t pubkeys_start = varint_offset;
            size_t pubkeys_bytes_needed = count * 32;
            if (pubkeys_start + pubkeys_bytes_needed > tx.extra.size())
              break;

            // Extract pubkeys
            additional_tx_pub_keys.reserve(count);
            for (size_t i = 0; i < count; i++) {
              crypto::public_key pk;
              std::memcpy(&pk.data, &tx.extra[pubkeys_start + i * 32], 32);
              additional_tx_pub_keys.push_back(pk);
            }
            break; // Found and parsed, done
          }
        }

        // Validate additional pubkeys count matches outputs (if present)
        bool has_valid_additional =
            !additional_tx_pub_keys.empty() &&
            additional_tx_pub_keys.size() == tx.vout.size();

        // Carrot v1: coinbase/protocol transactions store the enote ephemeral
        // pubkeys (D_e) in a Carrot-specific tx.extra field (NOT the legacy tx
        // pubkey fields). We must extract and store per-output D_e so Phase 1
        // can compute the 3-byte Carrot view tag deterministically.
        const bool is_carrot_tx = carrot::is_carrot_transaction_v1(tx);
        std::vector<mx25519_pubkey> carrot_ephemeral_pubkeys;
        std::optional<carrot::encrypted_payment_id_t>
            carrot_encrypted_payment_id;
        // v6.0.2 FIX: Accept either 1 pubkey (shared D_e) or N pubkeys
        // (per-output) Previously required exact N match, which failed for
        // shared D_e case
        const bool carrot_extra_loaded =
            is_carrot_tx &&
            carrot::try_load_carrot_extra_v1(tx.extra, carrot_ephemeral_pubkeys,
                                             carrot_encrypted_payment_id);
        const bool has_valid_carrot_ephemeral =
            carrot_extra_loaded &&
            (carrot_ephemeral_pubkeys.size() ==
                 tx.vout.size() ||                  // Per-output D_e
             carrot_ephemeral_pubkeys.size() == 1); // Shared D_e
        const bool is_shared_carrot_ephemeral =
            carrot_extra_loaded && carrot_ephemeral_pubkeys.size() == 1 &&
            tx.vout.size() > 1;

        // v5.19.0 FIX: Carrot transactions may have NO tag 0x01 tx_pub_key!
        // For pure Carrot transactions (post-HF10), all derivation keys are
        // stored as Carrot ephemeral pubkeys via try_load_carrot_extra_v1().
        // If tx_pub_key is null but we have valid Carrot ephemeral pubkeys,
        // use the first D_e as the tx_pub_key for CSP record purposes.
        // The per-output D_e will be stored in additional_pubkey field.
        if (tx_pub_key == crypto::null_pkey) {
          if (has_valid_carrot_ephemeral && !carrot_ephemeral_pubkeys.empty()) {
            // Use first Carrot D_e as fallback tx_pub_key
            // This ensures the CSP record is created for Carrot-only txs
            std::memcpy(&tx_pub_key.data, carrot_ephemeral_pubkeys[0].data, 32);
          } else if (has_valid_additional && !additional_tx_pub_keys.empty()) {
            // Fallback to first additional pubkey for non-Carrot txs
            tx_pub_key = additional_tx_pub_keys[0];
          } else {
            // No derivation key available - skip transaction
            continue;
          }
        }

        // CSP v6: Collect ALL input key_images for spent output detection
        // This enables clients to check if their outputs were spent by any TX
        std::vector<crypto::key_image> input_key_images;
        if (!is_coinbase) {
          input_key_images.reserve(tx.vin.size());
          for (const auto &vin : tx.vin) {
            if (auto *txin = boost::get<cryptonote::txin_to_key>(&vin)) {
              input_key_images.push_back(txin->k_image);
            }
          }
        }

        // First key_image for Carrot view tag computation (backward compat)
        crypto::key_image first_key_image{};
        bool has_first_key_image = !input_key_images.empty();
        if (has_first_key_image) {
          first_key_image = input_key_images[0];
        }

        global_tx_count++;

        // Write TxPubKey (32 bytes)
        csp_buffer.append(reinterpret_cast<const char *>(&tx_pub_key), 32);

        // Write BlockHeight (4 bytes, uint32 LE) - CSP v2+ for Carrot
        // input_context
        csp_buffer.append(reinterpret_cast<const char *>(&current_block_height),
                          4);

        // CSP v6: Write IsCoinbase (1 byte) + InputCount (2 bytes) +
        // InputKeyImages (32 bytes each)
        // - Coinbase (miner/protocol tx): is_coinbase=1, no inputs
        // - RingCT: is_coinbase=0, followed by input_count + key_images[]
        //   input_context for Carrot = 'R' || first_key_image
        uint8_t is_coinbase_byte = is_coinbase ? 1 : 0;
        csp_buffer.push_back(static_cast<char>(is_coinbase_byte));

        // CSP v6: If RingCT, write input_count + ALL key_images for spent
        // detection
        if (!is_coinbase) {
          uint16_t input_count = static_cast<uint16_t>(input_key_images.size());
          csp_buffer.append(reinterpret_cast<const char *>(&input_count), 2);

          for (const auto &ki : input_key_images) {
            csp_buffer.append(reinterpret_cast<const char *>(&ki), 32);
          }
          global_input_count += input_count;
        }

        // Write OutputCount (2 bytes, uint16 LE)
        uint16_t out_count = static_cast<uint16_t>(tx.vout.size());
        csp_buffer.append(reinterpret_cast<const char *>(&out_count), 2);

        // B. Process each output with CSP v3 format (includes additional
        // pubkey)
        for (size_t i = 0; i < tx.vout.size(); i++) {
          const auto &out = tx.vout[i];
          crypto::public_key output_key;
          uint8_t output_type = 0; // 0=no_tag, 1=tagged_key, 2=carrot_v1
          uint8_t view_tag_bytes[4] = {0, 0, 0, 0}; // 4 bytes, padded with 0x00

          // Handle different output types using boost::variant visitor pattern
          // out.target is a boost::variant, not std::variant
          if (auto *key_ptr =
                  boost::get<cryptonote::txout_to_key>(&out.target)) {
            // Type 0: Standard output (no view tag)
            output_key = key_ptr->key;
            output_type = 0;
          } else if (auto *tagged_ptr =
                         boost::get<cryptonote::txout_to_tagged_key>(
                             &out.target)) {
            // Type 1: Tagged output (1-byte view tag)
            output_key = tagged_ptr->key;
            output_type = 1;
            view_tag_bytes[0] = tagged_ptr->view_tag.data;
          } else if (auto *carrot_ptr =
                         boost::get<cryptonote::txout_to_carrot_v1>(
                             &out.target)) {
            // Type 2: Carrot v1 output (3-byte view tag)
            output_key = carrot_ptr->key;
            output_type = 2;
            // carrot::view_tag_t is a 3-byte struct
            view_tag_bytes[0] = carrot_ptr->view_tag.bytes[0];
            view_tag_bytes[1] = carrot_ptr->view_tag.bytes[1];
            view_tag_bytes[2] = carrot_ptr->view_tag.bytes[2];
            global_carrot_count++;
          } else {
            // Unknown output type - use null key
            output_key = crypto::null_pkey;
            output_type = 0;
          }

          // Write OutputKey (32 bytes)
          csp_buffer.append(reinterpret_cast<const char *>(&output_key), 32);

          // Write OutputType (1 byte)
          csp_buffer.push_back(static_cast<char>(output_type));

          // Write ViewTag (4 bytes, padded)
          csp_buffer.append(reinterpret_cast<const char *>(view_tag_bytes), 4);

          // CSP v3: Write HasAdditionalPubkey (1 byte) + AdditionalPubkey (32
          // bytes)
          // - Legacy: per-output additional tx pubkey for subaddress derivation
          // - Carrot: per-output D_e (mx25519 pubkey bytes) for view-tag
          // computation
          uint8_t has_additional = 0;
          const char *additional_ptr = nullptr;

          if (output_type == 2 && has_valid_carrot_ephemeral) {
            has_additional = 1;
            // v6.0.2 FIX: For shared D_e, use index 0 for all outputs
            size_t ephemeral_idx = is_shared_carrot_ephemeral ? 0 : i;
            additional_ptr = reinterpret_cast<const char *>(
                carrot_ephemeral_pubkeys[ephemeral_idx].data);
          } else if (has_valid_additional) {
            has_additional = 1;
            additional_ptr =
                reinterpret_cast<const char *>(&additional_tx_pub_keys[i]);
          }

          csp_buffer.push_back(static_cast<char>(has_additional));
          if (has_additional && additional_ptr) {
            csp_buffer.append(additional_ptr, 32);
          }

          global_output_count++;
        }
      }

      // Increment block height for next block
      current_block_height++;
    }

    // Write final TxCount to header
    memcpy(&csp_buffer[tx_count_offset], &global_tx_count, 4);

    // Allocate new buffer and copy CSP data (so caller can free epee buffer)
    uintptr_t csp_ptr =
        reinterpret_cast<uintptr_t>(new uint8_t[csp_buffer.size()]);
    if (!csp_ptr) {
      return "{\"error\":\"CSP allocation failed\"}";
    }
    memcpy(reinterpret_cast<void *>(csp_ptr), csp_buffer.data(),
           csp_buffer.size());

    auto total_end = std::chrono::high_resolution_clock::now();
    double total_ms =
        std::chrono::duration<double, std::milli>(total_end - total_start)
            .count();

    // Return CSP v6 buffer info as JSON
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "{"
        << "\"ptr\":" << csp_ptr << ","
        << "\"size\":" << csp_buffer.size() << ","
        << "\"csp_version\":6,"
        << "\"tx_count\":" << global_tx_count << ","
        << "\"output_count\":" << global_output_count << ","
        << "\"input_count\":" << global_input_count
        << "," // CSP v6: total inputs for stats
        << "\"carrot_count\":" << global_carrot_count << ","
        << "\"user_tx_count\":" << global_user_tx_count << ","
        << "\"user_tx_parsed\":" << global_user_tx_parsed << ","
        << "\"blocks_count\":" << res.blocks.size() << ","
        << "\"epee_size\":" << epee_size << ","
        << "\"compression_ratio\":"
        << (epee_size > 0
                ? static_cast<double>(csp_buffer.size()) / epee_size * 100
                : 0)
        << ","
        << "\"convert_ms\":" << total_ms << ","
        << "\"success\":true"
        << "}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"error\":\"unknown exception\"}";
  }
}

// ============================================================================
// CONVERT EPEE TO CSP WITH TRANSACTION INDEX
// Enhanced version that also outputs a transaction blob index for fast
// sparse extraction. This avoids re-parsing the Epee blob during rescan.
// ============================================================================

/**
 * convert_epee_to_csp_with_index - CSP conversion with transaction blob index
 *
 * This enhanced version outputs both:
 * 1. CSP buffer (same as convert_epee_to_csp)
 * 2. Index buffer containing tx blobs WITH OUTPUT INDICES AND TX HASH in CSP
 * order
 *
 * TXI v3 format (includes tx hash for proper sparse extraction!):
 *   Header: "TXI\x03" (4 bytes) + TxCount (4 bytes) + Reserved (8 bytes)
 *   For each tx:
 * [BlockHeight:4][TxHash:32][OutputIndexCount:2][OutputIndices:4*count][TxBlobSize:4][TxBlob:variable]
 *
 * This allows sparse extraction without WASM - just seek and read!
 * The tx hash is REQUIRED for fetching proper output indices from daemon.
 * The output indices are REQUIRED for process_new_transaction() to work.
 *
 * CRITICAL: Transaction order MUST match extract_sparse_txs exactly:
 *   miner_tx -> protocol_tx (if present) -> user_txs
 *
 * @param epee_ptr Pointer to getblocks.bin response in WASM heap
 * @param epee_size Size of Epee buffer in bytes
 * @param start_height_d Starting block height (for CSP header)
 * @return JSON with both buffer infos:
 *   {
 *     csp_ptr, csp_size,
 *     index_ptr, index_size,
 *     tx_count, output_count,
 *     success: true
 *   }
 */
std::string convert_epee_to_csp_with_index(uintptr_t epee_ptr, size_t epee_size,
                                           double start_height_d) {
  auto total_start = std::chrono::high_resolution_clock::now();
  uint64_t start_height = static_cast<uint64_t>(start_height_d);

  try {
    if (epee_ptr == 0 || epee_size < 10) {
      return "{\"error\":\"invalid epee buffer\"}";
    }

    const std::string epee_data(reinterpret_cast<const char *>(epee_ptr),
                                epee_size);

    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
    bool parsed = epee::serialization::load_t_from_binary(res, epee_data);

    if (!parsed) {
      return "{\"error\":\"epee parse failed\"}";
    }

    // Check if we have output indices in the response
    bool has_output_indices = !res.output_indices.empty();

    // CSP v6 buffer - with is_coinbase and ALL input key_images for RingCT
    // (enables spent output detection + correct Carrot RingCT view-tag context)
    std::string csp_buffer;
    csp_buffer.reserve(epee_size /
                       2); // CSP v6 larger due to all input key_images
    csp_buffer.append("CSP\x06", 4);
    uint32_t start_h = static_cast<uint32_t>(start_height);
    csp_buffer.append(reinterpret_cast<const char *>(&start_h), 4);
    size_t tx_count_offset = csp_buffer.size();
    uint32_t global_tx_count = 0;
    csp_buffer.append(std::string(4, '\0'));

    // TXI v3 buffer - stores tx blobs WITH OUTPUT INDICES AND TX HASH in CSP
    // order v3 adds 32-byte tx hash per entry, required for sparse extraction
    std::string index_buffer;
    index_buffer.reserve(
        epee_size + epee_size / 10); // Tx blobs + indices overhead + tx hashes
    index_buffer.append("TXI\x03", 4); // Magic + version 3 (with tx hash!)
    size_t index_count_offset = index_buffer.size();
    index_buffer.append(std::string(4, '\0')); // TxCount placeholder
    index_buffer.append(
        std::string(8, '\0')); // Reserved (future: checksum, etc)

    uint32_t global_output_count = 0;
    uint32_t global_carrot_count = 0;
    uint32_t global_user_tx_count = 0;
    uint32_t global_user_tx_parsed = 0;

    for (size_t block_idx = 0; block_idx < res.blocks.size(); ++block_idx) {
      const auto &block_entry = res.blocks[block_idx];
      uint64_t block_height = start_height + block_idx;

      cryptonote::block blk;
      if (!cryptonote::parse_and_validate_block_from_blob(block_entry.block,
                                                          blk)) {
        continue;
      }

      global_user_tx_count += block_entry.txs.size();

      // Collect txs with their blobs AND output indices
      // CRITICAL: Order must match extract_sparse_txs exactly!
      // tx_idx in output_indices: 0=miner, 1=protocol, 2+=user txs
      // FIX: Use pointer for tx to avoid copy that corrupts tx.extra
      struct TxWithIndices {
        const cryptonote::transaction *tx_ptr; // Pointer to avoid copy
        std::string blob;
        std::vector<uint64_t> output_indices;
        bool is_coinbase;
      };
      std::vector<TxWithIndices> txs;
      std::vector<cryptonote::transaction>
          user_txs_storage; // Storage for parsed user txs
      txs.reserve(2 + block_entry.txs.size());
      user_txs_storage.reserve(block_entry.txs.size());

      // 1. Miner tx - use pointer to original (no copy!)
      {
        TxWithIndices miner_tx_entry;
        miner_tx_entry.tx_ptr = &blk.miner_tx;
        miner_tx_entry.blob = cryptonote::tx_to_blob(blk.miner_tx);
        miner_tx_entry.is_coinbase = true;
        if (has_output_indices && block_idx < res.output_indices.size() &&
            !res.output_indices[block_idx].indices.empty()) {
          miner_tx_entry.output_indices =
              res.output_indices[block_idx].indices[0].indices;
        }
        txs.push_back(std::move(miner_tx_entry));
      }

      // 2. Protocol tx - use pointer to original (no copy!)
      if (blk.protocol_tx.vout.size() > 0) {
        TxWithIndices protocol_tx_entry;
        protocol_tx_entry.tx_ptr = &blk.protocol_tx;
        protocol_tx_entry.blob = cryptonote::tx_to_blob(blk.protocol_tx);
        protocol_tx_entry.is_coinbase = true;
        if (has_output_indices && block_idx < res.output_indices.size() &&
            res.output_indices[block_idx].indices.size() > 1) {
          protocol_tx_entry.output_indices =
              res.output_indices[block_idx].indices[1].indices;
        }
        txs.push_back(std::move(protocol_tx_entry));
      }

      // 3. User txs - parse and store, use pointers
      for (size_t tx_idx = 0; tx_idx < block_entry.txs.size(); ++tx_idx) {
        cryptonote::transaction tx;
        bool parsed = cryptonote::parse_and_validate_tx_from_blob(
            block_entry.txs[tx_idx].blob, tx);
        if (!parsed) {
          parsed = parse_audit_tx_minimal(block_entry.txs[tx_idx].blob, tx);
        }

        if (parsed) {
          user_txs_storage.push_back(std::move(tx));
          TxWithIndices user_tx_entry;
          user_tx_entry.tx_ptr = &user_txs_storage.back();
          user_tx_entry.blob = block_entry.txs[tx_idx].blob;
          user_tx_entry.is_coinbase = false;
          size_t indices_idx = tx_idx + 2;
          if (has_output_indices && block_idx < res.output_indices.size() &&
              indices_idx < res.output_indices[block_idx].indices.size()) {
            user_tx_entry.output_indices =
                res.output_indices[block_idx].indices[indices_idx].indices;
          }
          txs.push_back(std::move(user_tx_entry));
          global_user_tx_parsed++;
        } else {
          // std::cout << "DEBUG: [convert_epee_to_csp_with_index] Failed to "
          //              "parse tx in block "
          //           << block_height
          //           << ". Blob size: " << block_entry.txs[tx_idx].blob.size()
          //           << std::endl;
        }
      }

      // Process each transaction
      for (const auto &tx_entry : txs) {
        const auto &tx = *tx_entry.tx_ptr;
        bool is_coinbase = tx_entry.is_coinbase;

        if (tx.vout.empty())
          continue;

        crypto::public_key tx_pub_key =
            cryptonote::get_tx_pub_key_from_extra(tx);

        // CSP v3+: Get additional tx pubkeys for subaddress outputs
        std::vector<crypto::public_key> additional_tx_pub_keys =
            cryptonote::get_additional_tx_pub_keys_from_extra(tx);
        bool has_valid_additional =
            !additional_tx_pub_keys.empty() &&
            additional_tx_pub_keys.size() == tx.vout.size();

        // Carrot v1: extract per-output enote ephemeral pubkeys (D_e) from the
        // Carrot-specific tx.extra (required for coinbase/protocol Carrot
        // outputs).
        const bool is_carrot_tx = carrot::is_carrot_transaction_v1(tx);
        std::vector<mx25519_pubkey> carrot_ephemeral_pubkeys;
        std::optional<carrot::encrypted_payment_id_t>
            carrot_encrypted_payment_id;
        const bool carrot_extra_loaded =
            is_carrot_tx &&
            carrot::try_load_carrot_extra_v1(tx.extra, carrot_ephemeral_pubkeys,
                                             carrot_encrypted_payment_id);
        const bool has_valid_carrot_ephemeral =
            carrot_extra_loaded &&
            (carrot_ephemeral_pubkeys.size() == tx.vout.size() ||
             carrot_ephemeral_pubkeys.size() == 1); // Accept shared D_e too
        // v6.0.3 FIX: Detect shared D_e case (1 pubkey for multiple outputs)
        const bool is_shared_carrot_ephemeral =
            carrot_extra_loaded && carrot_ephemeral_pubkeys.size() == 1 &&
            tx.vout.size() > 1;

        // v5.19.0 FIX: Carrot transactions may have NO tag 0x01 tx_pub_key!
        // For pure Carrot transactions (post-HF10), all derivation keys are
        // stored as Carrot ephemeral pubkeys via try_load_carrot_extra_v1().
        // If tx_pub_key is null but we have valid Carrot ephemeral pubkeys,
        // use the first D_e as the tx_pub_key for CSP record purposes.
        if (tx_pub_key == crypto::null_pkey) {
          if (has_valid_carrot_ephemeral && !carrot_ephemeral_pubkeys.empty()) {
            // Use first Carrot D_e as fallback tx_pub_key
            std::memcpy(&tx_pub_key.data, carrot_ephemeral_pubkeys[0].data, 32);
          } else if (has_valid_additional && !additional_tx_pub_keys.empty()) {
            // Fallback to first additional pubkey for non-Carrot txs
            tx_pub_key = additional_tx_pub_keys[0];
          } else {
            // No derivation key available - skip transaction
            continue;
          }
        }

        // CSP v6: Collect ALL input key_images for spent output detection
        // Also provides first_key_image for Carrot RingCT input_context.
        std::vector<crypto::key_image> input_key_images;
        if (!tx_entry.is_coinbase && !tx.vin.empty()) {
          input_key_images.reserve(tx.vin.size());
          for (const auto &vin : tx.vin) {
            if (auto *txin = boost::get<cryptonote::txin_to_key>(&vin)) {
              input_key_images.push_back(txin->k_image);
            }
          }
        }

        global_tx_count++;

        // CSP v6: Write tx_pub_key + block_height + is_coinbase +
        // [input_count + input_key_images[] for non-coinbase] + output_count +
        // outputs
        csp_buffer.append(reinterpret_cast<const char *>(&tx_pub_key), 32);

        // Block height (4 bytes, uint32 LE) - for Carrot input_context
        uint32_t height32 = static_cast<uint32_t>(block_height);
        csp_buffer.append(reinterpret_cast<const char *>(&height32), 4);

        // CSP v4+: is_coinbase flag (1 byte)
        uint8_t is_coinbase_byte = tx_entry.is_coinbase ? 1 : 0;
        csp_buffer.push_back(static_cast<char>(is_coinbase_byte));

        // CSP v6: input_count (2) + all key_images (32 each) for non-coinbase
        if (!tx_entry.is_coinbase) {
          uint16_t input_count = static_cast<uint16_t>(
              std::min<size_t>(input_key_images.size(), 0xFFFF));
          csp_buffer.append(reinterpret_cast<const char *>(&input_count), 2);
          for (uint16_t i = 0; i < input_count; i++) {
            csp_buffer.append(
                reinterpret_cast<const char *>(&input_key_images[i]), 32);
          }
        }

        uint16_t out_count = static_cast<uint16_t>(tx.vout.size());
        csp_buffer.append(reinterpret_cast<const char *>(&out_count), 2);

        for (size_t i = 0; i < tx.vout.size(); i++) {
          const auto &out = tx.vout[i];
          crypto::public_key output_key;
          uint8_t output_type = 0; // 0=no_tag, 1=tagged_key, 2=carrot_v1
          uint8_t view_tag_bytes[4] = {0, 0, 0, 0};

          if (auto *key_ptr =
                  boost::get<cryptonote::txout_to_key>(&out.target)) {
            output_key = key_ptr->key;
            output_type = 0;
          } else if (auto *tagged_ptr =
                         boost::get<cryptonote::txout_to_tagged_key>(
                             &out.target)) {
            output_key = tagged_ptr->key;
            output_type = 1;
            view_tag_bytes[0] = tagged_ptr->view_tag.data;
          } else if (auto *carrot_ptr =
                         boost::get<cryptonote::txout_to_carrot_v1>(
                             &out.target)) {
            output_key = carrot_ptr->key;
            output_type = 2;
            view_tag_bytes[0] = carrot_ptr->view_tag.bytes[0];
            view_tag_bytes[1] = carrot_ptr->view_tag.bytes[1];
            view_tag_bytes[2] = carrot_ptr->view_tag.bytes[2];
            global_carrot_count++;
          } else {
            output_key = crypto::null_pkey;
            output_type = 0;
          }

          // CSP v3: OutputKey (32) + OutputType (1) + ViewTag (4) +
          // HasAdditional (1) + [AdditionalPubkey (32)]
          csp_buffer.append(reinterpret_cast<const char *>(&output_key), 32);
          csp_buffer.push_back(static_cast<char>(output_type));
          csp_buffer.append(reinterpret_cast<const char *>(view_tag_bytes), 4);

          // CSP v3: Additional pubkey field
          // - Legacy: per-output additional tx pubkey for subaddress derivation
          // - Carrot: per-output D_e (mx25519 pubkey bytes) for view-tag
          // computation
          uint8_t has_additional = 0;
          const char *additional_ptr = nullptr;

          if (output_type == 2 && has_valid_carrot_ephemeral) {
            has_additional = 1;
            // v6.0.3 FIX: For shared D_e, use index 0 for all outputs
            size_t ephemeral_idx = is_shared_carrot_ephemeral ? 0 : i;
            additional_ptr = reinterpret_cast<const char *>(
                carrot_ephemeral_pubkeys[ephemeral_idx].data);
          } else if (has_valid_additional) {
            has_additional = 1;
            additional_ptr =
                reinterpret_cast<const char *>(&additional_tx_pub_keys[i]);
          }

          csp_buffer.push_back(static_cast<char>(has_additional));
          if (has_additional && additional_ptr) {
            csp_buffer.append(additional_ptr, 32);
          }

          global_output_count++;
        }

        // TXI v3: Write
        // [BlockHeight:4][TxHash:32][OutputIndexCount:2][OutputIndices:4*count][TxBlobSize:4][TxBlob]
        index_buffer.append(reinterpret_cast<const char *>(&height32), 4);

        // Compute and write tx hash (32 bytes) - required for sparse extraction
        crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);
        index_buffer.append(reinterpret_cast<const char *>(&tx_hash), 32);

        uint16_t idx_count =
            static_cast<uint16_t>(tx_entry.output_indices.size());
        index_buffer.append(reinterpret_cast<const char *>(&idx_count), 2);

        for (uint64_t idx : tx_entry.output_indices) {
          uint32_t idx32 = static_cast<uint32_t>(idx);
          index_buffer.append(reinterpret_cast<const char *>(&idx32), 4);
        }

        uint32_t blob_size = static_cast<uint32_t>(tx_entry.blob.size());
        index_buffer.append(reinterpret_cast<const char *>(&blob_size), 4);
        index_buffer.append(tx_entry.blob);
      }
    }

    // Finalize headers
    memcpy(&csp_buffer[tx_count_offset], &global_tx_count, 4);
    memcpy(&index_buffer[index_count_offset], &global_tx_count, 4);

    // Allocate output buffers
    uintptr_t csp_ptr =
        reinterpret_cast<uintptr_t>(new uint8_t[csp_buffer.size()]);
    uintptr_t index_ptr =
        reinterpret_cast<uintptr_t>(new uint8_t[index_buffer.size()]);

    if (!csp_ptr || !index_ptr) {
      if (csp_ptr)
        delete[] reinterpret_cast<uint8_t *>(csp_ptr);
      if (index_ptr)
        delete[] reinterpret_cast<uint8_t *>(index_ptr);
      return "{\"error\":\"allocation failed\"}";
    }

    memcpy(reinterpret_cast<void *>(csp_ptr), csp_buffer.data(),
           csp_buffer.size());
    memcpy(reinterpret_cast<void *>(index_ptr), index_buffer.data(),
           index_buffer.size());

    auto total_end = std::chrono::high_resolution_clock::now();
    double total_ms =
        std::chrono::duration<double, std::milli>(total_end - total_start)
            .count();

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "{"
        << "\"csp_ptr\":" << csp_ptr << ","
        << "\"csp_size\":" << csp_buffer.size() << ","
        << "\"csp_version\":6,"
        << "\"index_ptr\":" << index_ptr << ","
        << "\"index_size\":" << index_buffer.size() << ","
        << "\"tx_count\":" << global_tx_count << ","
        << "\"output_count\":" << global_output_count << ","
        << "\"carrot_count\":" << global_carrot_count << ","
        << "\"user_tx_count\":" << global_user_tx_count << ","
        << "\"user_tx_parsed\":" << global_user_tx_parsed << ","
        << "\"blocks_count\":" << res.blocks.size() << ","
        << "\"epee_size\":" << epee_size << ","
        << "\"has_output_indices\":" << (has_output_indices ? "true" : "false")
        << ","
        << "\"csp_ratio\":"
        << (epee_size > 0
                ? static_cast<double>(csp_buffer.size()) / epee_size * 100
                : 0)
        << ","
        << "\"index_ratio\":"
        << (epee_size > 0
                ? static_cast<double>(index_buffer.size()) / epee_size * 100
                : 0)
        << ","
        << "\"convert_ms\":" << total_ms << ","
        << "\"txi_version\":3,"
        << "\"success\":true"
        << "}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"error\":\"unknown exception\"}";
  }
}

/**
 * extract_key_images - Extract all input key images from Epee binary blocks
 *
 * Used for building the server-side Key Image Index (Spent Output Index).
 * This maps KeyImage -> TxHash, allowing the wallet to instantly check
 * if its outputs have been spent without re-scanning the chain.
 *
 * @param epee_ptr Pointer to getblocks.bin response in WASM heap
 * @param epee_size Size of Epee buffer
 * @param start_height_d Starting block height
 * @return JSON with key images: { key_images: [{key_image, tx_hash, height},
 * ...] }
 */
std::string extract_key_images(uintptr_t epee_ptr, size_t epee_size,
                               double start_height_d) {
  uint64_t start_height = static_cast<uint64_t>(start_height_d);

  if (epee_ptr == 0 || epee_size < 10) {
    return "{\"error\":\"invalid epee buffer\"}";
  }

  // Convert pointer to string (epee uses std::string for binary data)
  const std::string epee_data(reinterpret_cast<const char *>(epee_ptr),
                              epee_size);

  // Parse Epee response
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
  bool parsed = epee::serialization::load_t_from_binary(res, epee_data);

  if (!parsed) {
    return "{\"error\":\"epee parse failed\"}";
  }

  std::ostringstream json;
  json << "{\"success\":true,\"stats\":{\"blocks_parsed\":" << res.blocks.size()
       << "},\"key_images\":[";

  bool first = true;
  uint64_t current_height = start_height;

  for (const auto &block_entry : res.blocks) {
    // Parse block to determine base index (miner=0, protocol=1?)
    cryptonote::block blk;
    if (!cryptonote::parse_and_validate_block_from_blob(block_entry.block,
                                                        blk)) {
      current_height++;
      continue;
    }

    // Miner TX is always index 0
    // Protocol TX is index 1 if it has outputs
    size_t protocol_offset = (blk.protocol_tx.vout.size() > 0) ? 1 : 0;
    size_t user_tx_base_index = 1 + protocol_offset;

    // We only care about user transactions for key images (miner txs have no
    // inputs)
    for (size_t i = 0; i < block_entry.txs.size(); ++i) {
      const auto &tx_blob_entry = block_entry.txs[i];
      cryptonote::transaction tx;

      if (cryptonote::parse_and_validate_tx_from_blob(tx_blob_entry.blob, tx)) {

        crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);
        std::string tx_hash_str = epee::string_tools::pod_to_hex(tx_hash);
        uint64_t tx_index = user_tx_base_index + i;

        // Iterate over inputs to find Key Images
        for (const auto &vin : tx.vin) {
          if (vin.type() == typeid(cryptonote::txin_to_key)) {
            const auto &in_to_key = boost::get<cryptonote::txin_to_key>(vin);

            if (!first)
              json << ",";
            first = false;

            std::string ki_str =
                epee::string_tools::pod_to_hex(in_to_key.k_image);

            json << "{\"key_image\":\"" << ki_str << "\","
                 << "\"tx_hash\":\"" << tx_hash_str << "\","
                 << "\"height\":" << current_height << ","
                 << "\"tx_index\":" << tx_index << "}";
          }
        }
      }
    }
    current_height++;
  }

  json << "]}";
  return json.str();
}

// ============================================================================
// INSPECT EPEE BLOCK - Debug function to inspect TX count at specific height
// ============================================================================
/**
 * Inspect Epee data to see how many TXs are at a specific block height.
 * This helps diagnose if getblocks.bin is returning all TXs.
 */
std::string inspect_epee_block(uintptr_t epee_ptr, size_t epee_size,
                               double start_height_d, double target_height_d) {
  try {
    uint64_t start_height = static_cast<uint64_t>(start_height_d);
    uint64_t target_height = static_cast<uint64_t>(target_height_d);

    if (epee_ptr == 0 || epee_size < 10) {
      return "{\"error\":\"invalid epee buffer\"}";
    }

    const std::string epee_data(reinterpret_cast<const char *>(epee_ptr),
                                epee_size);

    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
    bool parsed = epee::serialization::load_t_from_binary(res, epee_data);

    if (!parsed) {
      return "{\"error\":\"epee parse failed\"}";
    }

    // Find the target block
    uint64_t block_idx = target_height - start_height;
    if (block_idx >= res.blocks.size()) {
      std::ostringstream oss;
      oss << "{\"error\":\"target height " << target_height
          << " not in range (only " << res.blocks.size()
          << " blocks starting at " << start_height << ")\"}";
      return oss.str();
    }

    const auto &block_entry = res.blocks[block_idx];

    cryptonote::block blk;
    if (!cryptonote::parse_and_validate_block_from_blob(block_entry.block,
                                                        blk)) {
      return "{\"error\":\"block parse failed\"}";
    }

    // Collect TX pubkeys
    std::vector<std::string> tx_pubkeys;
    std::vector<size_t> user_tx_blob_sizes;
    std::vector<std::string>
        user_tx_blob_headers; // First 16 bytes of each blob
    uint32_t parse_successes = 0;
    uint32_t parse_failures = 0;

    // Miner TX
    crypto::public_key miner_pubkey =
        cryptonote::get_tx_pub_key_from_extra(blk.miner_tx);
    std::ostringstream miner_hex;
    for (size_t i = 0; i < 32; i++)
      miner_hex << std::hex << std::setfill('0') << std::setw(2)
                << (int)(unsigned char)miner_pubkey.data[i];
    tx_pubkeys.push_back(miner_hex.str());

    // Protocol TX
    crypto::public_key protocol_pubkey =
        cryptonote::get_tx_pub_key_from_extra(blk.protocol_tx);
    std::ostringstream protocol_hex;
    for (size_t i = 0; i < 32; i++)
      protocol_hex << std::hex << std::setfill('0') << std::setw(2)
                   << (int)(unsigned char)protocol_pubkey.data[i];
    tx_pubkeys.push_back(protocol_hex.str());

    // Detailed parsing diagnostics per TX
    std::vector<std::string> parse_diagnostics;

    // User TXs
    for (const auto &tx_blob_entry : block_entry.txs) {
      user_tx_blob_sizes.push_back(tx_blob_entry.blob.size());

      // Capture first 16 bytes of blob for debugging
      std::ostringstream header_hex;
      for (size_t i = 0; i < std::min(size_t(16), tx_blob_entry.blob.size());
           i++) {
        header_hex << std::hex << std::setfill('0') << std::setw(2)
                   << (int)(unsigned char)tx_blob_entry.blob[i];
      }
      user_tx_blob_headers.push_back(header_hex.str());

      std::ostringstream diag;

      // Try full parse first
      cryptonote::transaction tx;
      if (cryptonote::parse_and_validate_tx_from_blob(tx_blob_entry.blob, tx)) {
        crypto::public_key user_pubkey =
            cryptonote::get_tx_pub_key_from_extra(tx);
        std::ostringstream user_hex;
        for (size_t i = 0; i < 32; i++)
          user_hex << std::hex << std::setfill('0') << std::setw(2)
                   << (int)(unsigned char)user_pubkey.data[i];
        tx_pubkeys.push_back(user_hex.str());
        parse_successes++;

        diag << "OK:v=" << tx.version << ",vin=" << tx.vin.size()
             << ",vout=" << tx.vout.size()
             << ",rct=" << (int)tx.rct_signatures.type
             << ",outPk=" << tx.rct_signatures.outPk.size();
      } else {
        tx_pubkeys.push_back("PARSE_FAILED");
        parse_failures++;

        // Try prefix-only parse to see where failure occurs
        cryptonote::transaction_prefix tx_prefix;
        binary_archive<false> ba_prefix{
            epee::strspan<std::uint8_t>(tx_blob_entry.blob)};
        bool prefix_ok = ::serialization::serialize_noeof(ba_prefix, tx_prefix);

        if (prefix_ok) {
          diag << "FAIL:v=" << tx_prefix.version
               << ",vin=" << tx_prefix.vin.size()
               << ",vout=" << tx_prefix.vout.size()
               << ",type=" << (int)tx_prefix.type
               << ",blobsz=" << tx_blob_entry.blob.size();

          // Get prefix size so we know where RCT starts
          size_t prefix_bytes_read = ba_prefix.getpos();
          diag << ",prefix_sz=" << prefix_bytes_read;

          // Try to manually read RCT sig base parts
          try {
            // Create a sub-blob starting after the prefix
            std::string rct_blob(tx_blob_entry.blob.begin() + prefix_bytes_read,
                                 tx_blob_entry.blob.end());
            binary_archive<false> ba_rct{epee::strspan<std::uint8_t>(rct_blob)};

            // Read type
            uint8_t rct_type;
            ba_rct.serialize_varint(rct_type);
            diag << ",rct=" << (int)rct_type;

            // txnFee
            uint64_t fee;
            ba_rct.serialize_varint(fee);
            diag << ",fee=" << fee;

            // ecdhInfo (outputs count)
            for (size_t i = 0; i < tx_prefix.vout.size(); i++) {
              rct::key amount_enc;
              for (size_t j = 0; j < 8; j++) {
                ba_rct.serialize_blob(&amount_enc.bytes[j], 1);
              }
            }
            diag << ",ecdh_ok";

            // outPk (outputs count)
            for (size_t i = 0; i < tx_prefix.vout.size(); i++) {
              rct::key mask;
              ba_rct.serialize_blob(mask.bytes, 32);
            }
            diag << ",outPk_ok";

            // p_r (32 bytes)
            rct::key p_r;
            ba_rct.serialize_blob(p_r.bytes, 32);
            diag << ",p_r_ok";

            // salvium_data - type
            uint8_t salvium_type;
            ba_rct.serialize_varint(salvium_type);
            diag << ",salvium_type=" << (int)salvium_type;

            // pr_proof (96 bytes - 3 keys)
            rct::key pr_R, pr_z1, pr_z2;
            ba_rct.serialize_blob(pr_R.bytes, 32);
            ba_rct.serialize_blob(pr_z1.bytes, 32);
            ba_rct.serialize_blob(pr_z2.bytes, 32);
            diag << ",pr_proof_ok";

            // sa_proof (96 bytes - 3 keys)
            rct::key sa_R, sa_z1, sa_z2;
            ba_rct.serialize_blob(sa_R.bytes, 32);
            ba_rct.serialize_blob(sa_z1.bytes, 32);
            ba_rct.serialize_blob(sa_z2.bytes, 32);
            diag << ",sa_proof_ok";

            // If SalviumZeroAudit, read additional fields
            if (salvium_type == 1) { // SalviumZeroAudit
              // cz_proof (96 bytes)
              rct::key cz_R, cz_z1, cz_z2;
              ba_rct.serialize_blob(cz_R.bytes, 32);
              ba_rct.serialize_blob(cz_z1.bytes, 32);
              ba_rct.serialize_blob(cz_z2.bytes, 32);
              diag << ",cz_proof_ok";

              // input_verification_data vector count
              uint64_t ivd_count;
              ba_rct.serialize_varint(ivd_count);
              diag << ",ivd_count=" << ivd_count;

              // Read each input_verification_data entry
              bool ivd_ok = true;
              for (size_t vi = 0; vi < ivd_count && ivd_ok; vi++) {
                // aR (key_derivation = 32 bytes)
                crypto::key_derivation aR;
                ba_rct.serialize_blob(aR.data, 32);

                // amount (varint)
                uint64_t amount;
                ba_rct.serialize_varint(amount);

                // i (varint)
                uint64_t i_val;
                ba_rct.serialize_varint(i_val);

                // origin_tx_type (varint)
                uint64_t origin_tx_type;
                ba_rct.serialize_varint(origin_tx_type);

                // If origin_tx_type != UNSET (0), read additional fields
                if (origin_tx_type != 0) {
                  crypto::key_derivation aR_stake;
                  ba_rct.serialize_blob(aR_stake.data, 32);

                  uint64_t i_stake;
                  ba_rct.serialize_varint(i_stake);
                }
              }
              if (ivd_ok) {
                diag << ",ivd_read_ok,pos_after_ivd=" << ba_rct.getpos();
              }

              // spend_pubkey (32 bytes)
              crypto::public_key spend_pk;
              ba_rct.serialize_blob(spend_pk.data, 32);
              diag << ",spend_pk_ok";

              // enc_view_privkey_str - variable length string
              uint64_t str_len;
              ba_rct.serialize_varint(str_len);
              diag << ",enc_str_len=" << str_len;

              // Actually read the string bytes
              if (str_len <= 500 && str_len > 0) {
                std::string enc_str(str_len, '\0');
                for (size_t si = 0; si < str_len; si++) {
                  ba_rct.serialize_blob(&enc_str[si], 1);
                }
                diag << ",enc_str_read_ok";
              }

              diag << ",pos=" << ba_rct.getpos() << ",remain="
                   << (tx_blob_entry.blob.size() - prefix_bytes_read -
                       ba_rct.getpos());
            }
          } catch (...) {
            diag << "|MANUAL_PARSE_EXCEPTION";
          }

          // Now try actual serialize_base
          cryptonote::transaction tx_base;
          binary_archive<false> ba_base{
              epee::strspan<std::uint8_t>(tx_blob_entry.blob)};
          bool base_ok = tx_base.serialize_base(ba_base);

          if (base_ok) {
            diag << "|BASE_OK,final_pos=" << ba_base.getpos();
          } else {
            diag << "|BASE_FAIL,failed_at=" << ba_base.getpos();

            // Try our fallback minimal parser for AUDIT txs
            cryptonote::transaction tx_minimal;
            if (parse_audit_tx_minimal(tx_blob_entry.blob, tx_minimal)) {
              diag << "|MINIMAL_OK,type=" << (int)tx_minimal.type
                   << ",vout=" << tx_minimal.vout.size()
                   << ",outPk=" << tx_minimal.rct_signatures.outPk.size();
            } else {
              diag << "|MINIMAL_FAIL";
            }
          }
        } else {
          diag << "FAIL_PREFIX";
        }
      }
      parse_diagnostics.push_back(diag.str());
    }

    std::ostringstream oss;
    oss << "{"
        << "\"height\":" << target_height << ","
        << "\"start_height\":" << start_height << ","
        << "\"block_idx\":" << block_idx << ","
        << "\"total_blocks\":" << res.blocks.size() << ","
        << "\"user_tx_count_in_epee\":" << block_entry.txs.size() << ","
        << "\"user_tx_parse_successes\":" << parse_successes << ","
        << "\"user_tx_parse_failures\":" << parse_failures << ","
        << "\"miner_tx_outputs\":" << blk.miner_tx.vout.size() << ","
        << "\"protocol_tx_outputs\":" << blk.protocol_tx.vout.size() << ","
        << "\"user_tx_blob_sizes\":[";

    for (size_t i = 0; i < user_tx_blob_sizes.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << user_tx_blob_sizes[i];
    }

    oss << "],\"user_tx_blob_headers\":[";

    for (size_t i = 0; i < user_tx_blob_headers.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << "\"" << user_tx_blob_headers[i] << "\"";
    }

    oss << "],\"tx_pubkeys\":[";

    for (size_t i = 0; i < tx_pubkeys.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << "\"" << tx_pubkeys[i] << "\"";
    }

    oss << "],\"parse_diagnostics\":[";

    for (size_t i = 0; i < parse_diagnostics.size(); i++) {
      if (i > 0)
        oss << ",";
      oss << "\"" << parse_diagnostics[i] << "\"";
    }

    oss << "],"
        << "\"success\":true"
        << "}";

    return oss.str();

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"error\":\"unknown exception\"}";
  }
}

// ============================================================================
// SPARSE TRANSACTION EXTRACTION
// Extract only specific transactions by index from an Epee blob.
// This dramatically reduces bandwidth for targeted rescan - download ~8MB
// instead of ~2GB when 96% of chunks have view tag matches.
// ============================================================================

/**
 * Extract specific transactions from an Epee getblocks.bin response.
 *
 * @param ptr - Pointer to Epee binary data in WASM heap
 * @param epee_size - Size of Epee data in bytes
 * @param indices_json - JSON array of transaction indices to extract, e.g. "[4,
 * 12, 155]"
 * @param start_height - Starting block height (for response metadata)
 *
 * @returns JSON with pointer to sparse binary data:
 *   {
 *     "ptr": <heap pointer>,
 *     "size": <bytes>,
 *     "tx_count": <number of extracted txs>,
 *     "success": true
 *   }
 *
 * Sparse format v2 (includes output indices for wallet scanning):
 *   [TxCount:4] + for each tx:
 *     [GlobalIndex:4][BlockHeight:4][OutputIndexCount:2][OutputIndices:4*count][TxSize:4][TxBlob:variable]
 *
 * The output indices are REQUIRED for process_new_transaction() to work
 * correctly.
 */
std::string extract_sparse_txs(uintptr_t ptr, size_t epee_size,
                               const std::string &indices_json,
                               double start_height_d) {
  try {
    // Convert double to uint64_t for internal use
    uint64_t start_height = static_cast<uint64_t>(start_height_d);

    // Parse requested indices from JSON array
    std::set<uint32_t> requested_indices;

    // Simple JSON array parser for "[1,2,3]" format
    size_t pos = indices_json.find('[');
    if (pos == std::string::npos) {
      return "{\"error\":\"Invalid indices JSON - expected array\"}";
    }

    std::string nums = indices_json.substr(pos + 1);
    size_t end = nums.find(']');
    if (end != std::string::npos) {
      nums = nums.substr(0, end);
    }

    // Parse comma-separated integers
    std::istringstream iss(nums);
    std::string token;
    while (std::getline(iss, token, ',')) {
      // Trim whitespace
      token.erase(0, token.find_first_not_of(" \t"));
      token.erase(token.find_last_not_of(" \t") + 1);
      if (!token.empty()) {
        requested_indices.insert(static_cast<uint32_t>(std::stoul(token)));
      }
    }

    if (requested_indices.empty()) {
      return "{\"error\":\"No valid indices provided\"}";
    }

    // Parse Epee blob using Monero's native parser
    const uint8_t *epee_data = reinterpret_cast<const uint8_t *>(ptr);
    std::string epee_str(reinterpret_cast<const char *>(epee_data), epee_size);

    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
    if (!epee::serialization::load_t_from_binary(res, epee_str)) {
      return "{\"error\":\"Failed to parse Epee data\"}";
    }

    // Check for output indices and asset indices
    bool has_output_indices = !res.output_indices.empty();
    bool has_asset_indices = !res.asset_type_output_indices.empty();

    // Build sparse output buffer
    // Format v6 (SPR6): [SPR6][TxCount:4] + for each tx:
    //   [GlobalIndex:4][BlockHeight:4][Timestamp:8][BlockVersion:1][TxHash:32]
    //   [OutputIndexCount:2][OutputIndices:4*count]
    //   [AssetIndexCount:2][AssetIndices:4*count]
    //   [TxSize:4][TxBlob:variable]
    std::string sparse_buffer;
    sparse_buffer.reserve(1024 * 1024); // 1MB initial reserve

    // Write SPR6 header
    sparse_buffer.append("SPR6", 4);

    // Reserve space for tx count header
    uint32_t tx_count = 0;
    sparse_buffer.append(4, '\0'); // Placeholder for tx_count

    // Global transaction index counter
    uint32_t global_tx_index = 0;

    // Process each block - SAME ORDER as convert_epee_to_csp
    for (size_t block_idx = 0; block_idx < res.blocks.size(); ++block_idx) {
      const auto &block_entry = res.blocks[block_idx];
      uint64_t block_height = start_height + block_idx;

      // Parse block to get miner tx and timestamp and VERSION
      cryptonote::block blk;
      if (!cryptonote::parse_and_validate_block_from_blob(block_entry.block,
                                                          blk)) {
        continue; // Skip malformed blocks (same as CSP generation)
      }
      uint64_t block_timestamp = blk.timestamp;
      uint8_t block_version = blk.major_version;

      // Collect all transactions with their output indices
      // tx_idx in output_indices: 0=miner, 1=protocol, 2+=user txs
      struct TxWithMeta {
        const cryptonote::transaction *tx_ptr;
        std::string blob;
        std::vector<uint64_t> output_indices;
        std::vector<uint64_t> asset_indices;
        crypto::hash tx_hash;
        bool has_hash;
      };
      std::vector<TxWithMeta> txs;
      std::vector<cryptonote::transaction> user_txs_storage;
      txs.reserve(2 + block_entry.txs.size());
      user_txs_storage.reserve(block_entry.txs.size());

      // Miner tx
      {
        TxWithMeta miner_tx_entry;
        miner_tx_entry.tx_ptr = &blk.miner_tx;
        miner_tx_entry.blob = cryptonote::tx_to_blob(blk.miner_tx);
        miner_tx_entry.tx_hash = cryptonote::get_transaction_hash(blk.miner_tx);
        miner_tx_entry.has_hash = true;

        if (has_output_indices && block_idx < res.output_indices.size() &&
            !res.output_indices[block_idx].indices.empty()) {
          miner_tx_entry.output_indices =
              res.output_indices[block_idx].indices[0].indices;
        }
        if (has_asset_indices &&
            block_idx < res.asset_type_output_indices.size() &&
            !res.asset_type_output_indices[block_idx].indices.empty()) {
          miner_tx_entry.asset_indices =
              res.asset_type_output_indices[block_idx].indices[0].indices;
        }
        txs.push_back(std::move(miner_tx_entry));
      }

      // Protocol tx
      if (blk.protocol_tx.vout.size() > 0) {
        TxWithMeta protocol_tx_entry;
        protocol_tx_entry.tx_ptr = &blk.protocol_tx;
        protocol_tx_entry.blob = cryptonote::tx_to_blob(blk.protocol_tx);
        protocol_tx_entry.tx_hash =
            cryptonote::get_transaction_hash(blk.protocol_tx);
        protocol_tx_entry.has_hash = true;

        if (has_output_indices && block_idx < res.output_indices.size() &&
            res.output_indices[block_idx].indices.size() > 1) {
          protocol_tx_entry.output_indices =
              res.output_indices[block_idx].indices[1].indices;
        }
        if (has_asset_indices &&
            block_idx < res.asset_type_output_indices.size() &&
            res.asset_type_output_indices[block_idx].indices.size() > 1) {
          protocol_tx_entry.asset_indices =
              res.asset_type_output_indices[block_idx].indices[1].indices;
        }
        txs.push_back(std::move(protocol_tx_entry));
      }

      // User txs
      for (size_t tx_idx = 0; tx_idx < block_entry.txs.size(); ++tx_idx) {
        cryptonote::transaction tx;
        crypto::hash tx_hash;
        // Check if hash is included in parse result (it usually is)
        bool parsed = cryptonote::parse_and_validate_tx_from_blob(
            block_entry.txs[tx_idx].blob, tx, tx_hash);

        if (!parsed) {
          parsed = parse_audit_tx_minimal(block_entry.txs[tx_idx].blob, tx);
          if (parsed) {
            // For manually parsed txs, compute hash
            tx_hash = cryptonote::get_transaction_hash(tx);
          }
        }

        if (parsed) {
          user_txs_storage.push_back(std::move(tx));
          TxWithMeta user_tx_entry;
          user_tx_entry.tx_ptr = &user_txs_storage.back();
          user_tx_entry.blob = block_entry.txs[tx_idx].blob;
          user_tx_entry.tx_hash = tx_hash;
          user_tx_entry.has_hash = true;

          size_t indices_idx = tx_idx + 2;
          if (has_output_indices && block_idx < res.output_indices.size() &&
              indices_idx < res.output_indices[block_idx].indices.size()) {
            user_tx_entry.output_indices =
                res.output_indices[block_idx].indices[indices_idx].indices;
          }
          if (has_asset_indices &&
              block_idx < res.asset_type_output_indices.size() &&
              indices_idx <
                  res.asset_type_output_indices[block_idx].indices.size()) {
            user_tx_entry.asset_indices =
                res.asset_type_output_indices[block_idx]
                    .indices[indices_idx]
                    .indices;
          }
          txs.push_back(std::move(user_tx_entry));
        }
      }

      // Process each transaction
      for (const auto &tx_entry : txs) {
        const auto &tx = *tx_entry.tx_ptr;

        // Skip if no outputs (same as CSP)
        if (tx.vout.empty())
          continue;

        // Get tx_pub_key with same fallback logic as convert_epee_to_csp
        crypto::public_key tx_pub_key =
            cryptonote::get_tx_pub_key_from_extra(tx);

        if (tx_pub_key == crypto::null_pkey) {
          // Try Carrot ephemeral pubkeys first
          const bool is_carrot_tx = carrot::is_carrot_transaction_v1(tx);
          std::vector<mx25519_pubkey> carrot_ephemeral_pubkeys;
          std::optional<carrot::encrypted_payment_id_t>
              carrot_encrypted_payment_id;
          const bool carrot_extra_loaded =
              is_carrot_tx && carrot::try_load_carrot_extra_v1(
                                  tx.extra, carrot_ephemeral_pubkeys,
                                  carrot_encrypted_payment_id);
          const bool has_valid_carrot_ephemeral =
              carrot_extra_loaded &&
              (carrot_ephemeral_pubkeys.size() == tx.vout.size() ||
               carrot_ephemeral_pubkeys.size() == 1);

          if (has_valid_carrot_ephemeral && !carrot_ephemeral_pubkeys.empty()) {
            // Use first Carrot D_e as fallback tx_pub_key
            std::memcpy(&tx_pub_key.data, carrot_ephemeral_pubkeys[0].data, 32);
          } else {
            // Try additional tx pubkeys
            std::vector<crypto::public_key> additional_tx_pub_keys;
            for (size_t pos = 0; pos < tx.extra.size(); pos++) {
              if (tx.extra[pos] == 0x04) { // TX_EXTRA_TAG_ADDITIONAL_PUBKEYS
                size_t count = 0;
                size_t varint_offset = pos + 1;
                size_t shift = 0;
                while (varint_offset < tx.extra.size()) {
                  uint8_t byte = tx.extra[varint_offset++];
                  count |= static_cast<size_t>(byte & 0x7F) << shift;
                  if ((byte & 0x80) == 0)
                    break;
                  shift += 7;
                  if (shift > 63)
                    break;
                }
                if (count > 0 && count <= 256) {
                  size_t pubkeys_start = varint_offset;
                  size_t pubkeys_bytes_needed = count * 32;
                  if (pubkeys_start + pubkeys_bytes_needed <= tx.extra.size()) {
                    additional_tx_pub_keys.reserve(count);
                    for (size_t i = 0; i < count; i++) {
                      crypto::public_key pk;
                      std::memcpy(&pk.data, &tx.extra[pubkeys_start + i * 32],
                                  32);
                      additional_tx_pub_keys.push_back(pk);
                    }
                  }
                }
                break;
              }
            }
            bool has_valid_additional =
                !additional_tx_pub_keys.empty() &&
                additional_tx_pub_keys.size() == tx.vout.size();
            if (has_valid_additional) {
              tx_pub_key = additional_tx_pub_keys[0];
            } else {
              // No derivation key available - skip transaction (same as CSP)
              continue;
            }
          }
        }

        // This transaction IS in the CSP - check if it's requested
        if (requested_indices.count(global_tx_index)) {
          // Write: [GlobalIndex:4]
          sparse_buffer.append(reinterpret_cast<const char *>(&global_tx_index),
                               4);

          // Write: [BlockHeight:4]
          uint32_t height32 = static_cast<uint32_t>(block_height);
          sparse_buffer.append(reinterpret_cast<const char *>(&height32), 4);

          // Write: [Timestamp:8] (SPR6)
          sparse_buffer.append(reinterpret_cast<const char *>(&block_timestamp),
                               8);

          // Write: [BlockVersion:1] (SPR6)
          sparse_buffer.append(reinterpret_cast<const char *>(&block_version),
                               1);

          // Write: [TxHash:32] (SPR6)
          sparse_buffer.append(
              reinterpret_cast<const char *>(&tx_entry.tx_hash), 32);

          // Write: [OutputIndexCount:2]
          uint16_t idx_count =
              static_cast<uint16_t>(tx_entry.output_indices.size());
          sparse_buffer.append(reinterpret_cast<const char *>(&idx_count), 2);

          // Write: [OutputIndices:4*count] (truncate uint64_t to uint32_t)
          for (uint64_t idx : tx_entry.output_indices) {
            uint32_t idx32 = static_cast<uint32_t>(idx);
            sparse_buffer.append(reinterpret_cast<const char *>(&idx32), 4);
          }

          // Write: [AssetIndexCount:2] (SPR5)
          uint16_t asset_idx_count =
              static_cast<uint16_t>(tx_entry.asset_indices.size());
          sparse_buffer.append(reinterpret_cast<const char *>(&asset_idx_count),
                               2);

          // Write: [AssetIndices:4*count]
          for (uint64_t idx : tx_entry.asset_indices) {
            uint32_t idx32 = static_cast<uint32_t>(idx);
            sparse_buffer.append(reinterpret_cast<const char *>(&idx32), 4);
          }

          // Write: [TxSize:4][TxBlob]
          uint32_t tx_size = static_cast<uint32_t>(tx_entry.blob.size());
          sparse_buffer.append(reinterpret_cast<const char *>(&tx_size), 4);
          sparse_buffer.append(tx_entry.blob);

          tx_count++;
        }

        // Increment index ONLY for transactions that were included in CSP
        global_tx_index++;
      }
    }

    // Write actual tx_count to header (after SPR6)
    // Format: [SPR6][TxCount:4]
    memcpy(&sparse_buffer[4], &tx_count, 4);

    // Allocate WASM heap memory for result
    uintptr_t result_ptr =
        reinterpret_cast<uintptr_t>(new uint8_t[sparse_buffer.size()]);
    if (!result_ptr) {
      return "{\"error\":\"Failed to allocate sparse buffer\"}";
    }
    memcpy(reinterpret_cast<void *>(result_ptr), sparse_buffer.data(),
           sparse_buffer.size());

    // Return result as JSON
    std::ostringstream oss;
    oss << "{"
        << "\"ptr\":" << result_ptr << ","
        << "\"size\":" << sparse_buffer.size() << ","
        << "\"tx_count\":" << tx_count << ","
        << "\"requested_count\":" << requested_indices.size() << ","
        << "\"total_scanned\":" << global_tx_index << ","
        << "\"success\":true"
        << "}";

    return oss.str();

  } catch (const std::exception &e) {
    return std::string("{\"error\":\"") + e.what() + "\"}";
  } catch (...) {
    return "{\"error\":\"Unknown error in extract_sparse_txs\"}";
  }
}

/**
 * compare_scalarmult_no_cofactor - Compare scalar*P (without ??8) between ref10
 * and donna64
 *
 * This helps isolate whether the bug is in scalar multiplication or cofactor
 * multiplication. Uses the same test vectors as the main debug function.
 */
std::string compare_scalarmult_no_cofactor() {
  std::ostringstream oss;
  oss << "{";

  try {
    // Test vectors (same as debug)
    static const unsigned char tx_pub[32] = {
        0xe3, 0xe1, 0xe3, 0x52, 0x58, 0xe9, 0xd3, 0x8e, 0x42, 0xd6, 0x77,
        0x65, 0x46, 0xf5, 0x4d, 0x51, 0xfb, 0x2b, 0x5c, 0x33, 0x28, 0xde,
        0x93, 0xac, 0xe2, 0x55, 0xa8, 0x36, 0x5f, 0x58, 0x3b, 0x09};

    static const unsigned char view_sec[32] = {
        0x3e, 0x70, 0x46, 0x15, 0xa5, 0xdf, 0x83, 0xb5, 0x63, 0x71, 0xd5,
        0xc7, 0x05, 0x8e, 0x14, 0x16, 0xb8, 0x46, 0x73, 0x4e, 0x81, 0xa5,
        0x73, 0x2b, 0x3b, 0xf5, 0x91, 0x3e, 0x53, 0x10, 0x32, 0x09};

    // ====================================================================
    // TEST 1: Compute 2*P using ref10
    // ====================================================================
    ge_p3 point_ref10;
    ge_p1p1 t_ref10;
    ge_p2 p2_ref10, p2_doubled_ref10;
    unsigned char ref10_2P[32];

    if (ge_frombytes_vartime(&point_ref10, tx_pub) != 0) {
      oss << "\"error\":\"ref10 ge_frombytes failed\"}";
      return oss.str();
    }

    // Double P: p3 -> p2 -> dbl -> p1p1 -> p2 -> bytes
    ge_p3_to_p2(&p2_ref10, &point_ref10);
    ge_p2_dbl(&t_ref10, &p2_ref10);
    ge_p1p1_to_p2(&p2_doubled_ref10, &t_ref10);
    ge_tobytes(ref10_2P, &p2_doubled_ref10);

    oss << "\"ref10_2P\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2) << (int)ref10_2P[i];
    }
    oss << std::dec << "\",";

    // ====================================================================
    // TEST 2: Compute 2*P using donna64 via precomputation
    // The donna64 precomputed table has pre[1] = 2*P
    // We can extract it via the debug function
    // ====================================================================

    // Run the full trace to populate debug buffers
    int trace_ret = donna64_debug_full_trace();
    oss << "\"trace_ret\":" << trace_ret << ",";

    // Get precomp_2P from debug
    oss << "\"donna64_precomp_2P\":\"";
    for (int i = 0; i < 32; i++) {
      int b = donna64_debug_get_precomp_2P(i);
      oss << std::hex << std::setfill('0') << std::setw(2) << (b & 0xFF);
    }
    oss << std::dec << "\",";

    // Compare
    unsigned char donna64_2P[32];
    for (int i = 0; i < 32; i++) {
      donna64_2P[i] = (unsigned char)donna64_debug_get_precomp_2P(i);
    }
    bool match_2P = (memcmp(ref10_2P, donna64_2P, 32) == 0);
    oss << "\"2P_match\":" << (match_2P ? "true" : "false") << ",";

    // ====================================================================
    // TEST 2.5: Compare scalar decomposition
    // ====================================================================
    // Compute ref10's e[] array
    signed char ref10_e[64];
    {
      int carry = 0, carry2;
      for (int i = 0; i < 31; i++) {
        carry += view_sec[i];
        carry2 = (carry + 8) >> 4;
        ref10_e[2 * i] = carry - (carry2 << 4);
        carry = (carry2 + 8) >> 4;
        ref10_e[2 * i + 1] = carry2 - (carry << 4);
      }
      carry += view_sec[31];
      carry2 = (carry + 8) >> 4;
      ref10_e[62] = carry - (carry2 << 4);
      ref10_e[63] = carry2;
    }

    // Compare with donna64's e[]
    oss << "\"ref10_e\":[";
    for (int i = 0; i < 64; i++) {
      if (i > 0)
        oss << ",";
      oss << (int)ref10_e[i];
    }
    oss << "],";

    oss << "\"donna64_e\":[";
    for (int i = 0; i < 64; i++) {
      if (i > 0)
        oss << ",";
      oss << donna64_debug_get_scalar_e(i);
    }
    oss << "],";

    bool e_match = true;
    int e_first_diff = -1;
    for (int i = 0; i < 64; i++) {
      if ((int)ref10_e[i] != donna64_debug_get_scalar_e(i)) {
        e_match = false;
        e_first_diff = i;
        break;
      }
    }
    oss << "\"e_match\":" << (e_match ? "true" : "false") << ",";
    if (!e_match) {
      oss << "\"e_first_diff\":" << e_first_diff << ",";
    }

    // ====================================================================
    // TEST 3: First iteration comparison (i=63)
    // Since e[63] = 1 (positive), the first iteration should add 1P
    // to identity, giving us 1P as the sum after first iteration.
    // donna64 captures this in donna64_debug_iter0.
    // ====================================================================
    oss << "\"e63\":" << (int)ref10_e[63] << ",";

    // Get donna64 iter0 from debug function (already captured)
    oss << "\"donna64_iter0\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << donna64_debug_get_iter0(i);
    }
    oss << std::dec << "\",";

    // If e[63]=1 (positive), iter0 should equal 1P (the original point)
    // Let's compare iter0 to the original point
    unsigned char donna64_iter0[32];
    for (int i = 0; i < 32; i++) {
      donna64_iter0[i] = (unsigned char)donna64_debug_get_iter0(i);
    }
    bool iter0_equals_P = (memcmp(donna64_iter0, tx_pub, 32) == 0);
    oss << "\"iter0_equals_P\":" << (iter0_equals_P ? "true" : "false") << ",";

    // Get donna64 iter1 (state after iteration 62)
    oss << "\"donna64_iter1\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << donna64_debug_get_iter1(i);
    }
    oss << std::dec << "\",";

    // Get donna64 16P state from iteration 62 (after 4 doublings, before add)
    oss << "\"donna64_iter62_16P\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << donna64_debug_get_iter62_16P(i);
    }
    oss << std::dec << "\",";

    // Get donna64 after_scalarmult from debug function (scalar * P before
    // cofactor) This is what donna64_generate_key_derivation_debug produces
    // BEFORE multiplying by 8
    oss << "\"donna64_debug_after_scalarmult\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << donna64_debug_get_after_scalarmult(i);
    }
    oss << std::dec << "\",";

    // ====================================================================
    // TEST 4: Full scalar mult comparison
    // ====================================================================
    ge_p2 result_p2_ref10;
    unsigned char ref10_result[32];
    ge_scalarmult(&result_p2_ref10, view_sec, &point_ref10);
    ge_tobytes(ref10_result, &result_p2_ref10);

    oss << "\"ref10_scalarmult\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (int)ref10_result[i];
    }
    oss << std::dec << "\",";

    unsigned char donna64_result[32];
    int donna64_ret = donna64_ge_scalarmult(donna64_result, tx_pub, view_sec);

    oss << "\"donna64_ret\":" << donna64_ret << ",";
    oss << "\"donna64_scalarmult\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (int)donna64_result[i];
    }
    oss << std::dec << "\",";

    bool match =
        (donna64_ret == 0) && (memcmp(ref10_result, donna64_result, 32) == 0);
    oss << "\"scalarmult_match\":" << (match ? "true" : "false");

    if (!match && donna64_ret == 0) {
      int first_diff = -1;
      for (int i = 0; i < 32; i++) {
        if (ref10_result[i] != donna64_result[i]) {
          first_diff = i;
          break;
        }
      }
      oss << ",\"first_diff_byte\":" << first_diff;
    }

    oss << "}";

  } catch (const std::exception &e) {
    oss << "\"error\":\"" << e.what() << "\"}";
  }

  return oss.str();
}

/**
 * compute_nP_ref10 - Compute n*P using ref10 for arbitrary small n
 *
 * This computes n*P where n is a decimal string and P is the test tx_pub.
 * Used to verify donna64 intermediate iteration states.
 *
 * @param n_str Decimal string representation of n (can be negative for
 * subtraction)
 * @return JSON with result point as hex
 */
std::string compute_nP_ref10(const std::string &n_str) {
  std::ostringstream oss;
  oss << "{";

  try {
    // Parse n from string (support signed values)
    long long n = std::stoll(n_str);
    bool negative = (n < 0);
    if (negative)
      n = -n;

    // Test point P (same as all other debug functions)
    static const unsigned char tx_pub[32] = {
        0xe3, 0xe1, 0xe3, 0x52, 0x58, 0xe9, 0xd3, 0x8e, 0x42, 0xd6, 0x77,
        0x65, 0x46, 0xf5, 0x4d, 0x51, 0xfb, 0x2b, 0x5c, 0x33, 0x28, 0xde,
        0x93, 0xac, 0xe2, 0x55, 0xa8, 0x36, 0x5f, 0x58, 0x3b, 0x09};

    // Convert n to 32-byte little-endian scalar
    unsigned char scalar[32] = {0};
    unsigned long long temp = (unsigned long long)n;
    for (int i = 0; i < 8 && temp; i++) {
      scalar[i] = temp & 0xFF;
      temp >>= 8;
    }

    // Decompress point
    ge_p3 P;
    if (ge_frombytes_vartime(&P, tx_pub) != 0) {
      oss << "\"error\":\"ge_frombytes failed\"}";
      return oss.str();
    }

    // Compute scalar * P using ref10
    ge_p2 result_p2;
    ge_scalarmult(&result_p2, scalar, &P);

    // Serialize result
    unsigned char result[32];
    ge_tobytes(result, &result_p2);

    // If negative, we need -n*P. For Ed25519, negation flips the x coordinate
    // sign. The compressed form stores y with x-sign in top bit of byte 31.
    if (negative) {
      result[31] ^= 0x80; // Flip the x-coordinate sign bit
    }

    oss << "\"n\":" << (negative ? -n : n) << ",";
    oss << "\"result\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2) << (int)result[i];
    }
    oss << std::dec << "\",";
    oss << "\"success\":true}";

  } catch (const std::exception &e) {
    oss << "\"error\":\"" << e.what() << "\"}";
  }

  return oss.str();
}

/**
 * verify_donna64_iterations - Compute ref10 expected values for donna64
 * iterations
 *
 * For each iteration, compute the expected cumulative scalar and compare
 * with donna64's captured state.
 *
 * @param num_iterations How many iterations to verify (1-64)
 * @return JSON with per-iteration comparison results
 */
std::string verify_donna64_iterations(int num_iterations) {
  std::ostringstream oss;
  oss << "{";

  try {
    if (num_iterations < 1)
      num_iterations = 1;
    if (num_iterations > 64)
      num_iterations = 64;

    // Test vectors
    static const unsigned char tx_pub[32] = {
        0xe3, 0xe1, 0xe3, 0x52, 0x58, 0xe9, 0xd3, 0x8e, 0x42, 0xd6, 0x77,
        0x65, 0x46, 0xf5, 0x4d, 0x51, 0xfb, 0x2b, 0x5c, 0x33, 0x28, 0xde,
        0x93, 0xac, 0xe2, 0x55, 0xa8, 0x36, 0x5f, 0x58, 0x3b, 0x09};

    static const unsigned char view_sec[32] = {
        0x3e, 0x70, 0x46, 0x15, 0xa5, 0xdf, 0x83, 0xb5, 0x63, 0x71, 0xd5,
        0xc7, 0x05, 0x8e, 0x14, 0x16, 0xb8, 0x46, 0x73, 0x4e, 0x81, 0xa5,
        0x73, 0x2b, 0x3b, 0xf5, 0x91, 0x3e, 0x53, 0x10, 0x32, 0x09};

    // Decompress point
    ge_p3 P;
    if (ge_frombytes_vartime(&P, tx_pub) != 0) {
      oss << "\"error\":\"ge_frombytes failed\"}";
      return oss.str();
    }

    // Compute scalar decomposition e[]
    signed char e[64];
    {
      int carry = 0, carry2;
      for (int i = 0; i < 31; i++) {
        carry += view_sec[i];
        carry2 = (carry + 8) >> 4;
        e[2 * i] = carry - (carry2 << 4);
        carry = (carry2 + 8) >> 4;
        e[2 * i + 1] = carry2 - (carry << 4);
      }
      carry += view_sec[31];
      carry2 = (carry + 8) >> 4;
      e[62] = carry - (carry2 << 4);
      e[63] = carry2;
    }

    // Run donna64 full trace to populate debug buffers
    donna64_debug_full_trace();

    // Iterate and compare
    oss << "\"iterations\":[";

    // Use 128-bit arithmetic for cumulative scalar (could overflow 64-bit)
    // Actually for 64 iterations with max digit 8, max scalar is ~8*16^63 which
    // is huge. We need to use the scalar as-is and let ref10 handle the full
    // computation.
    //
    // Alternative approach: compute partial scalar from e[] and use
    // ge_scalarmult The partial scalar after iter_num iterations processing
    // e[63], e[62], ..., e[63-iter_num] can be computed as: partial =
    // e[63]*16^iter_num + e[62]*16^(iter_num-1) + ... + e[63-iter_num]
    //
    // But this gets astronomically large. Instead, we can express the partial
    // result as a scalar multiplication using the FULL original scalar, then
    // compare intermediate states.
    //
    // Actually the simplest approach: for small n, compute n*P directly.
    // For iteration 0: n = e[63] = 1 -> 1*P
    // For iteration 1: n = 16*1 + e[62] = 16 - 7 = 9 -> 9*P
    // For iteration 2: n = 16*9 + e[61] = 144 + 3 = 147 -> 147*P
    // etc.

    int64_t cumulative = 0;
    int first_mismatch = -1;

    for (int iter_num = 0; iter_num < num_iterations; iter_num++) {
      int loop_i = 63 - iter_num;
      int e_val = e[loop_i];
      cumulative = 16 * cumulative + e_val;

      // Compute cumulative*P using ref10
      // Handle negative cumulative by computing |cumulative|*P and negating
      bool neg = (cumulative < 0);
      int64_t abs_cum = neg ? -cumulative : cumulative;

      // Convert to 32-byte scalar
      unsigned char scalar[32] = {0};
      int64_t temp = abs_cum;
      for (int i = 0; i < 8 && temp; i++) {
        scalar[i] = temp & 0xFF;
        temp >>= 8;
      }

      // Compute scalar * P
      ge_p2 result_p2;
      ge_scalarmult(&result_p2, scalar, &P);

      unsigned char ref10_state[32];
      ge_tobytes(ref10_state, &result_p2);

      // Negate if needed
      if (neg) {
        ref10_state[31] ^= 0x80;
      }

      // Get donna64 state for this iteration
      unsigned char donna64_state[32];
      for (int b = 0; b < 32; b++) {
        donna64_state[b] =
            (unsigned char)donna64_debug_get_all_iter(iter_num, b);
      }

      // Compare
      bool match = (memcmp(ref10_state, donna64_state, 32) == 0);

      if (iter_num > 0)
        oss << ",";
      oss << "{\"iter\":" << iter_num << ",\"i\":" << loop_i
          << ",\"e\":" << e_val;
      oss << ",\"cumulative\":" << cumulative;
      oss << ",\"ref10\":\"";
      for (int b = 0; b < 32; b++) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << (int)ref10_state[b];
      }
      oss << std::dec << "\",\"donna64\":\"";
      for (int b = 0; b < 32; b++) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << (int)donna64_state[b];
      }
      oss << std::dec << "\",\"match\":" << (match ? "true" : "false") << "}";

      if (!match && first_mismatch < 0) {
        first_mismatch = iter_num;
      }
    }

    oss << "],";
    oss << "\"first_mismatch\":" << first_mismatch << ",";
    oss << "\"success\":true}";

  } catch (const std::exception &e) {
    oss << "\"error\":\"" << e.what() << "\"}";
  }

  return oss.str();
}

/**
 * debug_iter3_substeps - Debug iteration 3 with sub-step granularity
 *
 * Iteration 3 processes i=60, e[60]=2, cumulative 147 ??? 2354
 * This captures every intermediate step to find the exact bug.
 */
std::string debug_iter3_substeps() {
  std::ostringstream oss;
  oss << "{";

  try {
    // Test vectors
    static const unsigned char tx_pub[32] = {
        0xe3, 0xe1, 0xe3, 0x52, 0x58, 0xe9, 0xd3, 0x8e, 0x42, 0xd6, 0x77,
        0x65, 0x46, 0xf5, 0x4d, 0x51, 0xfb, 0x2b, 0x5c, 0x33, 0x28, 0xde,
        0x93, 0xac, 0xe2, 0x55, 0xa8, 0x36, 0x5f, 0x58, 0x3b, 0x09};

    static const unsigned char view_sec[32] = {
        0x3e, 0x70, 0x46, 0x15, 0xa5, 0xdf, 0x83, 0xb5, 0x63, 0x71, 0xd5,
        0xc7, 0x05, 0x8e, 0x14, 0x16, 0xb8, 0x46, 0x73, 0x4e, 0x81, 0xa5,
        0x73, 0x2b, 0x3b, 0xf5, 0x91, 0x3e, 0x53, 0x10, 0x32, 0x09};

    // Decompress point P
    ge_p3 P;
    if (ge_frombytes_vartime(&P, tx_pub) != 0) {
      oss << "\"error\":\"ge_frombytes failed\"}";
      return oss.str();
    }

    // ====================================================================
    // Use ref10 to compute expected intermediate values
    // ====================================================================

    auto compute_nP = [&](int64_t n) -> std::string {
      bool neg = (n < 0);
      uint64_t abs_n = neg ? -n : n;
      unsigned char scalar[32] = {0};
      for (int i = 0; i < 8; i++) {
        scalar[i] = (abs_n >> (8 * i)) & 0xFF;
      }
      ge_p2 result_p2;
      ge_scalarmult(&result_p2, scalar, &P);
      unsigned char result[32];
      ge_tobytes(result, &result_p2);
      if (neg)
        result[31] ^= 0x80;
      std::ostringstream hex;
      for (int i = 0; i < 32; i++) {
        hex << std::hex << std::setfill('0') << std::setw(2) << (int)result[i];
      }
      return hex.str();
    };

    // Expected values from ref10
    std::string ref10_147P = compute_nP(147);   // Start of iter3
    std::string ref10_294P = compute_nP(294);   // After 1st doubling
    std::string ref10_588P = compute_nP(588);   // After 2nd doubling
    std::string ref10_1176P = compute_nP(1176); // After 3rd doubling
    std::string ref10_2352P = compute_nP(2352); // After 4th doubling
    std::string ref10_2P = compute_nP(2);       // Table entry for e=2
    std::string ref10_2354P = compute_nP(2354); // Final result of iter3

    oss << "\"ref10\":{";
    oss << "\"147P\":\"" << ref10_147P << "\",";
    oss << "\"294P\":\"" << ref10_294P << "\",";
    oss << "\"588P\":\"" << ref10_588P << "\",";
    oss << "\"1176P\":\"" << ref10_1176P << "\",";
    oss << "\"2352P\":\"" << ref10_2352P << "\",";
    oss << "\"2P\":\"" << ref10_2P << "\",";
    oss << "\"2354P\":\"" << ref10_2354P << "\"";
    oss << "},";

    // ====================================================================
    // Get donna64's iter2 state (147P) and iter3 state (2354P)
    // ====================================================================

    // Run donna64 full trace
    donna64_debug_full_trace();

    // Get donna64's iter2 result (should be 147P)
    unsigned char donna64_iter2[32];
    for (int b = 0; b < 32; b++) {
      donna64_iter2[b] = (unsigned char)donna64_debug_get_all_iter(2, b);
    }

    // Get donna64's iter3 result (should be 2354P but isn't)
    unsigned char donna64_iter3[32];
    for (int b = 0; b < 32; b++) {
      donna64_iter3[b] = (unsigned char)donna64_debug_get_all_iter(3, b);
    }

    oss << "\"donna64\":{";
    oss << "\"iter2_147P\":\"";
    for (int i = 0; i < 32; i++)
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (int)donna64_iter2[i];
    oss << std::dec << "\",";
    oss << "\"iter3_2354P\":\"";
    for (int i = 0; i < 32; i++)
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (int)donna64_iter3[i];
    oss << std::dec << "\"";
    oss << "},";

    // ====================================================================
    // Check donna64's precomputed 2P
    // ====================================================================

    unsigned char donna64_2P[32];
    for (int i = 0; i < 32; i++) {
      donna64_2P[i] = (unsigned char)donna64_debug_get_precomp_2P(i);
    }

    oss << "\"donna64_2P\":\"";
    for (int i = 0; i < 32; i++)
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (int)donna64_2P[i];
    oss << std::dec << "\",";

    // Check if 2P matches
    bool match_2P = (memcmp(donna64_2P, ref10_2P.c_str(), 32) == 0);
    // Actually need to compare bytes properly
    unsigned char ref10_2P_bytes[32];
    for (int i = 0; i < 32; i++) {
      int hi = (ref10_2P[i * 2] >= 'a') ? (ref10_2P[i * 2] - 'a' + 10)
                                        : (ref10_2P[i * 2] - '0');
      int lo = (ref10_2P[i * 2 + 1] >= 'a') ? (ref10_2P[i * 2 + 1] - 'a' + 10)
                                            : (ref10_2P[i * 2 + 1] - '0');
      ref10_2P_bytes[i] = (hi << 4) | lo;
    }
    match_2P = (memcmp(donna64_2P, ref10_2P_bytes, 32) == 0);
    oss << "\"2P_match\":" << (match_2P ? "true" : "false") << ",";

    // ====================================================================
    // Check donna64's iter2 matches 147P
    // ====================================================================

    unsigned char ref10_147P_bytes[32];
    for (int i = 0; i < 32; i++) {
      int hi = (ref10_147P[i * 2] >= 'a') ? (ref10_147P[i * 2] - 'a' + 10)
                                          : (ref10_147P[i * 2] - '0');
      int lo = (ref10_147P[i * 2 + 1] >= 'a')
                   ? (ref10_147P[i * 2 + 1] - 'a' + 10)
                   : (ref10_147P[i * 2 + 1] - '0');
      ref10_147P_bytes[i] = (hi << 4) | lo;
    }
    bool match_147P = (memcmp(donna64_iter2, ref10_147P_bytes, 32) == 0);
    oss << "\"iter2_match\":\"" << (match_147P ? "true" : "false") << "\",";

    // ====================================================================
    // Now the key test: manually apply iter3 operations using ref10
    // Start with donna64's iter2 result and apply iter3 operations
    // ====================================================================

    // Decompress donna64's iter2 result (147P) into a point
    ge_p3 iter2_point;
    ge_p1p1 tmp_p1p1;
    ge_p2 tmp_p2;
    unsigned char doubled1[32], doubled2[32], doubled3[32], doubled4[32];

    // Actually donna64's iter2 is in P2 form stored as compressed.
    // We need to start from P2 and do the doublings.
    // Let's instead use ref10 to compute what donna64 SHOULD have after each
    // step.

    // The key insight: If donna64's iter2 output (147P) is correct,
    // then we need to verify that donna64's doubling and addition are correct.

    // Since we can't directly call donna64's internal functions from here,
    // let's verify the expected results:
    oss << "\"analysis\":{";
    oss << "\"iter2_correct\":" << (match_147P ? "true" : "false") << ",";

    // If iter2 is correct but iter3 is wrong, the bug is in the 4 doublings or
    // the addition
    unsigned char ref10_2354P_bytes[32];
    for (int i = 0; i < 32; i++) {
      int hi = (ref10_2354P[i * 2] >= 'a') ? (ref10_2354P[i * 2] - 'a' + 10)
                                           : (ref10_2354P[i * 2] - '0');
      int lo = (ref10_2354P[i * 2 + 1] >= 'a')
                   ? (ref10_2354P[i * 2 + 1] - 'a' + 10)
                   : (ref10_2354P[i * 2 + 1] - '0');
      ref10_2354P_bytes[i] = (hi << 4) | lo;
    }
    bool match_2354P = (memcmp(donna64_iter3, ref10_2354P_bytes, 32) == 0);
    oss << "\"iter3_correct\":" << (match_2354P ? "true" : "false") << ",";

    // If 2P is correct and 147P is correct, but 2354P is wrong,
    // then the bug is in the 4 doublings (147???2352) OR the addition
    // (2352+2=2354)

    // Let's check if donna64's iter3 result equals 2352P (the 4-doubled value)
    // If so, the addition is failing
    unsigned char ref10_2352P_bytes[32];
    for (int i = 0; i < 32; i++) {
      int hi = (ref10_2352P[i * 2] >= 'a') ? (ref10_2352P[i * 2] - 'a' + 10)
                                           : (ref10_2352P[i * 2] - '0');
      int lo = (ref10_2352P[i * 2 + 1] >= 'a')
                   ? (ref10_2352P[i * 2 + 1] - 'a' + 10)
                   : (ref10_2352P[i * 2 + 1] - '0');
      ref10_2352P_bytes[i] = (hi << 4) | lo;
    }
    bool iter3_equals_2352P =
        (memcmp(donna64_iter3, ref10_2352P_bytes, 32) == 0);
    oss << "\"iter3_equals_2352P\":" << (iter3_equals_2352P ? "true" : "false")
        << ",";

    // If iter3 == 2352P, then the addition of 2P failed
    // If iter3 != 2352P and iter3 != 2354P, the doublings failed

    oss << "\"bug_location\":\"";
    if (match_2354P) {
      oss << "NO_BUG";
    } else if (iter3_equals_2352P) {
      oss << "ADDITION_FAILED";
    } else if (!match_147P) {
      oss << "ITER2_ALREADY_WRONG";
    } else {
      oss << "DOUBLINGS_OR_ADDITION_FAILED";
    }
    oss << "\"";
    oss << "}";

    oss << ",\"success\":true}";

  } catch (const std::exception &e) {
    oss << "\"error\":\"" << e.what() << "\"}";
  }

  return oss.str();
}

// ============================================================================
// compute_view_tag_for_output - Debug helper to compute view tag
// ============================================================================
// Usage: compute_view_tag_for_output(pubkeyHex, viewKeyHex, outputIndex)
// Returns: {view_tag: 0-255, derivation: hex, success: true}
std::string compute_view_tag_for_output(const std::string &pubkey_hex,
                                        const std::string &view_key_hex,
                                        uint32_t output_index) {
  std::ostringstream oss;
  oss << "{";

  try {
    if (pubkey_hex.length() != 64) {
      oss << "\"error\":\"pubkey must be 64 hex chars\",\"success\":false}";
      return oss.str();
    }
    if (view_key_hex.length() != 64) {
      oss << "\"error\":\"view_key must be 64 hex chars\",\"success\":false}";
      return oss.str();
    }

    // Parse pubkey and view_key
    unsigned char pubkey[32], view_key[32];
    if (!epee::string_tools::hex_to_pod(pubkey_hex, pubkey)) {
      oss << "\"error\":\"invalid pubkey hex\",\"success\":false}";
      return oss.str();
    }
    if (!epee::string_tools::hex_to_pod(view_key_hex, view_key)) {
      oss << "\"error\":\"invalid view_key hex\",\"success\":false}";
      return oss.str();
    }

    // Compute key derivation using donna64
    crypto::key_derivation derivation;
    int deriv_result = donna64_generate_key_derivation(
        reinterpret_cast<unsigned char *>(&derivation), pubkey, view_key);

    if (deriv_result != 0) {
      oss << "\"error\":\"key derivation failed (code " << deriv_result
          << ")\",\"success\":false}";
      return oss.str();
    }

    // Output derivation hex
    oss << "\"derivation\":\"";
    for (int i = 0; i < 32; i++) {
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (int)derivation.data[i];
    }
    oss << "\",";

// Compute view tag: H("view_tag" || derivation || varint(output_index))[0]
#pragma pack(push, 1)
    struct {
      char salt[8];
      unsigned char derivation[32];
      char output_index_varint[8];
    } buf;
#pragma pack(pop)

    memcpy(buf.salt, "view_tag", 8);
    memcpy(buf.derivation, &derivation, 32);

    char *varint_end = buf.output_index_varint;
    tools::write_varint(varint_end, static_cast<size_t>(output_index));
    size_t buf_len = 8 + 32 + (varint_end - buf.output_index_varint);

    crypto::hash view_tag_hash;
    crypto::cn_fast_hash(&buf, buf_len, view_tag_hash);

    uint8_t view_tag = view_tag_hash.data[0];

    oss << "\"view_tag\":" << (int)view_tag << ",";
    oss << "\"view_tag_hex\":\"" << std::hex << std::setfill('0')
        << std::setw(2) << (int)view_tag << "\",";
    oss << "\"output_index\":" << std::dec << output_index << ",";
    oss << "\"success\":true}";

  } catch (const std::exception &e) {
    oss << "\"error\":\"" << e.what() << "\",\"success\":false}";
  }

  return oss.str();
}

// ============================================================================
// EXTRACT STAKE INFO - For building stake cache on server
// ============================================================================
// Parses a transaction blob and extracts STAKE transaction info if applicable.
// Used by server to build a cache of ALL stakes for efficient return detection.
//
// Usage (Node.js):
//   const ptr = wasmModule.allocate_binary_buffer(txBlob.length);
//   wasmModule.HEAPU8.set(txBlob, ptr);
//   const resultJson = wasmModule.extract_stake_info(ptr, txBlob.length,
//   blockHeight); wasmModule.free_binary_buffer(ptr); const result =
//   JSON.parse(resultJson); if (result.is_stake) { ... }
//
// Returns: {is_stake, return_address, tx_hash, amount, success}
// ============================================================================
std::string extract_stake_info(uintptr_t tx_ptr, size_t tx_size,
                               double block_height_d) {
  std::ostringstream oss;
  oss << "{";

  try {
    uint64_t block_height = static_cast<uint64_t>(block_height_d);
    const uint8_t *tx_data = reinterpret_cast<const uint8_t *>(tx_ptr);

    // Parse transaction blob
    cryptonote::transaction tx;
    crypto::hash tx_hash;
    std::string tx_blob(reinterpret_cast<const char *>(tx_data), tx_size);

    bool parse_success =
        cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash);

    if (!parse_success) {
      oss << "\"is_stake\":false,\"error\":\"parse_failed\",\"success\":true}";
      return oss.str();
    }

    // Check if this is a STAKE transaction (type 6)
    if (tx.type != cryptonote::transaction_type::STAKE) {
      oss << "\"is_stake\":false,\"success\":true}";
      return oss.str();
    }

    // Extract stake info
    // STAKE transactions use protocol_tx_data.return_address for the stake
    // return
    crypto::public_key return_address = tx.protocol_tx_data.return_address;

    // Convert keys to hex
    std::string tx_hash_hex = epee::string_tools::pod_to_hex(tx_hash);
    std::string return_address_hex =
        epee::string_tools::pod_to_hex(return_address);

    // Get amount (from amount_burnt field for STAKE)
    uint64_t amount = tx.amount_burnt;

    oss << "\"is_stake\":true,";
    oss << "\"tx_hash\":\"" << tx_hash_hex << "\",";
    oss << "\"return_address\":\"" << return_address_hex << "\",";
    oss << "\"amount\":" << amount << ",";
    oss << "\"block_height\":" << block_height << ",";
    oss << "\"success\":true}";

  } catch (const std::exception &e) {
    oss << "\"is_stake\":false,\"error\":\"" << e.what()
        << "\",\"success\":false}";
  }

  return oss.str();
}

// ============================================================================
// EXTRACT ALL STAKES FROM EPEE BLOCK DATA - For server-side stake cache
// ============================================================================
// Parses an entire Epee binary blob (getblocks.bin response) and returns
// all STAKE transactions found. Used by server to build complete stake cache.
//
// @param epee_ptr Pointer to Epee block data in WASM heap
// @param epee_size Size of Epee data in bytes
// @param start_height_d Starting block height for this chunk
// @return JSON: {stakes: [{tx_hash, return_address, amount, block_height},
// ...],
//                stats: {blocks_parsed, stakes_found, txs_scanned}, success}
// ============================================================================
std::string extract_all_stakes(uintptr_t epee_ptr, size_t epee_size,
                               double start_height_d) {
  std::ostringstream oss;
  uint64_t start_height = static_cast<uint64_t>(start_height_d);

  // Stats
  uint32_t blocks_parsed = 0;
  uint32_t stakes_found = 0;
  uint32_t txs_scanned = 0;

  try {
    if (epee_ptr == 0 || epee_size < 10) {
      return "{\"error\":\"invalid epee buffer\",\"success\":false}";
    }

    // Convert pointer to string (epee uses std::string for binary data)
    const std::string epee_data(reinterpret_cast<const char *>(epee_ptr),
                                epee_size);

    // Parse Epee response using Monero's native serialization
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
    bool parsed = epee::serialization::load_t_from_binary(res, epee_data);

    if (!parsed) {
      return "{\"error\":\"epee parse failed\",\"success\":false}";
    }

    // Build stakes array
    oss << "{\"stakes\":[";
    bool first_stake = true;
    uint32_t current_block_height = static_cast<uint32_t>(start_height);

    // Process each block in the response
    for (const auto &block_entry : res.blocks) {
      // Parse block blob
      cryptonote::block blk;
      if (!cryptonote::parse_and_validate_block_from_blob(block_entry.block,
                                                          blk)) {
        current_block_height++;
        continue;
      }
      blocks_parsed++;

      // Check protocol_tx for STAKE (protocol txs can be STAKE type)
      if (blk.protocol_tx.vout.size() > 0) {
        txs_scanned++;
        if (blk.protocol_tx.type == cryptonote::transaction_type::STAKE) {
          // Extract stake info from protocol tx
          crypto::hash tx_hash =
              cryptonote::get_transaction_hash(blk.protocol_tx);

          // For protocol txs, use protocol_tx_data.return_address
          // But also check return_address field on the tx itself
          crypto::public_key return_address =
              blk.protocol_tx.protocol_tx_data.return_address;
          if (return_address == crypto::null_pkey) {
            return_address = blk.protocol_tx.return_address;
          }
          // Also try return_address_list if available
          if (return_address == crypto::null_pkey &&
              !blk.protocol_tx.return_address_list.empty()) {
            return_address = blk.protocol_tx.return_address_list[0];
          }

          uint64_t amount = blk.protocol_tx.amount_burnt;

          // v5.0.0: Extract first_key_image and stake_output_key for Carrot
          // return detection For post-Carrot (HF10 block 334750+), we need
          // these to populate return_output_map
          std::string first_key_image_hex = "";
          std::string stake_output_key_hex = "";

          // Get first key_image from inputs (if RingCT tx with inputs)
          if (blk.protocol_tx.vin.size() > 0) {
            const auto *txin =
                boost::get<cryptonote::txin_to_key>(&blk.protocol_tx.vin[0]);
            if (txin) {
              first_key_image_hex =
                  epee::string_tools::pod_to_hex(txin->k_image);
            }
          }

          // Get P_change output key for Carrot return verification.
          // For STAKE TXs with a change output, P_change is typically the LAST
          // output. For no-change STAKE TXs, this is the only output.
          if (!blk.protocol_tx.vout.empty()) {
            crypto::public_key out_key;
            const auto &vout = blk.protocol_tx.vout;
            const size_t p_change_idx = vout.size() - 1;
            if (cryptonote::get_output_public_key(vout[p_change_idx],
                                                  out_key)) {
              stake_output_key_hex = epee::string_tools::pod_to_hex(out_key);
            }
          }

          if (!first_stake)
            oss << ",";
          first_stake = false;
          stakes_found++;

          oss << "{";
          oss << "\"tx_hash\":\"" << epee::string_tools::pod_to_hex(tx_hash)
              << "\",";
          oss << "\"return_address\":\""
              << epee::string_tools::pod_to_hex(return_address) << "\",";
          oss << "\"amount\":" << amount << ",";
          oss << "\"block_height\":" << current_block_height << ",";
          oss << "\"tx_type\":\"STAKE\",";
          oss << "\"first_key_image\":\"" << first_key_image_hex << "\",";
          oss << "\"stake_output_key\":\"" << stake_output_key_hex << "\"";
          oss << "}";
        }
      }

      // Check user transactions for STAKE
      for (const auto &tx_blob_entry : block_entry.txs) {
        txs_scanned++;
        cryptonote::transaction tx;
        crypto::hash tx_hash;

        if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob_entry.blob, tx,
                                                         tx_hash)) {
          continue;
        }

        if (tx.type == cryptonote::transaction_type::STAKE) {
          // For user STAKE txs, try multiple return_address fields:
          // 1. tx.return_address (single address)
          // 2. tx.return_address_list[0] (list of addresses)
          // 3. tx.protocol_tx_data.return_address (protocol data)
          crypto::public_key return_address = tx.return_address;
          if (return_address == crypto::null_pkey &&
              !tx.return_address_list.empty()) {
            return_address = tx.return_address_list[0];
          }
          if (return_address == crypto::null_pkey) {
            return_address = tx.protocol_tx_data.return_address;
          }

          uint64_t amount = tx.amount_burnt;

          // v5.0.0: Extract first_key_image and stake_output_key for Carrot
          // return detection
          std::string first_key_image_hex = "";
          std::string stake_output_key_hex = "";

          // Get first key_image from inputs (if RingCT tx with inputs)
          if (tx.vin.size() > 0) {
            const auto *txin = boost::get<cryptonote::txin_to_key>(&tx.vin[0]);
            if (txin) {
              first_key_image_hex =
                  epee::string_tools::pod_to_hex(txin->k_image);
            }
          }

          // Get P_change output key for Carrot return verification.
          // For STAKE TXs with a change output, P_change is typically the LAST
          // output. For no-change STAKE TXs, this is the only output.
          if (!tx.vout.empty()) {
            crypto::public_key out_key;
            const size_t p_change_idx = tx.vout.size() - 1;
            if (cryptonote::get_output_public_key(tx.vout[p_change_idx],
                                                  out_key)) {
              stake_output_key_hex = epee::string_tools::pod_to_hex(out_key);
            }
          }

          if (!first_stake)
            oss << ",";
          first_stake = false;
          stakes_found++;

          oss << "{";
          oss << "\"tx_hash\":\"" << epee::string_tools::pod_to_hex(tx_hash)
              << "\",";
          oss << "\"return_address\":\""
              << epee::string_tools::pod_to_hex(return_address) << "\",";
          oss << "\"amount\":" << amount << ",";
          oss << "\"block_height\":" << current_block_height << ",";
          oss << "\"tx_type\":\"STAKE\",";
          oss << "\"first_key_image\":\"" << first_key_image_hex << "\",";
          oss << "\"stake_output_key\":\"" << stake_output_key_hex << "\"";
          oss << "}";
        }

        // ================================================================
        // AUDIT TRANSACTION DETECTION (type 8) - v5.1.0
        // AUDIT was active from HF6 (154,750) to HF8 (172,000)
        // Lock period: 7200 blocks (return at audit_height + 7201)
        // ================================================================
        else if (tx.type == cryptonote::transaction_type::AUDIT) {
          // AUDIT uses tx.return_address for the return output
          crypto::public_key return_address = tx.return_address;

          // Also try return_address_list if single is null
          if (return_address == crypto::null_pkey &&
              !tx.return_address_list.empty()) {
            return_address = tx.return_address_list[0];
          }

          uint64_t amount = tx.amount_burnt;

          // Get first key_image from inputs
          std::string first_key_image_hex = "";
          if (tx.vin.size() > 0) {
            const auto *txin = boost::get<cryptonote::txin_to_key>(&tx.vin[0]);
            if (txin) {
              first_key_image_hex =
                  epee::string_tools::pod_to_hex(txin->k_image);
            }
          }

          // Get spend_pubkey from salvium_data (for P_change output matching)
          std::string spend_pubkey_hex = "";
          if (tx.rct_signatures.salvium_data.salvium_data_type ==
              rct::SalviumZeroAudit) {
            spend_pubkey_hex = epee::string_tools::pod_to_hex(
                tx.rct_signatures.salvium_data.spend_pubkey);
          }

          if (!first_stake)
            oss << ",";
          first_stake = false;
          stakes_found++;

          oss << "{";
          oss << "\"tx_hash\":\"" << epee::string_tools::pod_to_hex(tx_hash)
              << "\",";
          oss << "\"return_address\":\""
              << epee::string_tools::pod_to_hex(return_address) << "\",";
          oss << "\"amount\":" << amount << ",";
          oss << "\"block_height\":" << current_block_height << ",";
          oss << "\"tx_type\":\"AUDIT\",";
          oss << "\"first_key_image\":\"" << first_key_image_hex << "\",";
          oss << "\"spend_pubkey\":\"" << spend_pubkey_hex << "\"";
          oss << "}";
        }
      }

      current_block_height++;
    }

    oss << "],";
    oss << "\"stats\":{";
    oss << "\"blocks_parsed\":" << blocks_parsed << ",";
    oss << "\"stakes_found\":" << stakes_found << ",";
    oss << "\"txs_scanned\":" << txs_scanned;
    oss << "},";
    oss << "\"success\":true}";

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\",\"success\":false}";
  }

  return oss.str();
}

// ============================================================================
// EXTRACT RETURN TRANSACTION HEIGHTS
// v5.52.0: Fast index of all RETURN-type transaction heights
// Used by Phase 2b to fetch sparse RETURN txs instead of rescanning entire chain
// ============================================================================
std::string extract_return_tx_heights(uintptr_t epee_ptr, size_t epee_size,
                                      double start_height_d) {
  std::ostringstream oss;
  uint64_t start_height = static_cast<uint64_t>(start_height_d);

  // Stats
  uint32_t blocks_parsed = 0;
  uint32_t returns_found = 0;
  uint32_t txs_scanned = 0;

  // Debug: count all tx types
  std::map<int, uint32_t> tx_type_counts;

  try {
    if (epee_ptr == 0 || epee_size < 10) {
      return "{\"error\":\"invalid epee buffer\",\"success\":false}";
    }

    const std::string epee_data(reinterpret_cast<const char *>(epee_ptr),
                                epee_size);

    // Parse Epee response
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res;
    bool parsed = epee::serialization::load_t_from_binary(res, epee_data);

    if (!parsed) {
      return "{\"error\":\"epee parse failed\",\"success\":false}";
    }

    // Build heights array (deduplicated - one entry per height even if multiple
    // RETURN txs)
    std::set<uint32_t> return_heights;
    uint32_t current_block_height = static_cast<uint32_t>(start_height);

    for (const auto &block_entry : res.blocks) {
      cryptonote::block blk;
      if (!cryptonote::parse_and_validate_block_from_blob(block_entry.block,
                                                          blk)) {
        current_block_height++;
        continue;
      }
      blocks_parsed++;

      // Check user transactions for RETURN type
      for (const auto &tx_blob_entry : block_entry.txs) {
        txs_scanned++;
        cryptonote::transaction tx;
        crypto::hash tx_hash;

        if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob_entry.blob, tx,
                                                         tx_hash)) {
          continue;
        }

        // Count all tx types for debugging
        int tx_type_int = static_cast<int>(tx.type);
        tx_type_counts[tx_type_int]++;

        // RETURN transactions are user-initiated returns of funds
        if (tx.type == cryptonote::transaction_type::RETURN) {
          return_heights.insert(current_block_height);
          returns_found++;
        }
      }

      current_block_height++;
    }

    // Build JSON response
    oss << "{\"heights\":[";
    bool first = true;
    for (uint32_t h : return_heights) {
      if (!first)
        oss << ",";
      first = false;
      oss << h;
    }
    oss << "],";
    oss << "\"stats\":{";
    oss << "\"blocks_parsed\":" << blocks_parsed << ",";
    oss << "\"returns_found\":" << returns_found << ",";
    oss << "\"unique_heights\":" << return_heights.size() << ",";
    oss << "\"txs_scanned\":" << txs_scanned << ",";
    oss << "\"tx_types\":{";
    bool first_type = true;
    for (const auto &kv : tx_type_counts) {
      if (!first_type)
        oss << ",";
      first_type = false;
      oss << "\"" << kv.first << "\":" << kv.second;
    }
    oss << "}";
    oss << "},";
    oss << "\"success\":true}";

  } catch (const std::exception &e) {
    return "{\"error\":\"" + std::string(e.what()) + "\",\"success\":false}";
  }

  return oss.str();
}

std::string debug_inspect_tx_keys(std::string tx_hex) {
  std::string tx_blob;
  epee::string_tools::parse_hexstr_to_binbuff(tx_hex, tx_blob);

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  cryptonote::blobdata blob_data = tx_blob;
  if (!cryptonote::parse_and_validate_tx_from_blob(blob_data, tx, tx_hash)) {
    return "{\"success\":false, \"error\":\"Parse failed\"}";
  }

  std::ostringstream oss;
  oss << "{\"success\":true, \"tx_hash\":\""
      << epee::string_tools::pod_to_hex(tx_hash) << "\"";

  crypto::public_key tx_pub = cryptonote::get_tx_pub_key_from_extra(tx);
  oss << ", \"tx_pub_key\":\"" << epee::string_tools::pod_to_hex(tx_pub)
      << "\"";

  std::vector<crypto::public_key> additionals =
      cryptonote::get_additional_tx_pub_keys_from_extra(tx);
  oss << ", \"additional_keys\":[";
  for (size_t i = 0; i < additionals.size(); ++i) {
    if (i > 0)
      oss << ",";
    oss << "\"" << epee::string_tools::pod_to_hex(additionals[i]) << "\"";
  }
  oss << "]";

  oss << ", \"extra_size\":" << tx.extra.size();
  oss << "}";
  return oss.str();
}

std::string debug_probe_derivation(std::string pub_hex, std::string sec_hex) {
  crypto::public_key pub;
  crypto::secret_key sec;
  epee::string_tools::hex_to_pod(pub_hex, pub);
  epee::string_tools::hex_to_pod(sec_hex, sec);

  crypto::key_derivation derivation;
  bool r = crypto::generate_key_derivation(pub, sec, derivation);

  std::ostringstream oss;
  oss << "{\"success\":" << (r ? "true" : "false") << ", \"derivation\":\""
      << epee::string_tools::pod_to_hex(derivation) << "\", \"tags\":[";
  for (size_t i = 0; i < 20; i++) {
    crypto::view_tag t;
    crypto::derive_view_tag(derivation, i, t);
    if (i > 0)
      oss << ",";
    oss << (int)*(unsigned char *)&t;
  }
  oss << "]}";
  return oss.str();
}

// ============================================================================
// Embind Registration
// ============================================================================
#ifdef __cplusplus
extern "C" {
#endif
void crypto_get_random_state(void *out_state);
void crypto_set_random_state(const void *in_state);
#ifdef __cplusplus
}
#endif

// Expose RNG state control for deterministic retries
std::string get_random_state() {
  uint8_t state[200]; // hash_state size
  crypto_get_random_state(state);
  fprintf(stderr,
          "[WASM DEBUG] get_random_state: first 4 bytes = %02x%02x%02x%02x\n",
          state[0], state[1], state[2], state[3]);
  return epee::string_encoding::base64_encode(state, 200);
}

void set_random_state(const std::string &base64_state) {
  std::string binary_state = epee::string_encoding::base64_decode(base64_state);
  if (binary_state.size() != 200) {
    fprintf(stderr,
            "[WASM ERROR] set_random_state: Invalid state size %zu (expected "
            "200)\n",
            binary_state.size());
    return;
  }

  // Log first 4 bytes before setting
  uint8_t before[200];
  crypto_get_random_state(before);
  fprintf(stderr, "[WASM DEBUG] set_random_state: BEFORE = %02x%02x%02x%02x, ",
          before[0], before[1], before[2], before[3]);

  crypto_set_random_state(binary_state.data());

  // Log first 4 bytes after setting
  uint8_t after[200];
  crypto_get_random_state(after);
  fprintf(stderr, "AFTER = %02x%02x%02x%02x\n", after[0], after[1], after[2],
          after[3]);
}

EMSCRIPTEN_BINDINGS(salvium_wallet) {
  emscripten::function("get_random_state", &get_random_state);
  emscripten::function("set_random_state", &set_random_state);

  // WasmWallet class
  class_<WasmWallet>("WasmWallet")
      .constructor<>()
      // Creation / Restoration
      .function("create_random", &WasmWallet::create_random)
      .function("restore_from_seed", &WasmWallet::restore_from_seed)
      .function("restore_from_recovery_key_hex",
                &WasmWallet::restore_from_recovery_key_hex)
      .function("init_view_only", &WasmWallet::init_view_only)
      // Legacy Keys / Address
      .function("get_address", &WasmWallet::get_address)
      .function("get_secret_view_key", &WasmWallet::get_secret_view_key)
      .function("get_public_view_key", &WasmWallet::get_public_view_key)
      .function("get_secret_spend_key", &WasmWallet::get_secret_spend_key)
      .function("get_public_spend_key", &WasmWallet::get_public_spend_key)
      .function("get_seed", &WasmWallet::get_seed)
      // Carrot Secret Keys (6 keys)
      .function("get_carrot_s_master", &WasmWallet::get_carrot_s_master)
      .function("get_carrot_k_prove_spend",
                &WasmWallet::get_carrot_k_prove_spend)
      .function("get_carrot_s_view_balance",
                &WasmWallet::get_carrot_s_view_balance)
      .function("get_carrot_k_view_incoming",
                &WasmWallet::get_carrot_k_view_incoming)
      .function("get_carrot_k_generate_image",
                &WasmWallet::get_carrot_k_generate_image)
      .function("get_carrot_s_generate_address",
                &WasmWallet::get_carrot_s_generate_address)
      // Carrot Address
      .function("get_carrot_address", &WasmWallet::get_carrot_address)
      .function("get_carrot_account_spend_pubkey",
                &WasmWallet::get_carrot_account_spend_pubkey)
      .function("get_carrot_account_view_pubkey",
                &WasmWallet::get_carrot_account_view_pubkey)
      .function("get_carrot_main_spend_pubkey",
                &WasmWallet::get_carrot_main_spend_pubkey)
      .function("get_carrot_main_view_pubkey",
                &WasmWallet::get_carrot_main_view_pubkey)
      // Balance
      .function("get_balance", &WasmWallet::get_balance)
      .function("get_unlocked_balance", &WasmWallet::get_unlocked_balance)
      .function("get_wallet_diagnostic", &WasmWallet::get_wallet_diagnostic)
      .function("debug_transfer_vin", &WasmWallet::debug_transfer_vin)
      .function("debug_input_candidates", &WasmWallet::debug_input_candidates)
      .function("debug_tx_input_selection",
                &WasmWallet::debug_tx_input_selection)
      .function("debug_create_tx_path", &WasmWallet::debug_create_tx_path)
      .function("debug_fee_params", &WasmWallet::debug_fee_params)
      // Daemon Connection
      .function("set_daemon", &WasmWallet::set_daemon)
      .function("get_daemon_address", &WasmWallet::get_daemon_address)
      .function("init_daemon", &WasmWallet::init_daemon)
      .function("refresh", &WasmWallet::refresh)
      // Sync / Block Scanning
      .function("get_blockchain_height", &WasmWallet::get_blockchain_height)
      .function("get_wallet_height", &WasmWallet::get_wallet_height)
      .function("get_short_chain_history_json",
                &WasmWallet::get_short_chain_history_json)
      .function("get_refresh_start_height",
                &WasmWallet::get_refresh_start_height)
      .function("set_refresh_start_height",
                &WasmWallet::set_refresh_start_height)
      .function("set_wallet_height", &WasmWallet::set_wallet_height)
      .function("process_blocks", &WasmWallet::process_blocks)
      .function("process_blocks_binary", &WasmWallet::process_blocks_binary)
      .function("ingest_blocks_binary", &WasmWallet::ingest_blocks_binary)
      .function("ingest_blocks_from_uint8array",
                &WasmWallet::ingest_blocks_from_uint8array)
      .function("ingest_blocks_raw", &WasmWallet::ingest_blocks_raw)
      .function("fast_forward_blocks", &WasmWallet::fast_forward_blocks)
      .function("fast_forward_blocks_from_uint8array",
                &WasmWallet::fast_forward_blocks_from_uint8array)
      // ========================================================================
      // OPTIMIZED SCANNING (v1.3.0) - Eliminates main thread bottlenecks
      // ========================================================================
      // For workers: scan_blocks_fast returns 0=MISS, 1=HIT, -1=error (no JSON)
      .function("scan_blocks_fast", &WasmWallet::scan_blocks_fast)
      // Get scan results after HIT (only call if scan_blocks_fast returned 1)
      .function("get_last_scan_result", &WasmWallet::get_last_scan_result)
      .function("get_last_scan_block_hash",
                &WasmWallet::get_last_scan_block_hash)
      .function("get_last_scan_block_count",
                &WasmWallet::get_last_scan_block_count)
      // For master wallet: blind fast-forward (no binary parsing on main
      // thread!)
      .function("advance_height_blind", &WasmWallet::advance_height_blind)
      // ========================================================================
      .function("test_wasm", &WasmWallet::test_wasm)
      // Status
      .function("get_last_error", &WasmWallet::get_last_error)
      .function("is_initialized", &WasmWallet::is_initialized)
      // Subaddresses (Phase 6 Step 2)
      .function("get_num_subaddresses", &WasmWallet::get_num_subaddresses)
      .function("create_subaddress", &WasmWallet::create_subaddress)
      .function("get_subaddress", &WasmWallet::get_subaddress)
      .function("get_all_subaddresses", &WasmWallet::get_all_subaddresses)
      // Transfers (Phase 6 Step 1)
      .function("get_transfers_as_json", &WasmWallet::get_transfers_as_json)
      // Transaction Creation (Phase 6 Step 3)
      .function("create_transaction_json", &WasmWallet::create_transaction_json)
      .function("create_stake_transaction_json",
                &WasmWallet::create_stake_transaction_json)
      .function("create_return_transaction_json",
                &WasmWallet::create_return_transaction_json)
      .function("create_sweep_all_transaction_json",
                &WasmWallet::create_sweep_all_transaction_json)
      .function("estimate_fee_json", &WasmWallet::estimate_fee_json)
      // Split Transaction Architecture (Prepare + Complete)
      // These separate input selection from signing, allowing deterministic
      // decoy fetching
      .function("prepare_transaction_json",
                &WasmWallet::prepare_transaction_json)
      .function("complete_transaction_json",
                &WasmWallet::complete_transaction_json)
      .function("clear_prepared_transaction",
                &WasmWallet::clear_prepared_transaction)
      .function("get_prepared_transaction_info",
                &WasmWallet::get_prepared_transaction_info)
      // Output export/import (for persisting wallet state across page refresh)
      .function("export_outputs_hex", &WasmWallet::export_outputs_hex)
      .function("import_outputs_hex", &WasmWallet::import_outputs_hex)
      // Full wallet cache export/import (preserves FULL state including m_tx
      // data)
      .function("export_wallet_cache_hex", &WasmWallet::export_wallet_cache_hex)
      .function("import_wallet_cache_hex", &WasmWallet::import_wallet_cache_hex)
      // ========================================================================
      // SPARSE TRANSACTION INGESTION - For bandwidth-optimized targeted rescan
      // ========================================================================
      // Process transactions from sparse format (from /api/wallet/sparse-txs)
      // Format: [TxCount:4] + [GlobalIndex:4][TxSize:4][TxBlob]...
      .function("ingest_sparse_transactions",
                &WasmWallet::ingest_sparse_transactions)
      // Scan a single transaction blob (hex) - useful fallback if sparse ingest
      // fails
      .function("scan_tx", &WasmWallet::scan_tx)
      // Get mempool transaction info (amount, fee, direction) after scan_tx
      .function("get_mempool_tx_info", &WasmWallet::get_mempool_tx_info)
      // DEBUG: Trace a single transaction to understand why outputs aren't
      // detected
      .function("debug_scan_transaction", &WasmWallet::debug_scan_transaction)
      // DEBUG: Get locked coins info for protocol_tx troubleshooting
      .function("get_locked_coins_info", &WasmWallet::get_locked_coins_info)
      // ========================================================================
      // KEY IMAGE FUNCTIONS - For spent output detection (CSP v6)
      // ========================================================================
       // Get key images as JSON: {key_images: [{key_image, tx_hash, ...}], ...}
       .function("get_key_images", &WasmWallet::get_key_images)
       // CSP v6: Get key images as CSV for scan_csp_batch_with_spent()
       // Returns: "aabb...cc,ddeeff...00,..." (only unspent outputs)
       .function("get_key_images_csv", &WasmWallet::get_key_images_csv)
       .function("get_key_images_csv_len", &WasmWallet::get_key_images_csv_len)
       .function("get_key_images_csv_prefix",
                 &WasmWallet::get_key_images_csv_prefix)
       .function("get_key_images_csv_chunk_count",
                 &WasmWallet::get_key_images_csv_chunk_count)
      .function("get_key_images_csv_chunk", &WasmWallet::get_key_images_csv_chunk)

      // Export spent-only key images as CSV: "ki:height,ki:height,..."
      .function("get_spent_key_images_csv", &WasmWallet::get_spent_key_images_csv)
      .function("get_spent_key_images_csv_len",
                &WasmWallet::get_spent_key_images_csv_len)
      .function("get_spent_key_images_csv_chunk_count",
                &WasmWallet::get_spent_key_images_csv_chunk_count)
      .function("get_spent_key_images_csv_chunk",
                &WasmWallet::get_spent_key_images_csv_chunk)

      // Export return addresses for RETURN transaction detection
      // These are K_r values from our outgoing transfers that recipients can
      // use to send RETURN transactions back to us
      .function("get_return_addresses_csv",
                &WasmWallet::get_return_addresses_csv)

      // Check if TX spends any of our outputs
       .function("check_tx_spends_our_outputs",
                 &WasmWallet::check_tx_spends_our_outputs)

      // Mark outputs as spent from TX blob
      .function("process_spent_outputs", &WasmWallet::process_spent_outputs)
      // Mark outputs as spent directly by key image CSV (most efficient for
      // Phase 1b) Format: "ki1:height1,ki2:height2,..." where ki is 64-char hex
      .function("mark_spent_by_key_images",
                &WasmWallet::mark_spent_by_key_images)
      // ========================================================================
      // WORKER OPTIMIZATION - Manual map injection to avoid crypto derivation
      // Uses CSV strings to avoid register_vector which breaks Node.js
      // ========================================================================
.function("get_subaddress_spend_keys_csv",
                &WasmWallet::get_subaddress_spend_keys_csv)
      .function("get_subaddress_spend_keys_csv_len",
                &WasmWallet::get_subaddress_spend_keys_csv_len)
      .function("get_subaddress_spend_keys_csv_prefix",
                &WasmWallet::get_subaddress_spend_keys_csv_prefix)
      .function("get_subaddress_spend_keys_csv_chunk_count",
                &WasmWallet::get_subaddress_spend_keys_csv_chunk_count)
      .function("get_subaddress_spend_keys_csv_chunk",
                &WasmWallet::get_subaddress_spend_keys_csv_chunk)
      .function("init_view_only_with_map", &WasmWallet::init_view_only_with_map)

      // v4.5.0: Add stake/audit return addresses for protocol_tx detection
      // Workers don't process AUDIT/STAKE TXs, so pre-populate from stake cache
      .function("add_return_addresses", &WasmWallet::add_return_addresses)
      // v5.0.0: Register stake return info for post-Carrot protocol_tx
      // detection Carrot outputs require full return_output_info_t, not just
      // subaddress map
      .function("register_stake_return_info",
                &WasmWallet::register_stake_return_info)
      .function("get_wallet_diagnostic", &WasmWallet::get_wallet_diagnostic)
      .function("debug_transfer_vin", &WasmWallet::debug_transfer_vin)
      .function("debug_input_candidates", &WasmWallet::debug_input_candidates);

  function("validate_address", &validate_address);
  function("get_version", &get_version);
  function("get_sparse_build_id", &get_sparse_build_id);
  function("test_crypto", &test_crypto);
  function("benchmark_key_derivation", &benchmark_key_derivation);

  // ========================================================================
  // CRYPTO DIAGNOSTIC FUNCTIONS - For debugging donna64 integration
  // ========================================================================
  // Compare ref10 vs donna64 speed to diagnose if donna64 is actually being
  // used
  function("diagnose_crypto_speed", &diagnose_crypto_speed);
  // Benchmark donna64 directly via C function (no C++ overhead)
  function("donna64_direct_benchmark", &donna64_direct_benchmark);
  // COMPREHENSIVE ref10 vs donna64 comparison with intermediate values
  // Usage: compare_ref10_donna64(txPubHex, viewSecHex)
  // Returns JSON with derivations, all intermediate values, and comparison
  function("compare_ref10_donna64", &compare_ref10_donna64);
  // FULL iteration-by-iteration debug with ALL 64 donna64 states
  // Returns JSON with all iteration states for finding exact divergence point
  function("debug_iteration_by_iteration", &debug_iteration_by_iteration);
  // Compare scalar*P (without ??8 cofactor) between ref10 and donna64
  // Helps isolate whether bug is in scalarmult or cofactor multiplication
  function("compare_scalarmult_no_cofactor", &compare_scalarmult_no_cofactor);
  // Compute n*P using ref10 for arbitrary n (decimal string)
  // Usage: compute_nP_ref10("147") -> {n:147, result:"...", success:true}
  function("compute_nP_ref10", &compute_nP_ref10);
  // Verify donna64 iterations against ref10 computed values
  // Usage: verify_donna64_iterations(10) -> compares first 10 iterations
  function("verify_donna64_iterations", &verify_donna64_iterations);
  // Debug iteration 3 with sub-step granularity to find exact bug location
  function("debug_iter3_substeps", &debug_iter3_substeps);

  // ========================================================================
  // VIEW TAG COMPUTATION - For JavaScript pre-filtering optimization
  // ========================================================================
  // Compute single view tag: returns JSON {view_tag: 0-255, success: true}
  function("compute_view_tag", &compute_view_tag);
  // Compute batch of view tags for one TX: more efficient (reuses derivation)
  function("compute_view_tags_batch", &compute_view_tags_batch);

  // ========================================================================
  // CARROT VIEW TAG DEBUG - Full trace of view tag computation
  // ========================================================================
  // Compute Carrot view tag with all intermediate values for debugging
  // Usage: debug_carrot_view_tag(D_e_hex, K_o_hex, k_vi_hex, is_coinbase,
  // block_height, first_key_image_hex) Returns: {inputs: {...}, steps: {ecdh,
  // input_context, view_tag}, computed_view_tag: [b0, b1, b2]}
  function("debug_carrot_view_tag", &debug_carrot_view_tag);

  // Compute Carrot INTERNAL enote view tag (for change/selfsend outputs)
  // Usage: debug_carrot_internal_view_tag(K_o_hex, s_view_balance_hex,
  // first_key_image_hex) Returns: {inputs: {...}, computed_view_tag: [b0, b1,
  // b2], computed_view_tag_hex: "..."}
  function("debug_carrot_internal_view_tag", &debug_carrot_internal_view_tag);

  // ========================================================================
  // COMPACT SCAN PROTOCOL (CSP) - ZERO-COPY BINARY SCANNING
  // ========================================================================
  // Scan flat binary CSP buffer with pointer arithmetic (no allocations!)
  // Usage:
  //   const ptr = Module.allocate_binary_buffer(cspBuffer.byteLength);
  //   Module.HEAPU8.set(new Uint8Array(cspBuffer), ptr);
  //   const resultJson = Module.scan_csp_batch(ptr, cspBuffer.byteLength,
  //   viewSecretKeyHex); Module.free_binary_buffer(ptr); const result =
  //   JSON.parse(resultJson);
  // Returns: {matches: [{tx, out, tag}...], spent: [], stats: {...}, success:
  // true}
  function("scan_csp_batch", &scan_csp_batch);

  // CSP v6: Scan with spent output detection
  // Extra param: key_images_hex - comma-separated 64-char hex key images
  // Returns: {matches: [...], spent: [{tx, height, input, key_image}...],
  // stats: {...}}
  function("scan_csp_batch_with_spent", &scan_csp_batch_with_spent);

  // v4.2.0: Scan with stake return height filtering (eliminates 65% coinbase
  // false positives) stake_return_heights: comma-separated decimal heights
  // (e.g., "21601,21602,43202") Only coinbase outputs at these heights will be
  // passed through
  function("scan_csp_batch_with_stake_filter",
           &scan_csp_batch_with_stake_filter);

  // v5.1.0: Scan with FULL ownership verification (reduces Phase 1 to ~3K
  // matches) subaddress_map_csv: from get_subaddress_spend_keys_csv() -
  // "pubkey:major:minor:derive_type,..." Returns only VERIFIED matches, cutting
  // Phase 2A fetch time by 89%
  function("scan_csp_with_ownership", &scan_csp_with_ownership);

  // CSP v6: Scan with FULL ownership verification + spent detection
  // key_images_hex: comma-separated 64-char hex key images (from
  // get_key_images_csv())
  function("scan_csp_with_ownership_and_spent",
           &scan_csp_with_ownership_and_spent);

  // Phase 1b FAST: Key-image-only scan (skips all output processing)
  // ~10x faster than full scan - ONLY checks TX inputs for our key images
  // Use for spent detection after Phase 1+2 have found all incoming outputs
  // key_images_csv: comma-separated 64-char hex (from get_key_images_csv())
  // Returns:
  // {spent:[{tx_idx,block_height,input_idx,key_image}],inputs_scanned,spent_found}
  function("scan_csp_key_images_only", &scan_csp_key_images_only);

  // DEBUG: Find a specific transaction in CSP and compare view tags
  // Usage: debug_csp_find_tx(ptr, size, txPubkeyHex, viewSecretKeyHex)
  function("debug_csp_find_tx", &debug_csp_find_tx);

  // DEBUG: Parse a transaction blob and extract hash/pubkey/view_tags
  // Usage: debug_parse_tx_blob(ptr, size) -> {tx_hash, tx_pubkey, output_count,
  // output_view_tags}
  function("debug_parse_tx_blob", &debug_parse_tx_blob);

  // DEBUG: Parse AUDIT tx using manual parser and show return_address
  // Usage: debug_parse_audit_tx(ptr, size) -> {return_address, spend_pubkey,
  // ...}
  function("debug_parse_audit_tx", &debug_parse_audit_tx);

  // DEBUG: Derive subaddress public key from tx_pub, view_sec, out_key,
  // output_index This computes: derived_spend_key = out_key - H(derivation ||
  // output_index) * G Usage: debug_derive_subaddress_public_key(txPubHex,
  // viewSecHex, outKeyHex, outputIndex) Returns: {derivation,
  // derived_spend_key, view_tag, success:true}
  function("debug_derive_subaddress_public_key",
           &debug_derive_subaddress_public_key);

  // DEBUG: Compute derivation and view tag from pubkey + view_secret
  // Usage: debug_derive_view_tag(pubkeyHex, viewSecretHex, outputIdx)
  // Returns: {derivation, view_tag, view_tag_hex, derivation_ok}
  function("debug_derive_view_tag", &debug_derive_view_tag);

  // DEBUG: Derive spend key from output key using derivation
  // Usage: debug_derive_spend_key(outputKeyHex, additionalPubkeyHex,
  // viewSecretHex, outputIdx) Returns: {derived_spend_key, matches_main_spend,
  // ...}
  function("debug_derive_spend_key", &debug_derive_spend_key);

  // ========================================================================
  // SERVER-SIDE EPEE TO CSP CONVERSION
  // ========================================================================
  // Convert getblocks.bin (Epee) to CSP (Compact Scan Protocol) using Monero's
  // native epee parser. This runs on the Node.js backend, not in browser!
  // Usage (Node.js):
  //   const wasmModule = await SalviumWallet();
  //   const ptr = wasmModule.allocate_binary_buffer(epeeBuffer.length);
  //   wasmModule.HEAPU8.set(epeeBuffer, ptr);
  //   const resultJson = wasmModule.convert_epee_to_csp(ptr, epeeBuffer.length,
  //   startHeight); const result = JSON.parse(resultJson);
  //   // Copy CSP data from WASM heap: wasmModule.HEAPU8.slice(result.ptr,
  //   result.ptr + result.size) wasmModule.free_binary_buffer(ptr); // Free
  //   epee buffer wasmModule.free_binary_buffer(result.ptr);   // Free CSP
  //   buffer
  // Returns: {ptr, size, tx_count, output_count, convert_ms, success: true}
  function("convert_epee_to_csp", &convert_epee_to_csp);

  // ========================================================================
  // CONVERT EPEE TO CSP WITH TRANSACTION INDEX
  // ========================================================================
  // Enhanced version that also outputs a transaction blob index.
  // This enables instant sparse extraction without WASM re-parsing!
  // Usage (Node.js):
  //   const resultJson = wasmModule.convert_epee_to_csp_with_index(ptr, size,
  //   startHeight); const result = JSON.parse(resultJson);
  //   // result.csp_ptr, result.csp_size - CSP data
  //   // result.index_ptr, result.index_size - Transaction index data
  //   // Remember to free BOTH buffers!
  // Index format: "TXI\x01" + TxCount(4) + Reserved(8) + [BlobSize(4) +
  // Blob]...
  function("convert_epee_to_csp_with_index", &convert_epee_to_csp_with_index);

  // ========================================================================
  // INSPECT EPEE BLOCK - Debug function to inspect TX count at specific height
  // ========================================================================
  // Parses Epee data and returns detailed info about a specific block.
  // Usage (Node.js):
  //   const resultJson = wasmModule.inspect_epee_block(ptr, size, startHeight,
  //   targetHeight); const result = JSON.parse(resultJson);
  // Returns: {height, user_tx_count_in_epee, tx_pubkeys: [...], success: true}
  function("inspect_epee_block", &inspect_epee_block);

  // ========================================================================
  // SPARSE TRANSACTION EXTRACTION - For targeted rescan bandwidth reduction
  // ========================================================================
  // Extract only specific transactions from an Epee blob by index.
  // Used during targeted rescan to download ~8MB instead of ~2GB.
  // Usage (Node.js):
  //   const ptr = wasmModule.allocate_binary_buffer(epeeBuffer.length);
  //   wasmModule.HEAPU8.set(epeeBuffer, ptr);
  //   const resultJson = wasmModule.extract_sparse_txs(ptr, epeeBuffer.length,
  //   "[4, 12, 155]", startHeight); const result = JSON.parse(resultJson);
  //   // result.ptr points to sparse data, result.size is byte length
  //   const sparseData = wasmModule.HEAPU8.slice(result.ptr, result.ptr +
  //   result.size); wasmModule.free_binary_buffer(ptr);         // Free epee
  //   buffer wasmModule.free_binary_buffer(result.ptr); // Free sparse buffer
  // Sparse format: [TxCount:4] + [GlobalIndex:4][TxSize:4][TxBlob]...
  function("extract_sparse_txs", &extract_sparse_txs);

  // Diagnostic test functions (for debugging epee parsing issues)
  function("test_epee_parse", &test_epee_parse);
  function("test_getblocks_parse", &test_getblocks_parse);
  function("debug_inspect_tx_keys", &debug_inspect_tx_keys);
  function("debug_probe_derivation", &debug_probe_derivation);

  // ========================================================================
  // STAKE CACHE BUILDING - Extract stake info from transaction blobs
  // ========================================================================
  // Used by server to build a cache of ALL stakes for efficient return
  // detection. Usage: extract_stake_info(ptr, size, blockHeight) -> {is_stake,
  // return_address, ...}
  function("extract_stake_info", &extract_stake_info);

  // Extract ALL stakes from an entire Epee block chunk (BIN file)
  // Usage: extract_all_stakes(ptr, size, startHeight) -> {stakes: [...], stats,
  // success}
  function("extract_all_stakes", &extract_all_stakes);
  function("extract_return_tx_heights", &extract_return_tx_heights);
  function("extract_key_images", &extract_key_images);

  // ========================================================================
  // ZERO-COPY MEMORY FUNCTIONS
  // These allow JavaScript to write directly to WASM heap for maximum speed.
  // Usage:
  //   const ptr = Module._allocate_binary_buffer(buffer.byteLength);
  //   Module.HEAPU8.set(new Uint8Array(buffer), ptr);
  //   const result = wallet.ingest_blocks_raw(ptr, buffer.byteLength);
  //   Module._free_binary_buffer(ptr);
  // ========================================================================
  function("allocate_binary_buffer", &allocate_binary_buffer);
  function("free_binary_buffer", &free_binary_buffer);

  // HTTP Cache functions for transaction creation
  // JavaScript fetches decoys from daemon, injects here, then calls
  // create_transaction Usage:
  //   1. JS calls daemon /get_outs.bin via fetch()
  //   2. JS calls inject_decoy_outputs(responseArrayBuffer)
  //   3. JS calls create_transaction(...)
  //   4. wallet2 internally calls HTTP client which returns cached data
  function("inject_decoy_outputs", &inject_decoy_outputs);
  function("inject_decoy_outputs_base64", &inject_decoy_outputs_base64);
  function("inject_decoy_outputs_json", &inject_decoy_outputs_json);
  function("inject_decoy_outputs_from_json",
           &inject_decoy_outputs_from_json); // Parse JSON, construct binary
  function("inject_json_rpc_response",
           &inject_json_rpc_response); // For fee estimate, etc.
  function("inject_output_distribution", &inject_output_distribution);
  function("inject_output_distribution_from_json",
           &inject_output_distribution_from_json); // Parse JSON, serialize to
                                                   // binary epee
  function("set_blockchain_height",
           &set_blockchain_height); // For unlock time calculation after import
  function("clear_http_cache", &clear_http_cache);
  function("has_decoy_outputs", &has_decoy_outputs);

  // Two-phase transaction support: capture what outputs the wallet requests
  // 1. First TX attempt fails (cache miss), but captures request
  // 2. JS calls has_pending_get_outs_request() to check
  // 3. JS calls get_pending_get_outs_request() to get base64 request body
  // 4. JS parses request, fetches exact outputs, injects them
  // 5. Second TX attempt succeeds
  function("has_pending_get_outs_request", &has_pending_get_outs_request);
  function("get_pending_get_outs_request", &get_pending_get_outs_request);
  function("clear_pending_get_outs_request", &clear_pending_get_outs_request);

  // Direct RPC cache injection (bypasses HTTP layer format issues)
  // These populate wallet2's NodeRPCProxy cache directly
  function("inject_fee_estimate", &inject_fee_estimate);
  function("inject_hardfork_info", &inject_hardfork_info);
  function("inject_rpc_version", &inject_rpc_version);
  function("inject_daemon_info", &inject_daemon_info);

  // Block scanning functions for wallet refresh/sync
  // JavaScript fetches blocks from daemon, injects here, then calls refresh()
  // Usage:
  //   1. JS calls daemon /getblocks.bin via fetch() (POST with block_ids
  //   serialized)
  //   2. JS calls inject_blocks_response(responseArrayBuffer)
  //   3. JS calls wallet.refresh()
  //   4. wallet2 internally processes the cached blocks
  function("inject_blocks_response", &inject_blocks_response);
  function("inject_hashes_response", &inject_hashes_response);
  function("has_blocks_cached", &has_blocks_cached);
}
// Version Force: broadcast-fix-v2
