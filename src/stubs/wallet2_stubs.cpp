// wallet2_stubs.cpp - WASM stubs for wallet2 dependencies
// These stubs provide minimal implementations for functions that are:
// 1. Not needed for light wallet operation
// 2. Cannot be compiled to WASM (hardware-specific, network, etc.)

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>


// ============================================================================
// Miner stub is in separate file: miner_stub.cpp
// ============================================================================

// ============================================================================
// i18n translation stub - full implementation
// ============================================================================

#include <cstring>
#include <stdarg.h>
#include <stdio.h>


// Main translate function
const char *i18n_translate(const char *s, const std::string &context) {
  // Return the original string without translation
  return s;
}

// These are the actual symbols that i18n.cpp would export
extern "C" {
const char *i18n_get_language() { return "en"; }

int i18n_set_language(const char *directory, const char *language,
                      std::string &error) {
  // Successfully "set" to English (no-op)
  return 0;
}
}

// For wallet2 i18n usage
namespace i18n {
const char *tr(const char *s) { return s; }
} // namespace i18n

// ============================================================================
// mx25519 - X25519 Montgomery curve scalar multiplication
// NOTE: Now using real mx25519 library compiled from salvium/external/mx25519
// The stubs were removed to avoid duplicate symbol errors during linking.
// ============================================================================

// ============================================================================
// Hardfork data stubs - needed by wallet2 for version checking
// IMPORTANT: This data must match the actual Salvium hardfork schedule!
// Used for: protocol version selection, feature availability, daemon validation
// ============================================================================

// Include the hardforks header to get the struct definition with constructor
#include "hardforks/hardforks.h"

// Mainnet hard forks - MUST match salvium/src/hardforks/hardforks.cpp
const hardfork_t mainnet_hard_forks[] = {
    // version 1 from the start of the blockchain
    {1, 1, 0, 1341378000},
    // version 2 starts from block 89800 (Nov 4, 2024)
    {2, 89800, 0, 1729518000},
    // version 3 starts from block 121100 (Dec 19, 2024)
    {3, 121100, 0, 1734516900},
    // version 4 starts from block 121800 (Dec 20, 2024)
    {4, 121800, 0, 1734607000},
    // version 5 starts from block 136100 (Jan 9, 2025)
    {5, 136100, 0, 1736265945},
    // version 6 starts from block 154750 (Feb 4, 2025)
    {6, 154750, 0, 1738336000},
    // version 7 starts from block 161900 (Feb 14, 2025)
    {7, 161900, 0, 1739264400},
    // version 8 starts from block 172000 (Feb 28, 2025)
    {8, 172000, 0, 1740390000},
    // version 9 starts from block 179200 (Mar 10, 2025)
    {9, 179200, 0, 1740393800},
    // version 10 Carrot - starts from block 334750 (Oct 13, 2025)
    {10, 334750, 0, 1759142500},
};
const size_t num_mainnet_hard_forks =
    sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]);
const uint64_t mainnet_hard_fork_version_1_till = ((uint64_t)-1);

const hardfork_t testnet_hard_forks[] = {
    {1, 1, 0, 1341378000},
    {2, 250, 0, 1445355000},
    {3, 500, 0, 1729518000},
    {4, 600, 0, 1734607000},
};
const size_t num_testnet_hard_forks =
    sizeof(testnet_hard_forks) / sizeof(testnet_hard_forks[0]);
const uint64_t testnet_hard_fork_version_1_till = ((uint64_t)-1);

const hardfork_t stagenet_hard_forks[] = {
    {1, 1, 0, 1341378000},
};
const size_t num_stagenet_hard_forks =
    sizeof(stagenet_hard_forks) / sizeof(stagenet_hard_forks[0]);

// ============================================================================
// Carrot tx proof - NOW COMPILED FROM SALVIUM SOURCE
// The following stubs were removed because the real implementations
// are now compiled from salvium/src/crypto/crypto.cpp and
// salvium/src/device/device_default.cpp in Dockerfile.updatesource.
// Keeping stubs here would cause duplicate symbol linker errors.
// ============================================================================
