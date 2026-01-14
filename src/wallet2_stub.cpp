// =============================================================================
// wallet2_stub.cpp - Header Compilation Test
// =============================================================================
// Purpose: Verify that wallet2.h can be included without errors after
// applying the shadow header strategy for NodeRPCProxy.
//
// This is a "baby step" test - if this compiles, the header shadowing works
// and all dependencies are correctly set up.
//
// Build: Add to CMakeLists and attempt compilation
// =============================================================================

// NOTE: We do NOT define __linux__ because Boost.Asio would then try to
// include linux/version.h which doesn't exist in WASM environment.
// Instead we rely on BOOST_ASIO_DISABLE_* flags to disable Linux-specific features.

// Our shadow header should be found BEFORE the official one
// due to include_directories(BEFORE ...) in CMakeLists
#include "wallet/wallet2.h"

#include <iostream>

namespace wasm_test {

// Simple function to verify wallet2 header is parseable
void test_wallet2_header_inclusion() {
    std::cout << "wallet2.h included successfully!" << std::endl;
    
    // If we can reference types from wallet2, the header is working
    // Note: We're not instantiating yet, just checking type visibility
    
    // Check that NodeRPCProxy is visible (should be our shadow version)
    // tools::NodeRPCProxy* proxy_ptr = nullptr;
    // (void)proxy_ptr;
}

// More aggressive test - try to instantiate wallet2
// This will fail initially because wallet2 has many dependencies
// Uncomment when ready for Phase 2
/*
void test_wallet2_instantiation() {
    // This requires ALL dependencies to be properly linked:
    // - Boost (serialization, system, thread, chrono, filesystem)
    // - libsodium
    // - cryptonote_core (or stubs)
    // - ringct
    // - etc.
    
    tools::wallet2 w;
    std::cout << "wallet2 instantiated successfully!" << std::endl;
}
*/

} // namespace wasm_test

// Simple main for syntax-only compilation test
int main() {
    // If this compiles, it means:
    // 1. Shadow header was found before the original
    // 2. wallet2.h parsed without errors
    // 3. All dependencies resolved
    return sizeof(tools::wallet2);
}

// Export a simple test function via Embind
#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>

EMSCRIPTEN_BINDINGS(wallet2_stub) {
    emscripten::function("testWallet2Header", &wasm_test::test_wallet2_header_inclusion);
}
#endif
