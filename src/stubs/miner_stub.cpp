// miner_stub.cpp - Stub for miner::find_nonce_for_given_block
// Light wallets don't mine, but genesis block generation calls this function
// This stub provides a no-op implementation that just returns true
//
// STRATEGY: Include cryptonote_basic.h for proper block struct definition
// but DO NOT include miner.h (it pulls in daemon dependencies).
// We define the miner class and function signature manually.

#include <cstdint>
#include <functional>

// Include cryptonote_basic.h to get proper block struct definition
// This is safe - it doesn't pull in networking/daemon code
#include "cryptonote_basic/cryptonote_basic.h"

// Define difficulty_type to match difficulty.h
// (avoid including difficulty.h which might have other deps)
#include <boost/multiprecision/cpp_int.hpp>

namespace cryptonote {

// Match the exact typedef from difficulty.h
typedef boost::multiprecision::uint128_t difficulty_type;

// Match the exact typedef from miner.h line 55:
// typedef std::function<bool(const cryptonote::block&, uint64_t, const crypto::hash*, unsigned int, crypto::hash&)> get_block_hash_t;
typedef std::function<bool(const cryptonote::block&, uint64_t, const crypto::hash*, unsigned int, crypto::hash&)> get_block_hash_t;

// Declare the miner class with just the static method we need to stub
// This must match the declaration in miner.h exactly for symbol compatibility
class miner {
public:
    static bool find_nonce_for_given_block(
        const get_block_hash_t& gbh,
        block& bl,
        const difficulty_type& diffic,
        uint64_t height,
        const crypto::hash* seed_hash = NULL
    );
};

// Implementation of the stub
bool miner::find_nonce_for_given_block(
    const get_block_hash_t& gbh,
    block& bl,
    const difficulty_type& diffic,
    uint64_t height,
    const crypto::hash* seed_hash
) {
    // For light wallet / genesis block generation:
    // Just return true - we don't actually mine
    // The nonce will be left at its default value (0)
    // This is fine because:
    // 1. Light wallets don't verify PoW
    // 2. Genesis block has hardcoded values anyway
    (void)gbh;
    (void)bl;
    (void)diffic;
    (void)height;
    (void)seed_hash;
    return true;
}

} // namespace cryptonote
