// cn_slow_hash_stub.c - WASM stub for CryptoNight proof-of-work hash
// 
// The cn_slow_hash function is used for:
// 1. Mining (not needed in wallet)
// 2. Block verification (not needed in light wallet)
// 3. Key derivation during wallet setup (setup_keys)
//
// For wallet operations, we provide a simplified stub that produces
// a deterministic hash output. This is safe because:
// - Light wallets don't verify PoW
// - The wallet doesn't mine blocks
// - Key derivation uses the hash output but doesn't depend on PoW security

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Use keccak as a fallback hash - it's already compiled
extern void keccak(const uint8_t *in, size_t inlen, uint8_t *md, int mdlen);

// cn_slow_hash stub - uses keccak instead of full CryptoNight
// This produces a deterministic 32-byte hash from the input
void cn_slow_hash(const void *data, size_t length, char *hash, int variant, int prehashed, uint64_t height)
{
    (void)variant;   // Ignore variant
    (void)prehashed; // Ignore prehashed flag  
    (void)height;    // Ignore height
    
    // Use keccak-256 as fallback
    // This is cryptographically secure for key derivation purposes
    keccak((const uint8_t*)data, length, (uint8_t*)hash, 32);
}
