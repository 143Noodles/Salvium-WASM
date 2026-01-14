/**
 * donna64_crypto_ops.h - Define monero_crypto_* to use donna64 in WASM
 * 
 * This header, when included BEFORE crypto/wallet/crypto.h, will cause
 * the wallet code to use our fast donna64 implementation instead of ref10.
 * 
 * Add this to the include path with higher priority than salvium headers.
 */

#ifndef DONNA64_CRYPTO_OPS_H
#define DONNA64_CRYPTO_OPS_H

#ifdef __cplusplus
extern "C" {
#endif

// Forward declare donna64 function from donna64_ge.c
int donna64_generate_key_derivation(unsigned char *derivation,
                                    const unsigned char *tx_pub,
                                    const unsigned char *view_sec);

// Define the macro that crypto/wallet/crypto.h checks for
#define monero_crypto_generate_key_derivation donna64_monero_generate_key_derivation

/**
 * donna64_monero_generate_key_derivation - WASM-optimized key derivation
 * 
 * This function has the same signature expected by crypto/wallet/ops.h
 * 
 * @param derivation Output: 32-byte key derivation
 * @param tx_pub Input: 32-byte transaction public key
 * @param view_sec Input: 32-byte view secret key
 * @return 0 on success, -1 on failure
 */
static inline int donna64_monero_generate_key_derivation(
    unsigned char *derivation,
    const unsigned char *tx_pub,
    const unsigned char *view_sec)
{
    return donna64_generate_key_derivation(derivation, tx_pub, view_sec);
}

#ifdef __cplusplus
}
#endif

#endif /* DONNA64_CRYPTO_OPS_H */
