/**
 * donna64_embind.cpp - Embind bindings for donna64 fast crypto
 * 
 * This exposes the donna64 optimized key derivation to JavaScript via Embind.
 * It wraps the C functions in C++ for use with Emscripten's --bind feature.
 */

#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <sstream>

// Include the donna64 C header
extern "C" {
    #include "donna64_ge.h"
    
    // From donna64_crypto_hook.c
    int fast_generate_key_derivation(unsigned char *derivation_out,
                                     const unsigned char *tx_pub_in,
                                     const unsigned char *view_sec_in);
    int fast_batch_key_derivations(unsigned char *derivations_out,
                                   const unsigned char *tx_pubs_in,
                                   const unsigned char *view_sec_in,
                                   int count);
    int donna64_get_version(void);
    int donna64_benchmark(int iterations);
    int donna64_debug_test(void);
    int donna64_debug_get_byte(int index);
}

using namespace emscripten;

// ============================================================================
// Helper to convert hex string to bytes
// ============================================================================
static bool hex_to_bytes(const std::string& hex, unsigned char* out, size_t out_len) {
    if (hex.length() != out_len * 2) return false;
    
    for (size_t i = 0; i < out_len; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        
        int hi_val = (hi >= '0' && hi <= '9') ? (hi - '0') :
                     (hi >= 'a' && hi <= 'f') ? (hi - 'a' + 10) :
                     (hi >= 'A' && hi <= 'F') ? (hi - 'A' + 10) : -1;
        int lo_val = (lo >= '0' && lo <= '9') ? (lo - '0') :
                     (lo >= 'a' && lo <= 'f') ? (lo - 'a' + 10) :
                     (lo >= 'A' && lo <= 'F') ? (lo - 'A' + 10) : -1;
        
        if (hi_val < 0 || lo_val < 0) return false;
        out[i] = (unsigned char)((hi_val << 4) | lo_val);
    }
    return true;
}

// ============================================================================
// Helper to convert bytes to hex string
// ============================================================================
static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result.push_back(hex_chars[data[i] >> 4]);
        result.push_back(hex_chars[data[i] & 0x0f]);
    }
    return result;
}

// ============================================================================
// Donna64Scanner class - High-level API for JavaScript
// ============================================================================
class Donna64Scanner {
private:
    unsigned char m_view_secret[32];
    bool m_view_secret_set;
    
    // Reusable buffers
    unsigned char m_derivation[32];
    unsigned char m_tx_pub[32];

public:
    Donna64Scanner() : m_view_secret_set(false) {
        std::memset(m_view_secret, 0, 32);
        std::memset(m_derivation, 0, 32);
        std::memset(m_tx_pub, 0, 32);
    }
    
    /**
     * Get donna64 version
     */
    int get_version() const {
        return donna64_get_version();
    }
    
    /**
     * Set the view secret key (call once per wallet)
     * @param view_sec_hex 64-character hex string
     * @return true on success
     */
    bool set_view_secret_key(const std::string& view_sec_hex) {
        if (!hex_to_bytes(view_sec_hex, m_view_secret, 32)) {
            return false;
        }
        m_view_secret_set = true;
        return true;
    }
    
    /**
     * Generate key derivation for a single transaction
     * @param tx_pub_hex 64-character hex transaction public key
     * @return 64-character hex derivation, or empty string on failure
     */
    std::string generate_key_derivation(const std::string& tx_pub_hex) {
        if (!m_view_secret_set) return "";
        
        if (!hex_to_bytes(tx_pub_hex, m_tx_pub, 32)) {
            return "";
        }
        
        int result = fast_generate_key_derivation(m_derivation, m_tx_pub, m_view_secret);
        if (result != 1) {
            return "";  // Invalid point
        }
        
        return bytes_to_hex(m_derivation, 32);
    }
    
    /**
     * Run benchmark and return results as JSON
     * @param iterations Number of derivations to compute
     */
    std::string benchmark(int iterations) {
        auto start = std::chrono::high_resolution_clock::now();
        int success = donna64_benchmark(iterations);
        auto end = std::chrono::high_resolution_clock::now();
        
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double avg_us = (elapsed_ms * 1000.0) / iterations;
        double per_second = (iterations / elapsed_ms) * 1000.0;
        
        std::ostringstream oss;
        oss << "{"
            << "\"iterations\":" << iterations << ","
            << "\"success_count\":" << success << ","
            << "\"total_ms\":" << elapsed_ms << ","
            << "\"avg_microseconds\":" << avg_us << ","
            << "\"derivations_per_second\":" << static_cast<int>(per_second)
            << "}";
        return oss.str();
    }
};

// ============================================================================
// Standalone functions for direct use (raw pointers, zero-copy)
// These can be called via Module.ccall/cwrap after malloc/free
// ============================================================================

/**
 * donna64_derive - Zero-copy key derivation
 * All buffers must be pre-allocated in WASM heap
 * @param derivation_ptr Pointer to 32-byte output buffer
 * @param tx_pub_ptr Pointer to 32-byte tx public key
 * @param view_sec_ptr Pointer to 32-byte view secret key  
 * @return 1 on success, 0 on failure
 */
int donna64_derive(uintptr_t derivation_ptr, uintptr_t tx_pub_ptr, uintptr_t view_sec_ptr) {
    return fast_generate_key_derivation(
        reinterpret_cast<unsigned char*>(derivation_ptr),
        reinterpret_cast<const unsigned char*>(tx_pub_ptr),
        reinterpret_cast<const unsigned char*>(view_sec_ptr)
    );
}

/**
 * donna64_derive_batch - Zero-copy batch key derivation
 * @param derivations_ptr Pointer to (count * 32) byte output buffer
 * @param tx_pubs_ptr Pointer to (count * 32) byte input buffer
 * @param view_sec_ptr Pointer to 32-byte view secret key
 * @param count Number of derivations
 * @return Number of successful derivations
 */
int donna64_derive_batch(uintptr_t derivations_ptr, uintptr_t tx_pubs_ptr, 
                         uintptr_t view_sec_ptr, int count) {
    return fast_batch_key_derivations(
        reinterpret_cast<unsigned char*>(derivations_ptr),
        reinterpret_cast<const unsigned char*>(tx_pubs_ptr),
        reinterpret_cast<const unsigned char*>(view_sec_ptr),
        count
    );
}

// ============================================================================
// Embind registration
// ============================================================================
EMSCRIPTEN_BINDINGS(donna64_module) {
    // Donna64Scanner class for high-level usage
    class_<Donna64Scanner>("Donna64Scanner")
        .constructor<>()
        .function("get_version", &Donna64Scanner::get_version)
        .function("set_view_secret_key", &Donna64Scanner::set_view_secret_key)
        .function("generate_key_derivation", &Donna64Scanner::generate_key_derivation)
        .function("benchmark", &Donna64Scanner::benchmark);
    
    // Standalone functions for zero-copy performance
    function("donna64_derive", &donna64_derive);
    function("donna64_derive_batch", &donna64_derive_batch);
    function("donna64_get_version", &donna64_get_version);
    function("donna64_benchmark", &donna64_benchmark);
    function("donna64_debug_test", &donna64_debug_test);
    function("donna64_debug_get_byte", &donna64_debug_get_byte);
}
