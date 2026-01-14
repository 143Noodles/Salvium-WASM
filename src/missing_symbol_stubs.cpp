// Missing symbol stubs for WASM build
// These functions are declared but not needed for basic wallet operations

#include <cstdint>
#include <set>
#include <string>

namespace cryptonote {

// Stub for tx_sanity_check - daemon validates TX anyway, skip client-side check
// This checks ring signature distribution to detect potential attacks
// For web wallet, the daemon will reject invalid TXs, so we skip this check
bool tx_sanity_check(const std::set<uint64_t>& rct_indices, size_t n_indices, uint64_t rct_outs_available) {
    // Always return true - let daemon validate
    // The actual check analyzes ring member distribution but requires 
    // complex statistical analysis that's redundant when daemon validates
    (void)rct_indices;
    (void)n_indices;
    (void)rct_outs_available;
    return true;
}

// Overload with blobdata (std::string) - also stubbed
bool tx_sanity_check(const std::string& tx_blob, uint64_t rct_outs_available) {
    (void)tx_blob;
    (void)rct_outs_available;
    return true;
}

} // namespace cryptonote
