//
// wasm_node_rpc_proxy_compat.hpp
// Salvium Wallet2 WASM Port
//
// ============================================================================
// COMPATIBILITY LAYER: Makes WasmNodeRpcProxy a drop-in for NodeRPCProxy
// ============================================================================
//
// This header provides a WasmNodeRpcProxy class that EXACTLY matches the
// public interface of tools::NodeRPCProxy from wallet2.
//
// The preprocessor swap in CMakeLists:
//   add_compile_definitions(NodeRPCProxy=wasm_bridge::WasmNodeRpcProxy)
//
// Requires this class to have:
// 1. Same constructor signature
// 2. Same public method signatures
// 3. Same return types (boost::optional<std::string> for errors)
//
// The key difference: Instead of making HTTP calls, we read from local cache.
// ============================================================================

#ifndef WASM_NODE_RPC_PROXY_COMPAT_HPP
#define WASM_NODE_RPC_PROXY_COMPAT_HPP

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <functional>
#include <cstdint>
#include <boost/optional.hpp>
#include <boost/thread/recursive_mutex.hpp>

// Forward declarations to avoid including heavy headers
namespace epee {
namespace net_utils {
namespace http {
    class abstract_http_client;
}
}
}

namespace crypto {
    struct secret_key;
    struct hash;
}

namespace cryptonote {
    struct blobdata;
    struct block_header_response;
    struct COMMAND_RPC_GET_TRANSACTIONS;
}

// Include the RPC types we need
#include "rpc/core_rpc_server_commands_defs.h"
#include "wallet_rpc_helpers.h"
#include "crypto/crypto.h"

namespace wasm_bridge {

// ============================================================================
// Cached Data Structures (same as wasm_node_rpc_proxy.hpp)
// ============================================================================
struct CachedBlock {
    uint64_t height;
    std::string block_blob;
    std::vector<std::string> tx_blobs;
    uint64_t timestamp;
    std::string block_hash;
};

struct DaemonInfo {
    uint64_t height = 0;
    uint64_t target_height = 0;
    std::string difficulty;
    std::string top_block_hash;
    uint64_t adjusted_time = 0;
    bool offline = true;
};

// ============================================================================
// WasmNodeRpcProxy - EXACT interface match for tools::NodeRPCProxy
// ============================================================================
class WasmNodeRpcProxy {
public:
    // ========================================================================
    // Constructor - MUST match NodeRPCProxy exactly!
    // 
    // The http_client and mutex are stored but NOT USED in WASM.
    // We accept them to satisfy wallet2's constructor requirements.
    // ========================================================================
    WasmNodeRpcProxy(
        epee::net_utils::http::abstract_http_client &http_client,
        tools::rpc_payment_state_t &rpc_payment_state,
        boost::recursive_mutex &mutex
    );
    
    ~WasmNodeRpcProxy();

    // ========================================================================
    // Public Methods - EXACT signatures from NodeRPCProxy
    // ========================================================================
    
    void set_client_secret_key(const crypto::secret_key &skey);
    void invalidate();
    void set_offline(bool offline);

    /**
     * Get RPC version and daemon info
     * Original makes HTTP call to /get_info
     * WASM version returns from cache
     */
    boost::optional<std::string> get_rpc_version(
        uint32_t &rpc_version,
        std::vector<std::pair<uint8_t, uint64_t>> &daemon_hard_forks,
        uint64_t &height,
        uint64_t &target_height
    );

    /**
     * Get current blockchain height
     */
    boost::optional<std::string> get_height(uint64_t &height);
    
    /**
     * Set height (called when we know the height from injected data)
     */
    void set_height(uint64_t h);

    /**
     * Get target height (sync target)
     */
    boost::optional<std::string> get_target_height(uint64_t &height);

    /**
     * Get block weight limit
     */
    boost::optional<std::string> get_block_weight_limit(uint64_t &block_weight_limit);

    /**
     * Get adjusted time from daemon
     */
    boost::optional<std::string> get_adjusted_time(uint64_t &adjusted_time);

    /**
     * Get earliest height for a specific hardfork version
     */
    boost::optional<std::string> get_earliest_height(uint8_t version, uint64_t &earliest_height);

    /**
     * Get dynamic base fee estimate
     */
    boost::optional<std::string> get_dynamic_base_fee_estimate(
        uint64_t grace_blocks,
        uint64_t &fee
    );

    /**
     * Get dynamic base fee estimate (2021 scaling)
     */
    boost::optional<std::string> get_dynamic_base_fee_estimate_2021_scaling(
        uint64_t grace_blocks,
        std::vector<uint64_t> &fees
    );

    /**
     * Get fee quantization mask
     */
    boost::optional<std::string> get_fee_quantization_mask(uint64_t &fee_quantization_mask);

    /**
     * Get RPC payment info
     */
    boost::optional<std::string> get_rpc_payment_info(
        bool mining,
        bool &payment_required,
        uint64_t &credits,
        uint64_t &diff,
        uint64_t &credits_per_hash_found,
        cryptonote::blobdata &blob,
        uint64_t &height,
        uint64_t &seed_height,
        crypto::hash &seed_hash,
        crypto::hash &next_seed_hash,
        uint32_t &cookie
    );

    /**
     * Get transactions by hash
     * 
     * ⚠️ CRITICAL: This is heavily used during scanning!
     * Original: Makes HTTP call to /get_transactions
     * WASM: Returns from local transaction cache
     */
    boost::optional<std::string> get_transactions(
        const std::vector<crypto::hash> &txids,
        const std::function<void(
            const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request&,
            const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response&,
            bool
        )> &f
    );

    /**
     * Get block header by height
     */
    boost::optional<std::string> get_block_header_by_height(
        uint64_t height,
        cryptonote::block_header_response &block_header
    );

    // ========================================================================
    // WASM-SPECIFIC DATA INJECTION API
    // These methods are called from JavaScript to populate the cache.
    // They don't exist in the original NodeRPCProxy.
    // ========================================================================
    
    /**
     * Inject blocks into cache (called from JS)
     */
    void inject_block_data(const std::vector<CachedBlock>& blocks);
    
    /**
     * Inject single block
     */
    void inject_block(
        uint64_t height,
        const std::string& block_blob,
        const std::vector<std::string>& tx_blobs
    );
    
    /**
     * Inject daemon info (height, target_height, etc.)
     */
    void inject_daemon_info(const DaemonInfo& info);
    
    /**
     * Clear all cached data
     */
    void clear_cache();
    
    /**
     * Get cache status as JSON for debugging
     */
    std::string get_cache_status_json() const;
    
    /**
     * Check if we need more blocks
     */
    bool needs_more_blocks(uint64_t wallet_height, uint64_t target_height) const;

private:
    // References stored but not used (satisfy wallet2's requirements)
    epee::net_utils::http::abstract_http_client& m_http_client;
    tools::rpc_payment_state_t& m_rpc_payment_state;
    boost::recursive_mutex& m_daemon_rpc_mutex;
    
    // Client secret key (stored but unused in WASM)
    crypto::secret_key m_client_id_secret_key;
    
    // Offline flag
    bool m_offline;
    
    // Cached daemon info
    DaemonInfo m_daemon_info;
    
    // Block cache (height -> block data)
    std::map<uint64_t, CachedBlock> m_block_cache;
    
    // Mutex for thread safety
    mutable std::mutex m_cache_mutex;
    
    // Cache limits
    static constexpr size_t MAX_BLOCK_CACHE_SIZE = 10000;
    
    // Cached values (matching NodeRPCProxy's internal state)
    uint64_t m_height;
    uint64_t m_target_height;
    uint64_t m_block_weight_limit;
    uint64_t m_adjusted_time;
    uint32_t m_rpc_version;
    uint64_t m_earliest_height[256];
    uint64_t m_dynamic_base_fee_estimate;
    uint64_t m_fee_quantization_mask;
    std::vector<uint64_t> m_dynamic_base_fee_estimate_vector;
    std::vector<std::pair<uint8_t, uint64_t>> m_daemon_hard_forks;
    
    // Helper to prune old blocks from cache
    void prune_block_cache();
};

// ============================================================================
// Global accessor for the WASM proxy instance
// (Used by inject_* functions from JS)
// ============================================================================
WasmNodeRpcProxy& get_global_rpc_proxy();

} // namespace wasm_bridge

#endif // WASM_NODE_RPC_PROXY_COMPAT_HPP
