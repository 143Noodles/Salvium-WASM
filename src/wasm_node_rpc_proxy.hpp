//
// wasm_node_rpc_proxy.hpp
// Salvium Wallet2 WASM Port
//
// ============================================================================
// ⚠️ CRITICAL ARCHITECTURE: THE "PUSH" MODEL
// ============================================================================
//
// Problem: wallet2 is "chatty" - it makes many small RPC calls during refresh.
// If each call triggers Asyncify (unwind C++ stack → JS fetch → rewind),
// performance dies and the browser UI freezes.
//
// Solution: The PUSH model - JavaScript pushes data INTO C++, C++ never pulls.
//
// Flow:
//   1. JS fetches 1000 blocks from daemon
//   2. JS calls WasmNodeRpcProxy::inject_block_data(blocks)
//   3. Blocks are stored in a local std::deque buffer
//   4. JS calls wallet.refresh()
//   5. When wallet2 calls get_blocks(), we return from LOCAL BUFFER
//   6. If buffer is empty, return empty (pause refresh), NOT Asyncify fetch
//   7. Repeat from step 1
//
// This eliminates ALL Asyncify network overhead during scanning!
// ============================================================================

#ifndef WASM_NODE_RPC_PROXY_HPP
#define WASM_NODE_RPC_PROXY_HPP

#include <string>
#include <vector>
#include <deque>
#include <map>
#include <mutex>
#include <cstdint>
#include <memory>
#include <optional>

#ifdef __EMSCRIPTEN__
#include <emscripten/val.h>
#endif

namespace wasm_bridge {

// ============================================================================
// Block Data Structure (for local cache)
// ============================================================================
struct CachedBlock {
    uint64_t height;
    std::string block_blob;         // Raw block blob (hex or binary)
    std::vector<std::string> tx_blobs;  // Transaction blobs in this block
    uint64_t timestamp;             // Block timestamp
    std::string block_hash;         // Block hash
};

// ============================================================================
// Transaction Data Structure
// ============================================================================
struct CachedTransaction {
    std::string txid;
    std::string tx_blob;
    uint64_t block_height;
    uint64_t timestamp;
};

// ============================================================================
// Daemon Info Cache
// ============================================================================
struct DaemonInfo {
    uint64_t height;
    uint64_t target_height;
    uint64_t difficulty;
    std::string top_block_hash;
    uint64_t adjusted_time;
    bool offline;
    uint64_t last_update_time;      // Unix timestamp of last update
};

// ============================================================================
// WasmNodeRpcProxy - The "PUSH" Model RPC Proxy
// ============================================================================
//
// This class replaces tools::NodeRPCProxy for WASM builds.
// Instead of making HTTP calls, it serves data from a local cache
// that JavaScript populates via inject_* methods.
//
class WasmNodeRpcProxy {
public:
    WasmNodeRpcProxy();
    ~WasmNodeRpcProxy();

    // ========================================================================
    // Configuration
    // ========================================================================
    
    /**
     * Set the daemon URL (stored for JS reference, not used for connections)
     */
    void set_daemon_address(const std::string& address);
    std::string get_daemon_address() const;
    
    /**
     * Mark proxy as offline/online
     */
    void set_offline(bool offline);
    bool is_offline() const;

    // ========================================================================
    // DATA INJECTION API (Called from JavaScript)
    // These methods populate the local cache. JS is responsible for fetching.
    // ========================================================================
    
    /**
     * Inject a batch of blocks into the local cache
     * 
     * @param blocks Vector of CachedBlock structures
     * 
     * JS should call this after fetching blocks from the daemon:
     *   const blocks = await fetch('/get_blocks?start=1000&count=1000');
     *   wallet.inject_block_data(blocks);
     */
    void inject_block_data(const std::vector<CachedBlock>& blocks);
    
    /**
     * Inject a single block (convenience method)
     */
    void inject_block(uint64_t height, 
                      const std::string& block_blob,
                      const std::vector<std::string>& tx_blobs,
                      const std::string& block_hash = "",
                      uint64_t timestamp = 0);
    
    /**
     * Inject transaction data (for tx pool or historical lookups)
     */
    void inject_transactions(const std::vector<CachedTransaction>& txs);
    
    /**
     * Inject daemon info (height, difficulty, etc.)
     * JS should call this periodically (every few seconds)
     */
    void inject_daemon_info(const DaemonInfo& info);
    
    /**
     * Clear the block cache (e.g., on reorg)
     */
    void clear_block_cache();
    
    /**
     * Clear all caches
     */
    void clear_all_caches();

    // ========================================================================
    // DATA RETRIEVAL API (Called by wallet2)
    // These return data from the local cache, NEVER trigger network calls.
    // ========================================================================
    
    /**
     * Get blocks from local cache
     * 
     * @param start_height Starting block height
     * @param max_count Maximum blocks to return
     * @param blocks_out Output vector for block data
     * @return Number of blocks returned (0 if cache empty/exhausted)
     * 
     * ⚠️ If cache is empty, returns 0 - does NOT trigger Asyncify fetch!
     * wallet2's refresh loop will pause and JS can inject more blocks.
     */
    size_t get_blocks(uint64_t start_height,
                      size_t max_count,
                      std::vector<CachedBlock>& blocks_out);
    
    /**
     * Get a specific block by height
     * 
     * @return std::nullopt if not in cache
     */
    std::optional<CachedBlock> get_block(uint64_t height);
    
    /**
     * Get transactions by txid
     */
    std::vector<CachedTransaction> get_transactions(const std::vector<std::string>& txids);
    
    /**
     * Get daemon info from cache
     */
    DaemonInfo get_daemon_info() const;
    
    /**
     * Get current blockchain height (from cached daemon info)
     */
    uint64_t get_height() const;
    
    /**
     * Get target height (for sync progress)
     */
    uint64_t get_target_height() const;

    // ========================================================================
    // CACHE STATUS API (For JS to know when to inject more data)
    // ========================================================================
    
    /**
     * Get the highest block height currently in cache
     */
    uint64_t get_cached_height() const;
    
    /**
     * Get the lowest block height currently in cache
     */
    uint64_t get_cache_start_height() const;
    
    /**
     * Get number of blocks currently cached
     */
    size_t get_cache_size() const;
    
    /**
     * Check if more blocks are needed
     * 
     * @param wallet_height Current wallet sync height
     * @param target_height Target blockchain height
     * @param threshold Minimum blocks to keep ahead
     * @return true if JS should fetch more blocks
     */
    bool needs_more_blocks(uint64_t wallet_height,
                          uint64_t target_height,
                          size_t threshold = 1000) const;
    
    /**
     * Get cache status as JSON (for debugging)
     */
    std::string get_cache_status_json() const;

    // ========================================================================
    // PAUSE/RESUME CONTROL
    // ========================================================================
    
    /**
     * Check if refresh should pause (cache exhausted)
     * wallet2 can check this and gracefully yield
     */
    bool should_pause_refresh() const;
    
    /**
     * Signal that more data is available (after JS injects blocks)
     */
    void signal_data_available();

private:
    // Daemon configuration
    std::string m_daemon_address;
    bool m_offline;
    
    // Block cache (height -> block data)
    std::map<uint64_t, CachedBlock> m_block_cache;
    mutable std::mutex m_block_cache_mutex;
    
    // Transaction cache (txid -> tx data)
    std::map<std::string, CachedTransaction> m_tx_cache;
    mutable std::mutex m_tx_cache_mutex;
    
    // Daemon info cache
    DaemonInfo m_daemon_info;
    mutable std::mutex m_daemon_info_mutex;
    
    // Pause control
    bool m_needs_more_data;
    mutable std::mutex m_pause_mutex;
    
    // Cache limits
    static constexpr size_t MAX_CACHED_BLOCKS = 10000;  // ~2GB RAM max
    static constexpr size_t CACHE_TRIM_SIZE = 5000;     // Trim to this when full
    
    // Internal helpers
    void trim_cache_if_needed();
};

// ============================================================================
// Global proxy instance (singleton for wallet2 access)
// ============================================================================
WasmNodeRpcProxy& get_global_rpc_proxy();

} // namespace wasm_bridge

#endif // WASM_NODE_RPC_PROXY_HPP
