//
// wasm_node_rpc_proxy.cpp
// Salvium Wallet2 WASM Port
//
// Implementation of the PUSH model RPC proxy.
// See wasm_node_rpc_proxy.hpp for architecture documentation.
//

#include "wasm_node_rpc_proxy.hpp"
#include <sstream>
#include <algorithm>
#include <chrono>

namespace wasm_bridge {

// ============================================================================
// Global singleton
// ============================================================================
static WasmNodeRpcProxy g_rpc_proxy;

WasmNodeRpcProxy& get_global_rpc_proxy() {
    return g_rpc_proxy;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

WasmNodeRpcProxy::WasmNodeRpcProxy()
    : m_daemon_address("")
    , m_offline(true)
    , m_needs_more_data(true)
{
    m_daemon_info.height = 0;
    m_daemon_info.target_height = 0;
    m_daemon_info.difficulty = 0;
    m_daemon_info.offline = true;
    m_daemon_info.last_update_time = 0;
}

WasmNodeRpcProxy::~WasmNodeRpcProxy() = default;

// ============================================================================
// Configuration
// ============================================================================

void WasmNodeRpcProxy::set_daemon_address(const std::string& address) {
    m_daemon_address = address;
}

std::string WasmNodeRpcProxy::get_daemon_address() const {
    return m_daemon_address;
}

void WasmNodeRpcProxy::set_offline(bool offline) {
    m_offline = offline;
    std::lock_guard<std::mutex> lock(m_daemon_info_mutex);
    m_daemon_info.offline = offline;
}

bool WasmNodeRpcProxy::is_offline() const {
    return m_offline;
}

// ============================================================================
// DATA INJECTION API (Called from JavaScript)
// ============================================================================

void WasmNodeRpcProxy::inject_block_data(const std::vector<CachedBlock>& blocks) {
    std::lock_guard<std::mutex> lock(m_block_cache_mutex);
    
    for (const auto& block : blocks) {
        m_block_cache[block.height] = block;
    }
    
    // Trim cache if it's getting too large
    trim_cache_if_needed();
    
    // Signal that data is available
    signal_data_available();
}

void WasmNodeRpcProxy::inject_block(uint64_t height,
                                    const std::string& block_blob,
                                    const std::vector<std::string>& tx_blobs,
                                    const std::string& block_hash,
                                    uint64_t timestamp) {
    CachedBlock block;
    block.height = height;
    block.block_blob = block_blob;
    block.tx_blobs = tx_blobs;
    block.block_hash = block_hash;
    block.timestamp = timestamp;
    
    {
        std::lock_guard<std::mutex> lock(m_block_cache_mutex);
        m_block_cache[height] = block;
        trim_cache_if_needed();
    }
    
    signal_data_available();
}

void WasmNodeRpcProxy::inject_transactions(const std::vector<CachedTransaction>& txs) {
    std::lock_guard<std::mutex> lock(m_tx_cache_mutex);
    
    for (const auto& tx : txs) {
        m_tx_cache[tx.txid] = tx;
    }
}

void WasmNodeRpcProxy::inject_daemon_info(const DaemonInfo& info) {
    std::lock_guard<std::mutex> lock(m_daemon_info_mutex);
    m_daemon_info = info;
    m_daemon_info.last_update_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    m_offline = info.offline;
}

void WasmNodeRpcProxy::clear_block_cache() {
    std::lock_guard<std::mutex> lock(m_block_cache_mutex);
    m_block_cache.clear();
    m_needs_more_data = true;
}

void WasmNodeRpcProxy::clear_all_caches() {
    {
        std::lock_guard<std::mutex> lock(m_block_cache_mutex);
        m_block_cache.clear();
    }
    {
        std::lock_guard<std::mutex> lock(m_tx_cache_mutex);
        m_tx_cache.clear();
    }
    {
        std::lock_guard<std::mutex> lock(m_daemon_info_mutex);
        m_daemon_info = DaemonInfo();
    }
    m_needs_more_data = true;
}

// ============================================================================
// DATA RETRIEVAL API (Called by wallet2)
// ============================================================================

size_t WasmNodeRpcProxy::get_blocks(uint64_t start_height,
                                    size_t max_count,
                                    std::vector<CachedBlock>& blocks_out) {
    std::lock_guard<std::mutex> lock(m_block_cache_mutex);
    
    blocks_out.clear();
    
    // Find blocks in range [start_height, start_height + max_count)
    for (uint64_t h = start_height; h < start_height + max_count; ++h) {
        auto it = m_block_cache.find(h);
        if (it == m_block_cache.end()) {
            // Cache miss - stop here
            // ⚠️ DO NOT TRIGGER ASYNCIFY FETCH HERE!
            // Return what we have and let wallet2 pause
            break;
        }
        blocks_out.push_back(it->second);
    }
    
    // If we couldn't return any blocks, signal that we need more data
    if (blocks_out.empty() && max_count > 0) {
        std::lock_guard<std::mutex> pause_lock(m_pause_mutex);
        m_needs_more_data = true;
    }
    
    return blocks_out.size();
}

std::optional<CachedBlock> WasmNodeRpcProxy::get_block(uint64_t height) {
    std::lock_guard<std::mutex> lock(m_block_cache_mutex);
    
    auto it = m_block_cache.find(height);
    if (it != m_block_cache.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<CachedTransaction> WasmNodeRpcProxy::get_transactions(
    const std::vector<std::string>& txids) {
    std::lock_guard<std::mutex> lock(m_tx_cache_mutex);
    
    std::vector<CachedTransaction> result;
    for (const auto& txid : txids) {
        auto it = m_tx_cache.find(txid);
        if (it != m_tx_cache.end()) {
            result.push_back(it->second);
        }
    }
    return result;
}

DaemonInfo WasmNodeRpcProxy::get_daemon_info() const {
    std::lock_guard<std::mutex> lock(m_daemon_info_mutex);
    return m_daemon_info;
}

uint64_t WasmNodeRpcProxy::get_height() const {
    std::lock_guard<std::mutex> lock(m_daemon_info_mutex);
    return m_daemon_info.height;
}

uint64_t WasmNodeRpcProxy::get_target_height() const {
    std::lock_guard<std::mutex> lock(m_daemon_info_mutex);
    return m_daemon_info.target_height;
}

// ============================================================================
// CACHE STATUS API
// ============================================================================

uint64_t WasmNodeRpcProxy::get_cached_height() const {
    std::lock_guard<std::mutex> lock(m_block_cache_mutex);
    if (m_block_cache.empty()) {
        return 0;
    }
    return m_block_cache.rbegin()->first;  // Highest key
}

uint64_t WasmNodeRpcProxy::get_cache_start_height() const {
    std::lock_guard<std::mutex> lock(m_block_cache_mutex);
    if (m_block_cache.empty()) {
        return 0;
    }
    return m_block_cache.begin()->first;  // Lowest key
}

size_t WasmNodeRpcProxy::get_cache_size() const {
    std::lock_guard<std::mutex> lock(m_block_cache_mutex);
    return m_block_cache.size();
}

bool WasmNodeRpcProxy::needs_more_blocks(uint64_t wallet_height,
                                         uint64_t target_height,
                                         size_t threshold) const {
    std::lock_guard<std::mutex> lock(m_block_cache_mutex);
    
    // Always need blocks if wallet is behind target
    if (wallet_height >= target_height) {
        return false;  // Fully synced
    }
    
    // Check if we have enough blocks buffered ahead
    uint64_t cached_height = m_block_cache.empty() ? 0 : m_block_cache.rbegin()->first;
    
    // Need more if: cached_height < wallet_height + threshold
    return cached_height < wallet_height + threshold;
}

std::string WasmNodeRpcProxy::get_cache_status_json() const {
    std::ostringstream json;
    json << "{";
    json << "\"block_cache_size\":" << get_cache_size() << ",";
    json << "\"cache_start_height\":" << get_cache_start_height() << ",";
    json << "\"cache_end_height\":" << get_cached_height() << ",";
    json << "\"daemon_height\":" << get_height() << ",";
    json << "\"target_height\":" << get_target_height() << ",";
    json << "\"needs_more_data\":" << (should_pause_refresh() ? "true" : "false") << ",";
    json << "\"offline\":" << (m_offline ? "true" : "false");
    json << "}";
    return json.str();
}

// ============================================================================
// PAUSE/RESUME CONTROL
// ============================================================================

bool WasmNodeRpcProxy::should_pause_refresh() const {
    std::lock_guard<std::mutex> lock(m_pause_mutex);
    return m_needs_more_data;
}

void WasmNodeRpcProxy::signal_data_available() {
    std::lock_guard<std::mutex> lock(m_pause_mutex);
    m_needs_more_data = false;
}

// ============================================================================
// Internal Helpers
// ============================================================================

void WasmNodeRpcProxy::trim_cache_if_needed() {
    // Called with m_block_cache_mutex already held
    
    if (m_block_cache.size() <= MAX_CACHED_BLOCKS) {
        return;
    }
    
    // Remove oldest blocks (lowest heights) to trim to CACHE_TRIM_SIZE
    while (m_block_cache.size() > CACHE_TRIM_SIZE) {
        m_block_cache.erase(m_block_cache.begin());
    }
}

} // namespace wasm_bridge
