//
// wasm_bridge.cpp
// Salvium Wallet2 WASM Port
//
// Main Embind wrapper that exposes wallet2 functionality to JavaScript.
// Uses the PUSH model for data injection and batched IDBFS sync.
//

#include "wasm_bridge.hpp"
#include "wasm_node_rpc_proxy.hpp"
#include "wasm_filesystem.hpp"

#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <emscripten.h>
#endif

#include <sstream>
#include <iomanip>
#include <chrono>

// Forward declaration - we'll include wallet2.h when integrating
// For now, this is a stub implementation to verify the bridge compiles

namespace wasm_bridge {

// ============================================================================
// Implementation Structure (PIMPL pattern)
// ============================================================================
struct WalletWasm::Impl {
    // Wallet state
    bool wallet_open;
    std::string wallet_name;
    std::string primary_address;
    std::string view_key;
    std::string view_balance_key;
    std::string spend_key;
    std::string mnemonic;
    bool watch_only;
    uint64_t blockchain_height;
    
    // Network type
    std::string nettype;
    
    // Daemon URL (stored for reference, actual RPC uses push model)
    std::string daemon_address;
    
    // Refresh state
    bool refreshing;
    uint64_t refresh_start_height;
    
#ifdef __EMSCRIPTEN__
    // JavaScript callbacks
    emscripten::val block_fetch_callback;
    emscripten::val tx_submit_callback;
    emscripten::val rpc_callback;
#endif
    
    Impl() 
        : wallet_open(false)
        , watch_only(true)
        , blockchain_height(0)
        , nettype("mainnet")
        , refreshing(false)
        , refresh_start_height(0)
#ifdef __EMSCRIPTEN__
        , block_fetch_callback(emscripten::val::undefined())
        , tx_submit_callback(emscripten::val::undefined())
        , rpc_callback(emscripten::val::undefined())
#endif
    {}
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

WalletWasm::WalletWasm() 
    : m_impl(std::make_unique<Impl>())
    , m_last_error_code(WalletError::SUCCESS)
{
}

WalletWasm::~WalletWasm() {
    if (m_impl->wallet_open) {
        close_wallet();
    }
}

// ============================================================================
// Error Handling
// ============================================================================

void WalletWasm::set_error(WalletError code, const std::string& message) {
    m_last_error_code = code;
    m_last_error = message;
}

void WalletWasm::clear_error() {
    m_last_error_code = WalletError::SUCCESS;
    m_last_error.clear();
}

std::string WalletWasm::get_last_error() const {
    return m_last_error;
}

WalletError WalletWasm::get_last_error_code() const {
    return m_last_error_code;
}

// ============================================================================
// Initialization
// ============================================================================

bool WalletWasm::init(const std::string& nettype) {
    clear_error();
    
    if (nettype != "mainnet" && nettype != "testnet" && nettype != "stagenet") {
        set_error(WalletError::INTERNAL_ERROR, "Invalid network type: " + nettype);
        return false;
    }
    
    m_impl->nettype = nettype;
    
    // Initialize filesystem (IDBFS)
    auto& fs = get_global_filesystem();
    if (!fs.initialize()) {
        set_error(WalletError::INTERNAL_ERROR, "Failed to initialize filesystem");
        return false;
    }
    
    // Start auto-sync (every 30 seconds)
    fs.start_auto_sync();
    
    return true;
}

bool WalletWasm::set_daemon(const std::string& daemon_address,
                            const std::string& username,
                            const std::string& password) {
    clear_error();
    
    m_impl->daemon_address = daemon_address;
    
    // Configure the global RPC proxy
    auto& proxy = get_global_rpc_proxy();
    proxy.set_daemon_address(daemon_address);
    proxy.set_offline(false);
    
    // Note: In WASM, we don't actually connect - JS handles all network calls
    // and pushes data via inject_block_data()
    
    return true;
}

// ============================================================================
// Wallet Creation & Loading
// ============================================================================

std::string WalletWasm::create_wallet(const std::string& wallet_name,
                                       const std::string& password,
                                       const std::string& language) {
    clear_error();
    
    auto& fs = get_global_filesystem();
    if (fs.wallet_exists(wallet_name)) {
        set_error(WalletError::WALLET_ALREADY_EXISTS, "Wallet already exists: " + wallet_name);
        return "";
    }
    
    // TODO: Integrate with actual wallet2 creation
    // For now, this is a stub that returns a placeholder mnemonic
    
    m_impl->wallet_name = wallet_name;
    m_impl->wallet_open = true;
    m_impl->watch_only = false;
    m_impl->mnemonic = "placeholder mnemonic words go here this is just a stub implementation for testing";
    
    // Save wallet (triggers IDBFS sync)
    save_to_idbfs();
    
    return m_impl->mnemonic;
}

bool WalletWasm::restore_from_seed(const std::string& wallet_name,
                                   const std::string& password,
                                   const std::string& mnemonic,
                                   uint64_t restore_height) {
    clear_error();
    
    auto& fs = get_global_filesystem();
    if (fs.wallet_exists(wallet_name)) {
        set_error(WalletError::WALLET_ALREADY_EXISTS, "Wallet already exists: " + wallet_name);
        return false;
    }
    
    // TODO: Integrate with actual wallet2 restore
    
    m_impl->wallet_name = wallet_name;
    m_impl->wallet_open = true;
    m_impl->watch_only = false;
    m_impl->mnemonic = mnemonic;
    m_impl->blockchain_height = restore_height;
    
    save_to_idbfs();
    return true;
}

bool WalletWasm::restore_from_keys(const std::string& wallet_name,
                                   const std::string& password,
                                   const std::string& address,
                                   const std::string& view_key,
                                   const std::string& spend_key,
                                   uint64_t restore_height) {
    clear_error();
    
    auto& fs = get_global_filesystem();
    if (fs.wallet_exists(wallet_name)) {
        set_error(WalletError::WALLET_ALREADY_EXISTS, "Wallet already exists: " + wallet_name);
        return false;
    }
    
    // TODO: Integrate with actual wallet2 restore
    
    m_impl->wallet_name = wallet_name;
    m_impl->wallet_open = true;
    m_impl->watch_only = spend_key.empty();
    m_impl->primary_address = address;
    m_impl->view_key = view_key;
    m_impl->spend_key = spend_key;
    m_impl->blockchain_height = restore_height;
    
    save_to_idbfs();
    return true;
}

bool WalletWasm::open_wallet(const std::string& wallet_name,
                             const std::string& password) {
    clear_error();
    
    auto& fs = get_global_filesystem();
    if (!fs.wallet_exists(wallet_name)) {
        set_error(WalletError::FILE_NOT_FOUND, "Wallet not found: " + wallet_name);
        return false;
    }
    
    // TODO: Integrate with actual wallet2 load
    
    m_impl->wallet_name = wallet_name;
    m_impl->wallet_open = true;
    
    return true;
}

void WalletWasm::close_wallet() {
    if (!m_impl->wallet_open) return;
    
    // Save before closing
    save_to_idbfs();
    
    // Clear state
    m_impl->wallet_open = false;
    m_impl->wallet_name.clear();
    m_impl->primary_address.clear();
    m_impl->view_key.clear();
    m_impl->spend_key.clear();
    m_impl->mnemonic.clear();
}

bool WalletWasm::is_wallet_open() const {
    return m_impl->wallet_open;
}

// ============================================================================
// Wallet Information
// ============================================================================

std::string WalletWasm::get_address() const {
    return m_impl->primary_address;
}

std::string WalletWasm::get_subaddress(uint32_t account_index, uint32_t address_index) const {
    // TODO: Implement subaddress generation
    return "";
}

std::string WalletWasm::get_view_key() const {
    return m_impl->view_key;
}

std::string WalletWasm::get_view_balance_key() const {
    return m_impl->view_balance_key;
}

std::string WalletWasm::get_spend_key() const {
    if (m_impl->watch_only) return "";
    return m_impl->spend_key;
}

std::string WalletWasm::get_mnemonic() const {
    if (m_impl->watch_only) return "";
    return m_impl->mnemonic;
}

bool WalletWasm::is_watch_only() const {
    return m_impl->watch_only;
}

uint64_t WalletWasm::get_blockchain_height() const {
    return m_impl->blockchain_height;
}

// ============================================================================
// Balance & Transfers
// ============================================================================

uint64_t WalletWasm::get_balance(const std::string& asset_type,
                                  bool unlocked_only) const {
    // TODO: Implement actual balance calculation
    return 0;
}

uint64_t WalletWasm::get_balance_for_account(uint32_t account_index,
                                              const std::string& asset_type,
                                              bool unlocked_only) const {
    // TODO: Implement actual balance calculation
    return 0;
}

std::vector<TransferInfo> WalletWasm::get_transfers(uint64_t min_height,
                                                     uint64_t max_height,
                                                     int32_t account_index) const {
    // TODO: Implement transfer history
    return {};
}

// ============================================================================
// Transaction Scanning (Core Feature!)
// ============================================================================

std::string WalletWasm::scan_tx(const std::string& tx_blob_hex, uint64_t block_height) {
    clear_error();
    
    // TODO: Integrate with actual wallet scanner
    // This will use the existing wallet_scanner.cpp from the WASM build
    
    std::ostringstream json;
    json << "{\"status\":\"stub\",\"outputs\":[],\"height\":" << block_height << "}";
    return json.str();
}

std::string WalletWasm::process_block(const std::string& block_blob_hex,
                                       uint64_t block_height,
                                       const std::vector<std::string>& tx_blobs_hex) {
    clear_error();
    
    // TODO: Parse block and scan all transactions
    
    std::ostringstream json;
    json << "{\"status\":\"stub\",\"height\":" << block_height << ",\"tx_count\":" << tx_blobs_hex.size() << "}";
    return json.str();
}

void WalletWasm::feed_block_data(uint64_t height,
                                  const std::string& block_blob_hex,
                                  const std::vector<std::string>& tx_blobs_hex) {
    // Inject block into the RPC proxy cache
    auto& proxy = get_global_rpc_proxy();
    proxy.inject_block(height, block_blob_hex, tx_blobs_hex);
}

// ============================================================================
// Refresh / Sync
// ============================================================================

bool WalletWasm::start_refresh(uint64_t start_height) {
    clear_error();
    
    if (m_impl->refreshing) {
        set_error(WalletError::INTERNAL_ERROR, "Refresh already in progress");
        return false;
    }
    
    m_impl->refreshing = true;
    m_impl->refresh_start_height = start_height > 0 ? start_height : m_impl->blockchain_height;
    
    // TODO: Start actual refresh using wallet2
    // The refresh will pull from the RPC proxy cache (PUSH model)
    
    return true;
}

std::string WalletWasm::get_refresh_status() const {
    auto& proxy = get_global_rpc_proxy();
    
    std::ostringstream json;
    json << "{";
    json << "\"syncing\":" << (m_impl->refreshing ? "true" : "false") << ",";
    json << "\"current_height\":" << m_impl->blockchain_height << ",";
    json << "\"target_height\":" << proxy.get_target_height() << ",";
    json << "\"cache_status\":" << proxy.get_cache_status_json();
    json << "}";
    return json.str();
}

void WalletWasm::stop_refresh() {
    m_impl->refreshing = false;
}

// ============================================================================
// Transaction Creation
// ============================================================================

PendingTransaction WalletWasm::create_transaction(const std::string& destination,
                                                   uint64_t amount,
                                                   const std::string& asset_type,
                                                   uint32_t priority,
                                                   const std::string& payment_id) {
    PendingTransaction result;
    result.success = false;
    
    if (m_impl->watch_only) {
        result.error = "Cannot create transactions with watch-only wallet";
        return result;
    }
    
    // TODO: Implement actual transaction creation using wallet2
    
    result.error = "Transaction creation not yet implemented";
    return result;
}

PendingTransaction WalletWasm::create_stake_transaction(uint64_t amount) {
    PendingTransaction result;
    result.success = false;
    
    if (m_impl->watch_only) {
        result.error = "Cannot create transactions with watch-only wallet";
        return result;
    }
    
    // TODO: Implement stake transaction
    
    result.error = "Stake transaction not yet implemented";
    return result;
}

std::string WalletWasm::submit_transaction(const std::string& tx_blob_hex) {
    // TODO: Use JS callback to submit transaction
    return "";
}

// ============================================================================
// IDBFS Persistence
// ============================================================================

bool WalletWasm::save_to_idbfs() {
    auto& fs = get_global_filesystem();
    
    // TODO: Call wallet2::store() to save wallet state
    
    // Sync to IndexedDB
    return fs.sync_filesystem(false);
}

void WalletWasm::request_idbfs_sync() {
    auto& fs = get_global_filesystem();
    fs.request_async_sync();
}

// ============================================================================
// JavaScript Callback Registration
// ============================================================================

#ifdef __EMSCRIPTEN__

void WalletWasm::register_block_fetch_callback(emscripten::val callback) {
    m_impl->block_fetch_callback = callback;
}

void WalletWasm::register_tx_submit_callback(emscripten::val callback) {
    m_impl->tx_submit_callback = callback;
}

void WalletWasm::register_rpc_callback(emscripten::val callback) {
    m_impl->rpc_callback = callback;
}

#endif

} // namespace wasm_bridge


// ============================================================================
// EMBIND BINDINGS
// ============================================================================

#ifdef __EMSCRIPTEN__

using namespace emscripten;
using namespace wasm_bridge;

EMSCRIPTEN_BINDINGS(salvium_wallet2_wasm) {
    
    // --- Enums ---
    enum_<WalletError>("WalletError")
        .value("SUCCESS", WalletError::SUCCESS)
        .value("INVALID_PASSWORD", WalletError::INVALID_PASSWORD)
        .value("FILE_NOT_FOUND", WalletError::FILE_NOT_FOUND)
        .value("WALLET_ALREADY_EXISTS", WalletError::WALLET_ALREADY_EXISTS)
        .value("DAEMON_NOT_CONNECTED", WalletError::DAEMON_NOT_CONNECTED)
        .value("INSUFFICIENT_BALANCE", WalletError::INSUFFICIENT_BALANCE)
        .value("INVALID_ADDRESS", WalletError::INVALID_ADDRESS)
        .value("INVALID_TRANSACTION", WalletError::INVALID_TRANSACTION)
        .value("NETWORK_ERROR", WalletError::NETWORK_ERROR)
        .value("INTERNAL_ERROR", WalletError::INTERNAL_ERROR);
    
    // --- TransferInfo struct ---
    value_object<TransferInfo>("TransferInfo")
        .field("txid", &TransferInfo::txid)
        .field("amount", &TransferInfo::amount)
        .field("asset_type", &TransferInfo::asset_type)
        .field("fee", &TransferInfo::fee)
        .field("height", &TransferInfo::height)
        .field("timestamp", &TransferInfo::timestamp)
        .field("unlock_time", &TransferInfo::unlock_time)
        .field("incoming", &TransferInfo::incoming)
        .field("address", &TransferInfo::address)
        .field("subaddr_major", &TransferInfo::subaddr_major)
        .field("subaddr_minor", &TransferInfo::subaddr_minor)
        .field("payment_id", &TransferInfo::payment_id);
    
    // --- PendingTransaction struct ---
    value_object<PendingTransaction>("PendingTransaction")
        .field("tx_blob", &PendingTransaction::tx_blob)
        .field("tx_hash", &PendingTransaction::tx_hash)
        .field("tx_key", &PendingTransaction::tx_key)
        .field("fee", &PendingTransaction::fee)
        .field("amount", &PendingTransaction::amount)
        .field("error", &PendingTransaction::error)
        .field("success", &PendingTransaction::success);
    
    // --- CachedBlock struct (for inject_block_data) ---
    value_object<CachedBlock>("CachedBlock")
        .field("height", &CachedBlock::height)
        .field("block_blob", &CachedBlock::block_blob)
        .field("tx_blobs", &CachedBlock::tx_blobs)
        .field("timestamp", &CachedBlock::timestamp)
        .field("block_hash", &CachedBlock::block_hash);
    
    // --- DaemonInfo struct ---
    value_object<DaemonInfo>("DaemonInfo")
        .field("height", &DaemonInfo::height)
        .field("target_height", &DaemonInfo::target_height)
        .field("difficulty", &DaemonInfo::difficulty)
        .field("top_block_hash", &DaemonInfo::top_block_hash)
        .field("adjusted_time", &DaemonInfo::adjusted_time)
        .field("offline", &DaemonInfo::offline);
    
    // --- Vector types ---
    register_vector<std::string>("VectorString");
    register_vector<TransferInfo>("VectorTransferInfo");
    register_vector<CachedBlock>("VectorCachedBlock");
    
    // --- WalletWasm class ---
    class_<WalletWasm>("WalletWasm")
        .constructor<>()
        
        // Initialization
        .function("init", &WalletWasm::init)
        .function("set_daemon", &WalletWasm::set_daemon)
        
        // Wallet management
        .function("create_wallet", &WalletWasm::create_wallet)
        .function("restore_from_seed", &WalletWasm::restore_from_seed)
        .function("restore_from_keys", &WalletWasm::restore_from_keys)
        .function("open_wallet", &WalletWasm::open_wallet)
        .function("close_wallet", &WalletWasm::close_wallet)
        .function("is_wallet_open", &WalletWasm::is_wallet_open)
        
        // Wallet info
        .function("get_address", &WalletWasm::get_address)
        .function("get_subaddress", &WalletWasm::get_subaddress)
        .function("get_view_key", &WalletWasm::get_view_key)
        .function("get_view_balance_key", &WalletWasm::get_view_balance_key)
        .function("get_spend_key", &WalletWasm::get_spend_key)
        .function("get_mnemonic", &WalletWasm::get_mnemonic)
        .function("is_watch_only", &WalletWasm::is_watch_only)
        .function("get_blockchain_height", &WalletWasm::get_blockchain_height)
        
        // Balance & transfers
        .function("get_balance", &WalletWasm::get_balance)
        .function("get_balance_for_account", &WalletWasm::get_balance_for_account)
        .function("get_transfers", &WalletWasm::get_transfers)
        
        // Scanning (PUSH model)
        .function("scan_tx", &WalletWasm::scan_tx)
        .function("process_block", &WalletWasm::process_block)
        .function("feed_block_data", &WalletWasm::feed_block_data)
        
        // Refresh
        .function("start_refresh", &WalletWasm::start_refresh)
        .function("get_refresh_status", &WalletWasm::get_refresh_status)
        .function("stop_refresh", &WalletWasm::stop_refresh)
        
        // Transactions
        .function("create_transaction", &WalletWasm::create_transaction)
        .function("create_stake_transaction", &WalletWasm::create_stake_transaction)
        .function("submit_transaction", &WalletWasm::submit_transaction)
        
        // IDBFS
        .function("save_to_idbfs", &WalletWasm::save_to_idbfs)
        .function("request_idbfs_sync", &WalletWasm::request_idbfs_sync)
        
        // Error handling
        .function("get_last_error", &WalletWasm::get_last_error)
        .function("get_last_error_code", &WalletWasm::get_last_error_code)
        
        // JS callbacks
        .function("register_block_fetch_callback", &WalletWasm::register_block_fetch_callback)
        .function("register_tx_submit_callback", &WalletWasm::register_tx_submit_callback)
        .function("register_rpc_callback", &WalletWasm::register_rpc_callback);
    
    // --- Global RPC Proxy access (for direct block injection) ---
    function("inject_blocks", optional_override([](const std::vector<CachedBlock>& blocks) {
        get_global_rpc_proxy().inject_block_data(blocks);
    }));
    
    function("inject_daemon_info", optional_override([](const DaemonInfo& info) {
        get_global_rpc_proxy().inject_daemon_info(info);
    }));
    
    function("get_cache_status", optional_override([]() {
        return get_global_rpc_proxy().get_cache_status_json();
    }));
    
    function("needs_more_blocks", optional_override([](uint64_t wallet_height, uint64_t target_height) {
        return get_global_rpc_proxy().needs_more_blocks(wallet_height, target_height);
    }));
}

#endif // __EMSCRIPTEN__
