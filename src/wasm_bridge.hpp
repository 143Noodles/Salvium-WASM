//
// wasm_bridge.hpp
// Salvium Wallet2 WASM Port
//
// Main header for the WASM bridge layer that exposes wallet2 functionality
// to JavaScript via Emscripten's Embind system.
//

#ifndef WASM_BRIDGE_HPP
#define WASM_BRIDGE_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <functional>

#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <emscripten.h>
#endif

// Forward declarations to avoid pulling in heavy wallet2 headers
namespace tools {
    class wallet2;
}

namespace wasm_bridge {

// ============================================================================
// Error Codes
// ============================================================================
enum class WalletError {
    SUCCESS = 0,
    INVALID_PASSWORD = 1,
    FILE_NOT_FOUND = 2,
    WALLET_ALREADY_EXISTS = 3,
    DAEMON_NOT_CONNECTED = 4,
    INSUFFICIENT_BALANCE = 5,
    INVALID_ADDRESS = 6,
    INVALID_TRANSACTION = 7,
    NETWORK_ERROR = 8,
    INTERNAL_ERROR = 99
};

// ============================================================================
// Transfer Details (for get_transfers result)
// ============================================================================
struct TransferInfo {
    std::string txid;           // Transaction hash
    uint64_t amount;            // Amount in atomic units
    std::string asset_type;     // "SAL", "SAL1", etc.
    uint64_t fee;               // Transaction fee
    uint64_t height;            // Block height (0 if pending)
    uint64_t timestamp;         // Unix timestamp
    uint64_t unlock_time;       // Unlock time
    bool incoming;              // true = received, false = sent
    std::string address;        // Destination/source address
    uint32_t subaddr_major;     // Subaddress account
    uint32_t subaddr_minor;     // Subaddress index
    std::string payment_id;     // Payment ID (if any)
};

// ============================================================================
// Pending Transaction (for create_transaction result)
// ============================================================================
struct PendingTransaction {
    std::string tx_blob;        // Serialized transaction
    std::string tx_hash;        // Transaction hash
    std::string tx_key;         // Transaction secret key
    uint64_t fee;               // Fee in atomic units
    uint64_t amount;            // Total amount sent
    std::string error;          // Error message if failed
    bool success;               // Whether creation succeeded
};

// ============================================================================
// Callback Types for Async Operations
// ============================================================================

// Callback for block data fetch (JS -> C++)
// Returns block blob as hex string
using BlockDataCallback = std::function<std::string(uint64_t height)>;

// Callback for transaction fetch
using TxFetchCallback = std::function<std::string(const std::string& txid)>;

// Progress callback for refresh operations
using RefreshProgressCallback = std::function<void(uint64_t current_height, uint64_t target_height)>;

// ============================================================================
// WalletWasm - Main Wallet Class for WASM
// ============================================================================
class WalletWasm {
public:
    WalletWasm();
    ~WalletWasm();

    // ========================================================================
    // Initialization & Lifecycle
    // ========================================================================
    
    /**
     * Initialize the wallet subsystem
     * Must be called before any other operations
     * 
     * @param nettype Network type: "mainnet", "testnet", "stagenet"
     * @return true on success
     */
    bool init(const std::string& nettype);
    
    /**
     * Set the daemon connection for RPC calls
     * In WASM, this just stores the URL; actual calls go through JS
     * 
     * @param daemon_address URL like "http://localhost:12111"
     * @param username Optional RPC username
     * @param password Optional RPC password
     * @return true on success
     */
    bool set_daemon(const std::string& daemon_address, 
                    const std::string& username = "",
                    const std::string& password = "");

    // ========================================================================
    // Wallet Creation & Loading
    // ========================================================================
    
    /**
     * Create a new wallet with random seed
     * 
     * @param wallet_name Name for the wallet file (stored in IDBFS)
     * @param password Password to encrypt the wallet
     * @param language Mnemonic language ("English", "Spanish", etc.)
     * @return Mnemonic seed phrase, or empty string on error
     */
    std::string create_wallet(const std::string& wallet_name,
                              const std::string& password,
                              const std::string& language = "English");
    
    /**
     * Restore wallet from mnemonic seed
     * 
     * @param wallet_name Name for the wallet file
     * @param password Password to encrypt the wallet
     * @param mnemonic 25-word mnemonic seed
     * @param restore_height Block height to start scanning from
     * @return true on success
     */
    bool restore_from_seed(const std::string& wallet_name,
                          const std::string& password,
                          const std::string& mnemonic,
                          uint64_t restore_height = 0);
    
    /**
     * Restore wallet from view key (watch-only)
     * 
     * @param wallet_name Name for the wallet file
     * @param password Password to encrypt the wallet
     * @param address Primary address
     * @param view_key Private view key (hex)
     * @param restore_height Block height to start scanning from
     * @return true on success
     */
    bool restore_from_keys(const std::string& wallet_name,
                          const std::string& password,
                          const std::string& address,
                          const std::string& view_key,
                          const std::string& spend_key = "",
                          uint64_t restore_height = 0);
    
    /**
     * Open an existing wallet from IDBFS
     * 
     * @param wallet_name Name of the wallet file
     * @param password Password to decrypt the wallet
     * @return true on success
     */
    bool open_wallet(const std::string& wallet_name,
                     const std::string& password);
    
    /**
     * Close the current wallet (saves to IDBFS)
     */
    void close_wallet();
    
    /**
     * Check if a wallet is currently open
     */
    bool is_wallet_open() const;

    // ========================================================================
    // Wallet Information
    // ========================================================================
    
    /**
     * Get the primary address
     */
    std::string get_address() const;
    
    /**
     * Get a subaddress
     * 
     * @param account_index Account index
     * @param address_index Address index within account
     */
    std::string get_subaddress(uint32_t account_index, uint32_t address_index) const;
    
    /**
     * Get the private view key (hex)
     */
    std::string get_view_key() const;
    
    /**
     * Get the view balance key for Carrot addresses (hex)
     */
    std::string get_view_balance_key() const;
    
    /**
     * Get the private spend key (hex) - only for full wallets
     */
    std::string get_spend_key() const;
    
    /**
     * Get the mnemonic seed phrase - only for full wallets
     */
    std::string get_mnemonic() const;
    
    /**
     * Check if this is a watch-only wallet
     */
    bool is_watch_only() const;
    
    /**
     * Get the current synchronized height
     */
    uint64_t get_blockchain_height() const;

    // ========================================================================
    // Balance & Transfers
    // ========================================================================
    
    /**
     * Get balance for an asset type
     * 
     * @param asset_type Asset type (e.g., "SAL")
     * @param unlocked_only If true, return only unlocked balance
     * @return Balance in atomic units
     */
    uint64_t get_balance(const std::string& asset_type = "SAL",
                        bool unlocked_only = false) const;
    
    /**
     * Get balance for a specific subaddress account
     */
    uint64_t get_balance_for_account(uint32_t account_index,
                                     const std::string& asset_type = "SAL",
                                     bool unlocked_only = false) const;
    
    /**
     * Get all transfers (incoming and outgoing)
     * 
     * @param min_height Minimum block height (0 for all)
     * @param max_height Maximum block height (0 for all)
     * @param account_index Filter by account (-1 for all)
     * @return Vector of transfer details
     */
    std::vector<TransferInfo> get_transfers(uint64_t min_height = 0,
                                            uint64_t max_height = 0,
                                            int32_t account_index = -1) const;

    // ========================================================================
    // Transaction Scanning (The Core Feature!)
    // ========================================================================
    
    /**
     * Scan a single transaction blob for wallet outputs
     * This is the JavaScript-friendly entry point
     * 
     * @param tx_blob_hex Transaction blob as hex string
     * @param block_height Block height for this transaction
     * @return JSON string with scan results
     */
    std::string scan_tx(const std::string& tx_blob_hex, uint64_t block_height);
    
    /**
     * Process a block blob (parses and scans all transactions)
     * 
     * @param block_blob_hex Block blob as hex string
     * @param block_height Block height
     * @param tx_blobs_hex Vector of transaction blobs in the block
     * @return JSON string with scan results
     */
    std::string process_block(const std::string& block_blob_hex,
                              uint64_t block_height,
                              const std::vector<std::string>& tx_blobs_hex);
    
    /**
     * Feed block data from JavaScript (network hook)
     * Called by JS when it fetches block data from daemon
     * 
     * @param height Block height
     * @param block_blob_hex Block blob as hex
     * @param tx_blobs_hex Transaction blobs as hex
     */
    void feed_block_data(uint64_t height,
                         const std::string& block_blob_hex,
                         const std::vector<std::string>& tx_blobs_hex);

    // ========================================================================
    // Refresh / Sync
    // ========================================================================
    
    /**
     * Start a refresh operation
     * Uses the network hook to request blocks from JavaScript
     * 
     * @param start_height Starting height (0 = from last checkpoint)
     * @return true if refresh started successfully
     */
    bool start_refresh(uint64_t start_height = 0);
    
    /**
     * Check refresh status
     * 
     * @return JSON with { "syncing": bool, "current_height": n, "target_height": n }
     */
    std::string get_refresh_status() const;
    
    /**
     * Stop ongoing refresh
     */
    void stop_refresh();

    // ========================================================================
    // Transaction Creation
    // ========================================================================
    
    /**
     * Create a standard transfer transaction
     * 
     * @param destination Destination address
     * @param amount Amount in atomic units
     * @param asset_type Asset to send (e.g., "SAL")
     * @param priority Transaction priority (0-3)
     * @param payment_id Optional payment ID
     * @return PendingTransaction with result
     */
    PendingTransaction create_transaction(const std::string& destination,
                                         uint64_t amount,
                                         const std::string& asset_type = "SAL",
                                         uint32_t priority = 0,
                                         const std::string& payment_id = "");
    
    /**
     * Create a stake transaction
     * 
     * @param amount Amount to stake
     * @return PendingTransaction with result
     */
    PendingTransaction create_stake_transaction(uint64_t amount);
    
    /**
     * Submit a signed transaction to the network
     * 
     * @param tx_blob_hex Signed transaction blob as hex
     * @return Transaction hash on success, empty string on failure
     */
    std::string submit_transaction(const std::string& tx_blob_hex);

    // ========================================================================
    // IDBFS Persistence
    // ========================================================================
    
    /**
     * Save wallet state to IDBFS
     * Should be called after any wallet modification
     * 
     * @return true on success
     */
    bool save_to_idbfs();
    
    /**
     * Sync IDBFS to IndexedDB (must call from JS after save)
     * This is a reminder - actual sync happens in JavaScript
     */
    void request_idbfs_sync();

    // ========================================================================
    // Error Handling
    // ========================================================================
    
    /**
     * Get the last error message
     */
    std::string get_last_error() const;
    
    /**
     * Get the last error code
     */
    WalletError get_last_error_code() const;

    // ========================================================================
    // Network Hook Registration (called from JavaScript)
    // ========================================================================
    
#ifdef __EMSCRIPTEN__
    /**
     * Register JavaScript callback for fetching block data
     * 
     * @param callback JavaScript function: (height) => Promise<{block_blob, tx_blobs}>
     */
    void register_block_fetch_callback(emscripten::val callback);
    
    /**
     * Register JavaScript callback for submitting transactions
     * 
     * @param callback JavaScript function: (tx_blob) => Promise<tx_hash>
     */
    void register_tx_submit_callback(emscripten::val callback);
    
    /**
     * Register JavaScript callback for RPC calls
     * 
     * @param callback JavaScript function: (method, params) => Promise<result>
     */
    void register_rpc_callback(emscripten::val callback);
#endif

private:
    // Implementation details
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Error state
    mutable std::string m_last_error;
    mutable WalletError m_last_error_code;
    
    // Set error state
    void set_error(WalletError code, const std::string& message);
    void clear_error();
};

} // namespace wasm_bridge

#endif // WASM_BRIDGE_HPP
