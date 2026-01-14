//
// wasm_filesystem.hpp
// Salvium Wallet2 WASM Port
//
// ============================================================================
// ⚠️ IDBFS SYNC STRATEGY
// ============================================================================
//
// Problem: If we sync IDBFS after every write, and wallet2 writes checkpoints
// every 100 blocks, the scanner becomes bottlenecked by IndexedDB I/O.
//
// Solution: Batched sync with timer-based auto-save
//
// 1. All writes go to in-memory FS (fast)
// 2. JS timer triggers sync_filesystem() every 30 seconds
// 3. Manual save_wallet() always triggers immediate sync
// 4. On browser close, beforeunload handler triggers final sync
//
// Data Loss Risk: Maximum 30 seconds of scan progress. Acceptable tradeoff
// for ~10x faster scanning.
// ============================================================================

#ifndef WASM_FILESYSTEM_HPP
#define WASM_FILESYSTEM_HPP

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

namespace wasm_bridge {

// ============================================================================
// Filesystem Configuration
// ============================================================================

// Virtual mount point for wallets in IDBFS
constexpr const char* WALLET_MOUNT_POINT = "/wallets";

// Database name in IndexedDB
constexpr const char* IDBFS_DB_NAME = "salvium_wallet_fs";

// Auto-sync interval in milliseconds (30 seconds)
constexpr int AUTO_SYNC_INTERVAL_MS = 30000;

// ============================================================================
// Filesystem Status
// ============================================================================
struct FilesystemStatus {
    bool is_mounted;            // IDBFS mount successful
    bool has_pending_writes;    // Writes not yet synced to IndexedDB
    uint64_t last_sync_time;    // Unix timestamp of last successful sync
    size_t pending_bytes;       // Estimated bytes pending sync
    std::string error_message;  // Last error, if any
};

// ============================================================================
// WasmFilesystem - IDBFS Integration for Persistent Storage
// ============================================================================
class WasmFilesystem {
public:
    WasmFilesystem();
    ~WasmFilesystem();

    // ========================================================================
    // Initialization
    // ========================================================================
    
    /**
     * Initialize the virtual filesystem and mount IDBFS
     * Must be called before any wallet operations
     * 
     * @param callback Called when mount is complete (async operation)
     * @return true if mount operation started successfully
     */
    bool initialize(std::function<void(bool success)> callback = nullptr);
    
    /**
     * Check if filesystem is ready
     */
    bool is_ready() const;
    
    /**
     * Get current filesystem status
     */
    FilesystemStatus get_status() const;

    // ========================================================================
    // Sync Operations
    // ========================================================================
    
    /**
     * Sync in-memory FS to IndexedDB
     * 
     * ⚠️ This is an ASYNC operation using Asyncify!
     * It's the ONLY network-like operation we allow to use Asyncify.
     * 
     * @param populate If true, read from IndexedDB to memory (load)
     *                 If false, write from memory to IndexedDB (save)
     * @return true on success
     */
    bool sync_filesystem(bool populate = false);
    
    /**
     * Request async sync (returns immediately, sync happens in background)
     * Safe to call frequently - will coalesce multiple requests
     */
    void request_async_sync();
    
    /**
     * Start auto-sync timer
     * Automatically syncs every AUTO_SYNC_INTERVAL_MS milliseconds
     */
    void start_auto_sync();
    
    /**
     * Stop auto-sync timer
     */
    void stop_auto_sync();
    
    /**
     * Check if auto-sync is running
     */
    bool is_auto_sync_enabled() const;

    // ========================================================================
    // Wallet File Operations
    // ========================================================================
    
    /**
     * Get the full virtual path for a wallet
     * 
     * @param wallet_name Base name of wallet (e.g., "mywallet")
     * @return Full path (e.g., "/wallets/mywallet")
     */
    std::string get_wallet_path(const std::string& wallet_name) const;
    
    /**
     * Check if a wallet exists
     */
    bool wallet_exists(const std::string& wallet_name) const;
    
    /**
     * List all wallets in the filesystem
     */
    std::vector<std::string> list_wallets() const;
    
    /**
     * Delete a wallet and all associated files
     * 
     * @param wallet_name Name of wallet to delete
     * @param sync_after If true, sync to IndexedDB immediately
     * @return true on success
     */
    bool delete_wallet(const std::string& wallet_name, bool sync_after = true);
    
    /**
     * Get wallet file size (for progress estimation)
     */
    size_t get_wallet_size(const std::string& wallet_name) const;

    // ========================================================================
    // Low-Level File Operations
    // (Use these sparingly - prefer wallet-level operations)
    // ========================================================================
    
    /**
     * Write data to a file
     */
    bool write_file(const std::string& path, const std::vector<uint8_t>& data);
    bool write_file(const std::string& path, const std::string& data);
    
    /**
     * Read data from a file
     */
    bool read_file(const std::string& path, std::vector<uint8_t>& data_out);
    bool read_file(const std::string& path, std::string& data_out);
    
    /**
     * Check if a file exists
     */
    bool file_exists(const std::string& path) const;
    
    /**
     * Delete a file
     */
    bool delete_file(const std::string& path);
    
    /**
     * Create a directory (recursive)
     */
    bool create_directory(const std::string& path);

    // ========================================================================
    // Callbacks for JavaScript
    // ========================================================================
    
    /**
     * Register callback for sync completion
     */
    void on_sync_complete(std::function<void(bool success)> callback);
    
    /**
     * Register callback for errors
     */
    void on_error(std::function<void(const std::string& error)> callback);

private:
    bool m_initialized;
    bool m_mounted;
    bool m_auto_sync_enabled;
    bool m_sync_pending;
    uint64_t m_last_sync_time;
    std::string m_last_error;
    
    std::function<void(bool)> m_sync_callback;
    std::function<void(const std::string&)> m_error_callback;
    
    // Mark filesystem as dirty (needs sync)
    void mark_dirty();
    
    // Internal sync implementation
    bool do_sync(bool populate);
};

// ============================================================================
// Global filesystem instance (singleton)
// ============================================================================
WasmFilesystem& get_global_filesystem();

// ============================================================================
// JavaScript interop functions (declared extern "C" for Asyncify)
// ============================================================================

#ifdef __EMSCRIPTEN__
extern "C" {
    /**
     * Called from C++ to trigger IDBFS sync
     * This function is declared as ASYNCIFY_IMPORT
     */
    void js_sync_filesystem(int populate, int* result);
    
    /**
     * Called from JS when sync completes
     */
    void wasm_on_sync_complete(int success);
}
#endif

} // namespace wasm_bridge

#endif // WASM_FILESYSTEM_HPP
