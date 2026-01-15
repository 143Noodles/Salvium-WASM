//
// wasm_filesystem.cpp
// Salvium Wallet2 WASM Port
//
// Implementation of IDBFS integration with batched sync.
//

#include "wasm_filesystem.hpp"

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/val.h>
#endif

#include <fstream>
#include <sstream>
#include <cstring>
#include <chrono>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

namespace wasm_bridge {

// ============================================================================
// Global singleton
// ============================================================================
static WasmFilesystem g_filesystem;

WasmFilesystem& get_global_filesystem() {
    return g_filesystem;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

WasmFilesystem::WasmFilesystem()
    : m_initialized(false)
    , m_mounted(false)
    , m_auto_sync_enabled(false)
    , m_sync_pending(false)
    , m_last_sync_time(0)
{
}

WasmFilesystem::~WasmFilesystem() {
    stop_auto_sync();
    // Final sync before destruction
    if (m_mounted && m_sync_pending) {
        do_sync(false);
    }
}

// ============================================================================
// Initialization
// ============================================================================

bool WasmFilesystem::initialize(std::function<void(bool success)> callback) {
    if (m_initialized) {
        if (callback) callback(true);
        return true;
    }

#ifdef __EMSCRIPTEN__
    // Create the wallet directory
    EM_ASM({
        // Create mount point
        FS.mkdir('/wallets');
        
        // Mount IDBFS
        FS.mount(IDBFS, {}, '/wallets');
        
        // Populate from IndexedDB (load existing data)
        FS.syncfs(true, function(err) {
            if (typeof Module._wasm_on_fs_init !== 'undefined') {
                Module._wasm_on_fs_init(err ? 0 : 1);
            }
        });
    });
    
    // For now, assume success (async callback will update)
    m_mounted = true;
    m_initialized = true;
    
    if (callback) callback(true);
    return true;
#else
    // Non-WASM: just create directory
    create_directory(WALLET_MOUNT_POINT);
    m_mounted = true;
    m_initialized = true;
    if (callback) callback(true);
    return true;
#endif
}

bool WasmFilesystem::is_ready() const {
    return m_initialized && m_mounted;
}

FilesystemStatus WasmFilesystem::get_status() const {
    FilesystemStatus status;
    status.is_mounted = m_mounted;
    status.has_pending_writes = m_sync_pending;
    status.last_sync_time = m_last_sync_time;
    status.pending_bytes = 0;  // TODO: Track this
    status.error_message = m_last_error;
    return status;
}

// ============================================================================
// Sync Operations
// ============================================================================

bool WasmFilesystem::sync_filesystem(bool populate) {
    return do_sync(populate);
}

bool WasmFilesystem::do_sync(bool populate) {
    if (!m_mounted) {
        m_last_error = "Filesystem not mounted";
        return false;
    }

#ifdef __EMSCRIPTEN__
    int result = 0;
    
    // Call JavaScript to perform sync
    // This is an ASYNCIFY import - it will pause C++ execution
    js_sync_filesystem(populate ? 1 : 0, &result);
    
    if (result == 1) {
        m_sync_pending = false;
        m_last_sync_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        return true;
    } else {
        m_last_error = "IDBFS sync failed";
        return false;
    }
#else
    // Non-WASM: nothing to sync
    m_sync_pending = false;
    return true;
#endif
}

void WasmFilesystem::request_async_sync() {
    if (!m_mounted || !m_sync_pending) {
        return;
    }

#ifdef __EMSCRIPTEN__
    // Schedule async sync via JavaScript
    EM_ASM({
        if (!Module._syncPending) {
            Module._syncPending = true;
            setTimeout(function() {
                FS.syncfs(false, function(err) {
                    Module._syncPending = false;
                });
            }, 100);  // Small delay to batch multiple requests
        }
    });
#endif
}

void WasmFilesystem::start_auto_sync() {
    if (m_auto_sync_enabled) return;
    m_auto_sync_enabled = true;

#ifdef __EMSCRIPTEN__
    EM_ASM({
        // Store interval ID so we can clear it later
        Module._autoSyncInterval = setInterval(function() {
            if (Module._syncPending !== true) {
                Module._syncPending = true;
                FS.syncfs(false, function(err) {
                    Module._syncPending = false;
                });
            }
        }, $0);

        // Also sync on page unload
        window.addEventListener('beforeunload', function() {
            // Synchronous sync attempt (may not complete)
            try {
                FS.syncfs(false, function(){});
            } catch(e) {}
        });
    }, AUTO_SYNC_INTERVAL_MS);
#endif
}

void WasmFilesystem::stop_auto_sync() {
    if (!m_auto_sync_enabled) return;
    m_auto_sync_enabled = false;

#ifdef __EMSCRIPTEN__
    EM_ASM({
        if (Module._autoSyncInterval) {
            clearInterval(Module._autoSyncInterval);
            Module._autoSyncInterval = null;
        }
    });
#endif
}

bool WasmFilesystem::is_auto_sync_enabled() const {
    return m_auto_sync_enabled;
}

// ============================================================================
// Wallet File Operations
// ============================================================================

std::string WasmFilesystem::get_wallet_path(const std::string& wallet_name) const {
    return std::string(WALLET_MOUNT_POINT) + "/" + wallet_name;
}

bool WasmFilesystem::wallet_exists(const std::string& wallet_name) const {
    std::string keys_path = get_wallet_path(wallet_name) + ".keys";
    return file_exists(keys_path);
}

std::vector<std::string> WasmFilesystem::list_wallets() const {
    std::vector<std::string> wallets;
    
    DIR* dir = opendir(WALLET_MOUNT_POINT);
    if (!dir) return wallets;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        // Look for .keys files
        if (name.size() > 5 && name.substr(name.size() - 5) == ".keys") {
            // Remove .keys extension
            wallets.push_back(name.substr(0, name.size() - 5));
        }
    }
    
    closedir(dir);
    return wallets;
}

bool WasmFilesystem::delete_wallet(const std::string& wallet_name, bool sync_after) {
    std::string base_path = get_wallet_path(wallet_name);
    
    // Delete all wallet files
    delete_file(base_path);           // Cache file
    delete_file(base_path + ".keys"); // Keys file
    delete_file(base_path + ".address.txt"); // Address file
    
    if (sync_after) {
        mark_dirty();
        return do_sync(false);
    }
    
    mark_dirty();
    return true;
}

size_t WasmFilesystem::get_wallet_size(const std::string& wallet_name) const {
    std::string base_path = get_wallet_path(wallet_name);
    size_t total = 0;
    
    struct stat st;
    if (stat(base_path.c_str(), &st) == 0) {
        total += st.st_size;
    }
    if (stat((base_path + ".keys").c_str(), &st) == 0) {
        total += st.st_size;
    }
    
    return total;
}

// ============================================================================
// Low-Level File Operations
// ============================================================================

bool WasmFilesystem::write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        m_last_error = "Failed to open file for writing: " + path;
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    
    mark_dirty();
    return true;
}

bool WasmFilesystem::write_file(const std::string& path, const std::string& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        m_last_error = "Failed to open file for writing: " + path;
        return false;
    }
    
    file.write(data.data(), data.size());
    file.close();
    
    mark_dirty();
    return true;
}

bool WasmFilesystem::read_file(const std::string& path, std::vector<uint8_t>& data_out) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        m_last_error = "Failed to open file for reading: " + path;
        return false;
    }
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    data_out.resize(size);
    file.read(reinterpret_cast<char*>(data_out.data()), size);
    
    return true;
}

bool WasmFilesystem::read_file(const std::string& path, std::string& data_out) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        m_last_error = "Failed to open file for reading: " + path;
        return false;
    }
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    data_out.resize(size);
    file.read(&data_out[0], size);
    
    return true;
}

bool WasmFilesystem::file_exists(const std::string& path) const {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

bool WasmFilesystem::delete_file(const std::string& path) {
    if (unlink(path.c_str()) == 0) {
        mark_dirty();
        return true;
    }
    return false;  // File may not exist, that's OK
}

bool WasmFilesystem::create_directory(const std::string& path) {
    // Simple recursive mkdir
    std::string current;
    for (char c : path) {
        current += c;
        if (c == '/') {
            mkdir(current.c_str(), 0755);
        }
    }
    mkdir(path.c_str(), 0755);
    return true;
}

// ============================================================================
// Callbacks
// ============================================================================

void WasmFilesystem::on_sync_complete(std::function<void(bool success)> callback) {
    m_sync_callback = callback;
}

void WasmFilesystem::on_error(std::function<void(const std::string& error)> callback) {
    m_error_callback = callback;
}

void WasmFilesystem::mark_dirty() {
    m_sync_pending = true;
}

// ============================================================================
// JavaScript Interop
// ============================================================================

#ifdef __EMSCRIPTEN__

// This function is called from C++ via Asyncify
// It pauses C++ execution while JS performs the sync
EM_ASYNC_JS(int, js_sync_filesystem_impl, (int populate), {
    return new Promise((resolve) => {
        FS.syncfs(populate ? true : false, function(err) {
            resolve(err ? 0 : 1);
        });
    });
});

extern "C" {

void js_sync_filesystem(int populate, int* result) {
    *result = js_sync_filesystem_impl(populate);
}

void wasm_on_sync_complete(int success) {
    auto& fs = get_global_filesystem();
    // Trigger callback if registered
    // (Implementation would need access to private members)
}

// Called from JS when filesystem init completes
EMSCRIPTEN_KEEPALIVE
void wasm_on_fs_init(int success) {
    // Update global state
    // (Could trigger callback here)
}

} // extern "C"

#endif // __EMSCRIPTEN__

} // namespace wasm_bridge
