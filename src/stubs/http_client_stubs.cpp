// http_client_stubs.cpp - WASM HTTP client with response cache
//
// ARCHITECTURE:
// wallet2 makes direct HTTP calls for certain operations:
// - /get_outs.bin (decoy outputs for ring signatures)
// - /get_output_distribution.bin (output distribution for decoy selection)
//
// Since we can't make HTTP calls in WASM, we use a CACHE-BASED approach:
// 1. JavaScript fetches the data from daemon using fetch() API
// 2. JavaScript injects the data into our cache via inject_* methods
// 3. When wallet2 calls the HTTP client, we return cached data
// 4. If no cached data exists, the call fails (expected behavior)

#include "net/http.h"
#include "net/http_client.h"
#include <algorithm> // For std::find in fallback substitution mode
#include <cstdio> // For caching logic if needed, though we use std::string mostly
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

// Emscripten for console output
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

// Include RPC definitions for response construction
#include "rpc/core_rpc_server_commands_defs.h"
#include "serialization/keyvalue_serialization.h"
#include "storages/portable_storage.h"
#include "storages/portable_storage_template_helper.h"

namespace epee {
namespace net_utils {
namespace http {

// ============================================================================
// RTTI FIX: Define the abstract_http_client destructor out-of-line
// ============================================================================
abstract_http_client::~abstract_http_client() {}

// ============================================================================
// Global response cache for HTTP endpoints
// This allows JavaScript to pre-populate responses before wallet2 calls them
// ============================================================================

// Per-index output entry for additive caching
struct CachedOutputEntry {
  std::string key;  // 32-byte public key (binary)
  std::string mask; // 32-byte commitment mask (binary)
  bool unlocked;
  uint64_t height;
  std::string txid; // 32-byte hash (binary)
  uint64_t
      output_id; // Global output index (daemon returns this, wallet2 checks it)
};

struct WasmHttpResponseCache {
  std::mutex mutex;

  // Map from endpoint path to response data
  // Standard Key: "/get_outs.bin"
  // Hashed Key: "/get_outs.bin:12345678" (when body hashing is used)
  std::map<std::string, std::string> binary_responses;
  std::map<std::string, std::string> json_responses;

  // ADDITIVE OUTPUT CACHE - stores outputs by asset_type:index
  // This allows us to build a response from any requested indices
  // Key: "asset_type:index" (e.g. "SAL1:1098920"), Value: output entry
  // CRITICAL: Must include asset_type because same index can have different
  // data for different asset types (SAL vs SAL1)
  std::map<std::string, CachedOutputEntry> output_cache;

  // Helper to create cache key from asset_type and index
  static std::string make_output_key(const std::string &asset_type,
                                     uint64_t index) {
    return asset_type + ":" + std::to_string(index);
  }

  // Store the last get_outs request body so JS can fetch exact outputs
  // requested This enables two-phase transaction creation:
  // 1. First attempt fails with cache miss, but we capture the request
  // 2. JS reads the request, fetches exact outputs, injects them
  // 3. Second attempt succeeds
  std::string last_get_outs_request_body;
  bool has_pending_get_outs_request = false;

  // Singleton access
  static WasmHttpResponseCache &instance() {
    static WasmHttpResponseCache cache;
    return cache;
  }

  // Generate a cache key that includes validation of the body contents
  // Uses simple DJB2 hash to avoid complex dependencies
  std::string get_cache_key(const std::string &path, const std::string &body) {
    if (path.find("get_outs") != std::string::npos && !body.empty()) {
      unsigned long hash = 5381;
      for (size_t i = 0; i < body.size(); ++i) {
        hash = ((hash << 5) + hash) + (unsigned char)body[i];
      }
      std::string key = path + ":" + std::to_string(hash);
      fprintf(stderr,
              "[WASM HTTP] get_cache_key: path='%s', body_len=%zu, key='%s'\n",
              path.c_str(), body.size(), key.c_str());
      return key;
    }
    return path;
  }

  bool has_response(const std::string &path) const {
    // Exact match check
    if (binary_responses.count(path) > 0 || json_responses.count(path) > 0)
      return true;

    // For get_outs, check if any hashed key exists
    if (path.find("get_outs") != std::string::npos) {
      std::string prefix = path + ":";
      auto lower = binary_responses.lower_bound(prefix);
      if (lower != binary_responses.end() && lower->first.find(prefix) == 0) {
        return true;
      }
    }
    return false;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex);
    binary_responses.clear();
    json_responses.clear();
    output_cache.clear();
    last_get_outs_request_body.clear();
    has_pending_get_outs_request = false;
  }

  // For JSON-RPC, extract method from request body and use composite key
  std::string get_json_rpc_key(const std::string &path,
                               const std::string &body) {
    if (path != "/json_rpc" || body.empty()) {
      return path;
    }
    // Parse JSON-RPC to extract method name
    // Format:
    // {"jsonrpc":"2.0","id":"0","method":"get_fee_estimate","params":{}}

    // Find "method": pattern (with possible whitespace)
    size_t method_pos = body.find("\"method\"");
    if (method_pos == std::string::npos) {
      fprintf(stderr,
              "[WASM HTTP] get_json_rpc_key: no 'method' field found\n");
      return path;
    }

    // Find the colon after "method"
    size_t colon_pos = body.find(":", method_pos + 8);
    if (colon_pos == std::string::npos) {
      fprintf(stderr,
              "[WASM HTTP] get_json_rpc_key: no colon after 'method'\n");
      return path;
    }

    // Find opening quote of the method value
    size_t value_start = body.find("\"", colon_pos);
    if (value_start == std::string::npos) {
      fprintf(
          stderr,
          "[WASM HTTP] get_json_rpc_key: no opening quote for method value\n");
      return path;
    }

    // Find closing quote of the method value
    size_t value_end = body.find("\"", value_start + 1);
    if (value_end == std::string::npos) {
      fprintf(
          stderr,
          "[WASM HTTP] get_json_rpc_key: no closing quote for method value\n");
      return path;
    }

    // Extract the method name
    std::string method =
        body.substr(value_start + 1, value_end - value_start - 1);
    fprintf(stderr, "[WASM HTTP] get_json_rpc_key: extracted method='%s'\n",
            method.c_str());
    return path + ":" + method; // e.g., "/json_rpc:hard_fork_info"
  }
};

// ============================================================================
// WASM HTTP client - returns cached responses
// ============================================================================

static std::string simple_base64_encode(const unsigned char *bytes,
                                        size_t len) {
  static const char *base64_chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string ret;
  ret.reserve(((len + 2) / 3) * 4);

  for (size_t i = 0; i < len; i += 3) {
    unsigned int n = bytes[i] << 16;
    if (i + 1 < len)
      n |= bytes[i + 1] << 8;
    if (i + 2 < len)
      n |= bytes[i + 2];

    ret.push_back(base64_chars[(n >> 18) & 0x3F]);
    ret.push_back(base64_chars[(n >> 12) & 0x3F]);
    ret.push_back(i + 1 < len ? base64_chars[(n >> 6) & 0x3F] : '=');
    ret.push_back(i + 2 < len ? base64_chars[n & 0x3F] : '=');
  }
  return ret;
}

class wasm_http_client : public abstract_http_client {
private:
  std::string m_host;
  std::string m_port;
  http_response_info m_last_response;

public:
  wasm_http_client() = default;
  virtual ~wasm_http_client() = default;

  virtual void
  set_server(std::string host, std::string port, boost::optional<login> user,
             ssl_options_t ssl_options =
                 ssl_support_t::e_ssl_support_autodetect) override {
    m_host = std::move(host);
    m_port = std::move(port);
  }

  virtual void set_auto_connect(bool auto_connect) override {}

  virtual bool connect(std::chrono::milliseconds timeout) override {
    // Pretend we're connected - we'll check cache on invoke
    return true;
  }

  virtual bool disconnect() override { return true; }

  virtual bool is_connected(bool *ssl = NULL) override {
    if (ssl)
      *ssl = false;
    return true; // Pretend connected
  }

  virtual bool
  invoke(const boost::string_ref uri, const boost::string_ref method,
         const boost::string_ref body, std::chrono::milliseconds timeout,
         const http_response_info **ppresponse_info = NULL,
         const fields_list &additional_params = fields_list()) override {
    std::string path(uri.data(), uri.size());
    std::string body_str(body.data(), body.size());

    // Debug: Log what wallet2 is requesting
    fprintf(stderr, "[WASM HTTP] invoke() called for path: '%s' (len=%zu)\n",
            path.c_str(), path.size());
    if (!body_str.empty()) {
      fprintf(stderr, "[WASM HTTP] invoke() body: '%.100s'\n",
              body_str.c_str());
    }

    // EM_ASM for guaranteed browser console output (use console.error to bypass
    // filters)
#ifdef __EMSCRIPTEN__
    EM_ASM(
        {
          console.error('[WASM HTTP] invoke() called for path:',
                        UTF8ToString($0));
        },
        path.c_str());
#endif

    auto &cache = WasmHttpResponseCache::instance();
    std::lock_guard<std::mutex> lock(cache.mutex);

    // Calculate Hash-Based Key
    std::string key = cache.get_cache_key(path, body_str);

    // SPECIAL HANDLING: Build dynamic response from per-index cache for
    // get_outs.bin
    if (path.find("get_outs.bin") != std::string::npos &&
        !cache.output_cache.empty() && !body_str.empty()) {

      // Parse indices from request body (epee format)
      // Look for "index" field patterns
      std::vector<uint64_t> requested_indices;
      const unsigned char *bytes =
          reinterpret_cast<const unsigned char *>(body_str.data());
      size_t len = body_str.size();

      // Parse asset_type from request body (epee format)
      // Look for "asset_type" field followed by string value
      // EPEE string format: 0x0A (type string) + length_byte + "fieldname" +
      // 0x0A + str_len + str
      std::string asset_type = "SAL1"; // Default fallback
      {
        // Search for "asset_type" in the binary data
        const char *asset_type_needle = "asset_type";
        size_t needle_len = strlen(asset_type_needle);
        for (size_t pos = 0; pos + needle_len + 10 < len; pos++) {
          if (memcmp(bytes + pos, asset_type_needle, needle_len) == 0) {
            // Found "asset_type", now look for the string value
            // Skip past "asset_type" and look for the value
            size_t val_start = pos + needle_len;
            // EPEE format: after field name comes type byte (0x0A for string)
            // then variable-length string length, then string data
            if (val_start + 1 < len && bytes[val_start] == 0x0A) {
              // String type found, read length
              uint8_t str_len = bytes[val_start + 1];
              if (str_len > 0 && str_len < 16 &&
                  val_start + 2 + str_len <= len) {
                asset_type = std::string(
                    reinterpret_cast<const char *>(bytes + val_start + 2),
                    str_len);
                fprintf(stderr,
                        "[WASM HTTP] Parsed asset_type from request: '%s'\n",
                        asset_type.c_str());
              }
            }
            break;
          }
        }
      }

      // Look for "index" (0x05 + "index") in epee format
      // EPEE type codes (from portable_storage_base.h):
      // SERIALIZE_TYPE_UINT64 = 5 -> 8 bytes
      // SERIALIZE_TYPE_UINT32 = 6 -> 4 bytes
      // SERIALIZE_TYPE_UINT16 = 7 -> 2 bytes
      // SERIALIZE_TYPE_UINT8  = 8 -> 1 byte
      static const unsigned char index_sig[] = {0x05, 'i', 'n', 'd', 'e', 'x'};

      // Debug: log first occurrence type byte
      bool first_logged = false;

      for (size_t pos = 0; pos + sizeof(index_sig) + 1 <= len; pos++) {
        bool match = true;
        for (size_t j = 0; j < sizeof(index_sig) && match; j++) {
          if (bytes[pos + j] != index_sig[j])
            match = false;
        }
        if (match) {
          size_t type_pos = pos + sizeof(index_sig);
          uint8_t type_byte = bytes[type_pos];
          size_t val_pos = type_pos + 1;

          if (!first_logged) {
            fprintf(stderr,
                    "[WASM HTTP] First 'index' field: type_byte=0x%02x at "
                    "pos=%zu\n",
                    type_byte, type_pos);
            first_logged = true;
          }

          uint64_t idx = 0;
          size_t val_size = 0;

          // Parse based on EPEE SERIALIZE_TYPE codes
          switch (type_byte) {
          case 5:
            val_size = 8;
            break; // SERIALIZE_TYPE_UINT64
          case 6:
            val_size = 4;
            break; // SERIALIZE_TYPE_UINT32
          case 7:
            val_size = 2;
            break; // SERIALIZE_TYPE_UINT16
          case 8:
            val_size = 1;
            break; // SERIALIZE_TYPE_UINT8
          case 1:
            val_size = 8;
            break; // SERIALIZE_TYPE_INT64
          case 2:
            val_size = 4;
            break; // SERIALIZE_TYPE_INT32
          case 3:
            val_size = 2;
            break; // SERIALIZE_TYPE_INT16
          case 4:
            val_size = 1;
            break; // SERIALIZE_TYPE_INT8
          default:
            continue; // Unknown type, skip
          }

          if (val_pos + val_size <= len) {
            for (size_t b = 0; b < val_size; b++) {
              idx |= static_cast<uint64_t>(bytes[val_pos + b]) << (b * 8);
            }
            requested_indices.push_back(idx);
          }
        }
      }

      // Check if we have all requested indices in cache
      // Use asset_type:index composite key
      size_t found_count = 0;
      std::vector<uint64_t> missing_indices;
      for (uint64_t idx : requested_indices) {
        std::string cache_key =
            WasmHttpResponseCache::make_output_key(asset_type, idx);
        if (cache.output_cache.count(cache_key) > 0)
          found_count++;
        else
          missing_indices.push_back(idx);
      }

      fprintf(stderr,
              "[WASM HTTP] Per-index cache check: requested=%zu, found=%zu, "
              "total_cached=%zu\n",
              requested_indices.size(), found_count, cache.output_cache.size());

      // Debug: Show ALL requested indices
      fprintf(stderr, "[WASM HTTP] ALL %zu requested indices: ",
              requested_indices.size());
      for (size_t i = 0; i < requested_indices.size(); i++) {
        fprintf(stderr, "%llu ", (unsigned long long)requested_indices[i]);
      }
      fprintf(stderr, "\n");

      // Debug: Show index range statistics
      uint64_t max_idx = 0, min_idx = UINT64_MAX;
      for (uint64_t idx : requested_indices) {
        if (idx > max_idx)
          max_idx = idx;
        if (idx < min_idx)
          min_idx = idx;
      }
      fprintf(stderr, "[WASM HTTP] Index range: min=%llu, max=%llu\n",
              (unsigned long long)min_idx, (unsigned long long)max_idx);

      // Debug: Show first few cached keys (now asset_type:index strings)
      fprintf(stderr, "[WASM HTTP] First 5 cached keys: ");
      size_t count = 0;
      for (const auto &kv : cache.output_cache) {
        if (count >= 5)
          break;
        fprintf(stderr, "%s ", kv.first.c_str());
        count++;
      }
      fprintf(stderr, "\n");

      // Debug: Show missing indices (not in cache)
      if (!missing_indices.empty()) {
        fprintf(stderr, "[WASM HTTP] MISSING indices (not in cache): ");
        for (size_t i = 0; i < std::min(missing_indices.size(), (size_t)10);
             i++) {
          fprintf(stderr, "%llu ", (unsigned long long)missing_indices[i]);
        }
        if (missing_indices.size() > 10) {
          fprintf(stderr, "... (%zu more)", missing_indices.size() - 10);
        }
        fprintf(stderr, "\n");
      }

      // FIX: If parsing failed (no indices extracted), capture request
      if (requested_indices.empty()) {
        fprintf(stderr,
                "[WASM HTTP] get_outs.bin: No indices parsed from request, "
                "capturing for async fetch...\n");
        cache.last_get_outs_request_body = body_str;
        cache.has_pending_get_outs_request = true;
        return false;
      }

      // REQUIRE ALL indices to be found - partial response breaks ring
      // signature
      if (found_count == requested_indices.size()) {
        fprintf(stderr,
                "[WASM HTTP] Building dynamic response from per-index cache "
                "(found %zu/%zu)...\n",
                found_count, requested_indices.size());

        cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response resp;
        resp.status = "OK";
        resp.untrusted = false;

        for (uint64_t idx : requested_indices) {
          std::string cache_key =
              WasmHttpResponseCache::make_output_key(asset_type, idx);
          const auto &cached = cache.output_cache[cache_key];
          cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::outkey out;

          // Reconstruct outkey from cached components
          if (cached.key.size() == 32)
            memcpy(&out.key, cached.key.data(), 32);
          if (cached.mask.size() == 32)
            memcpy(&out.mask, cached.mask.data(), 32);
          out.unlocked = cached.unlocked;
          out.height = cached.height;
          if (cached.txid.size() == 32)
            memcpy(&out.txid, cached.txid.data(), 32);

          // CRITICAL: Use the CACHED output_id which is the global_output_index
          // The cache is keyed by asset_type_output_index (from request), but
          // wallet2 checks: daemon_resp.outs[i].output_id ==
          // td.m_global_output_index The daemon returns global_output_index in
          // output_id, which we stored in cache
          out.output_id = cached.output_id;

          resp.outs.push_back(out);
        }

        // Debug: Log first few outputs to verify they're set correctly
        fprintf(stderr, "[WASM HTTP] First 5 output_ids in response: ");
        for (size_t i = 0; i < std::min((size_t)5, resp.outs.size()); i++) {
          fprintf(stderr, "%llu ", (unsigned long long)resp.outs[i].output_id);
        }
        fprintf(stderr, "\n");

        // Log unlocked status for first 5
        fprintf(stderr, "[WASM HTTP] First 5 unlocked flags: ");
        for (size_t i = 0; i < std::min((size_t)5, resp.outs.size()); i++) {
          fprintf(stderr, "%d ", resp.outs[i].unlocked ? 1 : 0);
        }
        fprintf(stderr, "\n");

        // Log key bytes (first 8 bytes of first output's key as sanity check)
        // FIXED: Cast to unsigned char to avoid sign-extension (ffffffc6 bug)
        if (resp.outs.size() > 0) {
          const unsigned char *key_bytes =
              reinterpret_cast<const unsigned char *>(&resp.outs[0].key);
          const unsigned char *mask_bytes =
              reinterpret_cast<const unsigned char *>(&resp.outs[0].mask);
          fprintf(stderr,
                  "[WASM HTTP] First output key[0:8]:  "
                  "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                  key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3],
                  key_bytes[4], key_bytes[5], key_bytes[6], key_bytes[7]);
          fprintf(stderr,
                  "[WASM HTTP] First output mask[0:8]: "
                  "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                  mask_bytes[0], mask_bytes[1], mask_bytes[2], mask_bytes[3],
                  mask_bytes[4], mask_bytes[5], mask_bytes[6], mask_bytes[7]);
        }

        // Serialize response
        epee::byte_slice binary_response;
        if (epee::serialization::store_t_to_binary(resp, binary_response)) {
          m_last_response.m_response_code = 200;
          m_last_response.m_body = std::string(
              reinterpret_cast<const char *>(binary_response.data()),
              binary_response.size());
          m_last_response.m_response_comment = "OK";
          if (ppresponse_info)
            *ppresponse_info = &m_last_response;

          fprintf(
              stderr,
              "[WASM HTTP] Dynamic response built successfully (%zu bytes)\n",
              binary_response.size());
          return true;
        } else {
          fprintf(stderr, "[WASM ERROR] Failed to serialize dynamic response, "
                          "capturing request for async fetch...\n");
          // FIX: Don't fall through - capture request and return false
          cache.last_get_outs_request_body = body_str;
          cache.has_pending_get_outs_request = true;
          return false;
        }
      } else if (!missing_indices.empty()) {
        // Log which indices are missing for debugging
        fprintf(stderr, "[WASM HTTP] Missing %zu indices in cache: ",
                missing_indices.size());
        for (size_t i = 0; i < std::min(missing_indices.size(), (size_t)5);
             i++) {
          fprintf(stderr, "%llu ", (unsigned long long)missing_indices[i]);
        }
        if (missing_indices.size() > 5)
          fprintf(stderr, "...");
        fprintf(stderr, "\n");

        // FALLBACK MODE DISABLED: With RNG state save/restore, the fetch+retry
        // mechanism should work - wallet will pick the SAME decoys on retry.
        // Substitution breaks because the REAL output (user's actual output
        // being spent) must be exact, not substituted.
        // Only enable if RNG restore proves insufficient.
        // if (cache.output_cache.size() >= requested_indices.size()) {
        if (false && cache.output_cache.size() >= requested_indices.size()) {
          fprintf(stderr,
                  "[WASM HTTP] FALLBACK MODE: Substituting %zu missing indices "
                  "with cached outputs (have %zu cached)\n",
                  missing_indices.size(), cache.output_cache.size());

          cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response resp;
          resp.status = "OK";
          resp.untrusted = false;

          // Build iterator for substitute outputs
          auto substitute_it = cache.output_cache.begin();

          for (uint64_t idx : requested_indices) {
            CachedOutputEntry entry_data;
            std::string cache_key =
                WasmHttpResponseCache::make_output_key(asset_type, idx);

            if (cache.output_cache.count(cache_key) > 0) {
              // Use exact match
              entry_data = cache.output_cache[cache_key];
            } else {
              // Substitute with next available cached output
              while (substitute_it != cache.output_cache.end()) {
                // Just use the next available substitute
                entry_data = substitute_it->second;
                ++substitute_it;
                break;
              }
              // If we ran out of substitutes, use the first cached output
              if (entry_data.key.empty()) {
                entry_data = cache.output_cache.begin()->second;
              }
            }

            cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::outkey out;
            if (entry_data.key.size() == 32)
              memcpy(&out.key, entry_data.key.data(), 32);
            if (entry_data.mask.size() == 32)
              memcpy(&out.mask, entry_data.mask.data(), 32);
            out.unlocked = entry_data.unlocked;
            out.height = entry_data.height;
            if (entry_data.txid.size() == 32)
              memcpy(&out.txid, entry_data.txid.data(), 32);

            resp.outs.push_back(out);
          }

          // Serialize response
          epee::byte_slice binary_response;
          if (epee::serialization::store_t_to_binary(resp, binary_response)) {
            m_last_response.m_response_code = 200;
            m_last_response.m_body = std::string(
                reinterpret_cast<const char *>(binary_response.data()),
                binary_response.size());
            m_last_response.m_response_comment = "OK";
            if (ppresponse_info)
              *ppresponse_info = &m_last_response;

            fprintf(stderr,
                    "[WASM HTTP] FALLBACK response built (%zu outputs, %zu "
                    "bytes)\n",
                    resp.outs.size(), binary_response.size());
            return true;
          }
        }

        // If fallback failed or not enough cached outputs, capture request
        fprintf(stderr, "[WASM HTTP] get_outs.bin: Capturing request for async "
                        "fetch...\n");
        cache.last_get_outs_request_body = body_str;
        cache.has_pending_get_outs_request = true;
        return false;
      }
    }

    // CRITICAL: For get_outs.bin, NEVER use cached binary responses.
    // The cached response may have a different number of outputs than requested
    // (because wallet RNG selects different decoys each time).
    // This would cause wallet2 to fail with "wrong amounts count".
    // Instead, always capture the request for async fetch.
    if (path.find("get_outs.bin") != std::string::npos && !body_str.empty()) {
      fprintf(stderr,
              "[WASM HTTP] get_outs.bin: Skipping binary cache, capturing "
              "request for async fetch...\n");
      cache.last_get_outs_request_body = body_str;
      cache.has_pending_get_outs_request = true;
      return false;
    }

    // Try finding with hashed key first
    auto it = cache.binary_responses.find(key);

    // Fallback: Try Exact Path (legacy/empty body)
    // Since RNG restore doesn't produce deterministic decoys, we NEED this
    // fallback to have any chance of cache hits. The risk is "real output not
    // found" but that's better than guaranteed failure.
    if (it == cache.binary_responses.end()) {
      it = cache.binary_responses.find(path);
    }

    if (it != cache.binary_responses.end()) {
      fprintf(stderr, "[WASM HTTP] CACHE HIT: '%s' (Key: '%s')\n", path.c_str(),
              it->first.c_str());
      m_last_response.m_response_code = 200;
      m_last_response.m_body = it->second;
      m_last_response.m_response_comment = "OK";
      if (ppresponse_info)
        *ppresponse_info = &m_last_response;
      return true;
    }

    // Try partial match - wallet2 might request with different path format
    // e.g., "/get_outs.bin" vs "get_outs.bin" vs "/daemon/get_outs.bin"
    for (const auto &kv : cache.binary_responses) {
      if (path.find(kv.first) != std::string::npos ||
          kv.first.find(path) != std::string::npos) {
        fprintf(stderr,
                "[WASM HTTP] CACHE HIT (partial): req='%s' matched='%s'\n",
                path.c_str(), kv.first.c_str());
        m_last_response.m_response_code = 200;
        m_last_response.m_body = kv.second;
        m_last_response.m_response_comment = "OK";
        if (ppresponse_info)
          *ppresponse_info = &m_last_response;
        return true;
      }
    }

    // Check JSON cache - for /json_rpc, use method-based composite key
    std::string jsonKey = cache.get_json_rpc_key(path, body_str);

    auto jit = cache.json_responses.find(jsonKey);
    if (jit != cache.json_responses.end()) {
      fprintf(stderr, "[WASM HTTP] CACHE HIT (json method): '%s'\n",
              jsonKey.c_str());
      m_last_response.m_response_code = 200;
      m_last_response.m_body = jit->second;
      m_last_response.m_response_comment = "OK";
      if (ppresponse_info)
        *ppresponse_info = &m_last_response;
      return true;
    }

    // Fallback: try plain path for non-RPC JSON endpoints
    jit = cache.json_responses.find(path);
    if (jit != cache.json_responses.end()) {
      fprintf(stderr, "[WASM HTTP] CACHE HIT (json plain): '%s'\n",
              path.c_str());
      m_last_response.m_response_code = 200;
      m_last_response.m_body = jit->second;
      m_last_response.m_response_comment = "OK";
      if (ppresponse_info)
        *ppresponse_info = &m_last_response;
      return true;
    }

    // Special case: output distribution - check JSON cache first
    // WalletService injects the real distribution as JSON-RPC
    if (path.find("get_output_distribution") != std::string::npos) {
      // Check if we have a cached JSON-RPC response (injected by WalletService)
      std::string jsonKey = "/json_rpc:get_output_distribution";
      auto jit = cache.json_responses.find(jsonKey);
      if (jit != cache.json_responses.end()) {
        fprintf(stderr, "[WASM HTTP] CACHE HIT (json override): '%s'\n",
                jsonKey.c_str());
        m_last_response.m_response_code = 200;
        m_last_response.m_body = jit->second;
        m_last_response.m_response_comment = "OK";
        if (ppresponse_info)
          *ppresponse_info = &m_last_response;
        return true;
      }

      // NO MOCK FALLBACK - if distribution not cached, fail explicitly
      // This prevents privacy-compromising uniform decoy selection
      fprintf(stderr,
              "[WASM HTTP] ERROR: get_output_distribution not in cache - "
              "cannot create transaction without real distribution data\n");
      return false;
    }

    // No cached response - this endpoint wasn't pre-loaded
    // SPECIAL HANDLING: For get_outs.bin cache miss, capture the request
    // so JavaScript can fetch asynchronously and retry
    if (path.find("get_outs") != std::string::npos && !body_str.empty()) {
      fprintf(stderr, "[WASM HTTP] CACHE MISS for get_outs.bin - capturing "
                      "request for async fetch...\n");

      // Capture request for async retry - JavaScript will:
      // 1. Check has_pending_get_outs_request()
      // 2. Get the request via get_pending_get_outs_request_base64()
      // 3. Fetch outputs from daemon
      // 4. Inject outputs via inject_decoy_outputs_from_json()
      // 5. Retry the transaction creation
      cache.last_get_outs_request_body = body_str;
      cache.has_pending_get_outs_request = true;
      fprintf(stderr,
              "[WASM HTTP] Captured request body for async retry (%zu bytes)\n",
              cache.last_get_outs_request_body.size());
    }

    fprintf(
        stderr,
        "[WASM HTTP] CACHE MISS: path='%s' jsonKey='%s' - returning false\n",
        path.c_str(), jsonKey.c_str());
    return false;
  }

  virtual bool
  invoke_get(const boost::string_ref uri, std::chrono::milliseconds timeout,
             const std::string &body = std::string(),
             const http_response_info **ppresponse_info = NULL,
             const fields_list &additional_params = fields_list()) override {
    return invoke(uri, "GET", body, timeout, ppresponse_info,
                  additional_params);
  }

  virtual bool
  invoke_post(const boost::string_ref uri, const std::string &body,
              std::chrono::milliseconds timeout,
              const http_response_info **ppresponse_info = NULL,
              const fields_list &additional_params = fields_list()) override {
    return invoke(uri, "POST", body, timeout, ppresponse_info,
                  additional_params);
  }

  virtual uint64_t get_bytes_sent() const override { return 0; }
  virtual uint64_t get_bytes_received() const override { return 0; }
};

} // namespace http
} // namespace net_utils
} // namespace epee

// ============================================================================
// C-style API for JavaScript to inject cached responses
// These are called via Embind from JavaScript
// ============================================================================
extern "C" {

// Inject a binary response for an endpoint (e.g., "/get_outs.bin")
void wasm_http_inject_binary_response(const char *path, const char *data,
                                      size_t data_len) {
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);

  std::string s_path(path);
  std::string key = s_path;

  // Store under the calculated key (hashed for get_outs)
  cache.binary_responses[key] = std::string(data, data_len);

  // If this was a hashed key, also store under plain path as fallback
  if (key != s_path) {
    cache.binary_responses[s_path] = std::string(data, data_len);
    fprintf(stderr, "[WASM HTTP] Also cached under plain path: '%s'\n",
            s_path.c_str());
  }
}

// Inject a JSON response for an endpoint
void wasm_http_inject_json_response(const char *path, const char *json_data) {
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);
  cache.json_responses[path] = std::string(json_data);
}

// Clear all cached responses
void wasm_http_clear_cache() {
  fprintf(stderr, "[WASM HTTP] Clearing HTTP cache (called explicitly)\n");
  epee::net_utils::http::WasmHttpResponseCache::instance().clear();
}

// Check if a response is cached
bool wasm_http_has_cached_response(const char *path) {
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  return cache.has_response(path);
}

// Check if there's a pending get_outs request (cache miss occurred)
bool wasm_http_has_pending_get_outs_request() {
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);
  return cache.has_pending_get_outs_request;
}

// Get the pending get_outs request body as base64 encoded string
// (binary data can't be returned directly through C strings)
// Returns empty string if no pending request
// After calling this, the request is cleared to allow for retry
const char *wasm_http_get_pending_get_outs_request_base64() {
  static std::string base64_result;
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);

  if (!cache.has_pending_get_outs_request ||
      cache.last_get_outs_request_body.empty()) {
    base64_result = "";
    return base64_result.c_str();
  }

  // Convert to base64
  static const char *base64_chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  const unsigned char *bytes = reinterpret_cast<const unsigned char *>(
      cache.last_get_outs_request_body.data());
  size_t len = cache.last_get_outs_request_body.size();

  base64_result.clear();
  base64_result.reserve(((len + 2) / 3) * 4);

  for (size_t i = 0; i < len; i += 3) {
    unsigned int n = bytes[i] << 16;
    if (i + 1 < len)
      n |= bytes[i + 1] << 8;
    if (i + 2 < len)
      n |= bytes[i + 2];

    base64_result.push_back(base64_chars[(n >> 18) & 0x3F]);
    base64_result.push_back(base64_chars[(n >> 12) & 0x3F]);
    base64_result.push_back(i + 1 < len ? base64_chars[(n >> 6) & 0x3F] : '=');
    base64_result.push_back(i + 2 < len ? base64_chars[n & 0x3F] : '=');
  }

  fprintf(stderr,
          "[WASM HTTP] Returning pending get_outs request (%zu binary bytes -> "
          "%zu base64)\n",
          cache.last_get_outs_request_body.size(), base64_result.size());

  // Clear the pending request flag (but keep the data in case of retry)
  cache.has_pending_get_outs_request = false;

  return base64_result.c_str();
}

// Clear just the pending get_outs request
void wasm_http_clear_pending_get_outs_request() {
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);
  cache.last_get_outs_request_body.clear();
  cache.has_pending_get_outs_request = false;
}

// Get the hashed cache key for the pending get_outs request
// Returns the key that should be used when injecting outputs
// This ensures the cached outputs match what wallet2 will request on lookup
const char *wasm_http_get_pending_cache_key() {
  static std::string cache_key;
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);

  if (cache.last_get_outs_request_body.empty()) {
    cache_key = "/get_outs.bin";
    return cache_key.c_str();
  }

  // Compute DJB2 hash of the request body (same algorithm as get_cache_key)
  unsigned long hash = 5381;
  for (size_t i = 0; i < cache.last_get_outs_request_body.size(); ++i) {
    hash = ((hash << 5) + hash) +
           (unsigned char)cache.last_get_outs_request_body[i];
  }
  cache_key = "/get_outs.bin:" + std::to_string(hash);
  return cache_key.c_str();
}

// Add a single output to the per-index cache
// Called from wasm_bindings.cpp for each output parsed from JSON
// NOTE: cache_index is the asset_type_output_index (from request)
//       output_id is the global_output_index (from daemon response)
//       asset_type is "SAL" or "SAL1" etc to distinguish same indices across
//       types
void wasm_http_add_output_to_cache(const char *asset_type, uint64_t cache_index,
                                   const char *key, size_t key_len,
                                   const char *mask, size_t mask_len,
                                   bool unlocked, uint64_t height,
                                   const char *txid, size_t txid_len,
                                   uint64_t output_id) {
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);

  epee::net_utils::http::CachedOutputEntry entry;
  entry.key = std::string(key, key_len);
  entry.mask = std::string(mask, mask_len);
  entry.unlocked = unlocked;
  entry.height = height;
  entry.txid = std::string(txid, txid_len);
  entry.output_id =
      output_id; // Store the global_output_index for wallet2 verification

  // Use composite key: "asset_type:index"
  std::string composite_key =
      epee::net_utils::http::WasmHttpResponseCache::make_output_key(
          asset_type ? asset_type : "SAL1", cache_index);
  cache.output_cache[composite_key] = entry;
}

// Get count of cached outputs (for debugging)
size_t wasm_http_get_cached_output_count() {
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);
  return cache.output_cache.size();
}

// Check if a specific output index is cached for given asset type
bool wasm_http_has_cached_output(const char *asset_type, uint64_t index) {
  auto &cache = epee::net_utils::http::WasmHttpResponseCache::instance();
  std::lock_guard<std::mutex> lock(cache.mutex);
  std::string composite_key =
      epee::net_utils::http::WasmHttpResponseCache::make_output_key(
          asset_type ? asset_type : "SAL1", index);
  return cache.output_cache.count(composite_key) > 0;
}
}

namespace net {
namespace http {

bool client::set_proxy(const std::string &address) {
  // No proxy support in WASM
  return false;
}

std::unique_ptr<epee::net_utils::http::abstract_http_client>
client_factory::create() {
  // Return our cache-backed HTTP client
  return std::make_unique<epee::net_utils::http::wasm_http_client>();
}

} // namespace http
} // namespace net
