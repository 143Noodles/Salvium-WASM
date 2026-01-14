// Stub unbound.h for WASM builds
// DNS functionality is not needed in browser - we use JavaScript fetch() for network calls

#pragma once

// Define the minimum needed types and functions as no-ops

struct ub_ctx;
struct ub_result {
    char* qname;
    int qtype;
    int qclass;
    char** data;
    int* len;
    char* canonname;
    int rcode;
    void* answer_packet;
    int answer_len;
    int havedata;
    int nxdomain;
    int secure;
    int bogus;
    char* why_bogus;
    int was_ratelimited;
};

// Stub function declarations - return errors to indicate DNS not available
inline struct ub_ctx* ub_ctx_create(void) { return nullptr; }
inline void ub_ctx_delete(struct ub_ctx* ctx) { (void)ctx; }
inline int ub_ctx_resolvconf(struct ub_ctx* ctx, const char* fname) { (void)ctx; (void)fname; return -1; }
inline int ub_ctx_hosts(struct ub_ctx* ctx, const char* fname) { (void)ctx; (void)fname; return -1; }
inline int ub_ctx_add_ta(struct ub_ctx* ctx, const char* ta) { (void)ctx; (void)ta; return -1; }
inline int ub_ctx_add_ta_file(struct ub_ctx* ctx, const char* fname) { (void)ctx; (void)fname; return -1; }
inline int ub_ctx_set_fwd(struct ub_ctx* ctx, const char* addr) { (void)ctx; (void)addr; return -1; }
inline int ub_ctx_trustedkeys(struct ub_ctx* ctx, const char* fname) { (void)ctx; (void)fname; return -1; }
inline int ub_ctx_zone_add(struct ub_ctx* ctx, const char* zone_name, const char* zone_type) { (void)ctx; (void)zone_name; (void)zone_type; return -1; }
inline int ub_ctx_async(struct ub_ctx* ctx, int dothread) { (void)ctx; (void)dothread; return 0; }
inline int ub_resolve(struct ub_ctx* ctx, const char* name, int rrtype, int rrclass, struct ub_result** result) {
    (void)ctx; (void)name; (void)rrtype; (void)rrclass; (void)result;
    return -1;  // Return error - DNS not available in WASM
}
inline void ub_resolve_free(struct ub_result* result) { (void)result; }
inline const char* ub_strerror(int err) { (void)err; return "DNS not available in WASM"; }
inline int ub_ctx_set_option(struct ub_ctx* ctx, const char* opt, const char* val) { (void)ctx; (void)opt; (void)val; return -1; }
