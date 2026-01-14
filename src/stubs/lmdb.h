// LMDB stub header for WASM build
// Ring database not needed in browser context
#pragma once

#include <cstddef>

// Basic LMDB types (stub)
typedef struct MDB_env MDB_env;
typedef struct MDB_txn MDB_txn;
typedef struct MDB_cursor MDB_cursor;
typedef unsigned int MDB_dbi;

typedef struct MDB_val {
    size_t mv_size;
    void *mv_data;
} MDB_val;

// Environment info structure
typedef struct MDB_envinfo {
    void *me_mapaddr;
    size_t me_mapsize;
    size_t me_last_pgno;
    size_t me_last_txnid;
    unsigned int me_maxreaders;
    unsigned int me_numreaders;
} MDB_envinfo;

// Statistics structure
typedef struct MDB_stat {
    unsigned int ms_psize;
    unsigned int ms_depth;
    size_t ms_branch_pages;
    size_t ms_leaf_pages;
    size_t ms_overflow_pages;
    size_t ms_entries;
} MDB_stat;

typedef int (MDB_cmp_func)(const MDB_val *a, const MDB_val *b);

// Environment flags
#define MDB_FIXEDMAP    0x01
#define MDB_NOSUBDIR    0x4000
#define MDB_NOSYNC      0x10000
#define MDB_RDONLY      0x20000
#define MDB_NOMETASYNC  0x40000
#define MDB_WRITEMAP    0x80000
#define MDB_MAPASYNC    0x100000
#define MDB_NOTLS       0x200000
#define MDB_NOLOCK      0x400000
#define MDB_NORDAHEAD   0x800000
#define MDB_NOMEMINIT   0x1000000

// Database flags
#define MDB_REVERSEKEY  0x02
#define MDB_DUPSORT     0x04
#define MDB_INTEGERKEY  0x08
#define MDB_DUPFIXED    0x10
#define MDB_INTEGERDUP  0x20
#define MDB_REVERSEDUP  0x40
#define MDB_CREATE      0x40000

// Write flags
#define MDB_NOOVERWRITE 0x10
#define MDB_NODUPDATA   0x20
#define MDB_CURRENT     0x40
#define MDB_RESERVE     0x10000
#define MDB_APPEND      0x20000
#define MDB_APPENDDUP   0x40000
#define MDB_MULTIPLE    0x80000

// Cursor operations
typedef enum MDB_cursor_op {
    MDB_FIRST,
    MDB_FIRST_DUP,
    MDB_GET_BOTH,
    MDB_GET_BOTH_RANGE,
    MDB_GET_CURRENT,
    MDB_GET_MULTIPLE,
    MDB_LAST,
    MDB_LAST_DUP,
    MDB_NEXT,
    MDB_NEXT_DUP,
    MDB_NEXT_MULTIPLE,
    MDB_NEXT_NODUP,
    MDB_PREV,
    MDB_PREV_DUP,
    MDB_PREV_NODUP,
    MDB_SET,
    MDB_SET_KEY,
    MDB_SET_RANGE,
    MDB_PREV_MULTIPLE
} MDB_cursor_op;

// Error codes
#define MDB_SUCCESS          0
#define MDB_KEYEXIST        (-30799)
#define MDB_NOTFOUND        (-30798)
#define MDB_PAGE_NOTFOUND   (-30797)
#define MDB_CORRUPTED       (-30796)
#define MDB_PANIC           (-30795)
#define MDB_VERSION_MISMATCH (-30794)
#define MDB_INVALID         (-30793)
#define MDB_MAP_FULL        (-30792)
#define MDB_DBS_FULL        (-30791)
#define MDB_READERS_FULL    (-30790)
#define MDB_TLS_FULL        (-30789)
#define MDB_TXN_FULL        (-30788)
#define MDB_CURSOR_FULL     (-30787)
#define MDB_PAGE_FULL       (-30786)
#define MDB_MAP_RESIZED     (-30785)
#define MDB_INCOMPATIBLE    (-30784)
#define MDB_BAD_RSLOT       (-30783)
#define MDB_BAD_TXN         (-30782)
#define MDB_BAD_VALSIZE     (-30781)
#define MDB_BAD_DBI         (-30780)

#ifdef __cplusplus
extern "C" {
#endif

// Stub function declarations - all return error/no-op
inline const char *mdb_strerror(int err) { return "LMDB stub - not implemented"; }
inline const char *mdb_version(int *major, int *minor, int *patch) { 
    if(major) *major = 0; if(minor) *minor = 9; if(patch) *patch = 0;
    return "LMDB stub";
}

inline int mdb_env_create(MDB_env **env) { *env = nullptr; return MDB_SUCCESS; }
inline int mdb_env_open(MDB_env *env, const char *path, unsigned int flags, unsigned int mode) { return MDB_SUCCESS; }
inline int mdb_env_copy(MDB_env *env, const char *path) { return MDB_SUCCESS; }
inline int mdb_env_copy2(MDB_env *env, const char *path, unsigned int flags) { return MDB_SUCCESS; }
inline int mdb_env_stat(MDB_env *env, void *stat) { return MDB_SUCCESS; }
inline int mdb_env_info(MDB_env *env, void *info) { return MDB_SUCCESS; }
inline int mdb_env_sync(MDB_env *env, int force) { return MDB_SUCCESS; }
inline void mdb_env_close(MDB_env *env) {}
inline int mdb_env_set_flags(MDB_env *env, unsigned int flags, int onoff) { return MDB_SUCCESS; }
inline int mdb_env_get_flags(MDB_env *env, unsigned int *flags) { if(flags) *flags = 0; return MDB_SUCCESS; }
inline int mdb_env_get_path(MDB_env *env, const char **path) { if(path) *path = ""; return MDB_SUCCESS; }
inline int mdb_env_get_fd(MDB_env *env, int *fd) { if(fd) *fd = -1; return MDB_SUCCESS; }
inline int mdb_env_set_mapsize(MDB_env *env, size_t size) { return MDB_SUCCESS; }
inline int mdb_env_set_maxreaders(MDB_env *env, unsigned int readers) { return MDB_SUCCESS; }
inline int mdb_env_get_maxreaders(MDB_env *env, unsigned int *readers) { if(readers) *readers = 0; return MDB_SUCCESS; }
inline int mdb_env_set_maxdbs(MDB_env *env, unsigned int dbs) { return MDB_SUCCESS; }
inline int mdb_env_get_maxkeysize(MDB_env *env) { return 511; }

inline int mdb_txn_begin(MDB_env *env, MDB_txn *parent, unsigned int flags, MDB_txn **txn) { *txn = nullptr; return MDB_SUCCESS; }
inline MDB_env *mdb_txn_env(MDB_txn *txn) { return nullptr; }
inline size_t mdb_txn_id(MDB_txn *txn) { return 0; }
inline int mdb_txn_commit(MDB_txn *txn) { return MDB_SUCCESS; }
inline void mdb_txn_abort(MDB_txn *txn) {}
inline void mdb_txn_reset(MDB_txn *txn) {}
inline int mdb_txn_renew(MDB_txn *txn) { return MDB_SUCCESS; }

inline int mdb_dbi_open(MDB_txn *txn, const char *name, unsigned int flags, MDB_dbi *dbi) { if(dbi) *dbi = 0; return MDB_SUCCESS; }
inline int mdb_stat(MDB_txn *txn, MDB_dbi dbi, void *stat) { return MDB_SUCCESS; }
inline int mdb_dbi_flags(MDB_txn *txn, MDB_dbi dbi, unsigned int *flags) { if(flags) *flags = 0; return MDB_SUCCESS; }
inline void mdb_dbi_close(MDB_env *env, MDB_dbi dbi) {}
inline int mdb_drop(MDB_txn *txn, MDB_dbi dbi, int del) { return MDB_SUCCESS; }
inline int mdb_set_compare(MDB_txn *txn, MDB_dbi dbi, MDB_cmp_func *cmp) { return MDB_SUCCESS; }
inline int mdb_set_dupsort(MDB_txn *txn, MDB_dbi dbi, MDB_cmp_func *cmp) { return MDB_SUCCESS; }

inline int mdb_get(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data) { return MDB_NOTFOUND; }
inline int mdb_put(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data, unsigned int flags) { return MDB_SUCCESS; }
inline int mdb_del(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data) { return MDB_SUCCESS; }

inline int mdb_cursor_open(MDB_txn *txn, MDB_dbi dbi, MDB_cursor **cursor) { *cursor = nullptr; return MDB_SUCCESS; }
inline void mdb_cursor_close(MDB_cursor *cursor) {}
inline int mdb_cursor_renew(MDB_txn *txn, MDB_cursor *cursor) { return MDB_SUCCESS; }
inline MDB_txn *mdb_cursor_txn(MDB_cursor *cursor) { return nullptr; }
inline MDB_dbi mdb_cursor_dbi(MDB_cursor *cursor) { return 0; }
inline int mdb_cursor_get(MDB_cursor *cursor, MDB_val *key, MDB_val *data, MDB_cursor_op op) { return MDB_NOTFOUND; }
inline int mdb_cursor_put(MDB_cursor *cursor, MDB_val *key, MDB_val *data, unsigned int flags) { return MDB_SUCCESS; }
inline int mdb_cursor_del(MDB_cursor *cursor, unsigned int flags) { return MDB_SUCCESS; }
inline int mdb_cursor_count(MDB_cursor *cursor, size_t *countp) { if(countp) *countp = 0; return MDB_SUCCESS; }

inline int mdb_cmp(MDB_txn *txn, MDB_dbi dbi, const MDB_val *a, const MDB_val *b) { return 0; }
inline int mdb_dcmp(MDB_txn *txn, MDB_dbi dbi, const MDB_val *a, const MDB_val *b) { return 0; }

#ifdef __cplusplus
}
#endif
