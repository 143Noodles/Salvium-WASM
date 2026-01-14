// threadpool_stub.cpp - Empty stub for single-threaded WASM
// The actual implementation is now entirely in the shadow header:
// shadow_headers/common/threadpool.h
//
// This file exists only to satisfy the build system which expects a .o file
// for threadpool. With pthreads disabled, the synchronous implementation in
// the shadow header handles everything.

// Include the shadow header to pull in the header-only implementation
#include "common/threadpool.h"

// No additional code needed - everything is header-only
