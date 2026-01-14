// mlocker_stub.cpp - Stub for WASM (no memory locking needed in browser)
//
// NOTE: In the browser/WASM environment there is no swap, so mlock/munlock
// semantics are meaningless. This stub exists only to satisfy link symbols.
//
// IMPORTANT: wasm-build uses shadow headers (via `-isystem .../shadow_headers`)
// to remove pthread usage for iOS. We still include the headers that
// `mlocker.h` depends on so this stub compiles consistently.

#include "mlocker.h"
#include <map>
#include <mutex>

namespace epee {
// Static member definitions
size_t mlocker::page_size = 4096;
size_t mlocker::num_locked_objects = 0;


// Constructor/destructor - do nothing in WASM
mlocker::mlocker(void *ptr, size_t len) : ptr(ptr), len(len) {
  (void)ptr;
  (void)len;
}

mlocker::~mlocker() {}

// Static methods
size_t mlocker::get_page_size() { return 4096; }
size_t mlocker::get_num_locked_pages() { return 0; }
size_t mlocker::get_num_locked_objects() { return 0; }

void mlocker::lock(void *ptr, size_t len) {
  (void)ptr;
  (void)len;
}

void mlocker::unlock(void *ptr, size_t len) {
  (void)ptr;
  (void)len;
}

// Private static methods (definitions required for linking)
//
// These types are defined in `mlocker.h` (which is patched inside the build
// container to use std::* and shadow headers). Keep the implementation trivial.
std::mutex &mlocker::mutex() {
  static std::mutex m;
  return m;
}

std::map<size_t, unsigned int> &mlocker::map() {
  static std::map<size_t, unsigned int> m;
  return m;
}

void mlocker::lock_page(size_t page) { (void)page; }
void mlocker::unlock_page(size_t page) { (void)page; }
} // namespace epee
