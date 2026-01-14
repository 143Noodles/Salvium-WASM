// util_stub.cpp - Minimal stub for util.cpp to avoid SSL/TLS dependencies
// The real util.cpp has boost::asio SSL code that requires boost::lambda which isn't compiled

// Only provide the functions that might be needed
// Most of util.cpp is for networking/SSL which we don't use in WASM

namespace tools {
  // Stub for any util functions if needed
}
