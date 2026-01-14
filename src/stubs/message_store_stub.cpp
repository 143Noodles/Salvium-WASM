// message_store_stub.cpp - Stub for message store (not used in WASM wallet)
// The MMS (Multisig Messaging System) requires network access which isn't
// available in WASM. We provide stub implementations to satisfy the linker.

#include "wallet/message_store.h"

namespace mms {

// Constructor implementation - just initialize members, do nothing else
message_store::message_store(
    std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client)
    : m_active(false), m_num_authorized_signers(0), m_num_required_signers(0),
      m_auto_send(false), m_nettype(cryptonote::MAINNET), m_next_message_id(1),
      m_transporter(std::move(http_client)), m_run(false) {}

} // namespace mms
