// message_transporter_stub.cpp - Stub for HTTP/RPC message transport (not used
// in WASM wallet) The MMS (Multisig Messaging System) transporter requires
// Bitmessage network access which isn't available in WASM. We provide stub
// implementations to satisfy the linker.

#include "wallet/message_transporter.h"

namespace mms {

// Constructor implementation
message_transporter::message_transporter(
    std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client)
    : m_http_client(std::move(http_client)), m_run(false) {}

void message_transporter::set_options(
    const std::string &bitmessage_address,
    const epee::wipeable_string &bitmessage_login) {
  m_bitmessage_url = bitmessage_address;
  m_bitmessage_login = bitmessage_login;
}

bool message_transporter::send_message(const transport_message &message) {
  // Not implemented in WASM
  return false;
}

bool message_transporter::receive_messages(
    const std::vector<std::string> &destination_transport_addresses,
    std::vector<transport_message> &messages) {
  // Not implemented in WASM
  messages.clear();
  return false;
}

bool message_transporter::delete_message(const std::string &transport_id) {
  // Not implemented in WASM
  return false;
}

std::string
message_transporter::derive_transport_address(const std::string &seed) {
  // Not implemented in WASM
  return "";
}

bool message_transporter::delete_transport_address(
    const std::string &transport_address) {
  // Not implemented in WASM
  return false;
}

bool message_transporter::post_request(const std::string &request,
                                       std::string &answer) {
  // Not implemented in WASM
  return false;
}

std::string
message_transporter::get_str_between_tags(const std::string &s,
                                          const std::string &start_delim,
                                          const std::string &stop_delim) {
  return "";
}

void message_transporter::start_xml_rpc_cmd(std::string &xml,
                                            const std::string &method_name) {}

void message_transporter::add_xml_rpc_string_param(std::string &xml,
                                                   const std::string &param) {}

void message_transporter::add_xml_rpc_base64_param(std::string &xml,
                                                   const std::string &param) {}

void message_transporter::add_xml_rpc_integer_param(std::string &xml,
                                                    const int32_t &param) {}

void message_transporter::end_xml_rpc_cmd(std::string &xml) {}

} // namespace mms
