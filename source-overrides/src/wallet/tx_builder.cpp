// Copyright (c) 2025, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//paired header
#include "tx_builder.h"

//local headers
#include "carrot_core/config.h"
#include "carrot_core/device_ram_borrowed.h"
#include "carrot_core/enote_utils.h"
#include "carrot_core/exceptions.h"
#include "carrot_core/output_set_finalization.h"
#include "carrot_core/scan.h"
#include "carrot_core/scan_unsafe.cpp"
#include "carrot_core/address_utils.h"
#include "carrot_core/core_types.h"
#include "carrot_impl/address_device_ram_borrowed.h"
#include "carrot_impl/tx_builder_outputs.h"
#include "carrot_impl/format_utils.h"
#include "carrot_impl/input_selection.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "ringct/bulletproofs_plus.h"
#include "wallet/scanning_tools.cpp"
#include "common/container_helpers.h"
#include "carrot_core/payment_proposal.cpp"

//third party headers

//standard headers
#include <iterator>
#include <set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.tx_builder"

namespace tools
{
namespace wallet
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static constexpr T div_ceil(T dividend, T divisor)
{
    static_assert(std::is_unsigned_v<T>, "T not unsigned int");
    return (dividend + divisor - 1) / divisor;
}
//-------------------------------------------------------------------------------------------------------------------
const cryptonote::transaction_prefix *get_effective_transfer_tx(
    const wallet2::transfer_details &td,
    const wallet2 &w,
    const cryptonote::transaction **full_tx_out)
{
    if (full_tx_out)
        *full_tx_out = nullptr;

    // Hydrated full transactions carry the authoritative type and Carrot
    // extra.  A confirmed entry is only a transaction_prefix; use it next,
    // then fall back to the serialized transfer prefix.
    const auto runtime_it = w.m_runtime_full_txs.find(td.m_txid);
    if (runtime_it != w.m_runtime_full_txs.end())
    {
        if (full_tx_out)
            *full_tx_out = &runtime_it->second;
        return &runtime_it->second;
    }

    const auto confirmed_it = w.m_confirmed_txs.find(td.m_txid);
    if (confirmed_it != w.m_confirmed_txs.end())
        return &confirmed_it->second.m_tx;

    return &td.m_tx;
}

cryptonote::transaction_type get_effective_transfer_type(
    const wallet2::transfer_details &td,
    const wallet2 &w)
{
    return get_effective_transfer_tx(td, w)->type;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool is_transfer_usable_for_input_selection(const wallet2::transfer_details &td,
                                                   const std::uint32_t from_account,
                                                   const std::set<std::uint32_t> from_subaddresses,
                                                   const rct::xmr_amount ignore_above,
                                                   const rct::xmr_amount ignore_below,
                                                   const uint64_t top_block_index,
                                                   const std::string asset_type,
                                                   const wallet2 *wallet = nullptr)
{
    /**
     * This additional check appears to be for fcmp++.
    const uint64_t last_locked_block_index = cryptonote::get_last_locked_block_index(
        td.m_tx.unlock_time, td.m_block_height);
    */
    const cryptonote::transaction_type effective_type =
        wallet ? get_effective_transfer_type(td, *wallet) : td.m_tx.type;

    // Reject locked outputs
    size_t blocks_locked_for = CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    if (effective_type == cryptonote::transaction_type::MINER ||
        effective_type == cryptonote::transaction_type::PROTOCOL)
      blocks_locked_for = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

    const bool authority_usable = wallet
        ? has_transfer_spend_authority(td, *wallet)
        : (!td.m_key_image_partial && td.m_key_image_known &&
           td.m_key_image != crypto::key_image{});
    const bool basic_usable =
        !td.m_spent
        && td.amount() > 0
        && authority_usable
        && !td.m_frozen
        && (top_block_index +1 >= td.m_block_height + blocks_locked_for)
        // && last_locked_block_index <= top_block_index
        && td.m_subaddr_index.major == from_account
        && (from_subaddresses.empty() || from_subaddresses.count(td.m_subaddr_index.minor) == 1)
        && td.amount() >= ignore_below
        && td.amount() <= ignore_above
        && td.asset_type == asset_type
    ;

    if (!basic_usable)
        return false;

    if (wallet && effective_type == cryptonote::transaction_type::AUDIT)
    {
        const cryptonote::transaction_prefix *tx =
            get_effective_transfer_tx(td, *wallet);
        crypto::public_key output_key = crypto::null_pkey;
        if (td.m_internal_output_index >= tx->vout.size() ||
            !get_output_public_key(
                tx->vout[td.m_internal_output_index], output_key) ||
            output_key == crypto::null_pkey)
            return false;
        if (wallet->m_locked_coins.find(output_key) != wallet->m_locked_coins.end())
            return false;
    }

    if (!wallet)
        return true;

    if (effective_type != cryptonote::transaction_type::PROTOCOL &&
        effective_type != cryptonote::transaction_type::RETURN)
        return true;
    return validate_transfer_spend_authority(td, *wallet);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
namespace
{
std::optional<enote_view_incoming_scan_info_t> try_build_protocol_return_scan_info(
    const cryptonote::transaction &tx,
    const size_t local_output_index,
    const crypto::public_key &onetime_address,
    const wallet2::transfer_details &origin_td,
    const carrot::return_scan_hint_t &scan_hint,
    const wallet2 &w,
    std::string *trace_out = nullptr)
{
    if (tx.type != cryptonote::transaction_type::PROTOCOL ||
        local_output_index >= tx.vout.size())
    {
        if (trace_out)
            *trace_out = "proto=0";
        return std::nullopt;
    }

    if (trace_out)
        *trace_out = "proto=1";

    enote_view_incoming_scan_info_t protocol_scan_info{};
    protocol_scan_info.subaddr_index = carrot::subaddress_index_extended{
        {origin_td.m_subaddr_index.major, origin_td.m_subaddr_index.minor},
        carrot::AddressDeriveType::PreCarrot,
        false};
    protocol_scan_info.address_spend_pubkey = onetime_address;
    protocol_scan_info.amount_blinding_factor = rct::I;
    protocol_scan_info.main_tx_pubkey_index = 0;
    protocol_scan_info.is_carrot = false;
    protocol_scan_info.is_return = true;
    protocol_scan_info.amount = tx.vout.at(local_output_index).amount;
    protocol_scan_info.asset_type = origin_td.asset_type;
    protocol_scan_info.payment_id = crypto::null_hash;
    protocol_scan_info.return_address = onetime_address;

    if (!carrot::is_carrot_transaction_v1(tx))
    {
        if (trace_out)
            *trace_out += ",carrot=0";
        return protocol_scan_info;
    }
    if (trace_out)
        *trace_out += ",carrot=1";

    std::vector<mx25519_pubkey> enote_ephemeral_pubkeys;
    std::optional<carrot::encrypted_payment_id_t> encrypted_payment_id;
    if (!carrot::try_load_carrot_extra_v1(tx.extra,
                                          enote_ephemeral_pubkeys,
                                          encrypted_payment_id))
    {
        if (trace_out)
            *trace_out += ",extra=0";
        return std::nullopt;
    }
    if (trace_out)
        *trace_out += ",extra=1";

    carrot::CarrotEnoteV1 carrot_enote;
    if (!carrot::try_load_carrot_enote_from_transaction_v1(
            tx,
            epee::to_span(enote_ephemeral_pubkeys),
            local_output_index,
            carrot_enote))
    {
        if (trace_out)
            *trace_out += ",enote=0";
        return std::nullopt;
    }
    if (trace_out)
        *trace_out += ",enote=1";

    crypto::public_key address_spend_pubkey = crypto::null_pkey;
    rct::xmr_amount amount = 0;
    crypto::secret_key amount_blinding_factor = crypto::null_skey;
    auto &account =
        const_cast<carrot::carrot_and_legacy_account &>(w.get_account());
    if (!carrot::scan_return_output(
            carrot_enote.onetime_address,
            carrot_enote.enote_ephemeral_pubkey,
            carrot_enote.view_tag,
            carrot_enote.anchor_enc,
            carrot_enote.amount_enc,
            carrot_enote.amount_commitment,
            scan_hint.input_context,
            account,
            address_spend_pubkey,
            amount,
            amount_blinding_factor))
    {
        if (trace_out)
            *trace_out += ",scan_return=0";
        return std::nullopt;
    }
    if (trace_out)
        *trace_out += ",scan_return=1";

    crypto::secret_key k_return = crypto::null_skey;
    w.get_account().s_view_balance_dev.make_internal_return_privkey(
        scan_hint.input_context, scan_hint.K_o, k_return);
    mx25519_pubkey shared_secret_return_unctx;
    crypto::hash shared_secret_return;
    if (!carrot::make_carrot_uncontextualized_shared_key_receiver(
            k_return, carrot_enote.enote_ephemeral_pubkey,
            shared_secret_return_unctx))
    {
        if (trace_out)
            *trace_out += ",shared=0";
        return std::nullopt;
    }
    if (trace_out)
        *trace_out += ",shared=1";

    carrot::make_carrot_sender_receiver_secret(
        shared_secret_return_unctx.data,
        carrot_enote.enote_ephemeral_pubkey,
        scan_hint.input_context,
        shared_secret_return);
    crypto::secret_key sender_extension_g = crypto::null_skey;
    crypto::secret_key sender_extension_t = crypto::null_skey;
    carrot::make_carrot_onetime_address_extension_g(
        shared_secret_return, carrot_enote.amount_commitment,
        sender_extension_g);
    carrot::make_carrot_onetime_address_extension_t(
        shared_secret_return, carrot_enote.amount_commitment,
        sender_extension_t);

    protocol_scan_info.address_spend_pubkey = address_spend_pubkey;
    protocol_scan_info.amount_blinding_factor =
        rct::sk2rct(amount_blinding_factor);
    protocol_scan_info.is_carrot = true;
    protocol_scan_info.amount = amount;
    protocol_scan_info.sender_extension_g = sender_extension_g;
    protocol_scan_info.sender_extension_t = sender_extension_t;
    if (trace_out)
        *trace_out += ",ok=1";
    return protocol_scan_info;
}

bool try_get_validated_return_spend_metadata(
    const crypto::public_key &output_key,
    const wallet2 &w,
    const carrot::return_spend_metadata_t *&metadata_out,
    crypto::key_image *derived_key_image_out = nullptr)
{
    metadata_out = nullptr;

    const auto &return_spend_metadata =
        w.get_account().get_return_spend_metadata_map_ref();
    const auto metadata_it = return_spend_metadata.find(output_key);
    if (metadata_it == return_spend_metadata.end())
        return false;

    const auto &metadata = metadata_it->second;

    const auto derive_ki = [&](crypto::key_image &ki_out)
    {
        if (w.get_account().get_keys().s_master == crypto::null_skey)
        {
            ki_out = w.get_account().derive_key_image_view_only(
                metadata.K_spend_pubkey,
                metadata.sum_g,
                metadata.sender_extension_t,
                output_key);
        }
        else
        {
            ki_out = w.get_account().derive_key_image(
                metadata.K_spend_pubkey,
                metadata.sum_g,
                metadata.sender_extension_t,
                output_key);
        }
    };

    // Memoized fast path (wallet2::m_effective_ki_cache): the verdict and the
    // derived key image are a pure function of (account keys + account
    // subaddress map + this metadata entry). The cache is cleared via
    // invalidate_effective_ki_cache() whenever any of those inputs mutate.
    // Entries are only created for keys present in the metadata map.
    const auto cache_it = w.m_effective_ki_cache.find(output_key);
    if (cache_it != w.m_effective_ki_cache.end())
    {
        wallet2::effective_ki_cache_entry_t &entry = cache_it->second;
        if (!entry.verdict)
            return false;
        if (derived_key_image_out)
        {
            if (!entry.has_ki)
            {
                // The verdict was cached by a caller that did not request the
                // key image; derive it now. Matches the uncached path, which
                // returns false if derivation throws.
                try
                {
                    derive_ki(entry.ki);
                    entry.has_ki = true;
                }
                catch (const std::exception &)
                {
                    return false;
                }
            }
            *derived_key_image_out = entry.ki;
        }
        metadata_out = &metadata;
        return true;
    }

    if (!carrot::is_return_spend_metadata_complete(metadata) ||
        !carrot::is_return_spend_metadata_semantically_valid(metadata, output_key, nullptr))
    {
        w.m_effective_ki_cache[output_key] = wallet2::effective_ki_cache_entry_t{};
        return false;
    }

    try
    {
        if (!w.get_account().can_open_fcmp_onetime_address(
                metadata.K_spend_pubkey,
                metadata.sum_g,
                metadata.sender_extension_t,
                output_key))
        {
            w.m_effective_ki_cache[output_key] = wallet2::effective_ki_cache_entry_t{};
            return false;
        }

        wallet2::effective_ki_cache_entry_t entry;
        entry.verdict = true;
        if (derived_key_image_out)
        {
            derive_ki(entry.ki);
            entry.has_ki = true;
            *derived_key_image_out = entry.ki;
        }
        w.m_effective_ki_cache[output_key] = entry;

        metadata_out = &metadata;
        return true;
    }
    catch (const std::exception &)
    {
        // No cache write on exception: recompute on the next call, matching
        // the uncached behavior (return false on throw).
        return false;
    }
}

bool try_get_validated_return_spend_metadata(
    const wallet2::transfer_details &td,
    const wallet2 &w,
    const carrot::return_spend_metadata_t *&metadata_out,
    crypto::key_image *derived_key_image_out = nullptr)
{
    metadata_out = nullptr;
    const cryptonote::transaction_prefix *tx =
        get_effective_transfer_tx(td, w);
    if (tx->type != cryptonote::transaction_type::PROTOCOL &&
        tx->type != cryptonote::transaction_type::RETURN)
        return false;

    if (td.m_internal_output_index >= tx->vout.size())
        return false;

    crypto::public_key output_key = crypto::null_pkey;
    if (!get_output_public_key(tx->vout[td.m_internal_output_index], output_key))
        return false;
    return try_get_validated_return_spend_metadata(
        output_key, w, metadata_out, derived_key_image_out);
}

size_t find_wallet_transfer_index_from_container_by_effective_key_image(
    const wallet2::transfer_container &container,
    const crypto::key_image &ki,
    const wallet2 &w)
{
    bool selected_from_container = false;
    for (size_t idx = 0; idx < container.size(); ++idx)
    {
        const wallet2::transfer_details &td = container[idx];
        if (get_effective_transfer_key_image(td, w) != ki)
            continue;
        if (td.m_key_image_partial)
            CHECK_AND_ASSERT_THROW_MES(false, "Transfer detail lookups are not allowed for multisig partial key images");
        if (has_transfer_spend_authority(td, w))
        {
            selected_from_container = true;
            break;
        }
    }

    CHECK_AND_ASSERT_THROW_MES(selected_from_container, "Key image not found");

    const wallet2::transfer_container &wallet_transfers = w.get_transfers_ref();
    for (size_t idx = 0; idx < wallet_transfers.size(); ++idx)
    {
        const wallet2::transfer_details &td = wallet_transfers[idx];
        if (get_effective_transfer_key_image(td, w) != ki)
            continue;
        if (td.m_key_image_partial)
            CHECK_AND_ASSERT_THROW_MES(false, "Transfer detail lookups are not allowed for multisig partial key images");
        if (has_transfer_spend_authority(td, w))
            return idx;
    }

    CHECK_AND_ASSERT_THROW_MES(false, "Key image not found");
}
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
crypto::key_image get_effective_transfer_key_image(
    const wallet2::transfer_details &td,
    const wallet2 &w)
{
    const carrot::return_spend_metadata_t *validated_metadata = nullptr;
    crypto::key_image validated_key_image = crypto::key_image{};
    if (try_get_validated_return_spend_metadata(
            td, w, validated_metadata, &validated_key_image) &&
        validated_key_image != crypto::key_image{})
        return validated_key_image;

    return td.m_key_image;
}

bool has_validated_transfer_spend_authority(
    const wallet2::transfer_details &td,
    const wallet2 &w)
{
    if (td.m_key_image_partial)
        return false;
    const carrot::return_spend_metadata_t *metadata = nullptr;
    crypto::key_image derived_key_image{};
    return try_get_validated_return_spend_metadata(
               td, w, metadata, &derived_key_image) &&
           derived_key_image != crypto::key_image{};
}

bool has_transfer_spend_authority(
    const wallet2::transfer_details &td,
    const wallet2 &w)
{
    // View/watch-only wallets may derive tracking key images, but they do not
    // possess spend authority.  Keep this policy boundary ahead of any
    // metadata-derived or known-key-image acceptance.
    if (w.watch_only())
        return false;
    if (td.m_key_image_partial)
        return false;
    if (!td.m_key_image_known &&
        !has_validated_transfer_spend_authority(td, w))
        return false;
    return get_effective_transfer_key_image(td, w) != crypto::key_image{};
}

bool has_transfer_key_image(
    const wallet2::transfer_details &td,
    const wallet2 &w)
{
    if (td.m_key_image_partial)
        return false;

    const crypto::key_image effective_key_image =
        get_effective_transfer_key_image(td, w);
    if (effective_key_image == crypto::key_image{})
        return false;

    // A serialized key image is sufficient for tracking.  Otherwise accept
    // only the validated metadata-derived key image path used by Carrot
    // RETURN outputs.  Do not treat a merely non-zero sparse value as known.
    return (td.m_key_image_known && td.m_key_image != crypto::key_image{}) ||
           has_validated_transfer_spend_authority(td, w);
}

bool is_transfer_usable_for_return(
    const wallet2::transfer_details &td,
    wallet2 &w)
{
    if (td.m_key_image_partial)
        return false;
    if (w.is_spent(td, false) || td.m_frozen)
        return false;
    if (!has_transfer_spend_authority(td, w))
        return false;
    return w.is_transfer_unlocked(td);
}
//-------------------------------------------------------------------------------------------------------------------
// Resolve the canonical origin metadata used by legacy PROTOCOL/RETURN key
// image derivation.  Scanner order can leave m_td_origin_idx unset while the
// originating STAKE/AUDIT transfer is already confirmed; in that case mirror
// wallet2::process_new_scanned_transaction's exact return-address match.
bool resolve_transfer_origin_data(
    const wallet2::transfer_details &td,
    const wallet2 &w,
    cryptonote::origin_data &origin_tx_data)
{
    origin_tx_data = {};
    origin_tx_data.tx_type = cryptonote::transaction_type::UNSET;
    origin_tx_data.tx_pub_key = crypto::null_pkey;
    origin_tx_data.output_index = 0;

    const cryptonote::transaction_prefix *tx =
        get_effective_transfer_tx(td, w);
    if (tx->type != cryptonote::transaction_type::PROTOCOL &&
        tx->type != cryptonote::transaction_type::RETURN)
        return false;

    if (td.m_internal_output_index >= tx->vout.size())
        return false;

    crypto::public_key output_key = crypto::null_pkey;
    if (!cryptonote::get_output_public_key(
            tx->vout[td.m_internal_output_index], output_key) ||
        output_key == crypto::null_pkey)
        return false;

    // The scanner records the originating transfer in m_salvium_txs under
    // this exact payout output key.  Prefer that canonical link, and read all
    // origin fields from the same effective transaction view (runtime full,
    // confirmed prefix, then stored prefix).
    const auto populate_origin_from_index =
        [&](const size_t origin_idx) -> bool
    {
        if (origin_idx >= w.m_transfers.size())
            return false;
        const auto &origin_td = w.m_transfers[origin_idx];
        const cryptonote::transaction_prefix *origin_tx =
            get_effective_transfer_tx(origin_td, w);
        if (!origin_tx || origin_td.m_internal_output_index >= origin_tx->vout.size())
            return false;
        const crypto::public_key tx_pub_key =
            cryptonote::get_tx_pub_key_from_extra(
                *origin_tx, origin_td.m_pk_index);
        if (origin_tx->type == cryptonote::transaction_type::UNSET ||
            tx_pub_key == crypto::null_pkey)
            return false;
        origin_tx_data.tx_type = origin_tx->type;
        origin_tx_data.tx_pub_key = tx_pub_key;
        origin_tx_data.output_index = origin_td.m_internal_output_index;
        return true;
    };

    const auto salvium_it = w.m_salvium_txs.find(output_key);
    if (salvium_it != w.m_salvium_txs.end() &&
        populate_origin_from_index(salvium_it->second))
        return true;

    // Keep an explicit serialized origin index as a secondary source when a
    // wallet was materialized without the scanner's m_salvium_txs entry.
    if (td.m_td_origin_idx != std::numeric_limits<uint64_t>::max() &&
        populate_origin_from_index(td.m_td_origin_idx))
        return true;

    // Last-resort compatibility path for old/sparse wallets: mirror the
    // scanner's exact return-address match.  Some restored caches contain the
    // owned origin transfer and its hydrated transaction but neither a
    // confirmed-prefix entry nor m_salvium_txs/m_td_origin_idx.  Resolve that
    // transfer directly before falling back to the confirmed transaction map.
    for (size_t origin_idx = 0; origin_idx < w.m_transfers.size(); ++origin_idx)
    {
        const auto &origin_td = w.m_transfers[origin_idx];
        if (&origin_td == &td)
            continue;
        const cryptonote::transaction_prefix *candidate_tx =
            get_effective_transfer_tx(origin_td, w);
        if (!candidate_tx ||
            (candidate_tx->type != cryptonote::transaction_type::CONVERT &&
             candidate_tx->type != cryptonote::transaction_type::STAKE &&
             candidate_tx->type != cryptonote::transaction_type::AUDIT &&
             candidate_tx->type != cryptonote::transaction_type::CREATE_TOKEN))
            continue;
        crypto::public_key candidate_return = candidate_tx->return_address;
        if (candidate_return == crypto::null_pkey)
            candidate_return = candidate_tx->protocol_tx_data.return_address;
        if (candidate_return != output_key)
            continue;
        if (populate_origin_from_index(origin_idx))
            return true;
    }

    // Older confirmed-only caches predate the transfer linkage.  These legacy
    // STAKE/AUDIT entries historically used output zero, so retain that exact
    // confirmed-map fallback after the complete transfer-table search.
    for (const auto &entry : w.m_confirmed_txs)
    {
        const cryptonote::transaction_prefix *candidate_tx = &entry.second.m_tx;
        const auto runtime_candidate_it =
            w.m_runtime_full_txs.find(entry.first);
        if (runtime_candidate_it != w.m_runtime_full_txs.end())
            candidate_tx = &runtime_candidate_it->second;
        const cryptonote::transaction_prefix &candidate = *candidate_tx;
        if (candidate.type != cryptonote::transaction_type::STAKE &&
            candidate.type != cryptonote::transaction_type::AUDIT)
            continue;
        crypto::public_key candidate_return = candidate.return_address;
        if (candidate_return == crypto::null_pkey)
            candidate_return = candidate.protocol_tx_data.return_address;
        if (candidate_return != output_key)
            continue;
        origin_tx_data.tx_pub_key =
            cryptonote::get_tx_pub_key_from_extra(candidate);
        origin_tx_data.output_index = 0;
        origin_tx_data.tx_type = candidate.type;
        if (origin_tx_data.tx_pub_key != crypto::null_pkey)
            return true;
    }
    origin_tx_data = {};
    origin_tx_data.tx_type = cryptonote::transaction_type::UNSET;
    origin_tx_data.tx_pub_key = crypto::null_pkey;
    origin_tx_data.output_index = 0;
    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_transfer_spend_authority(
    const wallet2::transfer_details &td,
    const wallet2 &w)
{
    // A validator must never turn unknown, partial, or zero key-image state
    // into a spendable output.  The caller may still use such a transfer for
    // display, but selection and send validation fail closed.
    const bool validated_metadata =
        has_validated_transfer_spend_authority(td, w);
    if ((!td.m_key_image_known && !validated_metadata) ||
        td.m_key_image_partial ||
        (td.m_key_image == crypto::key_image{} && !validated_metadata))
        return false;

    try
    {
        const cryptonote::transaction *full_tx = nullptr;
        // The serialized transfer can be a sparse prefix.  Prefer the
        // complete runtime transaction, then confirmed prefix, then storage;
        // retain the full handle for Carrot's transaction overload.
        const cryptonote::transaction_prefix *tx =
            get_effective_transfer_tx(td, w, &full_tx);

        if (td.m_internal_output_index >= tx->vout.size())
            return false;

        crypto::public_key output_key = crypto::null_pkey;
        if (!cryptonote::get_output_public_key(
                tx->vout[td.m_internal_output_index], output_key) ||
            output_key == crypto::null_pkey)
            return false;

        cryptonote::tx_source_entry src;
        src.amount = td.amount();
        src.rct = td.is_rct();
        src.carrot = tx->vout[td.m_internal_output_index].target.type() ==
                     typeid(cryptonote::txout_to_carrot_v1);
        src.coinbase = !tx->vin.empty() &&
                       tx->vin[0].type() == typeid(cryptonote::txin_gen);
        src.block_index = td.m_block_height;
        src.asset_type = td.asset_type;
        src.mask = td.m_mask;
        src.address_spend_pubkey = td.m_recovered_spend_pubkey;
        // Both legacy key-image derivation and ordinary Carrot address opening
        // need the effective transaction's ephemeral keys.  Returned Carrot
        // metadata can open without them, but normal Carrot outputs cannot.
        src.real_out_tx_key =
            cryptonote::get_tx_pub_key_from_extra(*tx, td.m_pk_index);
        src.real_out_additional_tx_keys =
            cryptonote::get_additional_tx_pub_keys_from_extra(*tx);
        src.first_rct_key_image = crypto::key_image{};
        if (!tx->vin.empty() &&
            tx->vin[0].type() == typeid(cryptonote::txin_to_key))
        {
            src.first_rct_key_image =
                boost::get<cryptonote::txin_to_key>(tx->vin[0]).k_image;
        }

        cryptonote::origin_data origin_tx_data{};
        const bool have_origin_data =
            resolve_transfer_origin_data(td, w, origin_tx_data);

        cryptonote::tx_source_entry::output_entry real_oe;
        real_oe.first = td.m_asset_type_output_index;
        real_oe.second.dest = rct::pk2rct(output_key);
        real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
        src.outputs.push_back(real_oe);
        src.real_output = 0;
        src.real_output_in_tx_index = td.m_internal_output_index;
        src.origin_tx_data = origin_tx_data;

        if (!src.carrot)
        {
            // Legacy key-image derivation needs the main/additional tx
            // pubkeys and, for RingCT inputs, the first input context.  A
            // Carrot opening check must not reject a valid transaction merely
            // because its legacy tx pubkey is absent from a sparse prefix.
            if (src.real_out_tx_key == crypto::null_pkey)
                return false;

            // Historical PROTOCOL/RETURN payouts are not ordinary legacy
            // outputs: their spend key is derived from the originating STAKE,
            // AUDIT, or CONVERT transaction.  Without the canonical origin
            // link, the ordinary derivation must not claim authority.
            if ((tx->type == cryptonote::transaction_type::PROTOCOL ||
                 tx->type == cryptonote::transaction_type::RETURN) &&
                !have_origin_data)
                return false;

            hw::device &hwdev = w.get_account().get_keys().get_device();
            hw::reset_mode reset_mode(hwdev);
            hwdev.set_mode(hw::device::TRANSACTION_PARSE);
            cryptonote::keypair in_ephemeral;
            crypto::key_image derived_key_image;
            rct::salvium_input_data_t sid;
            const bool generated = cryptonote::generate_key_image_helper(
                w.get_account().get_keys(),
                w.get_account().get_subaddress_map_cn(), output_key,
                src.real_out_tx_key, src.real_out_additional_tx_keys,
                src.real_output_in_tx_index, in_ephemeral, derived_key_image,
                hwdev, have_origin_data, origin_tx_data, sid);
            const crypto::key_image expected_key_image =
                get_effective_transfer_key_image(td, w);
            return generated && in_ephemeral.pub == output_key &&
                   expected_key_image != crypto::key_image{} &&
                   derived_key_image == expected_key_image;
        }

        crypto::secret_key x_out = crypto::null_skey;
        crypto::secret_key y_out = crypto::null_skey;
        const bool opened = full_tx
            ? try_get_address_openings_x_y(
                  *full_tx, src, w, x_out, y_out, nullptr)
            : try_get_address_openings_x_y(
                  *tx, src, w, x_out, y_out, nullptr);
        if (!opened)
            return false;

        // Carrot authority is tied to the output's address opening, not to a
        // persisted key-image flag.  Re-derive the image from the effective
        // output context and require it to match the canonical/restored
        // effective image before allowing the transfer to be spent.
        crypto::key_image derived_key_image{};
        crypto::generate_key_image(output_key, x_out, derived_key_image);
        const crypto::key_image expected_key_image =
            get_effective_transfer_key_image(td, w);
        return expected_key_image != crypto::key_image{} &&
               derived_key_image == expected_key_image;
    }
    catch (...)
    {
        return false;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool build_payment_proposals(std::vector<carrot::CarrotPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<carrot::CarrotPaymentProposalVerifiableSelfSendV1> &selfsend_payment_proposals_inout,
    const cryptonote::tx_destination_entry &tx_dest_entry,
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddress_map)
{
    const auto subaddr_it = subaddress_map.find(tx_dest_entry.addr.m_spend_public_key);
    const bool is_selfsend_dest = subaddr_it != subaddress_map.cend();

    // Make N destinations
    if (is_selfsend_dest)
    {
        const carrot::subaddress_index subaddr_index{subaddr_it->second.major, subaddr_it->second.minor};
        selfsend_payment_proposals_inout.push_back(carrot::CarrotPaymentProposalVerifiableSelfSendV1{
            .proposal = carrot::CarrotPaymentProposalSelfSendV1{
                .destination_address_spend_pubkey = tx_dest_entry.addr.m_spend_public_key,
                .amount = tx_dest_entry.amount,
                .enote_type = carrot::CarrotEnoteType::PAYMENT,
                .asset_type = tx_dest_entry.asset_type
            },
            .subaddr_index = {subaddr_index, carrot::AddressDeriveType::Carrot, false},
        });
    }
    else // not *known* self-send address
    {
        const carrot::CarrotDestinationV1 dest{
            .address_spend_pubkey = tx_dest_entry.addr.m_spend_public_key,
            .address_view_pubkey = tx_dest_entry.addr.m_view_public_key,
            .is_subaddress = tx_dest_entry.is_subaddress
            //! @TODO: payment ID
        };

        normal_payment_proposals_inout.push_back(carrot::CarrotPaymentProposalV1{
            .destination = dest,
            .amount = tx_dest_entry.amount,
            .asset_type = tx_dest_entry.asset_type,
            .randomness = carrot::gen_janus_anchor(),
        });
    }

    return is_selfsend_dest;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static cryptonote::tx_destination_entry make_tx_destination_entry(
    const carrot::CarrotPaymentProposalV1 &payment_proposal)
{
    cryptonote::tx_destination_entry dest = cryptonote::tx_destination_entry(payment_proposal.amount,
        {payment_proposal.destination.address_spend_pubkey, payment_proposal.destination.address_view_pubkey, /*m_is_carrot*/true},
        payment_proposal.destination.is_subaddress);
    dest.is_integrated = payment_proposal.destination.payment_id != carrot::null_payment_id;
    dest.asset_type = payment_proposal.asset_type;
    return dest;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static cryptonote::tx_destination_entry make_tx_destination_entry(
    const carrot::CarrotPaymentProposalVerifiableSelfSendV1 &payment_proposal,
    const carrot::view_incoming_key_device &k_view_dev)
{
    crypto::public_key address_view_pubkey;
    CHECK_AND_ASSERT_THROW_MES(k_view_dev.view_key_scalar_mult_ed25519(
            payment_proposal.proposal.destination_address_spend_pubkey,
            address_view_pubkey),
        "make_tx_destination_entry: view-key multiplication failed");

   cryptonote::tx_destination_entry dest = cryptonote::tx_destination_entry(payment_proposal.proposal.amount,
       {payment_proposal.proposal.destination_address_spend_pubkey, address_view_pubkey, /*m_is_carrot*/true},
       payment_proposal.subaddr_index.index.is_subaddress());
    dest.asset_type = payment_proposal.proposal.asset_type;
    return dest;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::public_key find_change_address_spend_pubkey(
    const std::unordered_map<crypto::public_key, carrot::subaddress_index_extended> &subaddress_map,
    const std::uint32_t subaddr_account)
{
    const auto change_it = std::find_if(subaddress_map.cbegin(), subaddress_map.cend(),
        [subaddr_account](const auto &p) {
            return  p.second.index.major == subaddr_account &&
                    p.second.index.minor == 0 &&
                    p.second.derive_type == carrot::AddressDeriveType::Carrot &&
                    p.second.is_return_spend_key == false;
        });
    CHECK_AND_ASSERT_THROW_MES(change_it != subaddress_map.cend(),
        "find_change_address_spend_pubkey: missing change address (index "
        << subaddr_account << ",0) in subaddress map");

    const auto change_it_2 = std::find_if(std::next(change_it), subaddress_map.cend(),
        [subaddr_account](const auto &p) {
            return  p.second.index.major == subaddr_account &&
                    p.second.index.minor == 0 &&
                    p.second.derive_type == carrot::AddressDeriveType::Carrot &&
                    p.second.is_return_spend_key == false;
        });
    CHECK_AND_ASSERT_THROW_MES(change_it_2 == subaddress_map.cend(),
        "find_change_address_spend_pubkey: provided subaddress map is malformed!!! At least two spend pubkeys map to "
        "index " << subaddr_account << ",0 in the subaddress map!");

    return change_it->first;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
std::unordered_map<crypto::key_image, size_t> collect_non_burned_transfers_by_key_image(
    const wallet2::transfer_container &transfers,
    const wallet2 &w)
{
    std::unordered_map<crypto::key_image, size_t> best_transfer_index_by_ki;
    for (size_t i = 0; i < transfers.size(); ++i)
    {
        const wallet2::transfer_details &td = transfers.at(i);
        if (!has_transfer_spend_authority(td, w))
            continue;
        const crypto::key_image effective_key_image =
            get_effective_transfer_key_image(td, w);
        if (effective_key_image == crypto::key_image{})
            continue;
        const auto it = best_transfer_index_by_ki.find(effective_key_image);
        if (it == best_transfer_index_by_ki.end())
        {
            best_transfer_index_by_ki.insert({effective_key_image, i});
            continue;
        }
        const wallet2::transfer_details &other_td = transfers.at(it->second);
        if (td.amount() < other_td.amount())
            continue;
        else if (td.amount() > other_td.amount())
            it->second = i;
        else if (td.m_global_output_index > other_td.m_global_output_index)
            continue;
        else if (td.m_global_output_index < other_td.m_global_output_index)
            it->second = i;
    }
    return best_transfer_index_by_ki;
}
//-------------------------------------------------------------------------------------------------------------------
carrot::select_inputs_func_t make_wallet2_single_transfer_input_selector(
    wallet2 &w,
    const wallet2::transfer_container &transfers,
    const std::uint32_t from_account,
    const std::set<std::uint32_t> &from_subaddresses,
    const rct::xmr_amount ignore_above,
    const rct::xmr_amount ignore_below,
    const std::uint64_t top_block_index,
    const bool allow_carrot_external_inputs_in_normal_transfers,
    const bool allow_pre_carrot_inputs_in_normal_transfers,
    const std::string &asset_type,
    std::set<size_t> &selected_transfer_indices_out)
{
    // Collect transfer_container into a `std::vector<carrot::InputCandidate>` for usable inputs
    std::vector<carrot::InputCandidate> input_candidates;
    std::vector<size_t> input_candidates_transfer_indices;
    input_candidates.reserve(transfers.size());
    input_candidates_transfer_indices.reserve(transfers.size());
    for (size_t i = 0; i < transfers.size(); ++i)
    {
        const wallet2::transfer_details &td = transfers.at(i);
        if (is_transfer_usable_for_input_selection(td,
                                                   from_account,
                                                   from_subaddresses,
                                                   ignore_above,
                                                   ignore_below,
                                                   top_block_index,
                                                   asset_type,
                                                   &w))
        {
            const cryptonote::transaction_prefix *effective_tx =
                get_effective_transfer_tx(td, w);
            input_candidates.push_back(carrot::InputCandidate{
                .core = carrot::CarrotSelectedInput{
                    .amount = td.amount(),
                    .key_image = get_effective_transfer_key_image(td, w)
                },
                .is_pre_carrot = !carrot::is_carrot_transaction_v1(*effective_tx),
                .is_external = true, //! @TODO: derive this info from field in transfer_details
                .block_index = td.m_block_height
            });
            input_candidates_transfer_indices.push_back(i);
        }
    }

    // Create wrapper around `make_single_transfer_input_selector`
    return [input_candidates = std::move(input_candidates),
            input_candidates_transfer_indices = std::move(input_candidates_transfer_indices),
            allow_carrot_external_inputs_in_normal_transfers,
            allow_pre_carrot_inputs_in_normal_transfers,
            asset_type,
            &selected_transfer_indices_out
            ](
                const boost::multiprecision::uint128_t &nominal_output_sum,
                const std::map<std::size_t, rct::xmr_amount> &fee_by_input_count,
                const std::size_t num_normal_payment_proposals,
                const std::size_t num_selfsend_payment_proposals,
                std::vector<carrot::CarrotSelectedInput> &selected_inputs_outs
            ){
                const std::vector<carrot::input_selection_policy_t> policies{
                    &carrot::ispolicy::select_greedy_aging
                };

                std::uint32_t flags = 0;
                if (allow_carrot_external_inputs_in_normal_transfers)
                    flags |= carrot::InputSelectionFlags::ALLOW_EXTERNAL_INPUTS_IN_NORMAL_TRANSFERS;
                if (allow_pre_carrot_inputs_in_normal_transfers)
                    flags |= carrot::InputSelectionFlags::ALLOW_PRE_CARROT_INPUTS_IN_NORMAL_TRANSFERS;
                // for token transfers; fee is paid separately in SAL1 via rollup tx
                if (cryptonote::is_asset_type_token(asset_type))
                    flags |= carrot::InputSelectionFlags::IS_TOKEN_TRANSFER;

                // Make inner input selection functor
                std::set<size_t> selected_input_indices;
                const carrot::select_inputs_func_t inner = carrot::make_single_transfer_input_selector(
                    epee::to_span(input_candidates),
                    epee::to_span(policies),
                    flags,
                    &selected_input_indices);

                // Call input selection
                inner(nominal_output_sum,
                    fee_by_input_count,
                    num_normal_payment_proposals,
                    num_selfsend_payment_proposals,
                    selected_inputs_outs);

                // Collect converted selected_input_indices -> selected_transfer_indices_out
                selected_transfer_indices_out.clear();
                for (const size_t input_index : selected_input_indices)
                    selected_transfer_indices_out.insert(input_candidates_transfer_indices.at(input_index));
            };
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<cryptonote::tx_source_entry> get_sources(
    const std::vector<std::size_t> &selected_transfers,
    const std::string &source_asset,
    wallet2 &w
) {
    const wallet2::transfer_container &transfers = w.get_transfers_ref();

    // get decoys
    size_t fake_outputs_count = (cryptonote::is_asset_type_token(source_asset)) ? 0 : 15;
    // check here!
    // for tokens, check if there are enough decoys in the chain - if so ring_size= 16
    if (cryptonote::is_asset_type_token(source_asset))
    {
        uint64_t rct_start_height = 0;
        std::vector<uint64_t> distribution;
        uint64_t num_spendable_global_outs = 0;
        if (w.get_rct_distribution(false, source_asset, rct_start_height, distribution, num_spendable_global_outs)
            && num_spendable_global_outs > 15)
        {
            fake_outputs_count = 15;
        }
    }

    std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;
    std::unordered_set<crypto::public_key> valid_public_keys_cache;
    w.get_outs(outs, transfers, selected_transfers, fake_outputs_count, true, valid_public_keys_cache); // may throw

    LOG_PRINT_L2("preparing outputs");
    size_t out_index = 0;
    std::vector<cryptonote::tx_source_entry> sources;
    for(size_t idx: selected_transfers)
    {
        sources.resize(sources.size()+1);
        cryptonote::tx_source_entry& src = sources.back();
        THROW_WALLET_EXCEPTION_IF(idx >= w.get_num_transfer_details(), error::wallet_internal_error,
            "selected transfer index is outside wallet transfer table");
        const wallet2::transfer_details& td = w.get_transfer_details(idx);

        // Sanity check the asset_type for this TD is correct
        THROW_WALLET_EXCEPTION_IF(td.asset_type != source_asset, error::wallet_internal_error, "Input has wrong asset_type - expected " + source_asset + " but found " + td.asset_type);

        const cryptonote::transaction_prefix *effective_tx =
            get_effective_transfer_tx(td, w);
        const cryptonote::transaction_type effective_type =
            effective_tx->type;
        THROW_WALLET_EXCEPTION_IF(
            td.m_internal_output_index >= effective_tx->vout.size(),
            error::wallet_internal_error,
            "selected transfer output is missing from effective transaction");

        crypto::public_key effective_output_key = crypto::null_pkey;
        THROW_WALLET_EXCEPTION_IF(
            !get_output_public_key(
                effective_tx->vout[td.m_internal_output_index],
                effective_output_key),
            error::wallet_internal_error,
            "selected transfer output has no public key in effective transaction");

        src.amount = td.amount();
        src.rct = td.is_rct();
        src.carrot = effective_tx->vout[td.m_internal_output_index].target.type() ==
                     typeid(cryptonote::txout_to_carrot_v1);
        src.coinbase = !effective_tx->vin.empty() &&
                       effective_tx->vin[0].type() == typeid(cryptonote::txin_gen);
        src.block_index = td.m_block_height;
        src.asset_type = td.asset_type;

        // Create origin data through the same canonical resolver used by
        // spend validation.  This includes the scanner-compatible confirmed
        // STAKE/AUDIT fallback when scan order left m_td_origin_idx unset.
        const bool have_origin_data =
            resolve_transfer_origin_data(td, w, src.origin_tx_data);
        if (!src.carrot &&
            (effective_type == cryptonote::transaction_type::PROTOCOL ||
             effective_type == cryptonote::transaction_type::RETURN))
        {
            THROW_WALLET_EXCEPTION_IF(
                !have_origin_data, error::wallet_internal_error,
                "cannot locate legacy return_payment origin data");
        }

        //paste mixin transaction

        THROW_WALLET_EXCEPTION_IF(outs.size() < out_index + 1 ,  error::wallet_internal_error, "outs.size() < out_index + 1");
        THROW_WALLET_EXCEPTION_IF(outs[out_index].size() < fake_outputs_count ,  error::wallet_internal_error, "fake_outputs_count > random outputs found");

        typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
        for (size_t n = 0; n < fake_outputs_count + 1; ++n)
        {
            tx_output_entry oe;
            oe.first = std::get<0>(outs[out_index][n]);
            oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
            oe.second.mask = std::get<2>(outs[out_index][n]);
            src.outputs.push_back(oe);
        }

        //paste real transaction to the random index
        auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
        {
            // HERE BE DRAGONS!!!
            // SRCG: ring tweak to indexed per asset_type - DO NOT COMMIT UNTIL IT IS ALL WORKING
            //return a.first == td.m_global_output_index;
            return a.first == td.m_asset_type_output_index;
            // LAND AHOY!!!
        });
        if (it_to_replace == src.outputs.end())
        {
            const rct::key real_mask = rct::commit(td.amount(), td.m_mask);
            it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
            {
                return rct::rct2pk(a.second.dest) == effective_output_key &&
                       a.second.mask == real_mask;
            });
        }
        THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), error::wallet_internal_error,
            "real output not found");

        tx_output_entry real_oe;
        // HERE BE DRAGONS!!!
        // SRCG: ring tweak to indexed per asset_type - DO NOT COMMIT UNTIL IT IS ALL WORKING
        //real_oe.first = td.m_global_output_index;
        real_oe.first = it_to_replace->first;
        // LAND AHOY!!!
        real_oe.second.dest = rct::pk2rct(effective_output_key);
        real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
        *it_to_replace = real_oe;
        src.real_out_tx_key =
            get_tx_pub_key_from_extra(*effective_tx, td.m_pk_index);
        src.real_out_additional_tx_keys =
            get_additional_tx_pub_keys_from_extra(*effective_tx);
        src.real_output = it_to_replace - src.outputs.begin();
        src.real_output_in_tx_index = td.m_internal_output_index;
        src.mask = td.m_mask;
        src.address_spend_pubkey = td.m_recovered_spend_pubkey;
        const carrot::return_spend_metadata_t *validated_metadata = nullptr;
        if (try_get_validated_return_spend_metadata(td, w, validated_metadata))
        {
            src.address_spend_pubkey = validated_metadata->K_spend_pubkey;
            // Once we have return spend metadata that can actually open the
            // payout output, treat the payout itself as authoritative.
            src.origin_tx_data = {};
        }
        if (!effective_tx->vin.empty() &&
            effective_tx->vin[0].type() == typeid(cryptonote::txin_to_key)) {
            src.first_rct_key_image =
                boost::get<cryptonote::txin_to_key>(effective_tx->vin[0]).k_image;
        }

        if (false) // w.m_multisig // TODO:
            // note: multisig_kLRki is a legacy struct, currently only used as a key image shuttle into the multisig tx builder
            src.multisig_kLRki = {.k = {}, .L = {}, .R = {}, .ki = rct::ki2rct(td.m_key_image)};
        else
            src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
        detail::print_source_entry(src);
        ++out_index;
    }
    LOG_PRINT_L2("outputs prepared");

    return sources;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_createtoken(
    wallet2 &w,
    const cryptonote::token_metadata_t &token,
    const cryptonote::tx_destination_entry &de,
    const rct::xmr_amount fee_per_weight,
    const rct::xmr_amount fee_quantization_mask,
    const uint32_t subaddr_account,
    const std::set<uint32_t> &subaddr_indices,
    const std::uint64_t top_block_index)
{
    wallet2::transfer_container unused_transfers;
    w.get_transfers(unused_transfers, "SAL1");

    std::vector<carrot::CarrotTransactionProposalV1> tx_proposals;
    tx_proposals.reserve(1 / (carrot::CARROT_MAX_TX_OUTPUTS - 1) + 1);

    const crypto::public_key change_address_spend_pubkey
      = find_change_address_spend_pubkey(w.get_account().get_subaddress_map_ref(), subaddr_account);

    std::vector<cryptonote::tx_destination_entry> dsts = {de};
    while (!dsts.empty())
    {
        const std::size_t num_dsts_to_complete = std::min<std::size_t>(dsts.size(), carrot::CARROT_MAX_TX_OUTPUTS - 1);

        // build payment proposals and subtractable info from last `num_dsts_to_complete` dsts
        std::vector<carrot::CarrotPaymentProposalV1> normal_payment_proposals;
        std::vector<carrot::CarrotPaymentProposalVerifiableSelfSendV1> selfsend_payment_proposals;
        std::set<std::size_t> subtractable_normal_payment_proposals;
        std::set<std::size_t> subtractable_selfsend_payment_proposals;
        for (size_t i = 0; i < num_dsts_to_complete && !dsts.empty(); ++i)
        {
            const cryptonote::tx_destination_entry &dst = dsts.back();
            build_payment_proposals(normal_payment_proposals,
                selfsend_payment_proposals,
                dst,
                w.get_account().get_subaddress_map_cn());
            dsts.pop_back();
        }

        // make input selector
        std::set<size_t> selected_transfer_indices;
        carrot::select_inputs_func_t select_inputs = make_wallet2_single_transfer_input_selector(
            w,
            unused_transfers,
            subaddr_account,
            subaddr_indices,
            w.ignore_outputs_above(),
            w.ignore_outputs_below(),
            top_block_index,
            true, //allow_carrot_external_inputs_in_normal_transfers
            true, //allow_pre_carrot_inputs_in_normal_transfers
            std::string("SAL1"),
            selected_transfer_indices);

        // make proposal
        carrot::CarrotTransactionProposalV1 tx_proposal;
        carrot::make_carrot_transaction_proposal_v1_transfer(
            normal_payment_proposals,
            selfsend_payment_proposals,
            fee_per_weight,
            fee_quantization_mask,
            {},
            cryptonote::transaction_type::CREATE_TOKEN,
            std::move(select_inputs),
            change_address_spend_pubkey,
            {{subaddr_account, 0}, carrot::AddressDeriveType::Carrot, false},
            subtractable_normal_payment_proposals,
            subtractable_selfsend_payment_proposals,
            "SAL1",
            tx_proposal);

        // populate the sources
        std::vector<size_t> selected_transfer_indices_sorted;
        for (const auto &ki: tx_proposal.key_images_sorted) {
          selected_transfer_indices_sorted.push_back(
              find_wallet_transfer_index_from_container_by_effective_key_image(
                  unused_transfers, ki, w));
        }
        tx_proposal.sources = get_sources(selected_transfer_indices_sorted, "SAL1", w);

        // update `unused_transfers` for next proposal by removing selected transfers
        tools::for_all_in_vector_erase_no_preserve_order_if(unused_transfers,
            [&tx_proposal, &w](const wallet2::transfer_details &td) -> bool {
                const auto &used_kis = tx_proposal.key_images_sorted;
                const auto effective_ki = get_effective_transfer_key_image(td, w);
                const auto ki_it = std::find(used_kis.cbegin(), used_kis.cend(), effective_ki);
                return ki_it != used_kis.cend();
            }
        );

        tx_proposal.token = token;

        tx_proposals.push_back(std::move(tx_proposal));
    }
    return tx_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_createtoken(
    wallet2 &w,
    const cryptonote::token_metadata_t &token,
    const cryptonote::tx_destination_entry &de,
    const std::uint32_t priority,
    const std::uint32_t subaddr_account,
    const std::set<uint32_t> &subaddr_indices)
{
    const bool use_per_byte_fee = w.use_fork_rules(HF_VERSION_PER_BYTE_FEE, 0);
    CHECK_AND_ASSERT_THROW_MES(use_per_byte_fee,
        "make_carrot_transaction_proposals_wallet2_createtoken: not using per-byte base fee");

    const rct::xmr_amount fee_per_weight = w.get_base_fee(priority);
    MDEBUG("fee_per_weight = " << fee_per_weight << ", from priority = " << priority);

    const rct::xmr_amount fee_quantization_mask = w.get_fee_quantization_mask();
    MDEBUG("fee_quantization_mask = " << fee_quantization_mask << ", from priority = " << priority);

    const std::uint64_t current_chain_height = w.get_blockchain_current_height();
    CHECK_AND_ASSERT_THROW_MES(current_chain_height > 0,
        "make_carrot_transaction_proposals_wallet2_createtoken: chain height is 0, there is no top block");
    const std::uint64_t top_block_index = current_chain_height - 1;

    return make_carrot_transaction_proposals_wallet2_createtoken(
        w,
        token,
        de,
        fee_per_weight,
        fee_quantization_mask,
        subaddr_account,
        subaddr_indices,
        top_block_index);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_transfer(
    wallet2 &w,
    std::vector<cryptonote::tx_destination_entry> dsts,
    const rct::xmr_amount fee_per_weight,
    const rct::xmr_amount fee_quantization_mask,
    const std::vector<uint8_t> &extra,
    const cryptonote::transaction_type tx_type,
    const uint32_t subaddr_account,
    const std::set<uint32_t> &subaddr_indices,
    wallet2::unique_index_container subtract_fee_from_outputs,
    const std::uint64_t top_block_index)
{
    // Make sure all destinations have the SAME asset_type
    const std::string asset_type = dsts[0].asset_type;
    if (dsts.size() > 1) {
      for (size_t i=0; i<dsts.size(); ++i) {
        CHECK_AND_ASSERT_THROW_MES(dsts[i].asset_type == asset_type, "Mixed asset_types in transaction outputs is forbidden");
      }
    }

    wallet2::transfer_container unused_transfers;
    w.get_transfers(unused_transfers, asset_type);

    std::vector<carrot::CarrotTransactionProposalV1> tx_proposals;
    tx_proposals.reserve(dsts.size() / (carrot::CARROT_MAX_TX_OUTPUTS - 1) + 1);

    const crypto::public_key change_address_spend_pubkey
      = find_change_address_spend_pubkey(w.get_account().get_subaddress_map_ref(), subaddr_account);

    while (!dsts.empty())
    {
        const std::size_t num_dsts_to_complete = std::min<std::size_t>(dsts.size(), carrot::CARROT_MAX_TX_OUTPUTS - 1);

        // build payment proposals and subtractable info from last `num_dsts_to_complete` dsts
        std::vector<carrot::CarrotPaymentProposalV1> normal_payment_proposals;
        std::vector<carrot::CarrotPaymentProposalVerifiableSelfSendV1> selfsend_payment_proposals;
        std::set<std::size_t> subtractable_normal_payment_proposals;
        std::set<std::size_t> subtractable_selfsend_payment_proposals;
        for (size_t i = 0; i < num_dsts_to_complete && !dsts.empty(); ++i)
        {
            const cryptonote::tx_destination_entry &dst = dsts.back();
            const bool is_selfsend = build_payment_proposals(normal_payment_proposals,
                selfsend_payment_proposals,
                dst,
                w.get_account().get_subaddress_map_cn());
            if (subtract_fee_from_outputs.count(dsts.size() - 1))
            {
                if (is_selfsend)
                    subtractable_selfsend_payment_proposals.insert(selfsend_payment_proposals.size() - 1);
                else
                    subtractable_normal_payment_proposals.insert(normal_payment_proposals.size() - 1);
            }
            dsts.pop_back();
        }

        // make input selector
        std::set<size_t> selected_transfer_indices;
        carrot::select_inputs_func_t select_inputs = make_wallet2_single_transfer_input_selector(
            w,
            unused_transfers,
            subaddr_account,
            subaddr_indices,
            w.ignore_outputs_above(),
            w.ignore_outputs_below(),
            top_block_index,
            /*allow_carrot_external_inputs_in_normal_transfers=*/true,
            /*allow_pre_carrot_inputs_in_normal_transfers=*/true,
            asset_type,
            selected_transfer_indices);

        // make proposal
        carrot::CarrotTransactionProposalV1 tx_proposal;
        carrot::make_carrot_transaction_proposal_v1_transfer(
                                                             normal_payment_proposals,
                                                             selfsend_payment_proposals,
                                                             fee_per_weight,
                                                             fee_quantization_mask,
                                                             extra,
                                                             tx_type,
                                                             std::move(select_inputs),
                                                             change_address_spend_pubkey,
                                                             {{subaddr_account, 0}, carrot::AddressDeriveType::Carrot, false},
                                                             subtractable_normal_payment_proposals,
                                                             subtractable_selfsend_payment_proposals,
                                                             asset_type,
                                                             tx_proposal);

        // populate the sources
        std::vector<size_t> selected_transfer_indices_sorted;
        for (const auto &ki: tx_proposal.key_images_sorted) {
          selected_transfer_indices_sorted.push_back(
              find_wallet_transfer_index_from_container_by_effective_key_image(
                  unused_transfers, ki, w));
        }
        tx_proposal.sources = get_sources(selected_transfer_indices_sorted, asset_type, w);

        // update `unused_transfers` for next proposal by removing selected transfers
        tools::for_all_in_vector_erase_no_preserve_order_if(unused_transfers,
            [&tx_proposal, &w](const wallet2::transfer_details &td) -> bool {
                const auto &used_kis = tx_proposal.key_images_sorted;
                const auto effective_ki = get_effective_transfer_key_image(td, w);
                const auto ki_it = std::find(used_kis.cbegin(), used_kis.cend(), effective_ki);
                return ki_it != used_kis.cend();
            }
        );

        tx_proposals.push_back(std::move(tx_proposal));
    }

    return tx_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_transfer(
    wallet2 &w,
    const std::vector<cryptonote::tx_destination_entry> &dsts,
    const std::uint32_t priority,
    const std::vector<uint8_t> &extra,
    const cryptonote::transaction_type tx_type,
    const std::uint32_t subaddr_account,
    const std::set<uint32_t> &subaddr_indices,
    const wallet2::unique_index_container &subtract_fee_from_outputs)
{
    const bool use_per_byte_fee = w.use_fork_rules(HF_VERSION_PER_BYTE_FEE, 0);
    CHECK_AND_ASSERT_THROW_MES(use_per_byte_fee,
        "make_carrot_transaction_proposals_wallet2_transfer: not using per-byte base fee");

    // check if this is a token transfer (sal prefix) - tokens have zero fees
    const std::string asset_type =
        dsts.empty() ? "SAL1"
                     : (tx_type == cryptonote::transaction_type::BURN
                            ? "SAL1"
                            : dsts[0].asset_type);
    const bool is_token = cryptonote::is_asset_type_token(asset_type);

    const rct::xmr_amount fee_per_weight = /*is_token ? 0 :*/ w.get_base_fee(priority);
    MDEBUG("fee_per_weight = " << fee_per_weight << ", from priority = " << priority << ", is_token = " << is_token);

    const rct::xmr_amount fee_quantization_mask = w.get_fee_quantization_mask();
    MDEBUG("fee_quantization_mask = " << fee_quantization_mask << ", from priority = " << priority);

    const std::uint64_t current_chain_height = w.get_blockchain_current_height();
    CHECK_AND_ASSERT_THROW_MES(current_chain_height > 0,
        "make_carrot_transaction_proposals_wallet2_transfer: chain height is 0, there is no top block");
    const std::uint64_t top_block_index = current_chain_height - 1;

    return make_carrot_transaction_proposals_wallet2_transfer(
        w,
        dsts,
        fee_per_weight,
        fee_quantization_mask,
        extra,
        tx_type,
        subaddr_account,
        subaddr_indices,
        subtract_fee_from_outputs,
        top_block_index);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_sweep(
    wallet2 &w,
    const std::vector<crypto::key_image> &input_key_images,
    const cryptonote::account_public_address &address,
    const bool is_subaddress,
    const size_t n_dests_per_tx,
    const rct::xmr_amount fee_per_weight,
    const rct::xmr_amount fee_quantization_mask,
    const std::vector<uint8_t> &extra,
    const cryptonote::transaction_type tx_type,
    const std::uint64_t top_block_index)
{
    const size_t n_inputs = input_key_images.size();
    CARROT_CHECK_AND_THROW(n_inputs, carrot::too_few_inputs, "no key images provided");
    CARROT_CHECK_AND_THROW(n_dests_per_tx, carrot::too_few_outputs, "sweep must have at least one destination");
    CARROT_CHECK_AND_THROW(n_dests_per_tx <= carrot::CARROT_MAX_TX_OUTPUTS,
        carrot::too_many_outputs, "too many sweep destinations per transaction");

    // Make sure all destinations have the SAME asset_type
    std::string asset_type = "";
    for (const crypto::key_image &ki : input_key_images) {
      const wallet2::transfer_details &td = w.get_transfer_details(w.get_transfer_details(ki));
      if (asset_type == "")
        asset_type = td.asset_type;
      else
        CHECK_AND_ASSERT_THROW_MES(td.asset_type == asset_type, "Mixed asset_types in transaction inputs is forbidden");
    }

    wallet2::transfer_container unused_transfers;
    w.get_transfers(unused_transfers, asset_type);

    // Check that the key image is usable and isn't spent, collect amounts, and get subaddress account index
    std::vector<rct::xmr_amount> input_amounts;
    input_amounts.reserve(input_key_images.size());
    std::uint32_t subaddr_account = std::numeric_limits<std::uint32_t>::max();
    const auto best_transfers_by_ki =
        collect_non_burned_transfers_by_key_image(unused_transfers, w);
    for (const crypto::key_image &ki : input_key_images)
    {
        const auto ki_it = best_transfers_by_ki.find(ki);
        CHECK_AND_ASSERT_THROW_MES(ki_it != best_transfers_by_ki.cend(),
            __func__ << ": unknown key image");
        const wallet2::transfer_details &td = unused_transfers.at(ki_it->second);
        CHECK_AND_ASSERT_THROW_MES(is_transfer_usable_for_input_selection(td,
                                                                          td.m_subaddr_index.major,
                                                                          /*from_subaddresses=*/{},
                                                                          /*ignore_above=*/MONEY_SUPPLY,
                                                                          /*ignore_below=*/0,
                                                                          top_block_index,
                                                                          asset_type,
                                                                          &w),
                                   __func__ << ": transfer not usable as an input");
        input_amounts.push_back(td.amount());
        subaddr_account = std::min(subaddr_account, td.m_subaddr_index.major);
    }

    const crypto::public_key change_address_spend_pubkey
      = find_change_address_spend_pubkey(w.get_account().get_subaddress_map_ref(), subaddr_account);

    // get 1 payment proposal corresponding to (address, is_subaddres)
    std::vector<carrot::CarrotPaymentProposalV1> normal_payment_proposals;
    std::vector<carrot::CarrotPaymentProposalVerifiableSelfSendV1> selfsend_payment_proposals;
    for (size_t i = 0; i < n_dests_per_tx; ++i)
    {
        cryptonote::tx_destination_entry de;
        de.amount = 0;
        de.addr = address;
        de.is_subaddress = is_subaddress;
        de.asset_type = asset_type;
        const bool is_selfsend_dest = build_payment_proposals(normal_payment_proposals,
            selfsend_payment_proposals,
            de,
            w.get_account().get_subaddress_map_cn());
        CHECK_AND_ASSERT_THROW_MES((is_selfsend_dest && selfsend_payment_proposals.size() == i+1)
                || (!is_selfsend_dest && normal_payment_proposals.size() == i+1),
            __func__ << ": BUG in build_payment_proposals: incorrect count for payment proposal lists");
    }
    CARROT_CHECK_AND_THROW(normal_payment_proposals.size() < carrot::CARROT_MAX_TX_OUTPUTS,
        carrot::too_many_outputs, "too many *outgoing* sweep destinations per tx, we also need 1 self-send output");

    // make `n_txs` tx proposals with `n_output` payment proposals each
    const size_t n_txs = div_ceil<size_t>(n_inputs, carrot::CARROT_MAX_TX_INPUTS);
    std::vector<carrot::CarrotTransactionProposalV1> tx_proposals(n_txs);
    size_t ki_idx = 0;
    for (carrot::CarrotTransactionProposalV1 &tx_proposal : tx_proposals)
    {
        // if a 2-selfsend, 2-out tx, flip one of the enote types to get unique derivations
        if (selfsend_payment_proposals.size() == 2)
            selfsend_payment_proposals.back().proposal.enote_type = carrot::CarrotEnoteType::CHANGE;

        // collect inputs for this tx
        const size_t ki_idx_end = std::min<size_t>(n_inputs, ki_idx + carrot::CARROT_MAX_TX_INPUTS);
        std::vector<carrot::CarrotSelectedInput> selected_inputs;
        selected_inputs.reserve(n_inputs - ki_idx_end);
        for (; ki_idx < ki_idx_end; ++ki_idx)
            selected_inputs.push_back({input_amounts.at(ki_idx), input_key_images.at(ki_idx)});

        carrot::make_carrot_transaction_proposal_v1_sweep(normal_payment_proposals,
                                                          selfsend_payment_proposals,
                                                          fee_per_weight,
                                                          fee_quantization_mask,
                                                          extra,
                                                          tx_type,
                                                          std::move(selected_inputs),
                                                          change_address_spend_pubkey,
                                                          {{subaddr_account, 0}, carrot::AddressDeriveType::Carrot},
                                                          asset_type,
                                                          tx_proposal);

        // populate the sources
        std::vector<size_t> selected_transfer_indices_sorted;
        for (const auto &ki: tx_proposal.key_images_sorted) {
          selected_transfer_indices_sorted.push_back(
              find_wallet_transfer_index_from_container_by_effective_key_image(
                  unused_transfers, ki, w));
        }
        tx_proposal.sources = get_sources(selected_transfer_indices_sorted, asset_type, w);
    }

    CARROT_CHECK_AND_THROW(ki_idx == input_key_images.size(),
        carrot::carrot_logic_error, "BUG: sweep_all did not consume the correct num of key images while iterating");

    return tx_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_sweep(
    wallet2 &w,
    const std::vector<crypto::key_image> &input_key_images,
    const cryptonote::account_public_address &address,
    const bool is_subaddress,
    const size_t n_dests_per_tx,
    const std::uint32_t priority,
    const std::vector<uint8_t> &extra,
    const cryptonote::transaction_type tx_type)
{
    const rct::xmr_amount fee_per_weight = w.get_base_fee(priority);
    const rct::xmr_amount fee_quantization_mask = w.get_fee_quantization_mask();

    const std::uint64_t current_chain_height = w.get_blockchain_current_height();
    CHECK_AND_ASSERT_THROW_MES(current_chain_height > 0,
        "make_carrot_transaction_proposals_wallet2_sweep: chain height is 0, there is no top block");
    const std::uint64_t top_block_index = current_chain_height - 1;

    return make_carrot_transaction_proposals_wallet2_sweep(
        w,
        input_key_images,
        address,
        is_subaddress,
        n_dests_per_tx,
        fee_per_weight,
        fee_quantization_mask,
        extra,
        tx_type,
        top_block_index);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_sweep_all(
    wallet2 &w,
    const rct::xmr_amount only_below,
    const cryptonote::account_public_address &address,
    const bool is_subaddress,
    const size_t n_dests_per_tx,
    const rct::xmr_amount fee_per_weight,
    const rct::xmr_amount fee_quantization_mask,
    const std::vector<uint8_t> &extra,
    const cryptonote::transaction_type tx_type,
    const std::string &asset_type,
    const std::uint32_t subaddr_account,
    const std::set<uint32_t> &subaddr_indices,
    const std::uint64_t top_block_index)
{
    wallet2::transfer_container transfers;
    w.get_transfers(transfers, asset_type);

    const std::unordered_map<crypto::key_image, size_t> unburned_transfers_by_key_image =
        collect_non_burned_transfers_by_key_image(transfers, w);

    std::vector<crypto::key_image> input_key_images;
    input_key_images.reserve(transfers.size());
    for (std::size_t transfer_idx = 0; transfer_idx < transfers.size(); ++transfer_idx)
    {
        const wallet2::transfer_details &td = transfers.at(transfer_idx);

        if (!is_transfer_usable_for_input_selection(td,
                                                    subaddr_account,
                                                    subaddr_indices,
                                                    only_below ? only_below : MONEY_SUPPLY,
                                                    1, // ignore_below
                                                    top_block_index,
                                                    asset_type,
                                                    &w))
          continue;

        const crypto::key_image effective_key_image =
            get_effective_transfer_key_image(td, w);
        const auto ki_it = unburned_transfers_by_key_image.find(effective_key_image);
        if (ki_it == unburned_transfers_by_key_image.cend())
            continue;
        else if (ki_it->second != transfer_idx)
            continue;

        input_key_images.push_back(effective_key_image);
    }

    CHECK_AND_ASSERT_THROW_MES(!input_key_images.empty(), __func__ << ": no usable transfers to sweep");

    return make_carrot_transaction_proposals_wallet2_sweep(
        w,
        input_key_images,
        address,
        is_subaddress,
        n_dests_per_tx,
        fee_per_weight,
        fee_quantization_mask,
        extra,
        tx_type,
        top_block_index);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_sweep_all(
    wallet2 &w,
    const rct::xmr_amount only_below,
    const cryptonote::account_public_address &address,
    const bool is_subaddress,
    const size_t n_dests_per_tx,
    const std::uint32_t priority,
    const std::vector<uint8_t> &extra,
    const cryptonote::transaction_type tx_type,
    const std::string &asset_type,
    const std::uint32_t subaddr_account,
    const std::set<uint32_t> &subaddr_indices)
{
    const rct::xmr_amount fee_per_weight = w.get_base_fee(priority);
    const rct::xmr_amount fee_quantization_mask = w.get_fee_quantization_mask();

    const std::uint64_t current_chain_height = w.get_blockchain_current_height();
    CHECK_AND_ASSERT_THROW_MES(current_chain_height > 0,
        "make_carrot_transaction_proposals_wallet2_sweep: chain height is 0, there is no top block");
    const std::uint64_t top_block_index = current_chain_height - 1;

    return make_carrot_transaction_proposals_wallet2_sweep_all(
        w,
        only_below,
        address,
        is_subaddress,
        n_dests_per_tx,
        fee_per_weight,
        fee_quantization_mask,
        extra,
        tx_type,
        asset_type,
        subaddr_account,
        subaddr_indices,
        top_block_index);
}
//-------------------------------------------------------------------------------------------------------------------
namespace
{
bool try_get_address_openings_x_y_impl(
    const cryptonote::transaction_prefix &tx,
    const cryptonote::tx_source_entry &src,
    const wallet2 &w,
    crypto::secret_key &x_out,
    crypto::secret_key &y_out,
    const cryptonote::transaction *tx_full,
    std::string *failure_reason)
{
    if (src.real_output >= src.outputs.size())
    {
        if (failure_reason)
            *failure_reason = "invalid_real_output";
        return false;
    }
    const crypto::public_key return_output_key =
        rct::rct2pk(src.outputs[src.real_output].second.dest);
    const auto &return_scan_hints = w.get_account().get_return_scan_hint_map_ref();
    const auto &return_output_map = w.get_account().get_return_output_map_ref();
    auto scan_hint_it = return_scan_hints.find(return_output_key);
    const auto &return_spend_metadata_map =
        w.get_account().get_return_spend_metadata_map_ref();
    auto spend_metadata_it = return_spend_metadata_map.find(return_output_key);
    const carrot::return_spend_metadata_t *validated_metadata = nullptr;
    const auto derive_input_context_from_tx =
        [](const cryptonote::transaction_prefix &tx_prefix,
           carrot::input_context_t &input_context_out) -> bool
    {
        if (tx_prefix.vin.empty())
            return false;

        if (tx_prefix.vin[0].type() == typeid(cryptonote::txin_to_key))
        {
            input_context_out = carrot::make_carrot_input_context(
                boost::get<cryptonote::txin_to_key>(tx_prefix.vin[0]).k_image);
            return true;
        }

        if (tx_prefix.vin[0].type() == typeid(cryptonote::txin_gen))
        {
            input_context_out = carrot::make_carrot_input_context_coinbase(
                boost::get<cryptonote::txin_gen>(tx_prefix.vin[0]).height);
            return true;
        }

        return false;
    };
    carrot::input_context_t return_input_context = carrot::gen_input_context();
    const bool have_return_input_context =
        derive_input_context_from_tx(tx, return_input_context);

    // Canonical path: returned outputs should spend using persisted return
    // spend metadata only when it can actually open this payout output.
    if (try_get_validated_return_spend_metadata(
            return_output_key, w, validated_metadata))
    {
        bool r = w.get_account().try_searching_for_opening_for_onetime_address(
            validated_metadata->K_spend_pubkey,
            validated_metadata->sum_g,
            validated_metadata->sender_extension_t,
            x_out,
            y_out);
        if (r)
        {
            if (failure_reason)
                *failure_reason = "return_payment";
            return true;
        }
        if (failure_reason)
            *failure_reason = "return_payment_failed";
        return false;
    }

    if (spend_metadata_it != return_spend_metadata_map.end())
    {
        const auto &return_spend_metadata = spend_metadata_it->second;
        if (carrot::is_return_spend_metadata_complete(return_spend_metadata))
        {
            const auto can_use_origin_fallback =
                [](auto tx_type) -> bool
            {
                return tx_type == cryptonote::transaction_type::TRANSFER ||
                       tx_type == cryptonote::transaction_type::CREATE_TOKEN;
            };
            const bool allow_origin_fallback =
                can_use_origin_fallback(src.origin_tx_data.tx_type) ||
                (scan_hint_it != return_scan_hints.end() &&
                 can_use_origin_fallback(scan_hint_it->second.origin_tx_type));
            if (!allow_origin_fallback)
            {
                if (failure_reason)
                    *failure_reason = "return_payment_metadata_invalid";
                return false;
            }
            if (failure_reason)
                *failure_reason = "return_payment_metadata_invalid_fallback";
        }
        else if (failure_reason)
            *failure_reason = "return_payment_metadata_incomplete";
    }

    // Transitional path: if spend metadata is missing, we may still have a
    // scan-only return record. Use it only for migration-era recovery.
    if (scan_hint_it != return_scan_hints.end())
    {
        const auto &scan_hint = scan_hint_it->second;

        // Migration-only recovery path: if canonical spend metadata is missing,
        // require an explicit origin stake/audit linkage and reconstruct the
        // spend opening from that origin output plus the return tx sender
        // extensions. Legacy ROI is no longer authoritative here.
        auto find_transfer_index =
            [&w](cryptonote::transaction_type tx_type,
                 const crypto::public_key &tx_pub_key,
                 uint64_t output_index) -> size_t
        {
            for (size_t idx = 0; idx < w.m_transfers.size(); ++idx)
            {
                const auto &candidate_td = w.m_transfers[idx];
                const cryptonote::transaction_prefix *candidate_tx =
                    get_effective_transfer_tx(candidate_td, w);
                if (candidate_tx->type != tx_type)
                    continue;
                if (candidate_td.m_internal_output_index != output_index)
                    continue;

                const crypto::public_key candidate_tx_pub_key =
                    cryptonote::get_tx_pub_key_from_extra(*candidate_tx,
                                                          candidate_td.m_pk_index);
                const crypto::public_key candidate_tx_pub_key_default =
                    cryptonote::get_tx_pub_key_from_extra(*candidate_tx);
                if (candidate_tx_pub_key == tx_pub_key ||
                    candidate_tx_pub_key_default == tx_pub_key)
                {
                    return idx;
                }
            }
            return std::numeric_limits<size_t>::max();
        };

        size_t change_idx = std::numeric_limits<size_t>::max();
        if (src.origin_tx_data.tx_type != cryptonote::transaction_type::UNSET)
        {
            change_idx = find_transfer_index(static_cast<cryptonote::transaction_type>(src.origin_tx_data.tx_type),
                                             src.origin_tx_data.tx_pub_key,
                                             src.origin_tx_data.output_index);
        }
        if (change_idx == std::numeric_limits<size_t>::max() &&
            scan_hint.origin_tx_type != cryptonote::transaction_type::UNSET)
        {
            change_idx = find_transfer_index(scan_hint.origin_tx_type,
                                             scan_hint.origin_tx_pub_key,
                                             scan_hint.origin_output_index);
        }

        if (change_idx < w.m_transfers.size())
        {
            const auto &change_td = w.m_transfers[change_idx];
            const cryptonote::transaction *change_tx_full = nullptr;
            const cryptonote::transaction_prefix *change_tx =
                get_effective_transfer_tx(change_td, w, &change_tx_full);
            crypto::public_key change_output_key = crypto::null_pkey;
            const bool change_output_valid =
                change_td.m_internal_output_index < change_tx->vout.size() &&
                cryptonote::get_output_public_key(
                    change_tx->vout[change_td.m_internal_output_index],
                    change_output_key) &&
                change_output_key != crypto::null_pkey;
            if (change_output_valid &&
                change_output_key !=
                    rct::rct2pk(src.outputs[src.real_output].second.dest))
            {
                cryptonote::tx_source_entry change_src;
                change_src.amount = change_td.amount();
                change_src.rct = change_td.is_rct();
                change_src.carrot =
                    change_tx->vout[change_td.m_internal_output_index].target.type() ==
                    typeid(cryptonote::txout_to_carrot_v1);
                change_src.coinbase = !change_tx->vin.empty() &&
                                      change_tx->vin[0].type() == typeid(cryptonote::txin_gen);
                change_src.block_index = change_td.m_block_height;
                change_src.asset_type = change_td.asset_type;
                change_src.mask = change_td.m_mask;
                change_src.address_spend_pubkey = change_td.m_recovered_spend_pubkey;
                cryptonote::tx_source_entry::output_entry change_oe;
                change_oe.first = change_td.m_asset_type_output_index;
                change_oe.second.dest = rct::pk2rct(change_output_key);
                change_oe.second.mask = rct::commit(change_td.amount(), change_td.m_mask);
                change_src.outputs.push_back(change_oe);
                change_src.real_output = 0;
                change_src.real_output_in_tx_index = change_td.m_internal_output_index;
                change_src.real_out_tx_key =
                    cryptonote::get_tx_pub_key_from_extra(*change_tx, change_td.m_pk_index);
                change_src.real_out_additional_tx_keys =
                    cryptonote::get_additional_tx_pub_keys_from_extra(*change_tx);
                if (!change_tx->vin.empty() &&
                    change_tx->vin[0].type() == typeid(cryptonote::txin_to_key))
                {
                    change_src.first_rct_key_image =
                        boost::get<cryptonote::txin_to_key>(change_tx->vin[0]).k_image;
                }

                crypto::secret_key change_x = crypto::null_skey;
                crypto::secret_key change_y = crypto::null_skey;
                std::string ignored_reason;
                const bool change_opened = change_tx_full
                    ? try_get_address_openings_x_y(
                          *change_tx_full, change_src, w, change_x, change_y,
                          &ignored_reason)
                    : try_get_address_openings_x_y(
                          *change_tx, change_src, w, change_x, change_y,
                          &ignored_reason);
                if (change_opened)
                {
                    bool recomputed_match = false;
                    std::string exact_scan_trace;
                    std::optional<enote_view_incoming_scan_info_t> current_return_scan_info;
                    bool current_scan_info_present = false;
                    bool current_scan_info_is_return = false;
                    bool attempted_exact_scan = false;
                    size_t exact_scan_candidate_count = 0;
                    const cryptonote::transaction *current_tx_full = tx_full;
                    bool current_tx_from_runtime = false;
                    bool current_tx_is_carrot_v1 = false;
                    bool current_tx_extra_loaded = false;
                    if (!current_tx_full)
                    {
                        const crypto::public_key current_output_key =
                            rct::rct2pk(src.outputs[src.real_output].second.dest);
                        const auto current_output_it =
                            w.m_pub_keys.find(current_output_key);
                        if (current_output_it != w.m_pub_keys.end() &&
                            current_output_it->second < w.m_transfers.size())
                        {
                            const auto &current_td =
                                w.m_transfers[current_output_it->second];
                            const auto runtime_tx_it =
                                w.m_runtime_full_txs.find(current_td.m_txid);
                            if (runtime_tx_it != w.m_runtime_full_txs.end())
                            {
                                current_tx_full = &runtime_tx_it->second;
                                current_tx_from_runtime = true;
                            }
                        }
                    }
                    if (current_tx_full)
                    {
                        current_tx_is_carrot_v1 =
                            carrot::is_carrot_transaction_v1(*current_tx_full);
                    }
                    if (current_tx_full && current_tx_is_carrot_v1)
                    {
                        std::vector<mx25519_pubkey> enote_ephemeral_pubkeys;
                        std::optional<carrot::encrypted_payment_id_t> encrypted_payment_id;
                        current_tx_extra_loaded = carrot::try_load_carrot_extra_v1(
                            current_tx_full->extra, enote_ephemeral_pubkeys,
                            encrypted_payment_id);
                        if (current_tx_extra_loaded &&
                            src.real_output_in_tx_index < current_tx_full->vout.size())
                        {
                            auto current_scan_infos =
                                view_incoming_scan_transaction(
                                    *current_tx_full,
                                    const_cast<carrot::carrot_and_legacy_account &>(
                                        w.get_account()));
                            if (src.real_output_in_tx_index < current_scan_infos.size())
                            {
                                const auto &scan_info =
                                    current_scan_infos[src.real_output_in_tx_index];
                                if (scan_info)
                                {
                                    current_scan_info_present = true;
                                    current_scan_info_is_return =
                                        scan_info->is_return;
                                    if (scan_info->is_return)
                                        current_return_scan_info = scan_info;
                                }
                            }
                        }
                    }
                    if (!current_return_scan_info && current_tx_full)
                    {
                        const crypto::public_key current_output_key =
                            rct::rct2pk(src.outputs[src.real_output].second.dest);
                        std::string protocol_scan_trace;
                        auto rebuilt_protocol_scan_info =
                            try_build_protocol_return_scan_info(
                                *current_tx_full,
                                src.real_output_in_tx_index,
                                current_output_key,
                                change_td,
                                scan_hint,
                                w,
                                &protocol_scan_trace);
                        if (rebuilt_protocol_scan_info)
                        {
                            current_scan_info_present = true;
                            current_scan_info_is_return =
                                rebuilt_protocol_scan_info->is_return;
                            if (rebuilt_protocol_scan_info->is_return)
                                current_return_scan_info =
                                    std::move(rebuilt_protocol_scan_info);
                        }
                        else if (!protocol_scan_trace.empty())
                        {
                            exact_scan_trace = "protocol=" + protocol_scan_trace;
                        }
                    }
                    const std::vector<crypto::public_key> v_pubkeys{src.real_out_tx_key};
                    const std::vector<crypto::public_key> v_pubkeys_empty{};
                    const epee::span<const crypto::public_key> main_tx_ephemeral_pubkeys =
                        (src.real_out_tx_key == crypto::null_pkey) ? epee::to_span(v_pubkeys_empty)
                                                                   : epee::to_span(v_pubkeys);
                    const epee::span<const crypto::public_key> additional_tx_ephemeral_pubkeys =
                        epee::to_span(src.real_out_additional_tx_keys);

                    auto try_recompute_with_origin_output_key =
                        [&](const carrot::input_context_t &origin_input_context,
                            const crypto::public_key &origin_output_key,
                            const char *success_reason) -> bool
                    {
                    if (current_return_scan_info)
                    {
                        std::vector<crypto::public_key> canonical_spend_candidates;
                        canonical_spend_candidates.push_back(
                            change_td.m_recovered_spend_pubkey);
                        canonical_spend_candidates.push_back(
                            change_output_key);
                        const auto roi_it_local =
                            return_output_map.find(return_output_key);
                        if (roi_it_local != return_output_map.end())
                        {
                            canonical_spend_candidates.push_back(
                                roi_it_local->second.K_spend_pubkey);
                        }

                        for (const auto &canonical_spend_candidate :
                             canonical_spend_candidates)
                        {
                            if (canonical_spend_candidate == crypto::null_pkey)
                                continue;
                            attempted_exact_scan = true;
                            ++exact_scan_candidate_count;
                            if (!exact_scan_trace.empty())
                                exact_scan_trace += ";";
                            exact_scan_trace += "ko=" +
                                epee::string_tools::pod_to_hex(origin_output_key).substr(0, 12) +
                                ",sp=" +
                                epee::string_tools::pod_to_hex(canonical_spend_candidate).substr(0, 12);

                            if (current_return_scan_info->address_spend_pubkey !=
                                canonical_spend_candidate)
                            {
                                exact_scan_trace += ",scan=0";
                                continue;
                            }
                            exact_scan_trace += ",scan=1";

                            sc_add(to_bytes(x_out), to_bytes(change_x),
                                   to_bytes(current_return_scan_info->sender_extension_g));
                            sc_add(to_bytes(y_out), to_bytes(change_y),
                                   to_bytes(current_return_scan_info->sender_extension_t));

                            rct::key recomputed_onetime_address;
                            rct::addKeys2(recomputed_onetime_address,
                                          rct::sk2rct(x_out),
                                          rct::sk2rct(y_out),
                                          rct::pk2rct(crypto::get_T()));
                            if (rct::rct2pk(recomputed_onetime_address) ==
                                rct::rct2pk(src.outputs[src.real_output].second.dest))
                            {
                                recomputed_match = true;
                                if (failure_reason)
                                    *failure_reason = success_reason;
                                return true;
                            }
                            exact_scan_trace += ",match=0";
                        }
                    }
                    for (size_t i = 0; i < 2; ++i) {
                        std::vector<crypto::key_derivation> main_derivations;
                        std::vector<crypto::key_derivation> additional_derivations;
                        if (i == 0) {
                            wallet::perform_ecdh_derivations(
                                main_tx_ephemeral_pubkeys,
                                additional_tx_ephemeral_pubkeys,
                                w.get_account().get_keys().k_view_incoming,
                                w.get_account().get_keys().get_device(),
                                src.carrot,
                                main_derivations,
                                additional_derivations);
                        } else {
                            crypto::key_derivation main_derivation;
                            memcpy(main_derivation.data,
                                   w.get_account().get_keys().s_view_balance.data,
                                   sizeof(crypto::secret_key));
                            main_derivations.push_back(main_derivation);
                        }

                        const epee::span<const crypto::public_key> enote_ephemeral_pubkeys_pk =
                            main_tx_ephemeral_pubkeys.empty()
                                ? additional_tx_ephemeral_pubkeys
                                : main_tx_ephemeral_pubkeys;
                        const epee::span<const mx25519_pubkey> enote_ephemeral_pubkeys = {
                            reinterpret_cast<const mx25519_pubkey*>(enote_ephemeral_pubkeys_pk.data()),
                            enote_ephemeral_pubkeys_pk.size()
                        };
                        const bool shared_ephemeral_pubkey =
                            enote_ephemeral_pubkeys.size() == 1;
                        const size_t ephemeral_pubkey_index =
                            shared_ephemeral_pubkey ? 0 : src.real_output_in_tx_index;
                        const mx25519_pubkey &return_ephemeral_pubkey =
                            enote_ephemeral_pubkeys[ephemeral_pubkey_index];

                        crypto::secret_key k_return;
                        w.get_account().s_view_balance_dev.make_internal_return_privkey(
                            origin_input_context, origin_output_key, k_return);
                        mx25519_pubkey shared_secret_return_unctx;
                        crypto::hash shared_secret_return;
                        if (!carrot::make_carrot_uncontextualized_shared_key_receiver(
                                k_return, return_ephemeral_pubkey,
                                shared_secret_return_unctx))
                        {
                            if (failure_reason)
                                *failure_reason =
                                    "return_payment_from_origin_shared_secret_failed";
                            continue;
                        }

                        carrot::make_carrot_sender_receiver_secret(
                            shared_secret_return_unctx.data,
                            return_ephemeral_pubkey,
                            have_return_input_context
                                ? return_input_context
                                : origin_input_context,
                            shared_secret_return);

                        crypto::secret_key sender_extension_g_out = crypto::null_skey;
                        crypto::secret_key sender_extension_t_out = crypto::null_skey;
                        carrot::make_carrot_onetime_address_extension_g(
                            shared_secret_return,
                            src.outputs[src.real_output].second.mask,
                            sender_extension_g_out);
                        carrot::make_carrot_onetime_address_extension_t(
                            shared_secret_return,
                            src.outputs[src.real_output].second.mask,
                            sender_extension_t_out);

                        sc_add(to_bytes(x_out), to_bytes(change_x),
                               to_bytes(sender_extension_g_out));
                        sc_add(to_bytes(y_out), to_bytes(change_y),
                               to_bytes(sender_extension_t_out));

                        rct::key recomputed_onetime_address;
                        rct::addKeys2(recomputed_onetime_address,
                                      rct::sk2rct(x_out),
                                      rct::sk2rct(y_out),
                                      rct::pk2rct(crypto::get_T()));
                        if (rct::rct2pk(recomputed_onetime_address) ==
                            rct::rct2pk(src.outputs[src.real_output].second.dest))
                        {
                            recomputed_match = true;
                            if (failure_reason)
                                *failure_reason = success_reason;
                            return true;
                        }
                    }
                    return false;
                    };

                    if (try_recompute_with_origin_output_key(
                            scan_hint.input_context,
                            scan_hint.K_o,
                            "return_payment_from_origin"))
                    {
                        return true;
                    }

                    const auto roi_it = return_output_map.find(return_output_key);
                    if (roi_it != return_output_map.end() &&
                        roi_it->second.K_change != crypto::null_pkey &&
                        roi_it->second.K_change == change_output_key)
                    {
                        carrot::input_context_t repaired_origin_input_context =
                            carrot::gen_input_context();
                        const bool have_repaired_origin_input_context =
                            derive_input_context_from_tx(
                                *change_tx, repaired_origin_input_context);
                        for (size_t origin_output_index = 0;
                             origin_output_index < change_tx->vout.size();
                             ++origin_output_index)
                        {
                            crypto::public_key origin_output_key = crypto::null_pkey;
                            if (!cryptonote::get_output_public_key(
                                    change_tx->vout[origin_output_index],
                                    origin_output_key) ||
                                origin_output_key == crypto::null_pkey ||
                                origin_output_key == change_output_key)
                            {
                                continue;
                            }

                            if (try_recompute_with_origin_output_key(
                                    have_repaired_origin_input_context
                                        ? repaired_origin_input_context
                                        : scan_hint.input_context,
                                    origin_output_key,
                                    "return_payment_from_origin_repaired"))
                            {
                                return true;
                            }
                        }
                    }

                    if (!recomputed_match && failure_reason)
                    {
                        *failure_reason =
                            "return_payment_from_origin_recompute_mismatch";
                        if (!exact_scan_trace.empty())
                            *failure_reason += ":" + exact_scan_trace;
                        else
                        {
                            *failure_reason +=
                                std::string(":current_enote=") +
                                (current_return_scan_info ? "1" : "0") +
                                ",current_tx_full=" +
                                (current_tx_full ? "1" : "0") +
                                ",current_tx_runtime=" +
                                (current_tx_from_runtime ? "1" : "0") +
                                ",current_tx_carrot=" +
                                (current_tx_is_carrot_v1 ? "1" : "0") +
                                ",current_tx_extra=" +
                                (current_tx_extra_loaded ? "1" : "0") +
                                ",current_scan=" +
                                (current_scan_info_present ? "1" : "0") +
                                ",current_scan_return=" +
                                (current_scan_info_is_return ? "1" : "0") +
                                ",current_vout=" +
                                std::to_string(current_tx_full ? current_tx_full->vout.size() : 0) +
                                ",real_idx=" +
                                std::to_string(src.real_output_in_tx_index) +
                                ",exact_candidates=" +
                                std::to_string(exact_scan_candidate_count) +
                                ",exact_attempted=" +
                                (attempted_exact_scan ? "1" : "0");
                        }
                    }
                }
                else if (failure_reason)
                {
                    *failure_reason = "return_payment_origin_opening_failed:" +
                                      ignored_reason;
                }
            }
            else if (failure_reason)
            {
                *failure_reason = "return_payment_origin_same_key";
            }
        }
        else if (failure_reason)
        {
            *failure_reason = "return_payment_origin_missing";
        }
        if (failure_reason && failure_reason->empty())
            *failure_reason = "return_payment_scan_hint_only";
    }

    const std::vector<crypto::public_key> v_pubkeys{src.real_out_tx_key};
    const std::vector<crypto::public_key> v_pubkeys_empty{};
    const epee::span<const crypto::public_key> main_tx_ephemeral_pubkeys = (src.real_out_tx_key == crypto::null_pkey) ? epee::to_span(v_pubkeys_empty) :  epee::to_span(v_pubkeys);
    const epee::span<const crypto::public_key> additional_tx_ephemeral_pubkeys = epee::to_span(src.real_out_additional_tx_keys);

    // we have to try both internal and external derivations
    bool r = false;
    for (size_t i = 0; i < 2; ++i) {
        // perform ECDH derivations
        std::vector<crypto::key_derivation> main_derivations;
        std::vector<crypto::key_derivation> additional_derivations;
        if (i == 0) {
            wallet::perform_ecdh_derivations(
                main_tx_ephemeral_pubkeys,
                additional_tx_ephemeral_pubkeys,
                w.get_account().get_keys().k_view_incoming,
                w.get_account().get_keys().get_device(),
                src.carrot,
                main_derivations,
                additional_derivations
            );
        } else {
            crypto::key_derivation main_derivation;
            memcpy(main_derivation.data, w.get_account().get_keys().s_view_balance.data, sizeof(crypto::secret_key));
            main_derivations.push_back(main_derivation);
        }

        crypto::hash s_sender_receiver;
        if (main_derivations.empty() &&
            src.real_output_in_tx_index >= additional_derivations.size())
        {
            if (failure_reason)
                *failure_reason = "missing_additional_derivation";
            return false;
        }
        const crypto::key_derivation &kd = main_derivations.size()
            ? main_derivations[0]
            : additional_derivations[src.real_output_in_tx_index];
        const mx25519_pubkey s_sender_receiver_unctx = carrot::raw_byte_convert<mx25519_pubkey>(kd);

        // ephemeral pubkeys
        const epee::span<const crypto::public_key> enote_ephemeral_pubkeys_pk =
            main_tx_ephemeral_pubkeys.empty() ? additional_tx_ephemeral_pubkeys : main_tx_ephemeral_pubkeys;
        const epee::span<const mx25519_pubkey> enote_ephemeral_pubkeys = {
            reinterpret_cast<const mx25519_pubkey*>(enote_ephemeral_pubkeys_pk.data()),
            enote_ephemeral_pubkeys_pk.size()
        };

        const bool shared_ephemeral_pubkey = enote_ephemeral_pubkeys.size() == 1;
        const size_t ephemeral_pubkey_index = shared_ephemeral_pubkey ? 0 : src.real_output_in_tx_index;
        if (ephemeral_pubkey_index >= enote_ephemeral_pubkeys.size())
        {
            if (failure_reason)
                *failure_reason = "missing_ephemeral_pubkey";
            return false;
        }

        // input_context
        carrot::input_context_t input_context;
        if (src.coinbase) {
            input_context = carrot::make_carrot_input_context_coinbase(src.block_index);
        } else {
            input_context = carrot::make_carrot_input_context(src.first_rct_key_image);
        }

        // s^ctx_sr = H_32(s_sr, D_e, input_context)
        make_carrot_sender_receiver_secret(s_sender_receiver_unctx.data,
            enote_ephemeral_pubkeys[ephemeral_pubkey_index],
            input_context,
            s_sender_receiver);

        // get the k_og and k_ot
        crypto::secret_key sender_extension_g_out;
        crypto::secret_key sender_extension_t_out;
        crypto::public_key address_spend_pubkey_out;
        carrot::payment_id_t nominal_payment_id_out;
        carrot::janus_anchor_t nominal_janus_anchor_out;
        carrot::encrypted_janus_anchor_t encrypted_janus_anchor;
        carrot::encrypted_payment_id_t encrypted_payment_id;
        carrot::scan_carrot_dest_info(
            rct::rct2pk(src.outputs[src.real_output].second.dest),
            src.outputs[src.real_output].second.mask,
            encrypted_janus_anchor,
            encrypted_payment_id,
            s_sender_receiver,
            sender_extension_g_out,
            sender_extension_t_out,
            address_spend_pubkey_out,
            nominal_payment_id_out,
            nominal_janus_anchor_out
        );
        r = w.get_account().try_searching_for_opening_for_onetime_address(
            address_spend_pubkey_out,
            sender_extension_g_out,
            sender_extension_t_out,
            x_out,
            y_out
        );

        // If we found the opening, we can stop here
        if (r) {
            if (failure_reason)
                *failure_reason = (i == 0) ? "generic_internal" : "generic_external";
            break;
        }
    }

    // === Deterministic, order-independent returned-transfer reconstruction ===
    // The scan-time return metadata (return_output_info / scan hints / m_td_origin_idx) can be
    // missing or wrong: the WASM scans out of order across parallel workers, so a return's origin
    // change output may not be in m_transfers when the metadata is built, and the per-batch repair
    // (repair_return_output_metadata_from_transfers) only covers STAKE/AUDIT/CREATE_TOKEN origins,
    // not TRANSFER. The in-order CLI never hits this. Resolve it deterministically from the COMPLETE
    // owned-output set, which is available by spend/validation time:
    //   a returned output's onetime address is  K_r = make_internal_return_privkey(ic, K_src)*G + K_change
    // (carrot_core/scan.cpp try_scan_carrot_enote_internal_receiver), where K_change is an owned change
    // output and K_src ranges over its tx's output keys. Find the owned change output + K_src that
    // reproduce this exact return output; then the spend openings are  x = change_x + k_return,
    // y = change_y. Verification-gated (== on-chain dest), so it can never yield incorrect spend data.
    if (!r)
    {
        const crypto::public_key ret_key =
            rct::rct2pk(src.outputs[src.real_output].second.dest);
        const auto deterministic_input_context_from_tx =
            [](const cryptonote::transaction_prefix &tx_prefix,
               carrot::input_context_t &ic_out) -> bool
        {
            if (tx_prefix.vin.empty())
                return false;
            if (tx_prefix.vin[0].type() == typeid(cryptonote::txin_to_key))
            {
                ic_out = carrot::make_carrot_input_context(
                    boost::get<cryptonote::txin_to_key>(tx_prefix.vin[0]).k_image);
                return true;
            }
            if (tx_prefix.vin[0].type() == typeid(cryptonote::txin_gen))
            {
                ic_out = carrot::make_carrot_input_context_coinbase(
                    boost::get<cryptonote::txin_gen>(tx_prefix.vin[0]).height);
                return true;
            }
            return false;
        };
        for (size_t cidx = 0; cidx < w.m_transfers.size() && !r; ++cidx)
        {
            const auto &cand = w.m_transfers[cidx];
            const cryptonote::transaction *cand_tx_full = nullptr;
            const cryptonote::transaction_prefix *cand_tx =
                get_effective_transfer_tx(cand, w, &cand_tx_full);
            crypto::public_key K_change = crypto::null_pkey;
            if (cand.m_internal_output_index >= cand_tx->vout.size() ||
                !cryptonote::get_output_public_key(
                    cand_tx->vout[cand.m_internal_output_index], K_change) ||
                K_change == crypto::null_pkey || K_change == ret_key)
                continue;
            carrot::input_context_t cand_ic = carrot::gen_input_context();
            if (!deterministic_input_context_from_tx(*cand_tx, cand_ic))
                continue;
            crypto::secret_key matched_k_return = crypto::null_skey;
            bool found_origin = false;
            for (size_t oi = 0; oi < cand_tx->vout.size() && !found_origin; ++oi)
            {
                crypto::public_key src_ko = crypto::null_pkey;
                if (!cryptonote::get_output_public_key(cand_tx->vout[oi], src_ko) ||
                    src_ko == crypto::null_pkey)
                    continue;
                crypto::secret_key k_return;
                w.get_account().s_view_balance_dev.make_internal_return_privkey(
                    cand_ic, src_ko, k_return);
                crypto::public_key K_return;
                crypto::secret_key_to_public_key(k_return, K_return);
                const crypto::public_key K_r = rct::rct2pk(
                    rct::addKeys(rct::pk2rct(K_return), rct::pk2rct(K_change)));
                if (K_r == ret_key)
                {
                    matched_k_return = k_return;
                    found_origin = true;
                }
            }
            if (!found_origin)
                continue;
            // Recover the change output's openings (change_x, change_y): K_change = change_x*G + change_y*T.
            cryptonote::tx_source_entry cand_src;
            cand_src.amount = cand.amount();
            cand_src.rct = cand.is_rct();
            cand_src.carrot =
                cand_tx->vout[cand.m_internal_output_index].target.type() ==
                typeid(cryptonote::txout_to_carrot_v1);
            cand_src.coinbase = !cand_tx->vin.empty() &&
                                cand_tx->vin[0].type() == typeid(cryptonote::txin_gen);
            cand_src.block_index = cand.m_block_height;
            cand_src.asset_type = cand.asset_type;
            cand_src.mask = cand.m_mask;
            cand_src.address_spend_pubkey = cand.m_recovered_spend_pubkey;
            cryptonote::tx_source_entry::output_entry cand_oe;
            cand_oe.first = cand.m_asset_type_output_index;
            cand_oe.second.dest = rct::pk2rct(K_change);
            cand_oe.second.mask = rct::commit(cand.amount(), cand.m_mask);
            cand_src.outputs.push_back(cand_oe);
            cand_src.real_output = 0;
            cand_src.real_output_in_tx_index = cand.m_internal_output_index;
            cand_src.real_out_tx_key =
                cryptonote::get_tx_pub_key_from_extra(*cand_tx, cand.m_pk_index);
            cand_src.real_out_additional_tx_keys =
                cryptonote::get_additional_tx_pub_keys_from_extra(*cand_tx);
            if (!cand_tx->vin.empty() &&
                cand_tx->vin[0].type() == typeid(cryptonote::txin_to_key))
                cand_src.first_rct_key_image =
                    boost::get<cryptonote::txin_to_key>(cand_tx->vin[0]).k_image;
            crypto::secret_key change_x = crypto::null_skey;
            crypto::secret_key change_y = crypto::null_skey;
            std::string det_ignored;
            const bool cand_opened = cand_tx_full
                ? try_get_address_openings_x_y(
                      *cand_tx_full, cand_src, w, change_x, change_y,
                      &det_ignored)
                : try_get_address_openings_x_y(
                      *cand_tx, cand_src, w, change_x, change_y, &det_ignored);
            if (!cand_opened)
                continue;
            // K_r = k_return*G + K_change = (k_return + change_x)*G + change_y*T
            crypto::secret_key det_x = crypto::null_skey;
            sc_add(to_bytes(det_x), to_bytes(change_x), to_bytes(matched_k_return));
            rct::key det_recomputed;
            rct::addKeys2(det_recomputed, rct::sk2rct(det_x), rct::sk2rct(change_y),
                          rct::pk2rct(crypto::get_T()));
            if (rct::rct2pk(det_recomputed) == ret_key)
            {
                x_out = det_x;
                y_out = change_y;
                r = true;
                if (failure_reason)
                    *failure_reason = "return_payment_deterministic";
            }
        }
    }

    if (!r && failure_reason && failure_reason->empty())
        *failure_reason = "generic_failed";
    return r;
}
} // namespace
//-------------------------------------------------------------------------------------------------------------------
bool try_get_address_openings_x_y(
    const cryptonote::transaction_prefix &tx,
    const cryptonote::tx_source_entry &src,
    const wallet2 &w,
    crypto::secret_key &x_out,
    crypto::secret_key &y_out,
    std::string *failure_reason)
{
    return try_get_address_openings_x_y_impl(
        tx, src, w, x_out, y_out, nullptr, failure_reason);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_address_openings_x_y(
    const cryptonote::transaction &tx,
    const cryptonote::tx_source_entry &src,
    const wallet2 &w,
    crypto::secret_key &x_out,
    crypto::secret_key &y_out,
    std::string *failure_reason)
{
    return try_get_address_openings_x_y_impl(
        tx, src, w, x_out, y_out, &tx, failure_reason);
}
//-------------------------------------------------------------------------------------------------------------------
bool get_address_openings_x_y(
    const cryptonote::transaction &tx,
    const cryptonote::tx_source_entry &src,
    const wallet2 &w,
    crypto::secret_key &x_out,
    crypto::secret_key &y_out)
{
    std::string failure_reason;
    const bool ok = try_get_address_openings_x_y(tx, src, w, x_out, y_out, &failure_reason);
    if (ok)
        return true;

    if (failure_reason == "return_payment_failed")
        CHECK_AND_ASSERT_THROW_MES(false, "Failed to obtain openings for onetime address (return_payment)");

    CHECK_AND_ASSERT_THROW_MES(false, "Failed to obtain openings for onetime address");
    return false;
}
//-------------------------------------------------------------------------------------------------------------------
void encrypt_change_index(
    const std::vector<carrot::CarrotPaymentProposalV1> &proposals,
    const std::vector<carrot::CarrotPaymentProposalSelfSendV1> &selfsend_proposal_cores,
    const crypto::key_image &tx_first_key_image,
    const size_t change_index,
    const std::unordered_map<crypto::public_key, size_t> &payments_indices,
    std::vector<uint8_t> &change_masks_out
) {
    // 1. input context: input_context = "R" || KI_1
    const carrot::input_context_t input_context = carrot::make_carrot_input_context(tx_first_key_image);

    // 2. collect proposals and selfsend proposals destinations
    std::vector<std::tuple<crypto::public_key, size_t, bool>> destinations;
    for (const auto &p : proposals) {
        destinations.emplace_back(p.destination.address_spend_pubkey, payments_indices.at(p.destination.address_spend_pubkey), true);
    }
    for (const auto &p : selfsend_proposal_cores) {
        destinations.emplace_back(p.destination_address_spend_pubkey, payments_indices.at(p.destination_address_spend_pubkey), false);
    }

    // 3. sort by indices
    std::sort(destinations.begin(), destinations.end(),
        [](const auto &a, const auto &b) {
            return std::get<1>(a) < std::get<1>(b);
        }
    );

    // 4. calculate change masks
    for (const auto &d: destinations) {
        // get shared secret
        mx25519_pubkey eph_pubkey;
        mx25519_pubkey s_sender_receiver_unctx;
        if (std::get<2>(d)) {
            // normal payment proposal
            const auto it = std::find_if(proposals.begin(), proposals.end(),
                [&d](const carrot::CarrotPaymentProposalV1 &p) {
                    return p.destination.address_spend_pubkey == std::get<0>(d);
                });
            CHECK_AND_ASSERT_THROW_MES(it != proposals.end(), "Failed to find normal payment proposal");
            carrot::get_normal_proposal_ecdh_parts(
                *it,
                input_context,
                eph_pubkey,
                s_sender_receiver_unctx
            );
        } else {
            s_sender_receiver_unctx = crypto::rand<mx25519_pubkey>();
        }

        // derive a scalar from the shared secret
        crypto::secret_key output_index_key;
        crypto::key_derivation output_index_derivation;
        memcpy(output_index_derivation.data, s_sender_receiver_unctx.data, sizeof(output_index_derivation.data));
        crypto::derivation_to_scalar(
            output_index_derivation,
            std::get<1>(d),
            output_index_key
        );

        // Calculate the encrypted_change_index data for this output
        struct {
            char domain_separator[8];
            crypto::secret_key output_index_key;
        } eci_buf;
        std::memset(eci_buf.domain_separator, 0x0, sizeof(eci_buf.domain_separator));
        std::strncpy(eci_buf.domain_separator, "CHG_IDX", 8);
        eci_buf.output_index_key = output_index_key;
        crypto::secret_key eci_out;
        keccak((uint8_t *)&eci_buf, sizeof(eci_buf), (uint8_t*)&eci_out, sizeof(eci_out));
        uint8_t eci_data = change_index ^ eci_out.data[0];
        change_masks_out.push_back(eci_data);
    }
}
//-------------------------------------------------------------------------------------------------------------------
cryptonote::transaction finalize_all_proofs_from_transfer_details(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const wallet2 &w)
{
    const size_t n_inputs = tx_proposal.key_images_sorted.size();
    const size_t n_outputs = tx_proposal.normal_payment_proposals.size()
        + tx_proposal.selfsend_payment_proposals.size();
    CHECK_AND_ASSERT_THROW_MES(n_inputs, "finalize_all_proofs_from_transfer_details: no inputs");

    LOG_PRINT_L2("finalize_all_proofs_from_transfer_details: make all proofs for transaction proposal: "
        << n_inputs << "-in " << n_outputs << "-out, with "
        << tx_proposal.normal_payment_proposals.size() << " normal payment proposals, "
        << tx_proposal.selfsend_payment_proposals.size() << " self-send payment proposals, and a fee of "
        << cryptonote::print_money(tx_proposal.fee) << " SAL1");

    // Perf: const-reference the wallet-global container instead of deep
    // copying every transfer; get_transfers("") is a straight full copy so
    // all indices/iterator distances below are identical.
    const wallet2::transfer_container &transfers = w.get_transfers_ref();
    cryptonote::account_keys acc_keys = w.get_account().get_keys();

    // collect core selfsend proposals
    std::vector<carrot::CarrotPaymentProposalSelfSendV1> selfsend_payment_proposal_cores;
    selfsend_payment_proposal_cores.reserve(tx_proposal.selfsend_payment_proposals.size());
    for (const auto &selfsend_payment_proposal : tx_proposal.selfsend_payment_proposals)
        selfsend_payment_proposal_cores.push_back(selfsend_payment_proposal.proposal);

    //! @TODO: HW device
    carrot::cryptonote_hierarchy_address_device_ram_borrowed addr_dev(
        acc_keys.m_carrot_account_address.m_spend_public_key,
        acc_keys.k_view_incoming);

    // finalize enotes
    LOG_PRINT_L3("Getting output enote proposals");
    std::vector<carrot::RCTOutputEnoteProposal> output_enote_proposals;
    carrot::encrypted_payment_id_t encrypted_payment_id;
    size_t change_index = static_cast<size_t>(-1); // sentinel if no change output;
    carrot::RCTOutputEnoteProposal return_enote_out;
    std::unordered_map<crypto::public_key, size_t> payments_indices;
    carrot::get_output_enote_proposals(tx_proposal.normal_payment_proposals,
        selfsend_payment_proposal_cores,
        tx_proposal.dummy_encrypted_payment_id,
        &w.get_account().s_view_balance_dev,
        &addr_dev,
        tx_proposal.key_images_sorted.at(0),
        output_enote_proposals,
        return_enote_out,
        encrypted_payment_id,
        tx_proposal.tx_type,
        change_index,
        payments_indices,
        nullptr);
    CHECK_AND_ASSERT_THROW_MES(output_enote_proposals.size() == n_outputs,
        "finalize_all_proofs_from_transfer_details: unexpected number of output enote proposals");

    // collect all non-burned inputs owned by wallet
    const std::unordered_map<crypto::key_image, size_t> unburned_transfers_by_key_image =
        collect_non_burned_transfers_by_key_image(transfers, w);
    LOG_PRINT_L3("Did a burning bug pass, eliminated "
        << (transfers.size() - unburned_transfers_by_key_image.size())
        << " eligible transfers");

    // collect output amount blinding factors
    std::vector<rct::key> output_amount_blinding_factors;
    output_amount_blinding_factors.reserve(output_enote_proposals.size());
    for (const carrot::RCTOutputEnoteProposal &output_enote_proposal : output_enote_proposals)
        output_amount_blinding_factors.push_back(rct::sk2rct(output_enote_proposal.amount_blinding_factor));


    // collect enotes
    std::vector<carrot::CarrotEnoteV1> enotes(output_enote_proposals.size());
    for (size_t i = 0; i < enotes.size(); ++i)
        enotes[i] = output_enote_proposals.at(i).enote;

    // encrypt change index per output
    std::vector<uint8_t> change_masks;
    encrypt_change_index(
        tx_proposal.normal_payment_proposals,
        selfsend_payment_proposal_cores,
        tx_proposal.key_images_sorted.at(0),
        change_index,
        payments_indices,
        change_masks);

    // serialize transaction
    cryptonote::transaction tx = carrot::store_carrot_to_transaction_v1(enotes,
                                                                        tx_proposal.key_images_sorted,
                                                                        tx_proposal.sources,
                                                                        tx_proposal.fee,
                                                                        tx_proposal.tx_type,
                                                                        tx_proposal.amount_burnt,
                                                                        change_masks,
                                                                        tx_proposal.token,
                                                                        return_enote_out,
                                                                        encrypted_payment_id,
                                                                        const_cast<wallet2&>(w).get_current_hard_fork());

    // store the binding tag
    tx.rollup_binding_tag = tx_proposal.rollup_binding_tag;

    // Is this a ROLLUP TX? If so, store the rollup data
    if (tx_proposal.tx_type == cryptonote::transaction_type::ROLLUP)
      tx.layer2_rollup_data = tx_proposal.layer2_rollup_data;

    // aliases
    hw::device &hwdev = acc_keys.get_device();
    const auto &sources = tx_proposal.sources;

    // inputs
    // uint64_t amount_in = 0;
    rct::carrot_ctkeyV inSk;
    inSk.reserve(sources.size());
    std::vector<uint64_t> inamounts;
    std::vector<unsigned int> index;
    for (const auto& src: sources)
    {
        // amount_in += src.amount;
        inamounts.push_back(src.amount);
        index.push_back(src.real_output);

        // inSk: (x, y, mask)
        rct::carrot_ctkey ctkey;
        ctkey.mask = src.mask;
        if (src.carrot) {

            crypto::secret_key x, y;
            THROW_WALLET_EXCEPTION_IF(!get_address_openings_x_y(tx, src, w, x, y),
                error::wallet_internal_error, "Failed to get x and y for input");

            ctkey.x = rct::sk2rct(x);
            ctkey.y = rct::sk2rct(y);
        } else {
            // generate the secret key
            cryptonote::keypair in_ephemeral;
            crypto::key_image img;
            rct::salvium_input_data_t sid;
            const auto& out_key = reinterpret_cast<const crypto::public_key&>(src.outputs[src.real_output].second.dest);
            bool use_origin_data = (src.origin_tx_data.tx_type != cryptonote::transaction_type::UNSET);
            sid.origin_tx_type = src.origin_tx_data.tx_type;
            bool r = cryptonote::generate_key_image_helper(
                w.get_account().get_keys(),
                w.get_account().get_subaddress_map_cn(),
                out_key,
                src.real_out_tx_key,
                src.real_out_additional_tx_keys,
                src.real_output_in_tx_index,
                in_ephemeral,
                img,
                hwdev,
                use_origin_data,
                src.origin_tx_data, sid
            );
            THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image helper");

            ctkey.x = rct::sk2rct(in_ephemeral.sec);
            ctkey.y = rct::zero(); // not used in non-carrot txes
        }

        inSk.push_back(ctkey);
        memwipe(&ctkey, sizeof(rct::carrot_ctkey));
        // inPk: (public key, commitment)
        // will be done when filling in mixRing
    }

    // outputs
    // uint64_t amount_out = 0;
    std::vector<uint64_t> outamounts;
    rct::keyV destinations;
    std::vector<std::string> destination_asset_types;
    rct::ctkeyV outSk;
    for (const auto &oep : output_enote_proposals)
    {
        destinations.push_back(rct::pk2rct(oep.enote.onetime_address));
        destination_asset_types.push_back(oep.enote.asset_type);
        outamounts.push_back(oep.amount);
        // amount_out += oep.amount;

        rct::ctkey key;
        key.mask = rct::sk2rct(oep.amount_blinding_factor);
        outSk.push_back(key);
    }

    // change output x, y
    crypto::public_key change_address_spend_pubkey;
    for (const auto &p :selfsend_payment_proposal_cores) {
        if (p.enote_type == carrot::CarrotEnoteType::CHANGE) {
            change_address_spend_pubkey = p.destination_address_spend_pubkey;
        }
    }
    // need exactly one change output here; bail instead of indexing with the sentinel
    THROW_WALLET_EXCEPTION_IF(change_index >= output_enote_proposals.size()
            || change_address_spend_pubkey == crypto::public_key{},
        error::wallet_internal_error, "carrot tx build: no change output in proposal");

    const carrot::RCTOutputEnoteProposal &change_enote_proposal = output_enote_proposals.at(change_index);
    const carrot::input_context_t input_context = carrot::make_carrot_input_context(tx_proposal.key_images_sorted.at(0));
    crypto::hash s_sender_receiver;
    w.get_account().s_view_balance_dev.make_internal_sender_receiver_secret(
        change_enote_proposal.enote.enote_ephemeral_pubkey,
        input_context,
        s_sender_receiver);
    crypto::secret_key sender_extension_g;
    carrot::make_carrot_onetime_address_extension_g(s_sender_receiver, change_enote_proposal.enote.amount_commitment, sender_extension_g);
    crypto::secret_key sender_extension_t;
    carrot::make_carrot_onetime_address_extension_t(s_sender_receiver, change_enote_proposal.enote.amount_commitment, sender_extension_t);
    crypto::secret_key change_x, change_y;
    bool r = w.get_account().try_searching_for_opening_for_onetime_address(
        change_address_spend_pubkey,
        sender_extension_g,
        sender_extension_t,
        change_x,
        change_y
    );
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error,
        "Failed to obtain opening for onetime change address");

    // mixRing indexing is done the other way round for simple
    rct::ctkeyM mixRing(sources.size());
    for (size_t i = 0; i < sources.size(); ++i)
    {
        mixRing[i].resize(sources[i].outputs.size());
        for (size_t n = 0; n < sources[i].outputs.size(); ++n)
        {
            mixRing[i][n] = sources[i].outputs[n].second;
        }
    }

    // bpp
    tx.rct_signatures.p.bulletproofs_plus.push_back(
        rct::bulletproof_plus_PROVE(outamounts, output_amount_blinding_factors)
    );

    // store proofs
    crypto::hash tx_prefix_hash;
    get_transaction_prefix_hash(tx, tx_prefix_hash, hwdev);
    rct::salvium_data_t salvium_data;
    salvium_data.salvium_data_type = rct::SalviumOne;
    rct::genRctSimpleCarrot(
        rct::hash2rct(tx_prefix_hash),
        inSk,
        destinations,
        tx_proposal.tx_type,
        "SAL1",
        destination_asset_types,
        inamounts,
        outamounts,
        tx_proposal.fee,
        mixRing,
        index,
        outSk,
        rct::RCTConfig {
            rct::RangeProofType::RangeProofPaddedBulletproof,
            6,
        },
        hwdev,
        salvium_data,
        rct::sk2rct(change_x),
        rct::sk2rct(change_y),
        change_index,
        tx.rct_signatures
    );

    tx.pruned = false;
    return tx;
}
//-------------------------------------------------------------------------------------------------------------------
wallet2::pending_tx make_pending_carrot_tx(const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const wallet2::transfer_container &transfers,
    const wallet2 &w)
{
    const carrot::carrot_and_legacy_account &account = w.get_account();
    const std::size_t n_inputs = tx_proposal.key_images_sorted.size();
    const std::size_t n_outputs = tx_proposal.normal_payment_proposals.size() +
        tx_proposal.selfsend_payment_proposals.size();
    const bool shared_ephemeral_pubkey = n_outputs == 2;

    CARROT_CHECK_AND_THROW(
        tx_proposal.tx_type != cryptonote::transaction_type::UNSET,
        carrot::missing_components,
        "make_pending_carrot_tx: tx proposal has unset tx type"
    );
    CARROT_CHECK_AND_THROW(n_inputs >= 1, carrot::too_few_inputs, "carrot tx proposal missing inputs");
    if (tx_proposal.tx_type  == cryptonote::transaction_type::STAKE ||
        tx_proposal.tx_type == cryptonote::transaction_type::BURN ||
        tx_proposal.tx_type == cryptonote::transaction_type::CREATE_TOKEN ||
        tx_proposal.tx_type == cryptonote::transaction_type::ROLLUP) {
        CARROT_CHECK_AND_THROW(n_outputs == 1, carrot::too_few_outputs, "carrot tx proposal doesn't have correct number of outputs");
    } else {
        CARROT_CHECK_AND_THROW(n_outputs >= 2, carrot::too_few_outputs, "carrot tx proposal missing outputs");
    }

    const crypto::key_image &tx_first_key_image = tx_proposal.key_images_sorted.at(0);

    // Reconstruct selected transfers from the already-built sources. This
    // keeps pending-tx reconstruction aligned with canonical restored return
    // metadata even when a transfer's legacy stored key image differs.
    std::vector<std::size_t> selected_transfers;
    selected_transfers.reserve(n_inputs);
    std::stringstream key_images_string;
    for (size_t i = 0; i < n_inputs; ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(i < tx_proposal.sources.size(),
            "make_pending_carrot_tx: sources/key_images size mismatch");
        const auto &src = tx_proposal.sources.at(i);
        CHECK_AND_ASSERT_THROW_MES(src.real_output < src.outputs.size(),
            "make_pending_carrot_tx: invalid real_output in source");
        const crypto::public_key source_output_key =
            rct::rct2pk(src.outputs[src.real_output].second.dest);

        auto transfer_it = std::find_if(
            transfers.begin(), transfers.end(),
            [&w, &source_output_key](const wallet2::transfer_details &td) {
              const cryptonote::transaction_prefix *effective_tx =
                  get_effective_transfer_tx(td, w);
              if (!effective_tx || td.m_internal_output_index >= effective_tx->vout.size())
                  return false;
              crypto::public_key effective_output_key = crypto::null_pkey;
              if (!cryptonote::get_output_public_key(
                      effective_tx->vout[td.m_internal_output_index],
                      effective_output_key))
                  return false;
              return effective_output_key == source_output_key;
            });
        CHECK_AND_ASSERT_THROW_MES(transfer_it != transfers.end(),
            "make_pending_carrot_tx: source output not found in transfers");

        selected_transfers.push_back(
            static_cast<std::size_t>(std::distance(transfers.begin(), transfer_it)));
        if (i)
            key_images_string << ' ';
        key_images_string << tx_proposal.key_images_sorted.at(i);
    }

    // get order of payment proposals
    std::vector<carrot::RCTOutputEnoteProposal> output_enote_proposals;
    carrot::encrypted_payment_id_t encrypted_payment_id;
    std::vector<std::pair<bool, std::size_t>> sorted_payment_proposal_indices;
    carrot::get_output_enote_proposals_from_proposal_v1(tx_proposal,
        &account.s_view_balance_dev,
        ///*s_view_balance_dev=*/nullptr,
        &account.k_view_incoming_dev,
        output_enote_proposals,
        encrypted_payment_id,
        &sorted_payment_proposal_indices);

    // calculate change_dst index based whether 2-out tx has a dummy output
    // change_dst is set to dummy in 2-out self-send, otherwise last self-send
    const bool has_2out_dummy = n_outputs == 2
        && tx_proposal.normal_payment_proposals.size() == 1
        && tx_proposal.normal_payment_proposals.at(0).amount == 0;
    CHECK_AND_ASSERT_THROW_MES(!tx_proposal.selfsend_payment_proposals.empty(),
        "make_pending_carrot_tx: carrot tx proposal missing a self-send proposal");
    const std::pair<bool, std::size_t> change_dst_index{!has_2out_dummy,
        has_2out_dummy ? 0 : tx_proposal.selfsend_payment_proposals.size()-1};

    // collect destinations and private tx keys for normal enotes
    //! @TODO: payment proofs for special self-send, perhaps generate d_e deterministically
    cryptonote::tx_destination_entry change_dts;
    std::vector<cryptonote::tx_destination_entry> dests;
    std::vector<crypto::secret_key> ephemeral_privkeys;
    dests.reserve(n_outputs);
    ephemeral_privkeys.reserve(n_outputs);
    for (const std::pair<bool, std::size_t> &payment_idx : sorted_payment_proposal_indices)
    {
        cryptonote::tx_destination_entry dest;

        const bool is_selfsend = payment_idx.first;
        if (is_selfsend)
        {
            dest = make_tx_destination_entry(tx_proposal.selfsend_payment_proposals.at(payment_idx.second),
                account.k_view_incoming_dev);
            ephemeral_privkeys.push_back(crypto::null_skey);
        }
        else // !is_selfsend
        {
            const carrot::CarrotPaymentProposalV1 &normal_payment_proposal =
                tx_proposal.normal_payment_proposals.at(payment_idx.second);
            dest = make_tx_destination_entry(normal_payment_proposal);
            ephemeral_privkeys.push_back(carrot::get_enote_ephemeral_privkey(normal_payment_proposal,
                carrot::make_carrot_input_context(tx_first_key_image)));
        }

        if (payment_idx == change_dst_index)
            change_dts = dest;
        else
            dests.push_back(dest);
    }

    // collect subaddr account and minor indices
    const std::uint32_t subaddr_account = transfers.at(selected_transfers.at(0)).m_subaddr_index.major;
    std::set<std::uint32_t> subaddr_indices;
    for (const size_t selected_transfer : selected_transfers)
    {
        const wallet2::transfer_details &td = transfers.at(selected_transfer);
        const std::uint32_t other_subaddr_account = td.m_subaddr_index.major;
        if (other_subaddr_account != subaddr_account)
        {
            MWARNING("make_pending_carrot_tx: conflicting account indices: " << subaddr_account << " vs "
                << other_subaddr_account);
        }
        subaddr_indices.insert(td.m_subaddr_index.minor);
    }

    wallet2::pending_tx ptx;
    ptx.tx.set_null();
    ptx.dust = 0;
    ptx.fee = tx_proposal.fee;
    ptx.dust_added_to_fee = false;
    ptx.change_dts = change_dts;
    ptx.selected_transfers = std::move(selected_transfers);
    ptx.key_images = key_images_string.str();
    if (ephemeral_privkeys.size() == 1) {
      ptx.tx_key = ephemeral_privkeys.at(0);
      ptx.additional_tx_keys.clear();
    } else if (ephemeral_privkeys.size() == 2 && shared_ephemeral_pubkey) {
      ptx.tx_key = (ephemeral_privkeys.at(0) == crypto::null_skey) ? ephemeral_privkeys.at(1) : ephemeral_privkeys.at(0);
      ptx.additional_tx_keys.clear();
    } else {
      ptx.tx_key = crypto::null_skey;
      ptx.additional_tx_keys = std::move(ephemeral_privkeys);
    }
    ptx.dests = std::move(dests);
    ptx.multisig_sigs = {};
    ptx.multisig_tx_key_entropy = {};
    ptx.subaddr_account = subaddr_account;
    ptx.subaddr_indices = std::move(subaddr_indices);
    ptx.construction_data = tx_proposal;
    return ptx;
}
//-------------------------------------------------------------------------------------------------------------------
wallet2::pending_tx finalize_all_proofs_from_transfer_details_as_pending_tx(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const wallet2::transfer_container &transfers,
    const wallet2 &w)
{
    wallet2::pending_tx ptx = make_pending_carrot_tx(tx_proposal,
        transfers,
        w);

    ptx.tx = finalize_all_proofs_from_transfer_details(
        tx_proposal,
        w
    );

    return ptx;
}
//-------------------------------------------------------------------------------------------------------------------
wallet2::pending_tx finalize_all_proofs_from_transfer_details_as_pending_tx(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const wallet2 &w)
{
    // Perf: const-reference the wallet-global container instead of deep
    // copying every transfer; get_transfers("") is a straight full copy so
    // all indices/iterator distances below are identical.
    const wallet2::transfer_container &transfers = w.get_transfers_ref();

    return finalize_all_proofs_from_transfer_details_as_pending_tx(
        tx_proposal,
        transfers,
        w);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace wallet
} //namespace tools
