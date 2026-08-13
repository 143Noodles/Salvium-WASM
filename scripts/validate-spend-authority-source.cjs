#!/usr/bin/env node

// Focused source gate for the legacy stake-return spend-authority repair.
// This intentionally checks wiring and fail-closed invariants without needing
// a wallet fixture or a daemon: the WASM repository has no deterministic
// historical-wallet fixture at this layer.

const fs = require('node:fs');
const path = require('node:path');

const repo = path.resolve(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(repo, relative), 'utf8');
const txBuilder = read('source-overrides/src/wallet/tx_builder.cpp');
const txBuilderHeader = read('source-overrides/src/wallet/tx_builder.h');
const wallet2 = read('source-overrides/src/wallet/wallet2.cpp');
const bindings = read('src/wasm_bindings.cpp');

const fail = (message) => {
  throw new Error(`spend-authority source gate: ${message}`);
};
const requireText = (source, text, label) => {
  if (!source.includes(text)) fail(`missing ${label}: ${text}`);
};
const requireRegex = (source, regex, label) => {
  if (!regex.test(source)) fail(`missing ${label}: ${regex}`);
};

requireText(txBuilderHeader, 'get_effective_transfer_tx(', 'effective transaction declaration');
requireText(txBuilderHeader, 'get_effective_transfer_type(', 'effective transaction type declaration');
requireText(txBuilderHeader, 'validate_transfer_spend_authority(', 'public helper declaration');
requireText(txBuilderHeader, 'has_validated_transfer_spend_authority(', 'validated metadata authority declaration');
requireText(txBuilderHeader, 'has_transfer_spend_authority(', 'complete non-zero spend authority declaration');
requireText(txBuilderHeader, 'has_transfer_key_image(', 'tracking key-image declaration');
requireText(txBuilderHeader, 'is_transfer_usable_for_return(', 'return input eligibility declaration');
requireRegex(
  txBuilder,
  /is_transfer_usable_for_input_selection[\s\S]*?return validate_transfer_spend_authority\(td, \*wallet\);/,
  'input-selection wiring',
);
const nonBurned = txBuilder.slice(
  txBuilder.indexOf('std::unordered_map<crypto::key_image, size_t> collect_non_burned_transfers_by_key_image('),
  txBuilder.indexOf('carrot::select_inputs_func_t make_wallet2_single_transfer_input_selector(', txBuilder.indexOf('std::unordered_map<crypto::key_image, size_t> collect_non_burned_transfers_by_key_image(')),
);
requireText(nonBurned, 'has_transfer_spend_authority(td, w)', 'complete authority non-burned transfer collection');
requireText(nonBurned, 'get_effective_transfer_key_image(td, w)', 'effective key image non-burned collection');
const proposalTransferLookup = txBuilder.slice(
  txBuilder.indexOf('size_t find_wallet_transfer_index_from_container_by_effective_key_image('),
  txBuilder.indexOf('crypto::key_image get_effective_transfer_key_image(', txBuilder.indexOf('size_t find_wallet_transfer_index_from_container_by_effective_key_image(')),
);
if (!proposalTransferLookup) fail('proposal transfer lookup body not found');
requireText(proposalTransferLookup, 'get_effective_transfer_key_image(td, w)', 'effective proposal transfer lookup key image');
requireText(proposalTransferLookup, 'has_transfer_spend_authority(td, w)', 'complete proposal transfer lookup authority');
requireRegex(
  proposalTransferLookup,
  /if \(td\.m_key_image_partial\)[\s\S]*?CHECK_AND_ASSERT_THROW_MES[\s\S]*?if \(has_transfer_spend_authority\(td, w\)\)/,
  'proposal transfer lookup partial-key-image fail-closed ordering',
);
if ((proposalTransferLookup.match(/if \(td\.m_key_image_partial\)/g) || []).length < 2 ||
    (proposalTransferLookup.match(/has_transfer_spend_authority\(td, w\)/g) || []).length < 2)
  fail('proposal transfer lookup must guard both container and wallet-transfer loops');
if (/td\.m_key_image\s*==\s*ki/.test(proposalTransferLookup))
  fail('raw sparse key image in proposal transfer lookup');
const selector = txBuilder.slice(
  txBuilder.indexOf('carrot::select_inputs_func_t make_wallet2_single_transfer_input_selector('),
  txBuilder.indexOf('std::vector<cryptonote::tx_source_entry> get_sources('),
);
if (!selector) fail('input selector body not found');
const inputUsability = txBuilder.slice(
  txBuilder.indexOf('static bool is_transfer_usable_for_input_selection('),
  txBuilder.indexOf('size_t find_wallet_transfer_index_from_container_by_effective_key_image(', txBuilder.indexOf('static bool is_transfer_usable_for_input_selection(')),
);
requireText(inputUsability, 'has_transfer_spend_authority(td, *wallet)', 'complete input-selector authority');
requireText(inputUsability, 'td.m_key_image != crypto::key_image{}', 'non-zero input-selector fallback key image');
requireText(selector, 'get_effective_transfer_tx(td, w)', 'effective selector transaction view');
requireText(selector, '.is_pre_carrot = !carrot::is_carrot_transaction_v1(*effective_tx)', 'effective selector Carrot classification');
if (/is_carrot_transaction_v1\(td\.m_tx\)/.test(selector))
  fail('raw sparse transaction used for input selector Carrot classification');
requireRegex(
  wallet2,
  /is_native_spendable_for_unlocked_balance[\s\S]*?return tools::wallet::validate_transfer_spend_authority\(td, \*this\);/,
  'unlocked-balance wiring',
);
const unlockedBalance = wallet2.slice(
  wallet2.indexOf('const auto is_native_spendable_for_unlocked_balance ='),
  wallet2.indexOf('for(const auto& idx: m_transfers_indices[asset_type])', wallet2.indexOf('const auto is_native_spendable_for_unlocked_balance =')),
);
requireText(unlockedBalance, 'has_transfer_spend_authority(td, *this)', 'complete unlocked-balance spend authority precondition');
requireRegex(
  txBuilder,
  /get_sources\([\s\S]*?resolve_transfer_origin_data\(td, w, src\.origin_tx_data\);/,
  'signing source origin wiring',
);
requireRegex(
  bindings,
  /validate_outputs_for_send\(\) const[\s\S]*?tools::wallet::validate_transfer_spend_authority\(td, \*m_wallet\);/,
  'phase-4 send-preflight wiring',
);

const sources = txBuilder.slice(
  txBuilder.indexOf('std::vector<cryptonote::tx_source_entry> get_sources('),
  txBuilder.indexOf(
    'std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_createtoken(',
  ),
);
if (!sources) fail('get_sources body not found');
requireText(sources, 'get_effective_transfer_tx(td, w)', 'effective signing transaction view');
requireText(sources, 'effective_output_key', 'effective signing output key');
requireText(sources, 'get_output_public_key(', 'effective signing output extraction');
requireText(sources, 'get_tx_pub_key_from_extra(*effective_tx', 'effective signing tx pubkey');
requireText(sources, 'get_additional_tx_pub_keys_from_extra(*effective_tx', 'effective signing additional keys');
requireText(sources, 'effective_tx->vin', 'effective signing input context');
for (const [pattern, label] of [
  [/td\.get_public_key\(\)/, 'raw transfer output accessor in get_sources'],
  [/get_tx_pub_key_from_extra\(\s*td\.m_tx/, 'raw tx pubkey extraction in get_sources'],
  [/get_additional_tx_pub_keys_from_extra\(\s*td\.m_tx/, 'raw additional-key extraction in get_sources'],
  [/td\.m_tx\.vin/, 'raw input extraction in get_sources'],
]) {
  if (pattern.test(sources)) fail(`forbidden ${label}`);
}

const preflight = bindings.slice(
  bindings.indexOf('std::string validate_outputs_for_send() const'),
  bindings.indexOf('std::string get_stake_lifecycle() const', bindings.indexOf('std::string validate_outputs_for_send() const')),
);
if (!preflight) fail('send-preflight body not found');
requireText(preflight, 'get_effective_transfer_tx(td, *m_wallet)', 'effective phase-4 transaction view');
requireText(preflight, 'const cryptonote::transaction_type effective_type', 'effective phase-4 transaction type');
requireText(preflight, 'effective_tx->vout[td.m_internal_output_index]', 'effective phase-4 output extraction');
for (const [pattern, label] of [
  [/td\.m_tx\.type/, 'raw transfer type gate in phase-4 preflight'],
  [/safe_output_pubkey\(td/, 'sparse-prefix output precheck in phase-4 preflight'],
  [/output_pubkey_or_null\(td\)/, 'sparse-prefix output diagnostic in phase-4 preflight'],
]) {
  if (pattern.test(preflight)) fail(`forbidden ${label}`);
}

const helper = txBuilder.slice(
  txBuilder.indexOf('bool validate_transfer_spend_authority('),
  txBuilder.indexOf('static bool build_payment_proposals', txBuilder.indexOf('bool validate_transfer_spend_authority(')),
);
if (!helper) fail('central helper body not found');
const resolver = txBuilder.slice(
  txBuilder.indexOf('bool resolve_transfer_origin_data('),
  txBuilder.indexOf('bool validate_transfer_spend_authority('),
);
if (!resolver) fail('shared origin resolver body not found');
const spendAuthority = txBuilder.slice(
  txBuilder.indexOf('bool has_transfer_spend_authority('),
  txBuilder.indexOf('bool is_transfer_usable_for_return(', txBuilder.indexOf('bool has_transfer_spend_authority(')),
);
requireRegex(
  spendAuthority,
  /if \(w\.watch_only\(\)\)[\s\S]*?return false;[\s\S]*?if \(td\.m_key_image_partial\)[\s\S]*?return false;[\s\S]*?if \(!td\.m_key_image_known &&[\s\S]*?has_validated_transfer_spend_authority\(td, w\)\)[\s\S]*?return false;[\s\S]*?get_effective_transfer_key_image\(td, w\) != crypto::key_image\{\}/,
  'watch-only/partial/known/validated/non-zero spend-authority gate',
);
const trackingAuthority = txBuilder.slice(
  txBuilder.indexOf('bool has_transfer_key_image('),
  txBuilder.indexOf('bool is_transfer_usable_for_return(', txBuilder.indexOf('bool has_transfer_key_image(')),
);
requireRegex(
  trackingAuthority,
  /if \(td\.m_key_image_partial\)[\s\S]*?return false;[\s\S]*?effective_key_image[\s\S]*?crypto::key_image\{\}[\s\S]*?return \(td\.m_key_image_known[\s\S]*?has_validated_transfer_spend_authority\(td, w\)/,
  'partial/zero/known-or-validated tracking key-image gate',
);
const returnEligibility = txBuilder.slice(
  txBuilder.indexOf('bool is_transfer_usable_for_return('),
  txBuilder.indexOf('// Resolve the canonical origin metadata used by legacy PROTOCOL/RETURN key', txBuilder.indexOf('bool is_transfer_usable_for_return(')),
);
requireRegex(
  returnEligibility,
  /if \(td\.m_key_image_partial\)[\s\S]*?return false;[\s\S]*?is_spent\(td, false\)[\s\S]*?td\.m_frozen[\s\S]*?has_transfer_spend_authority\(td, w\)[\s\S]*?is_transfer_unlocked\(td\)/,
  'return input spendability gate',
);
requireText(helper, 'm_key_image_known', 'known-key-image guard');
requireText(helper, 'm_key_image_partial', 'partial-key-image guard');
requireText(helper, 'm_key_image == crypto::key_image{}', 'zero-key-image guard');
requireText(helper, 'has_validated_transfer_spend_authority(td, w)', 'validated metadata authority path');
requireText(helper, 'const cryptonote::transaction *full_tx', 'full transaction handle');
requireText(helper, 'generate_key_image_helper', 'legacy key-image derivation');
requireText(helper, 'origin_tx_data', 'origin metadata derivation');
requireText(helper, 'derived_key_image == expected_key_image', 'effective key-image comparison');
requireText(resolver, 'candidate.protocol_tx_data.return_address', 'canonical confirmed-origin fallback');
requireText(resolver, 'candidate_return != output_key', 'origin/output-key binding');
requireText(resolver, 'm_salvium_txs.find(output_key)', 'canonical scanner origin map lookup');
requireText(resolver, 'populate_origin_from_index', 'effective mapped origin hydration');
requireText(resolver, 'origin_td.m_internal_output_index', 'mapped origin output index');
requireText(helper, 'resolve_transfer_origin_data(td, w, origin_tx_data)', 'validator origin resolver use');
requireRegex(
  helper,
  /src\.real_out_tx_key\s*=\s*cryptonote::get_tx_pub_key_from_extra\(\*tx, td\.m_pk_index\)[\s\S]*?src\.real_out_additional_tx_keys\s*=\s*cryptonote::get_additional_tx_pub_keys_from_extra\(\*tx\)[\s\S]*?if \(!src\.carrot\)[\s\S]*?if \(src\.real_out_tx_key == crypto::null_pkey\)/,
  'shared Carrot/legacy ephemeral keys with legacy pubkey guard',
);
requireRegex(
  helper,
  /if \(!src\.carrot\)[\s\S]*?generate_key_image_helper[\s\S]*?\}[\s\S]*?crypto::secret_key x_out/,
  'Carrot branch after legacy derivation',
);

const effectiveTx = txBuilder.slice(
  txBuilder.indexOf('const cryptonote::transaction_prefix *get_effective_transfer_tx('),
  txBuilder.indexOf('static bool is_transfer_usable_for_input_selection(', txBuilder.indexOf('const cryptonote::transaction_prefix *get_effective_transfer_tx(')),
);
if (!effectiveTx) fail('effective transaction resolver body not found');
requireText(effectiveTx, 'm_runtime_full_txs', 'runtime full transaction preference');
requireText(effectiveTx, 'm_confirmed_txs', 'confirmed transaction preference');
requireRegex(effectiveTx, /m_runtime_full_txs[\s\S]*m_confirmed_txs/, 'runtime-over-confirmed preference');
requireRegex(
  effectiveTx,
  /get_effective_transfer_type\([\s\S]*?return get_effective_transfer_tx\(td, w\)->type;/,
  'sparse-prefix effective type resolution',
);

const getOuts = wallet2.slice(
  wallet2.indexOf('void wallet2::get_outs('),
  wallet2.indexOf('// save those outs in the ringdb for reuse', wallet2.indexOf('void wallet2::get_outs(')),
);
if (!getOuts) fail('wallet get_outs body not found');
requireText(getOuts, 'get_effective_transfer_tx(td, *this)', 'effective get_outs transaction view');
requireText(getOuts, 'effective_output_key', 'effective get_outs output key');
requireText(getOuts, 'real_out.key = effective_output_key', 'effective get_outs seed request key');
requireText(getOuts, 'daemon_resp.outs[i].key == effective_output_key', 'effective daemon response key comparison');
requireText(getOuts, 'std::make_tuple(real_index, effective_output_key, mask)', 'effective result ring key');
requireText(getOuts, 'std::make_tuple(td.m_asset_type_output_index, effective_output_key, mask)', 'effective no-mixin ring key');
if (/td\.get_public_key\(\)/.test(getOuts))
  fail('raw transfer output accessor in wallet get_outs');

const openingFallback = txBuilder.slice(
  txBuilder.indexOf('bool try_get_address_openings_x_y_impl('),
  txBuilder.indexOf('bool try_get_address_openings_x_y(', txBuilder.indexOf('bool try_get_address_openings_x_y_impl(')),
);
requireText(openingFallback, 'src.real_output >= src.outputs.size()', 'opening source real-output bounds gate');
requireText(openingFallback, 'src.real_output_in_tx_index >= additional_derivations.size()', 'opening additional-derivation bounds gate');
requireText(openingFallback, 'ephemeral_pubkey_index >= enote_ephemeral_pubkeys.size()', 'opening ephemeral-key bounds gate');
if (!openingFallback) fail('return-opening fallback body not found');
requireText(openingFallback, 'get_effective_transfer_tx(candidate_td, w)', 'effective origin candidate lookup');
requireText(openingFallback, 'get_effective_transfer_tx(change_td, w', 'effective change candidate lookup');
requireText(openingFallback, 'get_effective_transfer_tx(cand, w', 'effective deterministic candidate lookup');
if (/(?:candidate_td|change_td|cand)\.m_tx\b/.test(openingFallback) ||
    /(?:candidate_td|change_td|cand)\.get_public_key\(\)/.test(openingFallback))
  fail('raw sparse transfer used in return-opening fallback construction');
requireRegex(
  helper,
  /full_tx[\s\S]*?try_get_address_openings_x_y\(\s*\*full_tx/,
  'Carrot full-transaction opening overload',
);
requireRegex(
  helper,
  /src\.real_out_tx_key\s*=\s*cryptonote::get_tx_pub_key_from_extra\(\*tx[\s\S]*?src\.real_out_additional_tx_keys\s*=\s*cryptonote::get_additional_tx_pub_keys_from_extra\(\*tx\)[\s\S]*?if \(!src\.carrot\)/,
  'ordinary Carrot ephemeral-key context before legacy branch',
);
requireRegex(
  helper,
  /PROTOCOL[\s\S]*?RETURN[\s\S]*?![\s\S]*?have_origin_data[\s\S]*?return false;/,
  'legacy protocol/return missing-origin fail-closed guard',
);

const hydration = bindings.slice(
  bindings.indexOf('std::string cache_runtime_full_txs_from_sparse('),
  bindings.indexOf('std::string get_mempool_tx_info', bindings.indexOf('std::string cache_runtime_full_txs_from_sparse(')),
);
requireText(hydration, 'stored_hashes', 'hydration stored hash telemetry');
requireText(hydration, 'rejected_count', 'hydration rejection count telemetry');
requireText(hydration, '"parse_failed"', 'hydration parse-failure reason');
requireText(hydration, '"hash_mismatch"', 'hydration hash-mismatch reason');

const candidateHashes = bindings.slice(
  bindings.indexOf('std::string get_runtime_full_tx_candidate_hashes()'),
  bindings.indexOf('std::string cache_runtime_full_txs_from_sparse(', bindings.indexOf('std::string get_runtime_full_tx_candidate_hashes()')),
);
if (!candidateHashes) fail('runtime candidate hash body not found');
requireRegex(
  candidateHashes,
  /for \(const auto &td : m_wallet->m_transfers\) \{[\s\S]*?add_runtime_candidate\(td\.m_txid\);/,
  'raw-type-independent transfer txid candidates',
);
requireText(candidateHashes, 'm_salvium_txs', 'scanner origin map candidate enumeration');
requireText(candidateHashes, 'm_wallet->m_transfers[origin_idx].m_txid', 'scanner origin txid candidate');
requireText(candidateHashes, 'get_effective_transfer_tx(td, *m_wallet)', 'effective return candidate transaction view');
requireText(candidateHashes, 'm_wallet->m_transfers[td.m_td_origin_idx].m_txid', 'explicit origin-index txid candidate');
if (/switch \(td\.m_tx\.type\)/.test(candidateHashes))
  fail('raw sparse type switch gates runtime candidate enumeration');

const pending = txBuilder.slice(
  txBuilder.indexOf('wallet2::pending_tx make_pending_carrot_tx('),
  txBuilder.indexOf('// get order of payment proposals', txBuilder.indexOf('wallet2::pending_tx make_pending_carrot_tx(')),
);
if (!pending) fail('pending Carrot reconstruction body not found');
requireText(pending, 'const wallet2 &w', 'pending Carrot wallet context');
requireText(pending, 'get_effective_transfer_tx(td, w)', 'pending Carrot effective output context');
requireText(pending, 'get_output_public_key(', 'pending Carrot output-key matching');
if (/td\.get_public_key\(\)/.test(pending))
  fail('raw transfer output accessor in pending Carrot reconstruction');

requireRegex(
  helper,
  /crypto::generate_key_image\(output_key, x_out, derived_key_image\)[\s\S]*?derived_key_image == expected_key_image/,
  'Carrot derived key-image equality',
);

const transferSelected = wallet2.slice(
  wallet2.indexOf('template<typename T>\nvoid wallet2::transfer_selected('),
  wallet2.indexOf('void wallet2::transfer_selected_rct(', wallet2.indexOf('template<typename T>\nvoid wallet2::transfer_selected(')),
);
const transferSelectedRct = wallet2.slice(
  wallet2.indexOf('void wallet2::transfer_selected_rct('),
  wallet2.indexOf('std::vector<size_t> wallet2::pick_preferred_rct_inputs(', wallet2.indexOf('void wallet2::transfer_selected_rct(')),
);
for (const [source, label] of [[transferSelected, 'legacy transfer_selected'], [transferSelectedRct, 'Rct transfer_selected']]) {
  if (!source) fail(`${label} body not found`);
  requireText(source, 'get_effective_transfer_tx(td, *this)', `${label} effective tx`);
  requireText(source, 'effective_output_key', `${label} effective output key`);
  requireText(source, 'resolve_transfer_origin_data(td, *this, origin_tx_data)', `${label} canonical origin resolver`);
  requireText(source, 'effective_tx->vin', `${label} effective vin context`);
  if (/td\.get_public_key\(\)|get_tx_pub_key_from_extra\(td\.m_tx|get_additional_tx_pub_keys_from_extra\(td\.m_tx|td\.m_tx\.vin/.test(source))
    fail(`raw sparse source assembly in ${label}`);
}

for (const [name, start, end] of [
  ['rebuild_wallet_derived_state', 'void rebuild_wallet_derived_state()', 'void restore_account_cached_maps()'],
  ['repair_return_output_metadata_from_transfers', 'void repair_return_output_metadata_from_transfers()', 'std::optional<std::tuple<crypto::public_key, size_t, int>>'],
  ['find_origin_transfer_from_scan_hint', 'const tools::wallet2::transfer_details *find_origin_transfer_from_scan_hint(', 'crypto::key_image derive_wallet_key_image_for_return('],
  ['try_derive_return_sender_extensions_from_tx_prefix', 'bool try_derive_return_sender_extensions_from_tx_prefix(', 'bool try_recover_return_spend_data_from_transaction('],
]) {
  const startAt = bindings.indexOf(start);
  const endAt = bindings.indexOf(end, startAt + 1);
  const body = bindings.slice(startAt, endAt);
  if (!body) fail(`${name} body not found`);
  requireText(body, 'get_effective_transfer_tx', `${name} effective transaction view`);
}

const revalidation = bindings.slice(
  bindings.indexOf('std::string begin_output_ownership_revalidation()'),
  bindings.indexOf('std::string cancel_output_ownership_revalidation()', bindings.indexOf('std::string begin_output_ownership_revalidation()')),
);
requireText(revalidation, 'safe_output_pubkey(td, *m_wallet', 'effective ownership output identity');
const spentRepair = bindings.slice(
  bindings.indexOf('size_t repair_spent_transfers_from_wallet_txs()'),
  bindings.indexOf('void mark_derived_state_clean()', bindings.indexOf('size_t repair_spent_transfers_from_wallet_txs()')),
);
requireText(spentRepair, 'get_effective_transfer_tx(other_td, *m_wallet)', 'effective spending transaction view');
requireText(spentRepair, 'wallet_effective_key_images', 'effective wallet key-image set');
requireText(spentRepair, 'has_transfer_spend_authority(td, *m_wallet)', 'spent repair authority gate');
requireText(spentRepair, 'get_effective_transfer_key_image(td, *m_wallet)', 'effective spent-repair key image');
if (/other_td\.m_tx\.vin|find\(td\.m_key_image\)|m_wallet->m_key_images\.count\(txin\.k_image\)/.test(spentRepair))
  fail('raw sparse transaction/key image in spent-transfer repair');
const auditHeights = bindings.slice(
  bindings.indexOf('std::string get_audit_heights_needing_real_txid()'),
  bindings.indexOf('std::string get_runtime_full_tx_candidate_hashes()', bindings.indexOf('std::string get_audit_heights_needing_real_txid()')),
);
requireText(auditHeights, 'get_effective_transfer_type(td, *m_wallet)', 'effective audit classification');

const rebuild = bindings.slice(
  bindings.indexOf('void rebuild_wallet_derived_state()'),
  bindings.indexOf('void restore_account_cached_maps()', bindings.indexOf('void rebuild_wallet_derived_state()')),
);
requireText(rebuild, 'repair_transfer_asset_types_from_outputs()', 'effective asset repair before derived indexing');
requireText(rebuild, 'm_transfers_indices[td.asset_type].insert(idx)', 'derived asset index insertion after repair');

const selectAvailable = wallet2.slice(
  wallet2.indexOf('std::vector<size_t> wallet2::select_available_outputs('),
  wallet2.indexOf('//----------------------------------------------------------------------------------------------------', wallet2.indexOf('std::vector<size_t> wallet2::select_available_outputs(') + 1),
);
requireRegex(
  selectAvailable,
  /const auto has_spend_authority = \[this\][\s\S]*?has_transfer_spend_authority\(td, \*this\)[\s\S]*?if \(!has_spend_authority\(\*i\)\)[\s\S]*?if \(!is_transfer_unlocked\(\*i\)\)/,
  'available-output authority gate before unlock/callback',
);
requireText(selectAvailable, 'get_effective_transfer_tx(*i, *this)', 'effective available-output transaction');
requireText(selectAvailable, 'effective_tx->type', 'effective available-output type');
requireText(selectAvailable, 'get_output_public_key(', 'effective available-output key');
if (/i->m_tx\.type|i->get_public_key\(\)/.test(selectAvailable))
  fail('raw sparse metadata in select_available_outputs');

const createSingle = wallet2.slice(
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_single('),
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_return(', wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_single(')),
);
requireRegex(
  createSingle,
  /if \(td\.m_key_image_partial\)[\s\S]*?continue;[\s\S]*?get_effective_transfer_key_image\(td, \*this\)[\s\S]*?has_transfer_spend_authority\(td, \*this\)[\s\S]*?effective_key_image != crypto::key_image\{\}[\s\S]*?effective_key_image == ki/,
  'single-transfer explicit partial/authority/non-zero effective key-image gate',
);

const createReturn = wallet2.slice(
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_return('),
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_from(', wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_return(')),
);
requireText(createReturn, 'td_origin.m_internal_output_index >= effective_origin_tx->vout.size()', 'return origin-output bounds gate');
requireText(createReturn, 'td_origin.m_internal_output_index >= effective_origin_tx->return_address_list.size()', 'return address metadata bounds gate');
requireText(createReturn, 'td_origin.m_internal_output_index >= effective_origin_tx->return_address_change_mask.size()', 'return change-mask bounds gate');
if ((createReturn.match(/change_index >= effective_origin_tx->vout\.size\(\)/g) || []).length < 3)
  fail('all return-payment change-output branches require explicit bounds gates');
requireRegex(
  createReturn,
  /const auto validate_return_transfer = \[this\][\s\S]*?td_idx >= get_num_transfer_details\(\)[\s\S]*?is_transfer_usable_for_return\(td, \*this\)[\s\S]*?const transfer_details& td_origin =\s*validate_return_transfer\(transfers_indices\[0\]\)[\s\S]*?for \(const auto &td_idx : transfers_indices\)[\s\S]*?validate_return_transfer\(td_idx\)/,
  'wrapper return API validation before origin/proposal use',
);

const createFrom = wallet2.slice(
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_from('),
  wallet2.indexOf('void wallet2::cold_tx_aux_import(', wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_from(')),
);
requireRegex(
  createFrom,
  /if \(tx_type == cryptonote::transaction_type::RETURN\)[\s\S]*?td_idx >= get_num_transfer_details\(\)[\s\S]*?is_transfer_usable_for_return\(td, \*this\)[\s\S]*?for \(const size_t transfer_idx : unused_transfers_indices\)[\s\S]*?validate_return_transfer\(transfer_idx\)[\s\S]*?for \(const size_t transfer_idx : unused_dust_indices\)[\s\S]*?validate_return_transfer\(transfer_idx\)[\s\S]*?const bool do_carrot_tx_construction/,
  'lower-level return constructor validation before proposals/source use',
);

const pickPreferred = wallet2.slice(
  wallet2.indexOf('std::vector<size_t> wallet2::pick_preferred_rct_inputs('),
  wallet2.indexOf('bool wallet2::should_pick_a_second_output', wallet2.indexOf('std::vector<size_t> wallet2::pick_preferred_rct_inputs(')),
);
requireRegex(
  pickPreferred,
  /const auto has_spend_authority = \[this\][\s\S]*?has_transfer_spend_authority\(td, \*this\);/,
  'preferred RCT authority predicate',
);
requireRegex(pickPreferred, /has_spend_authority\(td\)[\s\S]*?is_transfer_unlocked\(td\)/, 'preferred RCT single/first-pair authority before unlock');
requireRegex(pickPreferred, /has_spend_authority\(td2\)[\s\S]*?is_transfer_unlocked\(td2\)/, 'preferred RCT second-pair authority before unlock');
if ((pickPreferred.match(/has_spend_authority\(td\)/g) || []).length < 2)
  fail('preferred RCT single and first-pair candidates missing authority gate');

const createTransactions2 = wallet2.slice(
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_2('),
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_all(', wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_2(')),
);
requireRegex(
  createTransactions2,
  /const auto has_spend_authority = \[this\][\s\S]*?has_transfer_spend_authority\(td, \*this\);[\s\S]*?has_spend_authority\(td\)[\s\S]*?is_transfer_unlocked\(td\)/,
  'create_transactions_2 candidate authority before unlock',
);
if (/!td\.m_key_image_partial/.test(createTransactions2))
  fail('raw partial-key-image filter remains in create_transactions_2 candidate gather');

const createTransactionsAll = wallet2.slice(
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_all('),
  wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_single(', wallet2.indexOf('std::vector<wallet2::pending_tx> wallet2::create_transactions_all(')),
);
requireRegex(
  createTransactionsAll,
  /const auto has_spend_authority = \[this\][\s\S]*?has_transfer_spend_authority\(td, \*this\);[\s\S]*?has_spend_authority\(td\)[\s\S]*?is_transfer_unlocked\(td\)/,
  'create_transactions_all candidate authority before unlock',
);
if (/!td\.m_key_image_partial/.test(createTransactionsAll))
  fail('raw partial-key-image filter remains in create_transactions_all candidate gather');

const getOutsRing = wallet2.slice(
  wallet2.indexOf('void wallet2::get_outs('),
  wallet2.indexOf('template<typename T>\nvoid wallet2::transfer_selected(', wallet2.indexOf('void wallet2::get_outs(')),
);
requireText(getOutsRing, 'has_transfer_spend_authority(td, *this)', 'complete ring reuse authority gate');
requireText(getOutsRing, 'get_effective_transfer_key_image(td, *this)', 'effective ringdb key image');

const transferLookupByKeyImageStart = wallet2.indexOf(
  'size_t wallet2::get_transfer_details(const crypto::key_image &ki) const',
);
const transferLookupFromContainerStart = wallet2.indexOf(
  'size_t wallet2::get_transfer_details_from_container(const crypto::key_image &ki, const transfer_container& container) const',
);
const transferLookupEnd = wallet2.indexOf(
  'bool wallet2::frozen(const transfer_details &td) const',
  transferLookupFromContainerStart,
);
const transferLookupByKeyImage = wallet2.slice(
  transferLookupByKeyImageStart,
  transferLookupFromContainerStart,
);
const transferLookupFromContainer = wallet2.slice(
  transferLookupFromContainerStart,
  transferLookupEnd,
);
for (const [source, label] of [
  [transferLookupByKeyImage, 'wallet transfer lookup'],
  [transferLookupFromContainer, 'container transfer lookup'],
]) {
  if (!source) fail(`${label} body not found`);
  requireText(source, 'get_effective_transfer_key_image(td, *this)', `${label} effective key image`);
  requireText(source, 'has_transfer_key_image(td, *this)', `${label} tracking key-image authority`);
  requireRegex(
    source,
    /if \(td\.m_key_image_partial\)[\s\S]*?CHECK_AND_ASSERT_THROW_MES[\s\S]*?if \(tools::wallet::has_transfer_key_image\(td, \*this\)\)/,
    `${label} partial-key-image fail-closed ordering`,
  );
  if (/td\.m_key_image\s*==\s*ki/.test(source))
    fail(`raw sparse key image in ${label}`);
}
requireText(transferLookupFromContainer, 'const transfer_details &td = container[idx];', 'container lookup source');

requireText(wallet2, 'get_effective_transfer_key_image(td, *this)', 'effective ringdb key image');
requireText(wallet2, 'get_effective_transfer_key_image(\n          m_transfers.at(transfer_idx), *this)', 'effective Carrot return constructor key image');

const rescanSpentStart = wallet2.indexOf('void wallet2::rescan_spent()');
const rescanSpentEnd = wallet2.indexOf(
  'void wallet2::rescan_blockchain(',
  rescanSpentStart,
);
const rescanSpent = wallet2.slice(rescanSpentStart, rescanSpentEnd);
if (!rescanSpent) fail('rescan_spent body not found');
  requireText(rescanSpent, 'has_transfer_key_image(td, *this)', 'rescan-spent tracking gate');
requireText(rescanSpent, 'get_effective_transfer_key_image(td, *this)', 'rescan-spent effective key image');
requireText(rescanSpent, 'queried_transfer_indices[query_index]', 'rescan-spent filtered response mapping');
if (/m_transfers\[n\]\.m_key_image|td\.m_key_image/.test(rescanSpent))
  fail('raw sparse key image in rescan_spent');

const scannedTransaction = wallet2.slice(
  wallet2.indexOf('void wallet2::process_new_scanned_transaction('),
  wallet2.indexOf('void wallet2::process_new_blockchain_entry(', wallet2.indexOf('void wallet2::process_new_scanned_transaction(')),
);
if (!scannedTransaction) fail('scanned-transaction processing body not found');
requireText(scannedTransaction, 'find_transfer_index_by_effective_key_image(', 'scanned-transaction canonical key-image lookup');
requireText(scannedTransaction, 'get_effective_transfer_tx(td_origin, *this)', 'scanned origin effective transaction');
requireText(scannedTransaction, 'td_origin.m_internal_output_index >= effective_origin_tx->vout.size()', 'scanned origin output bounds');
if (/td_origin\.m_tx\.(?:type|vout)/.test(scannedTransaction))
  fail('raw sparse origin transaction in scanned-transaction cleanup');

const bindingKeyImageLookup = bindings.slice(
  bindings.indexOf('static bool find_transfer_index_by_effective_key_image('),
  bindings.indexOf('uint64_t effective_wallet_height_for_unlock(', bindings.indexOf('static bool find_transfer_index_by_effective_key_image(')),
);
if (!bindingKeyImageLookup) fail('binding effective key-image lookup body not found');
requireText(
  bindingKeyImageLookup,
  'has_transfer_key_image(td, wallet)',
  'binding lookup known-or-validated tracking gate',
);
requireRegex(
  bindingKeyImageLookup,
  /has_transfer_key_image\(td, wallet\)[\s\S]*?get_effective_transfer_key_image\(td, wallet\)[\s\S]*?require_spend_authority[\s\S]*?has_transfer_spend_authority\(td, wallet\)/,
  'binding lookup tracking-before-authority ordering',
);

const returnBinding = bindings.slice(
  bindings.indexOf('std::string create_return_transaction_json('),
  bindings.indexOf('std::string get_stake_lifecycle() const', bindings.indexOf('std::string create_return_transaction_json(')),
);
if (!returnBinding) fail('return transaction wrapper body not found');
requireText(returnBinding, 'is_transfer_usable_for_return(td, *m_wallet)', 'return wrapper spendability gate');

const yieldSummary = wallet2.slice(
  wallet2.indexOf('bool wallet2::get_yield_summary_info('),
  wallet2.indexOf('void wallet2::process_new_transaction(', wallet2.indexOf('bool wallet2::get_yield_summary_info(')),
);
if (!yieldSummary) fail('yield-summary body not found');
requireText(yieldSummary, 'get_effective_transfer_tx(td, *this)', 'yield-summary effective transfer transaction');
requireText(yieldSummary, 'td.m_td_origin_idx >= m_transfers.size()', 'yield-summary origin bounds');
requireText(yieldSummary, 'get_effective_transfer_tx(origin_td, *this)', 'yield-summary effective origin transaction');
if (/td\.m_tx\.type|m_transfers\[td\.m_td_origin_idx\]\.m_tx\.type/.test(yieldSummary))
  fail('raw sparse transaction type in yield summary');

const offlineSign = wallet2.slice(
  wallet2.indexOf('bool wallet2::sign_tx(unsigned_tx_set &exported_txs, std::vector<wallet2::pending_tx> &txs, signed_tx_set &signed_txes)'),
  wallet2.indexOf('bool wallet2::sign_tx(unsigned_tx_set &exported_txs, const std::string &signed_filename', wallet2.indexOf('bool wallet2::sign_tx(unsigned_tx_set &exported_txs, std::vector<wallet2::pending_tx> &txs, signed_tx_set &signed_txes)')),
);
if (!offlineSign) fail('offline sign body not found');
requireText(offlineSign, 'selected_transfer_indices', 'offline selected-transfer authority set');
requireText(offlineSign, 'has_transfer_spend_authority(td, *this)', 'offline signing authority gate');
requireText(offlineSign, 'get_effective_transfer_key_image(td, *this)', 'offline effective key image');
requireText(offlineSign, 'signed_txes.key_images[i] = effective_key_image', 'offline effective key-image serialization');
if (/signed_txes\.key_images\[i\]\s*=\s*m_transfers\[i\]\.m_key_image/.test(offlineSign))
  fail('raw sparse key image serialized by offline sign');

const keyImageExport = wallet2.slice(
  wallet2.indexOf('std::pair<uint64_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> wallet2::export_key_images(bool all) const'),
  wallet2.indexOf('uint64_t wallet2::import_key_images(const std::string &filename', wallet2.indexOf('std::pair<uint64_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> wallet2::export_key_images(bool all) const')),
);
if (!keyImageExport) fail('key-image export body not found');
requireText(keyImageExport, 'get_effective_transfer_tx(td, *this)', 'key-image export effective transaction');
requireText(keyImageExport, 'carrot::is_carrot_transaction_v1(*effective_tx)', 'key-image export Carrot fail-closed gate');
requireText(keyImageExport, 'td.m_internal_output_index >= effective_tx->vout.size()', 'key-image export output bounds');
requireText(keyImageExport, 'get_output_public_key(', 'key-image export effective output key');
requireText(keyImageExport, 'get_tx_pub_key_from_extra(*effective_tx, td.m_pk_index)', 'key-image export effective tx pubkey');
requireText(keyImageExport, 'get_additional_tx_pub_keys_from_extra(*effective_tx)', 'key-image export effective additional keys');
requireText(keyImageExport, 'resolve_transfer_origin_data(td, *this, od)', 'key-image export origin resolver');
requireText(keyImageExport, 'has_transfer_spend_authority(td, *this)', 'key-image export authority gate');
requireText(keyImageExport, 'get_effective_transfer_key_image(td, *this)', 'key-image export effective key image');
if (/td\.get_public_key\(\)|td\.m_tx\.(?:extra|vout)/.test(keyImageExport))
  fail('raw sparse transfer context in key-image export');
if (/assert\(false\)/.test(keyImageExport))
  fail('unconditional assertion in key-image export');

const keyImageImportSigned = wallet2.slice(
  wallet2.indexOf('uint64_t wallet2::import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>> &signed_key_images'),
  wallet2.indexOf('bool wallet2::import_key_images(std::vector<crypto::key_image> key_images', wallet2.indexOf('uint64_t wallet2::import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>> &signed_key_images')),
);
if (!keyImageImportSigned) fail('signed key-image import body not found');
requireText(keyImageImportSigned, 'get_effective_transfer_tx(td, *this)', 'signed key-image import effective transaction');
requireText(keyImageImportSigned, 'carrot::is_carrot_transaction_v1(*effective_tx)', 'signed key-image import Carrot fail-closed gate');
requireText(keyImageImportSigned, 'get_output_public_key(', 'signed key-image import effective output key');
requireText(keyImageImportSigned, 'get_effective_transfer_key_image(td, *this)', 'signed key-image import effective key image');
requireText(keyImageImportSigned, 'has_validated_transfer_spend_authority(td, *this)', 'signed key-image import metadata consistency');
requireText(keyImageImportSigned, 'pending_key_image_owners', 'signed key-image import batch preflight');
requireRegex(
  keyImageImportSigned,
  /key_image == crypto::key_image\{\}[\s\S]*?existing_key_image_it = m_key_images\.find\(key_image\)/,
  'signed key-image zero rejection before cache lookup',
);
requireRegex(
  keyImageImportSigned,
  /existing_key_image_it = m_key_images\.find\(key_image\)[\s\S]*?existing_key_image_it->second != n \+ offset[\s\S]*?pending_key_image_owners[\s\S]*?PERF_TIMER_START\(import_key_images_B\)/,
  'signed key-image collision/duplicate preflight before mutation',
);
if (/td\.get_public_key\(\)/.test(keyImageImportSigned))
  fail('raw sparse output accessor in signed key-image import');

const keyImageImportRaw = wallet2.slice(
  wallet2.indexOf('bool wallet2::import_key_images(std::vector<crypto::key_image> key_images'),
  wallet2.indexOf('bool wallet2::import_key_images(signed_tx_set & signed_tx', wallet2.indexOf('bool wallet2::import_key_images(std::vector<crypto::key_image> key_images')),
);
if (!keyImageImportRaw) fail('raw key-image import body not found');
requireText(keyImageImportRaw, 'imported_key_image == crypto::key_image{}', 'zero key-image import marker');
requireText(keyImageImportRaw, 'get_effective_transfer_key_image(td, *this)', 'raw key-image import effective key image');
requireText(keyImageImportRaw, 'has_validated_transfer_spend_authority(td, *this)', 'raw key-image import metadata consistency');
requireText(keyImageImportRaw, 'get_effective_transfer_tx(td, *this)', 'raw key-image import effective transaction');
requireText(keyImageImportRaw, 'get_output_public_key(', 'raw key-image import effective output key');
requireText(keyImageImportRaw, 'pending_key_image_owners', 'raw key-image import batch preflight');
requireRegex(
  keyImageImportRaw,
  /pending_key_image_owners\.reserve[\s\S]*?existing_key_image_it = m_key_images\.find\(imported_key_image\)[\s\S]*?pending_key_image_owners\[imported_key_image\][\s\S]*?for \(size_t ki_idx = 0; ki_idx < key_images\.size\(\); \+\+ki_idx\)/,
  'raw key-image collision/duplicate preflight before mutation',
);
if (/td\.get_public_key\(\)/.test(keyImageImportRaw))
  fail('raw sparse output accessor in raw key-image import');

const frozenMultisig = wallet2.slice(
  wallet2.indexOf('bool wallet2::frozen(const multisig_tx_set& txs) const'),
  wallet2.indexOf('void wallet2::freeze(const crypto::key_image &ki)', wallet2.indexOf('bool wallet2::frozen(const multisig_tx_set& txs) const')),
);
if (!frozenMultisig) fail('multisig frozen body not found');
requireText(frozenMultisig, 'get_effective_transfer_key_image(td, *this)', 'frozen multisig effective key image');
if (/kis_to_sign\.count\(td\.m_key_image\)/.test(frozenMultisig))
  fail('raw key image in multisig frozen comparison');

const spendsOurs = wallet2.slice(
  wallet2.indexOf('bool wallet2::spends_one_of_ours('),
  wallet2.indexOf('bool wallet2::get_pricing_record(', wallet2.indexOf('bool wallet2::spends_one_of_ours(')),
);
if (!spendsOurs) fail('spends_one_of_ours body not found');
requireText(spendsOurs, 'find_transfer_index_by_effective_key_image(', 'spends-one-of-ours effective lookup helper');
if (/m_key_images\.find\(in_to_key\.k_image\)/.test(spendsOurs))
  fail('raw key-image map lookup in spends_one_of_ours');

const pendingRelease = wallet2.slice(
  wallet2.indexOf('void wallet2::process_unconfirmed_transfer('),
  wallet2.indexOf('void wallet2::update_pool_state(', wallet2.indexOf('void wallet2::process_unconfirmed_transfer(')),
);
if (!pendingRelease) fail('pending-transfer release body not found');
requireText(pendingRelease, 'has_transfer_spend_authority(td, *this)', 'failed-pending authority gate');
requireText(pendingRelease, 'get_effective_transfer_key_image(td, *this)', 'failed-pending effective key image');
requireText(pendingRelease, 'td.m_spent_height == 0', 'failed-pending optimistic-only release');
if (/td\.m_key_image\s*==\s*tx_in_to_key\.k_image/.test(pendingRelease))
  fail('raw key image in failed-pending release');

const detach = wallet2.slice(
  wallet2.indexOf('wallet2::detached_blockchain_data wallet2::detach_blockchain('),
  wallet2.indexOf('void wallet2::rescan_blockchain(', wallet2.indexOf('wallet2::detached_blockchain_data wallet2::detach_blockchain(')),
);
if (!detach) fail('detach-blockchain body not found');
requireRegex(
  detach,
  /for \(auto it_ki = m_key_images\.begin\(\);[\s\S]*?it_ki->second >= i_start[\s\S]*?m_key_images\.erase\(it_ki\)/,
  'detach removes every key-image cache alias owned by detached suffix',
);
if (/m_key_images\.find\(m_transfers\[i\]\.m_key_image\)/.test(detach))
  fail('raw key-image map erase in detach');

process.stdout.write('spend-authority source gate: ok\n');
