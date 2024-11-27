// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "tx_pool.h"

#include <algorithm>
#include <unordered_set>
#include <variant>
#include <vector>

#include "blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/locked_txn.h"
#include "common/boost_serialization_helper.h"
#include "common/exception.h"
#include "common/lock.h"
#include "common/median.h"
#include "common/util.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"
#include "cryptonote_core/ethereum_transactions.h"
#include "cryptonote_core/service_node_list.h"
#include "cryptonote_tx_utils.h"
#include "epee/warnings.h"

DISABLE_VS_WARNINGS(4244 4345 4503)  //'boost::foreach_detail_::or_' : decorated name length
                                     // exceeded, name was truncated

using namespace crypto;

namespace cryptonote {

static auto logcat = log::Cat("txpool");

namespace {
    // TODO: constants such as these should at least be in the header,
    //       but probably somewhere more accessible to the rest of the
    //       codebase.  As it stands, it is at best nontrivial to test
    //       whether or not changing these parameters (or adding new)
    //       will work correctly.
    time_t const MIN_RELAY_TIME =
            (60 * 5);  // only start re-relaying transactions after that many seconds
    time_t const MAX_RELAY_TIME = (60 * 60 * 4);  // at most that many seconds between resends

    // a kind of increasing backoff within min/max bounds
    uint64_t get_relay_delay(time_t now, time_t received) {
        time_t d = (now - received + MIN_RELAY_TIME) / MIN_RELAY_TIME * MIN_RELAY_TIME;
        if (d > MAX_RELAY_TIME)
            d = MAX_RELAY_TIME;
        return d;
    }

    uint64_t get_transaction_weight_limit(hf version) {
        // from v10, bulletproofs, limit a tx to 50% of the minimum block weight
        if (version >= hf::hf10_bulletproofs)
            return get_min_block_weight(version) / 2 - COINBASE_BLOB_RESERVED_SIZE;
        else
            return get_min_block_weight(version) - COINBASE_BLOB_RESERVED_SIZE;
    }
}  // namespace
//---------------------------------------------------------------------------------
// warning: bchs is passed here uninitialized, so don't do anything but store it
tx_memory_pool::tx_memory_pool(Blockchain& bchs) :
        m_cookie(0),
        m_blockchain(bchs),
        m_txpool_max_weight(DEFAULT_MEMPOOL_MAX_WEIGHT),
        m_txpool_weight(0) {}
//---------------------------------------------------------------------------------
bool tx_memory_pool::have_duplicated_non_standard_tx(
        transaction const& tx, hf hard_fork_version) const {

    std::vector<transaction> pool_txs;
    get_transactions(pool_txs);

    auto& service_node_list = m_blockchain.service_node_list;
    if (tx.type == txtype::state_change) {
        tx_extra_service_node_state_change state_change;
        if (!get_service_node_state_change_from_tx_extra(
                    tx.extra, state_change, hard_fork_version)) {
            log::error(
                    logcat,
                    "Could not get service node state change from tx: {}, possibly corrupt tx in "
                    "your blockchain, rejecting malformed state change",
                    get_transaction_hash(tx));
            return false;
        }

        crypto::public_key service_node_to_change;
        auto const quorum_type = service_nodes::quorum_type::obligations;
        auto const quorum_group = service_nodes::quorum_group::worker;

        // NOTE: We can fail to resolve a public key if we are popping blocks greater than the
        // number of quorums we store.
        bool const can_resolve_quorum_pubkey = service_node_list.get_quorum_pubkey(
                quorum_type,
                quorum_group,
                state_change.block_height,
                state_change.service_node_index,
                service_node_to_change);

        for (const transaction& pool_tx : pool_txs) {
            if (pool_tx.type != txtype::state_change)
                continue;

            tx_extra_service_node_state_change pool_tx_state_change;
            if (!get_service_node_state_change_from_tx_extra(
                        pool_tx.extra, pool_tx_state_change, hard_fork_version)) {
                log::info(
                        logcat,
                        "Could not get service node state change from tx: {}, possibly corrupt tx "
                        "in the pool",
                        get_transaction_hash(pool_tx));
                continue;
            }

            if (hard_fork_version >= hf::hf12_checkpointing) {
                crypto::public_key service_node_to_change_in_the_pool;
                bool same_service_node = false;
                if (can_resolve_quorum_pubkey && service_node_list.get_quorum_pubkey(
                                                         quorum_type,
                                                         quorum_group,
                                                         pool_tx_state_change.block_height,
                                                         pool_tx_state_change.service_node_index,
                                                         service_node_to_change_in_the_pool)) {
                    same_service_node =
                            (service_node_to_change == service_node_to_change_in_the_pool);
                } else {
                    same_service_node = (state_change == pool_tx_state_change);
                }

                if (same_service_node && pool_tx_state_change.state == state_change.state)
                    return true;
            } else {
                if (state_change == pool_tx_state_change)
                    return true;
            }
        }
    } else if (tx.type == txtype::key_image_unlock) {
        tx_extra_tx_key_image_unlock unlock;
        if (!cryptonote::get_field_from_tx_extra(tx.extra, unlock)) {
            log::error(
                    logcat,
                    "Could not get key image unlock from tx: {}, tx to add is possibly invalid, "
                    "rejecting",
                    get_transaction_hash(tx));
            return true;
        }

        for (const transaction& pool_tx : pool_txs) {
            if (pool_tx.type != tx.type)
                continue;

            tx_extra_tx_key_image_unlock pool_unlock;
            if (!cryptonote::get_field_from_tx_extra(pool_tx.extra, pool_unlock)) {
                log::info(
                        logcat,
                        "Could not get key image unlock from tx: {}, possibly corrupt tx in the "
                        "pool",
                        get_transaction_hash(tx));
                return true;
            }

            if (unlock == pool_unlock) {
                log::info(
                        logcat,
                        "New TX: {}, has TX: {} from the pool that is requesting to unlock the "
                        "same key image already.",
                        get_transaction_hash(tx),
                        get_transaction_hash(pool_tx));
                return true;
            }
        }

    } else if (tx.type == txtype::oxen_name_system) {
        tx_extra_oxen_name_system data;
        if (!cryptonote::get_field_from_tx_extra(tx.extra, data)) {
            log::error(
                    logcat,
                    "Could not get acquire name service from tx: {}, tx to add is possibly "
                    "invalid, rejecting",
                    get_transaction_hash(tx));
            return true;
        }

        for (const transaction& pool_tx : pool_txs) {
            if (pool_tx.type != tx.type)
                continue;

            tx_extra_oxen_name_system pool_data;
            if (!cryptonote::get_field_from_tx_extra(pool_tx.extra, pool_data)) {
                log::info(
                        logcat,
                        "Could not get acquire name service from tx: {}, possibly corrupt tx in "
                        "the pool",
                        get_transaction_hash(tx));
                return true;
            }

            if (data.type == pool_data.type && data.name_hash == pool_data.name_hash) {
                log::info(
                        logcat,
                        "New TX: {}, has TX: {} from the pool that is requesting the same ONS "
                        "entry already.",
                        get_transaction_hash(tx),
                        get_transaction_hash(pool_tx));
                return true;
            }
        }
    } else if (is_l2_event_tx(tx.type)) {
        std::string fail;
        auto event = eth::extract_event(tx, &fail);
        if (std::holds_alternative<std::monostate>(event)) {
            log::error(
                    logcat,
                    "Could not extract ethereum event data from state change tx {}: {}",
                    get_transaction_hash(tx),
                    fail);
            return true;
        }

        for (const transaction& pool_tx : pool_txs) {
            if (pool_tx.type != tx.type)
                continue;

            auto pool_event = eth::extract_event(pool_tx, &fail);
            if (std::holds_alternative<std::monostate>(pool_event)) {
                log::info(
                        logcat,
                        "Could not extract L2 event from tx: {}, possibly corrupt tx in the pool",
                        get_transaction_hash(tx));
                return true;
            }

            if (event == pool_event) {
                log::info(
                        logcat,
                        "New TX: {} has TX: {} from the pool with the same L2 event.",
                        get_transaction_hash(tx),
                        get_transaction_hash(pool_tx));
                return true;
            }
        }

        std::unique_lock b_lock{m_blockchain};
        auto txid = get_transaction_hash(tx);
        if (m_blockchain.have_tx(txid)) {
            log::info(logcat, "New L2 event TX {} is already in the blockchain.", txid);
            return true;
        }

    } else {
        if (tx.type != txtype::standard && tx.type != txtype::stake) {
            // NOTE(oxen): This is a developer error. If we come across this in production, be
            // conservative and just reject
            log::error(
                    logcat,
                    "Unrecognised transaction type: {} for tx: {}",
                    tx.type,
                    get_transaction_hash(tx));
            return true;
        }
    }

    return false;
}

// Blink notes: a blink quorum member adds an incoming blink tx into the mempool to make sure it
// can be accepted, but sets it as do_not_relay initially.  If it gets added, the quorum member
// sends a signature to other quorum members.  Once enough signatures are received it updates it
// to set `do_not_relay` to false and starts relaying it (other quorum members do the same).

//---------------------------------------------------------------------------------
bool tx_memory_pool::add_tx(
        transaction& tx,
        const crypto::hash& id,
        const std::string& blob,
        size_t tx_weight,
        tx_verification_context& tvc,
        const tx_pool_options& opts,
        hf hf_version,
        uint64_t* blink_rollback_height) {
    // this should already be called with that lock, but let's make it explicit for clarity
    std::unique_lock lock{m_transactions_lock};
    if (blob.size() == 0) {
        oxen::log::error(logcat, "Could not add to txpool, blob is empty of tx: {}", id);
        throw oxen::traced<std::runtime_error>("Could not add to txpool, blob empty");
    }

    if (tx.version == txversion::v0) {
        // v0 never accepted
        log::info(logcat, "transaction version 0 is invalid");
        tvc.m_verifivation_failed = true;
        return false;
    }

    // we do not accept transactions that timed out before, unless they're
    // kept_by_block
    if (!opts.kept_by_block &&
        m_timed_out_transactions.find(id) != m_timed_out_transactions.end()) {
        // not clear if we should set that, since verifivation (sic) did not fail before, since
        // the tx was accepted before timing out.
        tvc.m_verifivation_failed = true;
        return false;
    }

    if (!check_inputs_types_supported(tx)) {
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_input = true;
        return false;
    }

    uint64_t fee, burned;

    if (!get_tx_miner_fee(tx, fee, hf_version >= feature::FEE_BURNING, &burned)) {
        // This code is a bit convoluted: the above sets `fee`, and returns false for a pre-ringct
        // tx with a too-low fee, but for ringct (v2+) txes it just sets `fee` but doesn't check it
        // and always returns true: the actual v2 tx fee amount gets tested in the check_fee call
        // below
        tvc.m_verifivation_failed = true;
        tvc.m_fee_too_low = true;
        return false;
    }

    if (hf_version < hf::hf19_reward_batching) {
        if (!opts.kept_by_block && tx.is_transfer() &&
            !m_blockchain.check_fee(tx_weight, tx.vout.size(), fee, burned, opts)) {
            tvc.m_verifivation_failed = true;
            tvc.m_fee_too_low = true;
            return false;
        }
    }

    size_t tx_weight_limit = get_transaction_weight_limit(hf_version);
    if ((!opts.kept_by_block || hf_version >= feature::PER_BYTE_FEE) &&
        tx_weight > tx_weight_limit) {
        log::info(
                logcat,
                "transaction is too heavy: {} bytes, maximum weight: {}",
                tx_weight,
                tx_weight_limit);
        tvc.m_verifivation_failed = true;
        tvc.m_too_big = true;
        return false;
    }

    {
        std::vector<crypto::hash> conflict_txs;
        bool double_spend = have_tx_keyimges_as_spent(tx, &conflict_txs);

        if (double_spend) {
            if (opts.kept_by_block) {
                // The tx came from a block popped from the chain; we keep it around even if the key
                // images are spent so that we notice the double spend *unless* the tx is
                // conflicting with one or more blink txs, in which case we drop it because it can
                // never be accepted.
                auto blink_lock = blink_shared_lock();
                double_spend = false;
                for (const auto& tx_hash : conflict_txs) {
                    if (tx_hash != id && m_blinks.count(tx_hash)) {
                        // Warn on this because it almost certainly indicates something malicious
                        log::warning(
                                logcat,
                                "Not re-adding popped/incoming tx {} to the mempool: it conflicts "
                                "with blink tx {}",
                                id,
                                tx_hash);
                        double_spend = true;
                        break;
                    }
                }
            } else if (opts.approved_blink) {
                log::debug(
                        logcat,
                        "Incoming blink tx is approved, but has {} conflicting local tx(es); "
                        "dropping conflicts",
                        conflict_txs.size());
                if (remove_blink_conflicts(id, conflict_txs, blink_rollback_height))
                    double_spend = false;
                else
                    log::error(
                            logcat,
                            "Blink error: incoming blink tx cannot be accepted as it conflicts "
                            "with checkpointed txs");
            }

            if (double_spend) {
                mark_double_spend(tx);
                log::info(logcat, "Transaction with id= {} used already spent key images", id);
                tvc.m_verifivation_failed = true;
                tvc.m_double_spend = true;
                return false;
            }
        }
    }
    if (!opts.kept_by_block && have_duplicated_non_standard_tx(tx, hf_version)) {
        mark_double_spend(tx);
        log::info(logcat, "Transaction with id= {} already has a duplicate tx for height", id);
        tvc.m_verifivation_failed = true;
        tvc.m_double_spend = true;
        tvc.m_duplicate_nonstandard = true;
        return false;
    }

    if (!m_blockchain.check_tx_outputs(tx, tvc)) {
        log::info(logcat, "Transaction with id= {} has at least one invalid output", id);
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_output = true;
        return false;
    }

    // assume failure during verification steps until success is certain
    tvc.m_verifivation_failed = true;

    time_t receive_time = time(nullptr);

    crypto::hash max_used_block_id{};
    uint64_t max_used_block_height = 0;
    cryptonote::txpool_tx_meta_t meta{};

    bool inputs_okay = check_tx_inputs(
            tx,
            id,
            max_used_block_height,
            max_used_block_id,
            tvc,
            opts.kept_by_block,
            opts.approved_blink ? blink_rollback_height : nullptr);
    tx_priority prio = is_l2_event_tx(tx.type) ? tx_priority::l2_event
                     : !tx.is_transfer()       ? tx_priority::state_change
                                               : tx_priority::standard;
    if (!inputs_okay) {
        // if the transaction was valid before (kept_by_block), then it
        // may become valid again, so ignore the failed inputs check.
        if (opts.kept_by_block) {
            meta.weight = tx_weight;
            meta.fee = fee;
            meta.kept_by_block = opts.kept_by_block;
            meta.receive_time = receive_time;
            meta.last_relayed_time = receive_time;
            meta.relayed = opts.relayed;
            meta.do_not_relay = opts.do_not_relay;
            if (is_l2_event_tx(tx.type))
                meta.l2_height = eth::extract_event_l2_height(tx).value_or(0);
            meta.double_spend_seen =
                    (have_tx_keyimges_as_spent(tx) ||
                     have_duplicated_non_standard_tx(tx, hf_version));
            try {
                m_parsed_tx_cache.insert(std::make_pair(id, tx));
                std::unique_lock b_lock{m_blockchain};
                LockedTXN lock(m_blockchain);
                m_blockchain.db().add_txpool_tx(id, blob, meta);
                if (!insert_key_images(tx, id, opts.kept_by_block))
                    return false;
                m_txs_by_priority.emplace(
                        prio, fee / (double)(tx_weight ? tx_weight : 1), receive_time, id);
                lock.commit();
            } catch (const std::exception& e) {
                log::error(logcat, "Error adding transaction to txpool: {}", e.what());
                return false;
            }
            tvc.m_verifivation_impossible = true;
            tvc.m_added_to_pool = true;
        } else {
            log::info(logcat, "tx used wrong inputs, rejected");
            tvc.m_verifivation_failed = true;
            tvc.m_invalid_input = true;
            return false;
        }
    } else {
        // update transactions container
        meta.weight = tx_weight;
        meta.kept_by_block = opts.kept_by_block;
        meta.fee = fee;
        meta.max_used_block_id = max_used_block_id;
        meta.max_used_block_height = max_used_block_height;
        meta.receive_time = receive_time;
        meta.last_relayed_time = receive_time;
        meta.relayed = opts.relayed;
        meta.do_not_relay = opts.do_not_relay;
        if (is_l2_event_tx(tx.type))
            meta.l2_height = eth::extract_event_l2_height(tx).value_or(0);
        meta.double_spend_seen = false;

        try {
            if (opts.kept_by_block)
                m_parsed_tx_cache.insert(std::make_pair(id, tx));
            std::unique_lock b_lock{m_blockchain};
            LockedTXN lock(m_blockchain);
            m_blockchain.db().remove_txpool_tx(id);
            m_blockchain.db().add_txpool_tx(id, blob, meta);
            if (!insert_key_images(tx, id, opts.kept_by_block)) {
                oxen::log::error(logcat, "Failed to insert key images for tx: ", id);
                return false;
            }
            m_txs_by_priority.emplace(
                    prio, fee / (double)(tx_weight ? tx_weight : 1), receive_time, id);
            lock.commit();
        } catch (const std::exception& e) {
            log::error(logcat, "internal error: error adding transaction to txpool: {}", e.what());
            return false;
        }
        tvc.m_added_to_pool = true;

        if ((meta.fee > 0 || prio != tx_priority::standard) && !opts.do_not_relay)
            tvc.m_should_be_relayed = true;
    }

    tvc.m_verifivation_failed = false;
    m_txpool_weight += tx_weight;

    ++m_cookie;

    log::info(
            logcat,
            "Transaction added to pool: txid {} weight: {} fee/byte: {}",
            id,
            tx_weight,
            (fee / (double)(tx_weight ? tx_weight : 1)));

    if (!opts.kept_by_block && !opts.do_not_relay)
        for (auto& notify : m_tx_notify)
            notify(id, tx, blob, opts);

    prune(id);

    return true;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::add_tx(
        transaction& tx, tx_verification_context& tvc, const tx_pool_options& opts, hf version) {
    crypto::hash h{};
    std::string bl;
    t_serializable_object_to_blob(tx, bl);
    if (bl.size() == 0 || !get_transaction_hash(tx, h))
        return false;
    return add_tx(tx, h, bl, get_transaction_weight(tx, bl.size()), tvc, opts, version);
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::add_new_blink(
        const std::shared_ptr<blink_tx>& blink_ptr,
        tx_verification_context& tvc,
        bool& blink_exists) {
    assert((bool)blink_ptr);
    std::unique_lock lock{m_transactions_lock};
    auto& blink = *blink_ptr;
    auto& tx = var::get<transaction>(blink.tx);  // will throw if just a hash w/o a transaction
    auto txhash = get_transaction_hash(tx);

    {
        auto lock = blink_shared_lock();
        blink_exists = m_blinks.count(txhash);
        if (blink_exists)
            return false;
    }

    bool approved = blink.approved();
    auto hf_version = m_blockchain.get_network_version(blink.height);
    bool result = add_tx(tx, tvc, tx_pool_options::new_blink(approved, hf_version), hf_version);
    if (result && approved) {
        auto lock = blink_unique_lock();
        m_blinks[txhash] = blink_ptr;
    } else if (!result) {
        // Adding failed, but might have failed because another thread inserted it, so check again
        // for existence of the blink
        auto lock = blink_shared_lock();
        blink_exists = m_blinks.count(txhash);
    }
    return result;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::add_existing_blink(std::shared_ptr<blink_tx> blink_ptr) {
    assert(blink_ptr && blink_ptr->approved());
    auto& ptr = m_blinks[blink_ptr->get_txhash()];
    if (ptr)
        return false;

    ptr = blink_ptr;
    return true;
}
//---------------------------------------------------------------------------------
std::shared_ptr<blink_tx> tx_memory_pool::get_blink(const crypto::hash& tx_hash) const {
    auto it = m_blinks.find(tx_hash);
    if (it != m_blinks.end())
        return it->second;
    return {};
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::has_blink(const crypto::hash& tx_hash) const {
    return m_blinks.find(tx_hash) != m_blinks.end();
}

void tx_memory_pool::keep_missing_blinks(std::vector<crypto::hash>& tx_hashes) const {
    auto lock = blink_shared_lock();
    tx_hashes.erase(
            std::remove_if(
                    tx_hashes.begin(),
                    tx_hashes.end(),
                    [this](const crypto::hash& tx_hash) { return m_blinks.count(tx_hash) > 0; }),
            tx_hashes.end());
}

std::pair<std::vector<crypto::hash>, std::vector<uint64_t>>
tx_memory_pool::get_blink_hashes_and_mined_heights() const {
    std::pair<std::vector<crypto::hash>, std::vector<uint64_t>> hnh;
    auto& hashes = hnh.first;
    auto& heights = hnh.second;
    {
        auto lock = blink_shared_lock();
        if (!m_blinks.empty()) {
            hashes.reserve(m_blinks.size());
            for (auto& b : m_blinks)
                hashes.push_back(b.first);
        }
    }

    heights = m_blockchain.get_transactions_heights(hashes);

    // Filter out (and delete from the blink pool) any blinks that are in immutable blocks
    const uint64_t immutable_height = m_blockchain.get_immutable_height();
    size_t next_good = 0;
    for (size_t i = 0; i < hashes.size(); i++) {
        if (heights[i] > immutable_height || heights[i] == 0 /* unmined mempool blink */) {
            // Swap elements into the "good" part of the list so that when we're we'll have divided
            // the vector into [0, ..., next_good-1] elements containing the parts we want to
            // return, and [next_good, ...] containing the elements to remove from blink storage.
            if (i != next_good) {
                using std::swap;
                swap(heights[i], heights[next_good]);
                swap(hashes[i], hashes[next_good]);
            }
            next_good++;
        }
    }

    if (next_good < hashes.size()) {
        auto lock = blink_unique_lock();
        for (size_t i = next_good; i < hashes.size(); i++)
            m_blinks.erase(hashes[i]);
    }
    hashes.resize(next_good);
    heights.resize(next_good);

    return hnh;
}

std::map<uint64_t, crypto::hash> tx_memory_pool::get_blink_checksums() const {
    std::map<uint64_t, crypto::hash> result;

    auto hnh = get_blink_hashes_and_mined_heights();
    auto& hashes = hnh.first;
    auto& heights = hnh.second;

    for (size_t i = 0; i < hashes.size(); i++) {
        auto it = result.lower_bound(heights[i]);
        if (it == result.end() || it->first != heights[i])
            result.emplace_hint(it, heights[i], hashes[i]);
        else
            it->second ^= hashes[i];
    }
    return result;
}

//---------------------------------------------------------------------------------
std::vector<crypto::hash> tx_memory_pool::get_mined_blinks(
        const std::set<uint64_t>& want_heights) const {
    std::vector<crypto::hash> result;

    auto hnh = get_blink_hashes_and_mined_heights();
    auto& hashes = hnh.first;
    auto& heights = hnh.second;
    for (size_t i = 0; i < heights.size(); i++) {
        if (want_heights.count(heights[i]))
            result.push_back(hashes[i]);
    }
    return result;
}

//---------------------------------------------------------------------------------
bool tx_memory_pool::remove_blink_conflicts(
        const crypto::hash& id,
        const std::vector<crypto::hash>& conflict_txs,
        uint64_t* blink_rollback_height) {
    auto bl_lock = blink_shared_lock(std::defer_lock);
    std::unique_lock bc_lock{m_blockchain, std::defer_lock};
    std::lock(bl_lock, bc_lock);

    // Since this is a signed blink tx, we want to see if we can eject any existing mempool
    // txes to make room.

    // First check to see if any of the conflicting txes is itself an approved blink as a
    // safety check (it shouldn't be possible if the network is functioning properly).
    for (const auto& tx_hash : conflict_txs) {
        if (m_blinks.count(tx_hash)) {
            log::error(
                    logcat,
                    "Blink error: incoming blink tx {} conflicts with another blink tx {}",
                    id,
                    tx_hash);
            return false;
        }
    }

    uint64_t rollback_height_needed = blink_rollback_height ? *blink_rollback_height : 0;
    std::vector<crypto::hash> mempool_txs;

    // Next make sure none of the conflicting txes are mined in immutable blocks
    auto immutable_height = m_blockchain.get_immutable_height();
    auto heights = m_blockchain.get_transactions_heights(conflict_txs);
    for (size_t i = 0; i < heights.size(); ++i) {
        log::debug(
                logcat,
                "Conflicting tx {}{}",
                conflict_txs[i],
                (heights[i] ? "mined at height " + std::to_string(heights[i]) : "in mempool"));
        if (!heights[i]) {
            mempool_txs.push_back(conflict_txs[i]);
        } else if (heights[i] > immutable_height && blink_rollback_height) {
            if (rollback_height_needed == 0 || rollback_height_needed > heights[i])
                rollback_height_needed = heights[i];
            // else already set to something at least as early as this tx
        } else
            return false;
    }

    if (!mempool_txs.empty()) {
        LockedTXN txnlock(m_blockchain);
        for (auto& tx : mempool_txs) {
            log::warning(
                    logcat,
                    "Removing conflicting tx {} from mempool for incoming blink tx {}",
                    tx,
                    id);
            if (!remove_tx(tx)) {
                log::error(
                        logcat,
                        "Internal error: Unable to clear conflicting tx {} from mempool for "
                        "incoming blink tx {}",
                        tx,
                        id);
                return false;
            }
        }
        txnlock.commit();
    }

    if (blink_rollback_height && rollback_height_needed < *blink_rollback_height) {
        log::info(
                logcat,
                "Incoming blink tx requires a rollback to the {} to un-mine conflicting "
                "transactions",
                rollback_height_needed);
        *blink_rollback_height = rollback_height_needed;
    }

    return true;
}

//---------------------------------------------------------------------------------
size_t tx_memory_pool::get_txpool_weight() const {
    std::unique_lock lock{m_transactions_lock};
    return m_txpool_weight;
}
//---------------------------------------------------------------------------------
void tx_memory_pool::set_txpool_max_weight(size_t bytes) {
    std::unique_lock lock{m_transactions_lock};
    m_txpool_max_weight = bytes;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::remove_tx(
        const crypto::hash& txid,
        const txpool_tx_meta_t* meta,
        const sorted_tx_container::iterator* stc_it) {
    const auto it = stc_it ? *stc_it : find_tx_in_sorted_container(txid);
    if (it == m_txs_by_priority.end()) {
        log::error(logcat, "Failed to find tx in txpool sorted list");
        return false;
    }

    std::string tx_blob = m_blockchain.db().get_txpool_tx_blob(txid);
    cryptonote::transaction_prefix tx;
    if (!parse_and_validate_tx_prefix_from_blob(tx_blob, tx)) {
        log::error(logcat, "Failed to parse tx from txpool");
        return false;
    }

    txpool_tx_meta_t lookup_meta;
    if (!meta) {
        if (m_blockchain.db().get_txpool_tx_meta(txid, lookup_meta))
            meta = &lookup_meta;
        else {
            log::error(logcat, "Failed to find tx in txpool");
            return false;
        }
    }

    // remove first, in case this throws, so key images aren't removed
    log::info(
            logcat,
            "Removing tx {} from txpool: weight: {}, fee/byte: {}",
            txid,
            meta->weight,
            std::get<double>(*it));
    m_blockchain.db().remove_txpool_tx(txid);
    m_txpool_weight -= meta->weight;
    remove_transaction_keyimages(tx, txid);
    m_txs_by_priority.erase(it);

    return true;
}
//---------------------------------------------------------------------------------
void tx_memory_pool::prune(const crypto::hash& skip) {
    auto blink_lock = blink_shared_lock(std::defer_lock);
    std::unique_lock tx_lock{*this, std::defer_lock};
    std::unique_lock bc_lock{m_blockchain, std::defer_lock};
    std::lock(blink_lock, tx_lock, bc_lock);
    LockedTXN lock(m_blockchain);
    bool changed = false;

    // Tries checking conditions for pruning and, if appropriate, removing the tx.
    // Returns false on failure, true for no prune wanted or a successful prune.
    auto try_pruning = [this, &skip, &changed](auto& it, bool forward) -> bool {
        try {
            const auto& txid = std::get<crypto::hash>(*it);
            txpool_tx_meta_t meta;
            if (!m_blockchain.db().get_txpool_tx_meta(txid, meta)) {
                log::error(logcat, "Failed to find tx in txpool");
                return false;
            }
            auto del_it = forward ? it++ : it--;

            // don't prune the kept_by_block ones, they're likely added because we're adding a block
            // with those don't prune blink txes don't prune the one we just added
            if (meta.kept_by_block || this->has_blink(txid) || txid == skip)
                return true;

            if (this->remove_tx(txid, &meta, &del_it)) {
                changed = true;
                return true;
            }
            return false;
        } catch (const std::exception& e) {
            log::error(logcat, "Error while pruning txpool: {}", e.what());
            return false;
        }
    };

    const auto unexpired =
            std::time(nullptr) -
            static_cast<time_t>(tools::to_seconds(MEMPOOL_PRUNE_NON_STANDARD_TX_LIFETIME));
    for (auto it = m_txs_by_priority.begin(); it != m_txs_by_priority.end();) {
        const auto prio = std::get<tx_priority>(*it);
        const auto receive_time = std::get<std::time_t>(*it);

        if (prio == tx_priority::standard || receive_time >= unexpired)
            break;

        if (!try_pruning(it, true /*forward*/))
            return;
    }

    // this will never remove the first one, but we don't care
    auto it = m_txs_by_priority.end();
    if (it != m_txs_by_priority.begin())
        it = std::prev(it);
    while (m_txpool_weight > m_txpool_max_weight && it != m_txs_by_priority.begin()) {
        if (std::get<tx_priority>(*it) != tx_priority::standard)
            break;

        if (!try_pruning(it, false /*forward*/))
            return;
    }
    lock.commit();
    if (changed)
        ++m_cookie;
    if (m_txpool_weight > m_txpool_max_weight)
        log::info(
                logcat,
                "Pool weight after pruning is still larger than limit: {}/{}",
                m_txpool_weight,
                m_txpool_max_weight);
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::insert_key_images(
        const transaction_prefix& tx, const crypto::hash& id, bool kept_by_block) {
    for (const auto& in : tx.vin) {
        CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, txin, false);
        std::unordered_set<crypto::hash>& kei_image_set = m_spent_key_images[txin.k_image];
        CHECK_AND_ASSERT_MES(
                kept_by_block || kei_image_set.size() == 0,
                false,
                "internal error: kept_by_block={}, "
                "kei_image_set.size()={}\ntxin.k_image={}\ntx_id={}",
                kept_by_block,
                kei_image_set.size(),
                txin.k_image,
                id);
        auto ins_res = kei_image_set.insert(id);
        CHECK_AND_ASSERT_MES(
                ins_res.second,
                false,
                "internal error: try to insert duplicate iterator in key_image set");
    }
    ++m_cookie;
    return true;
}
//---------------------------------------------------------------------------------
// FIXME: Can return early before removal of all of the key images.
//       At the least, need to make sure that a false return here
//       is treated properly.  Should probably not return early, however.
bool tx_memory_pool::remove_transaction_keyimages(
        const transaction_prefix& tx, const crypto::hash& actual_hash) {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    // ND: Speedup
    for (const txin_v& vi : tx.vin) {
        CHECKED_GET_SPECIFIC_VARIANT(vi, txin_to_key, txin, false);
        auto it = m_spent_key_images.find(txin.k_image);
        CHECK_AND_ASSERT_MES(
                it != m_spent_key_images.end(),
                false,
                "failed to find transaction input in key images. img={}, txid={}",
                txin.k_image,
                actual_hash);
        std::unordered_set<crypto::hash>& key_image_set = it->second;
        CHECK_AND_ASSERT_MES(
                key_image_set.size(),
                false,
                "empty key_image set, img={}, txid={}",
                txin.k_image,
                actual_hash);

        auto it_in_set = key_image_set.find(actual_hash);
        CHECK_AND_ASSERT_MES(
                it_in_set != key_image_set.end(),
                false,
                "transaction id not found in key_image set, img={}, txid={}",
                txin.k_image,
                actual_hash);
        key_image_set.erase(it_in_set);
        if (!key_image_set.size()) {
            // it is now empty hash container for this key_image
            m_spent_key_images.erase(it);
        }
    }
    ++m_cookie;
    return true;
}
tx_memory_pool::key_images_container tx_memory_pool::get_spent_key_images(bool already_locked) {
    std::unique_lock tx_lock{*this, std::defer_lock};
    std::unique_lock bc_lock{m_blockchain, std::defer_lock};
    if (!already_locked)
        std::lock(tx_lock, bc_lock);

    return m_spent_key_images;
}

//---------------------------------------------------------------------------------
bool tx_memory_pool::take_tx(
        const crypto::hash& id,
        transaction& tx,
        std::string& txblob,
        size_t& tx_weight,
        uint64_t& fee,
        bool& relayed,
        bool& do_not_relay,
        bool& double_spend_seen) {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    auto sorted_it = find_tx_in_sorted_container(id);

    try {
        LockedTXN lock(m_blockchain);
        txpool_tx_meta_t meta;
        if (!m_blockchain.db().get_txpool_tx_meta(id, meta)) {
            log::error(logcat, "Failed to find tx in txpool");
            return false;
        }
        txblob = m_blockchain.db().get_txpool_tx_blob(id);
        auto ci = m_parsed_tx_cache.find(id);
        if (ci != m_parsed_tx_cache.end()) {
            tx = ci->second;
        } else if (!parse_and_validate_tx_from_blob(txblob, tx)) {
            log::error(logcat, "Failed to parse tx from txpool");
            return false;
        } else {
            tx.set_hash(id);
        }
        tx_weight = meta.weight;
        fee = meta.fee;
        relayed = meta.relayed;
        do_not_relay = meta.do_not_relay;
        double_spend_seen = meta.double_spend_seen;

        // remove first, in case this throws, so key images aren't removed
        m_blockchain.db().remove_txpool_tx(id);
        m_txpool_weight -= tx_weight;
        remove_transaction_keyimages(tx, id);
        lock.commit();
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to remove tx from txpool: {}", e.what());
        return false;
    }

    if (sorted_it != m_txs_by_priority.end())
        m_txs_by_priority.erase(sorted_it);
    ++m_cookie;
    return true;
}
//---------------------------------------------------------------------------------
void tx_memory_pool::on_idle() {
    m_remove_stuck_tx_interval.do_call([this]() { return remove_stuck_transactions(); });
}

void tx_memory_pool::add_notify(std::function<
                                void(const crypto::hash&,
                                     const transaction&,
                                     const std::string&,
                                     const tx_pool_options&)> notify) {
    std::unique_lock lock{m_transactions_lock};
    m_tx_notify.push_back(std::move(notify));
}

//---------------------------------------------------------------------------------
sorted_tx_container::iterator tx_memory_pool::find_tx_in_sorted_container(
        const crypto::hash& id) const {
    return std::find_if(m_txs_by_priority.begin(), m_txs_by_priority.end(), [&](const auto& a) {
        return std::get<crypto::hash>(a) == id;
    });
}
//---------------------------------------------------------------------------------
// TODO: investigate whether boolean return is appropriate
bool tx_memory_pool::remove_stuck_transactions() {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    std::list<std::pair<crypto::hash, uint64_t>> remove;
    m_blockchain.db().for_all_txpool_txes(
            [this, &remove](
                    const crypto::hash& txid, const txpool_tx_meta_t& meta, const std::string*) {
                uint64_t tx_age = time(nullptr) - meta.receive_time;

                if ((tx_age > tools::to_seconds(MEMPOOL_TX_LIVETIME) && !meta.kept_by_block) ||
                    (tx_age > tools::to_seconds(MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME) &&
                     meta.kept_by_block)) {
                    log::info(
                            logcat,
                            "Tx {} removed from tx pool due to outdated, age: {}",
                            txid,
                            tx_age);
                    auto sorted_it = find_tx_in_sorted_container(txid);
                    if (sorted_it == m_txs_by_priority.end()) {
                        log::info(
                                logcat,
                                "Removing tx {} from tx pool, but it was not found in the sorted "
                                "txs container!",
                                txid);
                    } else {
                        m_txs_by_priority.erase(sorted_it);
                    }
                    m_timed_out_transactions.insert(txid);
                    remove.push_back(std::make_pair(txid, meta.weight));
                }
                return true;
            },
            false);

    if (!remove.empty()) {
        LockedTXN lock(m_blockchain);
        for (const std::pair<crypto::hash, uint64_t>& entry : remove) {
            const crypto::hash& txid = entry.first;
            try {
                std::string bd = m_blockchain.db().get_txpool_tx_blob(txid);
                cryptonote::transaction_prefix tx;
                if (!parse_and_validate_tx_prefix_from_blob(bd, tx)) {
                    log::error(logcat, "Failed to parse tx from txpool");
                    // continue
                } else {
                    // remove first, so we only remove key images if the tx removal succeeds
                    m_blockchain.db().remove_txpool_tx(txid);
                    m_txpool_weight -= entry.second;
                    remove_transaction_keyimages(tx, txid);
                }
            } catch (const std::exception& e) {
                log::warning(logcat, "Failed to remove stuck transaction: {}", txid);
                // ignore error
            }
        }
        lock.commit();
        ++m_cookie;
    }
    return true;
}
//---------------------------------------------------------------------------------
// TODO: investigate whether boolean return is appropriate
bool tx_memory_pool::get_relayable_transactions(
        std::vector<std::pair<crypto::hash, std::string>>& txs) const {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    const uint64_t now = time(NULL);
    txs.reserve(m_blockchain.db().get_txpool_tx_count());
    m_blockchain.db().for_all_txpool_txes(
            [this, now, &txs](
                    const crypto::hash& txid, const txpool_tx_meta_t& meta, const std::string*) {
                if (!meta.do_not_relay &&
                    (!meta.relayed ||
                     now - meta.last_relayed_time > get_relay_delay(now, meta.receive_time))) {
                    // if the tx is older than half the max lifetime, we don't re-relay it, to avoid
                    // a problem mentioned by smooth where nodes would flush txes at slightly
                    // different times, causing flushed txes to be re-added when received from a
                    // node which was just about to flush it
                    uint64_t max_age = tools::to_seconds(
                            meta.kept_by_block ? MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME
                                               : MEMPOOL_TX_LIVETIME);
                    if (now - meta.receive_time <= max_age / 2) {
                        try {
                            std::string bd = m_blockchain.db().get_txpool_tx_blob(txid);
                            if (meta.fee == 0) {
                                cryptonote::transaction tx;
                                if (!cryptonote::parse_and_validate_tx_from_blob(bd, tx)) {
                                    log::info(
                                            logcat,
                                            "TX in pool could not be parsed from blob, txid: {}",
                                            txid);
                                    return true;
                                }

                                if (tx.type != txtype::state_change)
                                    return true;

                                tx_verification_context tvc;
                                uint64_t max_used_block_height = 0;
                                crypto::hash max_used_block_id{};
                                if (!m_blockchain.check_tx_inputs(
                                            tx, tvc, max_used_block_id, max_used_block_height)) {
                                    log::info(
                                            logcat,
                                            "TX type: {} considered for relaying failed tx inputs "
                                            "check, txid: {}, reason: {}",
                                            tx.type,
                                            txid,
                                            print_tx_verification_context(tvc, &tx));
                                    return true;
                                }
                            }

                            txs.push_back(std::make_pair(txid, bd));
                        } catch (const std::exception& e) {
                            log::error(logcat, "Failed to get transaction blob from db");
                            // ignore error
                        }
                    }
                }
                return true;
            },
            false);
    return true;
}
//---------------------------------------------------------------------------------
int tx_memory_pool::set_relayable(const std::vector<crypto::hash>& tx_hashes) {
    int updated = 0;
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);
    LockedTXN lock(m_blockchain);
    for (auto& tx : tx_hashes) {
        try {
            txpool_tx_meta_t meta;
            if (m_blockchain.db().get_txpool_tx_meta(tx, meta) && meta.do_not_relay) {
                meta.do_not_relay = false;
                m_blockchain.db().update_txpool_tx(tx, meta);
                ++updated;
            }
        } catch (const std::exception& e) {
            log::error(logcat, "Failed to upate txpool transaction metadata: {}", e.what());
        }
    }
    lock.commit();

    return updated;
}
//---------------------------------------------------------------------------------
void tx_memory_pool::set_relayed(const std::vector<std::pair<crypto::hash, std::string>>& txs) {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    const time_t now = time(NULL);
    LockedTXN lock(m_blockchain);
    for (auto& tx : txs) {
        try {
            txpool_tx_meta_t meta;
            if (m_blockchain.db().get_txpool_tx_meta(tx.first, meta)) {
                meta.relayed = true;
                meta.last_relayed_time = now;
                m_blockchain.db().update_txpool_tx(tx.first, meta);
            }
        } catch (const std::exception& e) {
            log::error(logcat, "Failed to update txpool transaction metadata: {}", e.what());
            // continue
        }
    }
    lock.commit();
}
//---------------------------------------------------------------------------------
size_t tx_memory_pool::get_transactions_count(bool include_unrelayed_txes) const {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);
    return m_blockchain.db().get_txpool_tx_count(include_unrelayed_txes);
}
//---------------------------------------------------------------------------------
void tx_memory_pool::get_transactions(
        std::vector<transaction>& txs, bool include_unrelayed_txes) const {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    txs.reserve(m_blockchain.db().get_txpool_tx_count(include_unrelayed_txes));
    m_blockchain.db().for_all_txpool_txes(
            [&txs](const crypto::hash& txid, const txpool_tx_meta_t&, const std::string* bd) {
                transaction tx;
                if (!parse_and_validate_tx_from_blob(*bd, tx)) {
                    log::error(logcat, "Failed to parse tx from txpool");
                    // continue
                    return true;
                }
                tx.set_hash(txid);
                txs.push_back(std::move(tx));
                return true;
            },
            true,
            include_unrelayed_txes);
}
//------------------------------------------------------------------
void tx_memory_pool::get_transaction_hashes(
        std::vector<crypto::hash>& txs,
        bool include_unrelayed_txes,
        bool include_only_blinked) const {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    txs.reserve(m_blockchain.db().get_txpool_tx_count(include_unrelayed_txes));
    m_blockchain.db().for_all_txpool_txes(
            [&txs, include_only_blinked, this](
                    const crypto::hash& txid, const txpool_tx_meta_t&, const std::string*) {
                bool include_tx = true;
                if (include_only_blinked)
                    include_tx = has_blink(txid);
                if (include_tx)
                    txs.push_back(txid);
                return true;
            },
            false,
            include_unrelayed_txes);
}
//------------------------------------------------------------------
tx_memory_pool::tx_stats tx_memory_pool::get_transaction_stats(bool include_unrelayed_txes) const {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    tx_stats stats{};
    const uint64_t now = time(NULL);
    std::map<uint64_t, std::pair<uint32_t, uint64_t>> agebytes;
    stats.txs_total = m_blockchain.db().get_txpool_tx_count(include_unrelayed_txes);
    std::vector<uint32_t> weights;
    weights.reserve(stats.txs_total);
    m_blockchain.db().for_all_txpool_txes(
            [&stats, &weights, now, &agebytes](
                    const crypto::hash&, const txpool_tx_meta_t& meta, const std::string*) {
                weights.push_back(meta.weight);
                stats.bytes_total += meta.weight;
                if (!stats.bytes_min || meta.weight < stats.bytes_min)
                    stats.bytes_min = meta.weight;
                if (meta.weight > stats.bytes_max)
                    stats.bytes_max = meta.weight;
                if (!meta.relayed)
                    stats.num_not_relayed++;
                stats.fee_total += meta.fee;
                if (!stats.oldest || meta.receive_time < stats.oldest)
                    stats.oldest = meta.receive_time;
                if (meta.receive_time < now - 600)
                    stats.num_10m++;
                if (meta.last_failed_height)
                    stats.num_failing++;
                uint64_t age = now < meta.receive_time ? 0 : now - meta.receive_time;
                auto& a = agebytes[age];
                a.first++;
                a.second += meta.weight;
                if (meta.double_spend_seen)
                    ++stats.num_double_spends;
                return true;
            },
            false,
            include_unrelayed_txes);
    stats.bytes_med = tools::median(std::move(weights));
    if (stats.txs_total > 1) {
        stats.histo.resize(10);

        /* looking for 98th percentile */
        size_t end = stats.txs_total * 0.02;
        uint64_t delta, factor;
        decltype(agebytes.begin()) it;
        if (end) {
            /* If enough txs, spread the first 98% of results across
             * the first 9 bins, drop final 2% in last bin.
             */
            it = agebytes.end();
            size_t cumulative_num = 0;
            /* Since agebytes is not empty and end is nonzero, the
             * below loop can always run at least once.
             */
            do {
                --it;
                cumulative_num += it->second.first;
            } while (it != agebytes.begin() && cumulative_num < end);
            stats.histo_98pc = it->first;
            factor = 9;
            delta = it->first;
            stats.histo.resize(10);
        } else {
            /* If not enough txs, don't reserve the last slot;
             * spread evenly across all 10 bins.
             */
            stats.histo_98pc = 0;
            it = agebytes.end();
            factor = 10;
            delta = now - stats.oldest;
        }
        if (!delta)
            delta = 1;
        auto i2 = agebytes.begin();
        for (; i2 != it; i2++) {
            size_t i = (i2->first * factor - 1) / delta;
            stats.histo[i].first += i2->second.first;
            stats.histo[i].second += i2->second.second;
        }
        for (; i2 != agebytes.end(); i2++) {
            auto& h = stats.histo[factor];
            h.first += i2->second.first;
            h.second += i2->second.second;
        }
    }

    return stats;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::check_for_key_images(
        const std::vector<crypto::key_image>& key_images, std::vector<bool>& spent) const {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    spent.clear();

    for (const auto& image : key_images) {
        spent.push_back(m_spent_key_images.find(image) == m_spent_key_images.end() ? false : true);
    }

    return true;
}
//---------------------------------------------------------------------------------
int tx_memory_pool::find_transactions(
        const std::unordered_set<crypto::hash>& tx_hashes,
        std::vector<std::string>& txblobs) const {
    if (tx_hashes.empty())
        return 0;
    txblobs.reserve(txblobs.size() + tx_hashes.size());
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    int added = 0;
    for (auto& id : tx_hashes) {
        try {
            std::string txblob;
            m_blockchain.db().get_txpool_tx_blob(id, txblob);
            txblobs.push_back(std::move(txblob));
            ++added;
        } catch (...) { /* ignore */
        }
    }
    return added;
}

//---------------------------------------------------------------------------------
std::vector<std::optional<transaction>> tx_memory_pool::load_transactions(
        const std::vector<crypto::hash>& tx_hashes) const {
    std::vector<std::optional<transaction>> result;
    result.reserve(tx_hashes.size());
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    for (auto& txid : tx_hashes) {
        auto& otx = result.emplace_back();
        try {
            std::string txblob;
            m_blockchain.db().get_txpool_tx_blob(txid, txblob);
            if (!parse_and_validate_tx_from_blob(txblob, otx.emplace())) {
                log::error(logcat, "Failed to parse tx from txpool");
                otx.reset();
                continue;
            }
            otx->set_hash(txid);
        } catch (...) {
            otx.reset();
        }
    }
    return result;
}

//---------------------------------------------------------------------------------
bool tx_memory_pool::get_transaction(const crypto::hash& id, std::string& txblob) const {
    std::vector<std::string> found;
    find_transactions({{id}}, found);
    if (found.empty())
        return false;
    txblob = std::move(found[0]);
    return true;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::on_blockchain_inc(block const& blk) {
    std::unique_lock lock{m_transactions_lock};
    m_input_cache.clear();
    m_parsed_tx_cache.clear();

    std::vector<transaction> pool_txs;
    get_transactions(pool_txs);
    if (pool_txs.empty())
        return true;

    // NOTE: For transactions in the pool, on new block received, if a Service
    // Node changed state any older state changes that the node cannot
    // transition to now are invalid and cannot be used, so take them out from
    // the pool.

    // Otherwise multiple state changes can queue up until they are applicable
    // and be applied on the node.
    uint64_t const block_height = blk.get_height();
    auto& service_node_list = m_blockchain.service_node_list;
    for (transaction const& pool_tx : pool_txs) {
        tx_extra_service_node_state_change state_change;
        crypto::public_key service_node_pubkey;
        if (pool_tx.type == txtype::state_change &&
            get_service_node_state_change_from_tx_extra(
                    pool_tx.extra, state_change, blk.major_version)) {
            // TODO(oxen): PERF(oxen): On pop_blocks we return all the TXs to the
            // pool. The greater the pop_blocks, the more txs that are queued in the
            // pool, and for every subsequent block you sync, get_transactions has
            // to allocate these transactions and we have to search every
            // transaction in the pool every synced block- causing great slowdown.

            // It'd be nice to optimise this or rearchitect the way this pruning is
            // done to be smarter.

            if (state_change.block_height >=
                block_height)  // NOTE: Can occur if we pop_blocks and old popped state changes are
                               // returned to the pool.
                continue;

            if (service_node_list.get_quorum_pubkey(
                        service_nodes::quorum_type::obligations,
                        service_nodes::quorum_group::worker,
                        state_change.block_height,
                        state_change.service_node_index,
                        service_node_pubkey)) {
                crypto::hash tx_hash;
                if (!get_transaction_hash(pool_tx, tx_hash)) {
                    log::error(
                            logcat,
                            "Failed to get transaction hash from txpool to check if we can prune a "
                            "state change");
                    continue;
                }

                txpool_tx_meta_t meta;
                if (!m_blockchain.db().get_txpool_tx_meta(tx_hash, meta)) {
                    log::error(
                            logcat,
                            "Failed to get tx meta from txpool to check if we can prune a state "
                            "change");
                    continue;
                }

                if (meta.kept_by_block)  // Do not prune transaction if kept by block (belongs to
                                         // alt block, so we need incase we switch to alt-chain)
                    continue;

                std::vector<service_nodes::service_node_pubkey_info> service_node_array =
                        service_node_list.get_service_node_list_state({service_node_pubkey});
                if (service_node_array.empty() ||
                    !service_node_array[0].info->can_transition_to_state(
                            blk.major_version, state_change.block_height, state_change.state)) {
                    transaction tx;
                    std::string blob;
                    size_t tx_weight;
                    uint64_t fee;
                    bool relayed, do_not_relay, double_spend_seen;
                    take_tx(tx_hash,
                            tx,
                            blob,
                            tx_weight,
                            fee,
                            relayed,
                            do_not_relay,
                            double_spend_seen);
                }
            }
        }
    }

    return true;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::on_blockchain_dec() {
    std::unique_lock lock{m_transactions_lock};
    m_input_cache.clear();
    m_parsed_tx_cache.clear();
    return true;
}
//------------------------------------------------------------------
std::vector<uint8_t> tx_memory_pool::have_txs(const std::vector<crypto::hash>& hashes) const {
    std::vector<uint8_t> result(hashes.size(), false);
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    auto& db = m_blockchain.db();
    for (size_t i = 0; i < hashes.size(); i++)
        result[i] = db.txpool_has_tx(hashes[i]);

    return result;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::have_tx(const crypto::hash& id) const {
    return have_txs({{id}})[0];
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::have_tx_keyimges_as_spent(
        const transaction& tx, std::vector<crypto::hash>* conflicting) const {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    bool ret = false;
    for (const auto& in : tx.vin) {
        CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, tokey_in, true);  // should never fail
        auto it = m_spent_key_images.find(tokey_in.k_image);
        if (it != m_spent_key_images.end()) {
            if (!conflicting)
                return true;
            ret = true;
            conflicting->insert(conflicting->end(), it->second.begin(), it->second.end());
        }
    }
    return ret;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::have_tx_keyimg_as_spent(const crypto::key_image& key_im) const {
    std::unique_lock lock{m_transactions_lock};
    return m_spent_key_images.end() != m_spent_key_images.find(key_im);
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::check_tx_inputs(
        cryptonote::transaction& tx,
        const crypto::hash& txid,
        uint64_t& max_used_block_height,
        crypto::hash& max_used_block_id,
        tx_verification_context& tvc,
        bool kept_by_block,
        uint64_t* blink_rollback_height) const {
    if (!kept_by_block) {
        const std::unordered_map<
                crypto::hash,
                std::tuple<bool, tx_verification_context, uint64_t, crypto::hash>>::const_iterator
                i = m_input_cache.find(txid);
        if (i != m_input_cache.end()) {
            bool ret;
            std::tie(ret, tvc, max_used_block_height, max_used_block_id) = i->second;
            return ret;
        }
    }
    std::unordered_set<crypto::key_image> key_image_conflicts;

    bool ret = m_blockchain.check_tx_inputs(
            tx,
            tvc,
            max_used_block_id,
            max_used_block_height,
            blink_rollback_height ? &key_image_conflicts : nullptr,
            kept_by_block);

    if (ret && !key_image_conflicts.empty()) {
        // There are some key image conflicts, but since we have blink_rollback_height this is an
        // approved blink tx that we want to accept via rollback, if possible.

        auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);
        uint64_t immutable = m_blockchain.get_immutable_height();
        uint64_t height = m_blockchain.get_current_blockchain_height();
        bool can_fix_with_a_rollback = false;
        if (height - immutable > 100) {
            // Sanity check; if this happens checkpoints are failing and we can't guarantee blinks
            // anyway (because the blink quorums are not immutable).
            log::error(
                    logcat,
                    "Unable to scan for conflicts: blockchain checkpoints are too far back");
        } else {
            log::debug(
                    logcat,
                    "Found {} conflicting key images for blink tx {}; checking to see if we can "
                    "roll back",
                    key_image_conflicts.size(),
                    txid);
            // Check all the key images of all the blockchain transactions in blocks since the
            // immutable height, and remove any conflicts from the set of conflicts, updating the
            // rollback height as we go.  If we remove all then rolling back will work, and we can
            // accept the blink, otherwise we have to refuse it (because immutable blocks have to
            // trump a blink tx).
            //
            // This sounds expensive, but in reality the blocks since the immutable checkpoint is
            // usually only around 8-12, we do this in reverse order (conflicts are most likely to
            // be in the last block or two), and there is little incentive to actively exploit this
            // since this code is here, and even if someone did want to they'd have to also be 51%
            // attacking the network to wipe out recently mined blinks -- but that can't work
            // anyway.
            //
            std::vector<cryptonote::block> blocks;
            if (m_blockchain.get_blocks(immutable + 1, height, blocks)) {
                std::vector<cryptonote::transaction> txs;
                uint64_t earliest = height;
                for (auto it = blocks.rbegin(); it != blocks.rend(); it++) {
                    const auto& block = *it;
                    auto block_height = block.get_height();
                    txs.clear();
                    if (!m_blockchain.get_transactions(block.tx_hashes, txs)) {
                        log::error(logcat, "Unable to get transactions for block {}", block.hash);
                        can_fix_with_a_rollback = false;
                        break;
                    }
                    for (const auto& tx : txs) {
                        for (const auto& in : tx.vin) {
                            if (auto* ttk = std::get_if<txin_to_key>(&in);
                                ttk && key_image_conflicts.erase(ttk->k_image)) {
                                earliest = std::min(earliest, block_height);
                                if (key_image_conflicts.empty())
                                    goto end;
                            }
                        }
                    }
                }
            end:
                if (key_image_conflicts.empty() && earliest < height && earliest > immutable) {
                    log::debug(
                            logcat, "Blink admission requires rolling back to height {}", earliest);
                    can_fix_with_a_rollback = true;
                    if (*blink_rollback_height == 0 || *blink_rollback_height > earliest)
                        *blink_rollback_height = earliest;
                }
            } else
                log::error(logcat, "Failed to retrieve blocks for trying a blink rollback!");
        }
        if (!can_fix_with_a_rollback) {
            log::warning(
                    logcat,
                    "Blink admission of {} is not possible even with a rollback: found {} key "
                    "image conflicts in immutable blocks",
                    txid,
                    key_image_conflicts.size());
            ret = false;
            tvc.m_double_spend = true;
        }
    }

    if (!kept_by_block)
        m_input_cache.insert(std::make_pair(
                txid, std::make_tuple(ret, tvc, max_used_block_height, max_used_block_id)));
    return ret;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::is_transaction_ready_to_go(
        txpool_tx_meta_t& txd,
        const crypto::hash& txid,
        const std::string& txblob,
        transaction& tx,
        hf version,
        uint64_t height,
        std::optional<uint64_t> l2_max) const {

    if (!parse_and_validate_tx_from_blob(txblob, tx))
        throw oxen::traced<std::runtime_error>{"failed to parse transaction blob"};
    tx.set_hash(txid);

    if (txd.l2_height != 0) {
        if (l2_max && txd.l2_height > *l2_max) {
            log::debug(
                    logcat,
                    "  state change from L2 height {} is not in in admissable L2 heights <= {}",
                    txd.l2_height,
                    *l2_max);
            return false;
        }
        if (!l2_max) {
            log::debug(
                    logcat,
                    "  state change from L2 height {} skipped; L2 transactions not requested "
                    "for this block",
                    txd.l2_height,
                    *l2_max);
            return false;
        }
    }

    // not the best implementation at this time, sorry :(
    // check is ring_signature already checked ?
    if (!txd.max_used_block_id) {  // not checked, lets try to check

        if (txd.last_failed_id &&
            m_blockchain.get_current_blockchain_height() > txd.last_failed_height &&
            txd.last_failed_id == m_blockchain.get_block_id_by_height(txd.last_failed_height))
            return false;  // we already sure that this tx is broken for this height

        tx_verification_context tvc;
        if (!check_tx_inputs(tx, txid, txd.max_used_block_height, txd.max_used_block_id, tvc)) {
            txd.last_failed_height = m_blockchain.get_current_blockchain_height() - 1;
            txd.last_failed_id = m_blockchain.get_block_id_by_height(txd.last_failed_height);
            return false;
        }
    } else {
        if (txd.max_used_block_height >= m_blockchain.get_current_blockchain_height())
            return false;
        if (true) {
            // if we already failed on this height and id, skip actual ring signature check
            if (txd.last_failed_id == m_blockchain.get_block_id_by_height(txd.last_failed_height))
                return false;
            // check ring signature again, it is possible (with very small chance) that this
            // transaction become again valid
            tx_verification_context tvc;
            if (!check_tx_inputs(tx, txid, txd.max_used_block_height, txd.max_used_block_id, tvc)) {
                txd.last_failed_height = m_blockchain.get_current_blockchain_height() - 1;
                txd.last_failed_id = m_blockchain.get_block_id_by_height(txd.last_failed_height);
                return false;
            }
        }
    }

    // check for key_images collisions with blockchain, just to be sure
    if (m_blockchain.have_tx_keyimges_as_spent(tx)) {
        txd.double_spend_seen = true;
        return false;
    }

    // TODO oxen delete this after HF20 has occurred:
    if (m_blockchain.service_node_list.is_premature_unlock(
                m_blockchain.nettype(), version, height, tx))
        return false;

    // If this is an event then only include it if we have an active l2 tracker and double-check
    // that it's an event we would actually vote for, so that we don't propose a block (as a pulse
    // leader) that we would ourselves reject.  This is important for purge pseudo-events (which can
    // go into the mempool but might be affected by subsequent SN changes that no longer warrant its
    // inclusion), but could also matter in weird cases (and never hurts) for other events.
    if (is_l2_event_tx(tx.type)) {
        auto* l2_tracker = m_blockchain.maybe_l2_tracker();
        if (!l2_tracker ||
            !std::visit(
                    [&l2_tracker](const auto& e) { return l2_tracker->get_vote_for(e); },
                    eth::extract_event(tx)))
            return false;
    }

    // transaction is ok.
    return true;
}
//---------------------------------------------------------------------------------
/**
 * @brief check if any of a transaction's spent key images are present in a given set
 *
 * @param kic the set of key images to check against
 * @param tx the transaction to check
 *
 * @return true if any key images present in the set, otherwise false
 */
static bool have_key_images(
        const std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx) {
    for (size_t i = 0; i != tx.vin.size(); i++) {
        CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], txin_to_key, itk, false);
        if (k_images.count(itk.k_image))
            return true;
    }
    return false;
}
//---------------------------------------------------------------------------------

/**
 * @brief append the key images from a transaction to the given set
 *
 * @param kic the set of key images to append to
 * @param tx the transaction
 *
 * @return false if any append fails, otherwise true
 */
static bool append_key_images(
        std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx) {
    for (size_t i = 0; i != tx.vin.size(); i++) {
        CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], txin_to_key, itk, false);
        auto i_res = k_images.insert(itk.k_image);
        CHECK_AND_ASSERT_MES(
                i_res.second,
                false,
                "internal error: key images pool cache - inserted duplicate image in set: {}",
                itk.k_image);
    }
    return true;
}
//---------------------------------------------------------------------------------
void tx_memory_pool::mark_double_spend(const transaction& tx) {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    bool changed = false;
    LockedTXN lock(m_blockchain);
    for (size_t i = 0; i != tx.vin.size(); i++) {
        CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], txin_to_key, itk, void());
        const key_images_container::const_iterator it = m_spent_key_images.find(itk.k_image);
        if (it != m_spent_key_images.end()) {
            for (const crypto::hash& txid : it->second) {
                txpool_tx_meta_t meta;
                if (!m_blockchain.db().get_txpool_tx_meta(txid, meta)) {
                    log::error(logcat, "Failed to find tx meta in txpool");
                    // continue, not fatal
                    continue;
                }
                if (!meta.double_spend_seen) {
                    log::debug(logcat, "Marking {} as double spending {}", txid, itk.k_image);
                    meta.double_spend_seen = true;
                    changed = true;
                    try {
                        m_blockchain.db().update_txpool_tx(txid, meta);
                    } catch (const std::exception& e) {
                        log::error(logcat, "Failed to update tx meta: {}", e.what());
                        // continue, not fatal
                    }
                }
            }
        }
    }
    lock.commit();
    if (changed)
        ++m_cookie;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::fill_block_template(
        block& bl,
        size_t median_weight,
        uint64_t already_generated_coins,
        size_t& total_weight,
        uint64_t& raw_fee,
        uint64_t& expected_reward,
        hf version,
        uint64_t height,
        std::optional<uint64_t> l2_max) {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    total_weight = 0;
    raw_fee = 0;
    uint64_t best_reward = 0;
    size_t max_total_weight;
    if (version < feature::ETH_BLS) {
        // NOTE: Calculate base line empty block reward
        oxen_block_reward_context block_reward_context = {};
        block_reward_context.height = height;

        block_reward_parts reward_parts = {};
        if (!get_oxen_block_reward(
                    median_weight,
                    total_weight,
                    already_generated_coins,
                    version,
                    reward_parts,
                    block_reward_context)) {
            log::error(logcat, "Failed to get block reward for empty block");
            return false;
        }

        best_reward = version >= hf::hf16_pulse ? 0 /*Empty block, starts with 0 fee*/
                                                : reward_parts.base_miner;
        max_total_weight = 2 * median_weight - COINBASE_BLOB_RESERVED_SIZE;
    } else {  // HF21+
        // Before SENT, there was the "full reward" limit (300kB) and then a hard limit of double
        // that (600kB), but over 300kB a quadratic penalty applied that reduced the miner (or pulse
        // leader) tx fee reward.
        //
        // Under SENT we don't have any Oxen rewards to subtract *from* so all OXEN tx fees just get
        // burned and the 300kB block weight soft limit (before HF21) just becomes a hard limit.
        max_total_weight = BLOCK_GRANTED_FULL_REWARD_ZONE_V5 - COINBASE_BLOB_RESERVED_SIZE;
    }

    std::unordered_set<crypto::key_image> k_images;

    // Track ONS buys because we can't put more than one for the same ONS name into the same block
    // (otherwise the *block* will fail but validation won't, because validation here won't see the
    // earlier tx has having taken effect, but the block addition will).
    std::unordered_set<crypto::hash> ons_buys;

    log::debug(
            logcat,
            "Filling block template, median weight {}, {} txes in the pool",
            median_weight,
            m_txs_by_priority.size());

    LockedTXN lock(m_blockchain);

    uint64_t next_reward = 0;
    uint64_t net_fee = 0;
    bl.tx_eth_count = 0;

    for (const auto& pooltx : m_txs_by_priority) {
        const auto& txid = std::get<crypto::hash>(pooltx);
        txpool_tx_meta_t meta;
        if (!m_blockchain.db().get_txpool_tx_meta(txid, meta)) {
            log::error(logcat, "  failed to find tx meta");
            continue;
        }
        log::debug(
                logcat,
                "Considering {}, weight {}, current block weight {}/{}, current reward {}",
                txid,
                meta.weight,
                total_weight,
                max_total_weight,
                print_money(best_reward));

        // Can not exceed maximum block weight
        if (total_weight + meta.weight > max_total_weight) {
            log::debug(logcat, "  would exceed maximum block weight");
            continue;
        }

        block_reward_parts next_reward_parts = {};
        if (version < feature::ETH_BLS) {
            // We don't check any of this under SENT because we simply have a hard limit that we
            // can't exceed (see comment above).

            // NOTE: Calculate the next block reward for the block producer
            oxen_block_reward_context next_block_reward_context = {};
            next_block_reward_context.height = height;
            next_block_reward_context.fee = raw_fee + meta.fee;

            if (!get_oxen_block_reward(
                        median_weight,
                        total_weight + meta.weight,
                        already_generated_coins,
                        version,
                        next_reward_parts,
                        next_block_reward_context)) {
                log::debug(logcat, "Block reward calculation bug");
                return false;
            }

            // NOTE: Use the net fee for comparison (after penalty is applied).
            // After HF16, penalty is applied on the miner fee. Before, penalty is
            // applied on the base reward.
            if (version >= hf::hf16_pulse) {
                next_reward = next_reward_parts.miner_fee;
            } else {
                next_reward = next_reward_parts.base_miner + next_reward_parts.miner_fee;
                assert(next_reward_parts.miner_fee == raw_fee + meta.fee);
            }

            // If we're getting lower reward tx, don't include this TX
            if (next_reward < best_reward) {
                log::debug(logcat, "  would decrease reward to {}", print_money(next_reward));
                continue;
            }
        }

        std::string txblob = m_blockchain.db().get_txpool_tx_blob(txid);
        cryptonote::transaction tx;

        // Skip transactions that are not ready to be
        // included into the blockchain or that are
        // missing key images
        const cryptonote::txpool_tx_meta_t original_meta = meta;
        bool ready = false;
        try {
            ready = is_transaction_ready_to_go(meta, txid, txblob, tx, version, height, l2_max);
        } catch (const std::exception& e) {
            log::error(logcat, "Failed to check transaction readiness: {}", e.what());
            // continue, not fatal
        }
        if (memcmp(&original_meta, &meta, sizeof(meta))) {
            try {
                m_blockchain.db().update_txpool_tx(txid, meta);
            } catch (const std::exception& e) {
                log::error(logcat, "Failed to update tx meta: {}", e.what());
                // continue, not fatal
            }
        }
        if (!ready) {
            log::debug(logcat, "  not ready to go");
            continue;
        }
        if (have_key_images(k_images, tx)) {
            log::debug(logcat, "  key images already seen");
            continue;
        }
        if (tx.type == txtype::oxen_name_system) {
            // TX validation above has checked that this isn't an ONS buy for a name that is already
            // registered, but it can't check that we don't create such a conflict from trying to
            // put two conflicting registrations in the same block: when actually processing such a
            // block the second one *would* be invalid because processing the first one created it.
            //
            // We only filter buys based on name_hash here which means technically we might
            // over-filter (e.g. if there is both a session + wallet ONS) but that's not a big deal
            // (one of the two will just get delayed for a block), and perfectly figuring out
            // whether two might conflict is complicated enough that it's not worth doing here.
            cryptonote::tx_extra_oxen_name_system ons;
            if (cryptonote::get_field_from_tx_extra(tx.extra, ons) && ons.is_buying() &&
                !ons_buys.emplace(ons.name_hash).second) {

                log::debug(logcat, "  conflicting ONS buy in mempool");
                continue;
            }
        }

        bl.tx_hashes.push_back(txid);
        if (meta.l2_height > 0)
            bl.tx_eth_count++;
        total_weight += meta.weight;
        raw_fee += meta.fee;
        net_fee = next_reward_parts.miner_fee;
        best_reward = next_reward;
        append_key_images(k_images, tx);
        log::debug(
                logcat,
                "  added, new block weight {}/{}, reward {}",
                total_weight,
                max_total_weight,
                print_money(best_reward));
    }
    lock.commit();

    expected_reward = best_reward;
    log::debug(
            logcat,
            "Block template filled with {} txes, weight {}/{}, reward {} (including {} in fees)",
            bl.tx_hashes.size(),
            total_weight,
            max_total_weight,
            print_money(best_reward),
            print_money(net_fee));
    return true;
}
//---------------------------------------------------------------------------------
size_t tx_memory_pool::validate(hf version) {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    size_t tx_weight_limit = get_transaction_weight_limit(version);
    std::unordered_set<crypto::hash> remove;

    m_txpool_weight = 0;
    m_blockchain.db().for_all_txpool_txes(
            [this, &remove, tx_weight_limit](
                    const crypto::hash& txid, const txpool_tx_meta_t& meta, const std::string*) {
                m_txpool_weight += meta.weight;
                if (meta.weight > tx_weight_limit) {
                    log::info(
                            logcat,
                            "Transaction {} is too big ({} bytes), removing it from pool",
                            txid,
                            meta.weight);
                    remove.insert(txid);
                } else if (m_blockchain.have_tx(txid)) {
                    log::info(
                            logcat,
                            "Transaction {} is in the blockchain, removing it from pool",
                            txid);
                    remove.insert(txid);
                }
                return true;
            },
            false);

    size_t n_removed = 0;
    if (!remove.empty()) {
        LockedTXN lock(m_blockchain);
        for (const crypto::hash& txid : remove) {
            try {
                std::string txblob = m_blockchain.db().get_txpool_tx_blob(txid);
                cryptonote::transaction tx;
                if (!parse_and_validate_tx_from_blob(txblob, tx)) {
                    log::error(logcat, "Failed to parse tx from txpool");
                    continue;
                }
                // remove tx from db first
                m_blockchain.db().remove_txpool_tx(txid);
                m_txpool_weight -= get_transaction_weight(tx, txblob.size());
                remove_transaction_keyimages(tx, txid);
                auto sorted_it = find_tx_in_sorted_container(txid);
                if (sorted_it == m_txs_by_priority.end()) {
                    log::info(
                            logcat,
                            "Removing tx {} from tx pool, but it was not found in the sorted txs "
                            "container!",
                            txid);
                } else {
                    m_txs_by_priority.erase(sorted_it);
                }
                ++n_removed;
            } catch (const std::exception& e) {
                log::error(logcat, "Failed to remove invalid tx from pool");
                // continue
            }
        }
        lock.commit();
    }
    if (n_removed > 0)
        ++m_cookie;
    return n_removed;
}
//---------------------------------------------------------------------------------
bool tx_memory_pool::init(size_t max_txpool_weight) {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    m_txpool_max_weight = max_txpool_weight ? max_txpool_weight : DEFAULT_MEMPOOL_MAX_WEIGHT;
    m_txs_by_priority.clear();
    m_spent_key_images.clear();
    m_txpool_weight = 0;
    std::vector<crypto::hash> remove;

    // first add the not kept by block, then the kept by block,
    // to avoid rejection due to key image collision
    for (int pass = 0; pass < 2; ++pass) {
        const bool kept = pass == 1;
        bool r = m_blockchain.db().for_all_txpool_txes(
                [this, &remove, kept](
                        const crypto::hash& txid,
                        const txpool_tx_meta_t& meta,
                        const std::string* bd) {
                    if (kept != (bool)meta.kept_by_block)
                        return true;
                    cryptonote::transaction_prefix tx;
                    if (!parse_and_validate_tx_prefix_from_blob(*bd, tx)) {
                        log::warning(logcat, "Failed to parse tx from txpool, removing");
                        remove.push_back(txid);
                        return true;
                    }
                    if (!insert_key_images(tx, txid, meta.kept_by_block)) {
                        log::error(logcat, "Failed to insert key images from txpool tx");
                        return false;
                    }

                    tx_priority prio = is_l2_event_tx(tx.type) ? tx_priority::l2_event
                                     : !tx.is_transfer()       ? tx_priority::state_change
                                                               : tx_priority::standard;
                    m_txs_by_priority.emplace(
                            prio, meta.fee / (double)meta.weight, meta.receive_time, txid);
                    m_txpool_weight += meta.weight;
                    return true;
                },
                true);
        if (!r)
            return false;
    }
    if (!remove.empty()) {
        LockedTXN lock(m_blockchain);
        for (const auto& txid : remove) {
            try {
                m_blockchain.db().remove_txpool_tx(txid);
            } catch (const std::exception& e) {
                log::warning(logcat, "Failed to remove corrupt transaction: {}", txid);
                // ignore error
            }
        }
        lock.commit();
    }

    m_cookie = 0;

    // Ignore deserialization error
    return true;
}

//---------------------------------------------------------------------------------
bool tx_memory_pool::deinit() {
    return true;
}
}  // namespace cryptonote
