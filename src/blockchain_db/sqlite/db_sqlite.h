// Copyright (c) 2021, The Oxen Project
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

#pragma once

#include <SQLiteCpp/SQLiteCpp.h>
#include <cryptonote_basic/cryptonote_basic_impl.h>  // cryptonote::address_parse_info...
#include <cryptonote_config.h>
#include <cryptonote_core/service_node_list.h>  // service_node_list::state_t...

#include <filesystem>
#include <sqlitedb/database.hpp>
#include <string>

namespace cryptonote {

using block_payments = std::
        unordered_map<std::variant<eth::address, cryptonote::account_public_address>, uint64_t>;

class BlockchainSQLite : public db::Database {
  public:
    explicit BlockchainSQLite(cryptonote::network_type nettype, std::filesystem::path db_path);
    BlockchainSQLite(const BlockchainSQLite&) = delete;

    // Database management functions. Should be called on creation of BlockchainSQLite
    void create_schema();
    void upgrade_schema();
    void reset_database();

    // Update the height stored in the SQL DB that indicates the last block height that this DB has
    // synchronised to in.
    void update_height(uint64_t new_height);

    enum class PaymentTableType {
        Nil,      // Table containing current state
        Archive,  // Table containing state stored periodically at HISTORY_ARCHIVE_INTERVAL
                  // intervals
        Recent,   // Table containing state stored from within the last HISTORY_RECENT_KEEP_WINDOW
    };

    // Rewinds the SQL DB to the specified height. This function is called internally by the SNL on
    // detach.
    void blockchain_detached(PaymentTableType type, uint64_t height);

    // Return the number of rows for the desired batched payments accrued table. The row count will
    // be for the 'height' specified. 'height' is ignored if type is nil as the default accrued
    // table only stores state for the current DB's height already. If 'height' is null then the row
    // count of the entire table will be returned.
    size_t batch_payments_accrued_row_count(PaymentTableType type, const uint64_t* height);

    // Add payments to the specified addresses to the SQL rewards table. The function throws if
    // insertion into the DB fails.
    void add_sn_rewards(const block_payments& payments);

  private:
    // This function throws if adding the rewards to the SQL tables for 'block'
    // fails.
    void reward_handler(
            const cryptonote::block& block,
            const service_nodes::service_node_list::state_t& service_nodes_state,
            block_payments payments = {});

    block_payments get_delayed_payments(uint64_t height);

    std::unordered_map<account_public_address, std::string> address_str_cache;
    std::pair<hf, cryptonote::address_parse_info> parsed_governance_addr = {hf::none, {}};
    std::string get_address_str(const cryptonote::batch_sn_payment& addr);
    std::pair<int, std::string> get_address_str(
            const std::variant<eth::address, cryptonote::account_public_address>& addr,
            uint64_t batching_interval);
    std::mutex address_str_cache_mutex;

    bool table_exists(const std::string& name);
    bool trigger_exists(const std::string& name);

  public:
    // Retrieves the amount (in atomic SENT) that has been accrued to the Ethereum `address`.
    // Returns the current height and the atomic lifetime value that the address is owed.  (Note
    // that, unlike Oxen addresses, these rewards never reset to zero; but rather the rewards
    // contract keeps track of the current paid and current total and pays out the difference).
    std::pair<uint64_t, uint64_t> get_accrued_rewards(const eth::address& address);

    // Retrieves the amount (in atomic OXEN) that has been accrued but not yet paid out to the Oxen
    // wallet `address`.  Returns the current height and the atomic unpaid amount that the address
    // is owed.
    std::pair<uint64_t, uint64_t> get_accrued_rewards(const account_public_address& address);

    // Returns the amount (in atomic SENT) that has been accrued to the Ethereum `address` as of the
    // given recent block height `at_height`.  Returns nullopt if `at_height` is higher than the
    // current block height, or lower than the oldest stored recent height (see network_config's
    // STORE_RECENT_REWARDS;, otherwise returns the balance.
    std::optional<uint64_t> get_accrued_rewards(const eth::address& address, uint64_t at_height);

    // Returns the amount (in atomic OXEN) that has been accrued to the Oxen wallet `address` as of
    // the given recent block height `at_height`.  Returns nullopt if `at_height` is higher than the
    // known height, or lower than the stored recent heights (see network_config's
    // STORE_RECENT_REWARDS); otherwise returns the balance.
    std::optional<uint64_t> get_accrued_rewards(
            const account_public_address& address, uint64_t height);

    // get_all_accrued_rewards -> queries the database for all the amount that has been accrued to
    // service nodes will return 2 vectors corresponding to the addresses and the atomic value in
    // oxen that the service nodes are owed.
    std::pair<std::vector<std::string>, std::vector<uint64_t>> get_all_accrued_rewards();

    // get_payments -> passing a block height will return an array of payments that should be
    // created in a coinbase transaction on that block given the current batching DB state.
    std::vector<cryptonote::batch_sn_payment> get_sn_payments(uint64_t block_height);

    // Takes the list of contributors from sn_info with their SN contribution amounts and will
    // calculate how much of the block rewards should be the allocated to the contributors. The
    // function will *add* the calculated amounts to the value in the given `payments`, creating new
    // entries (at value 0) as needed and adding to values that are already present.  Existing
    // values in the map are *not* cleared or replaced.
    //
    // Note that distribution_amount here is passed as milli-atomic OXEN for extra precision.
    void add_rewards(
            hf hf_version,
            uint64_t distribution_amount,
            const service_nodes::service_node_info& sn_info,
            block_payments& payments) const;

    // add/pop_block -> takes a block that contains new block rewards to be batched and added to the
    // database and/or batching payments that need to be subtracted from the database, in addition
    // it takes a reference to the service node state which it will use to calculate the individual
    // payouts. The function will then process this block add and subtracting to the batching DB
    // appropriately. This is the primary entry point for the blockchain to add to the batching
    // database. Each accepted block should call this passing in the SN list structure.
    bool add_block(
            const cryptonote::block& block,
            const service_nodes::service_node_list::state_t& service_nodes_state);

    struct exit_stake {
        eth::address addr;
        cryptonote::reward_money amount;
        uint32_t block_height;  // Block that the exit event was mined in
        uint32_t tx_index;  // Index of transaction in the block that the exit event was mined in
        uint32_t contributor_index;  // Index of the contributor in the event the exit stake is for
    };

    // Add a payment to the delayed_payments table. 'at_height' should be greater than or equal to
    // the height of the table or otherwise the payments may be deleted without taking effect. This
    // function asserts if 'at_height' does not meet this criteria.
    bool add_delayed_payments(
            std::span<const exit_stake> payments, uint64_t at_height, uint64_t delay_blocks);

    // validate_batch_payment -> used to make sure that list of miner_tx_vouts is correct. Compares
    // the miner_tx_vouts with a list previously extracted payments to make sure that the correct
    // persons are being paid.
    bool validate_batch_payment(
            const std::vector<std::pair<crypto::public_key, uint64_t>>& miner_tx_vouts,
            const std::vector<cryptonote::batch_sn_payment>& calculated_payments_from_batching_db,
            uint64_t block_height);

    // these keep track of payments made to SN operators after then payment has been made. Allows
    // for popping blocks back and knowing who got paid in those blocks. passing in a list of people
    // to be marked as paid in the paid_amounts vector. Block height will be added to the
    // batched_payments_paid database as height_paid.
    bool save_payments(uint64_t block_height, const std::vector<batch_sn_payment>& paid_amounts);
    bool delete_block_payments(uint64_t block_height);

    // Just before HF21, all pending oxen rewards for addresses not registered to transition
    // will be paid out.  At HF21, all pending oxen rewards for addresses which *are*
    // registered to transition will be converted to SENT.
    void set_rewards_hf21(const std::unordered_map<eth::address, uint64_t>& rewards);

    uint64_t height;

  protected:
    cryptonote::network_type m_nettype;
};

}  // namespace cryptonote
