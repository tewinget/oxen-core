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

#include "db_sqlite.h"

#include <common/exception.h>
#include <common/guts.h>
#include <cryptonote_basic/hardfork.h>
#include <cryptonote_config.h>
#include <cryptonote_core/blockchain.h>
#include <cryptonote_core/cryptonote_tx_utils.h>
#include <fmt/core.h>
#include <sodium.h>
#include <sqlite3.h>

#include <cassert>

namespace cryptonote {

static auto logcat = log::Cat("blockchain.db.sqlite");

BlockchainSQLite::BlockchainSQLite(
        cryptonote::network_type nettype, std::filesystem::path db_path) :
        db::Database(db_path, ""), m_nettype(nettype) {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);
    height = 0;

    if (!db.tableExists("batched_payments_accrued") || !db.tableExists("batched_payments_raw") ||
        !db.tableExists("batch_db_info")) {
        create_schema();
    }

    upgrade_schema();

    height = prepared_get<int64_t>("SELECT height FROM batch_db_info");

    uint64_t recent_count = prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued_recent");
    uint64_t recent_min_height = prepared_get<int>("SELECT MIN(height) FROM batched_payments_accrued_recent");
    uint64_t recent_max_height = prepared_get<int>("SELECT MAX(height) FROM batched_payments_accrued_recent");

    uint64_t archive_count = prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued_archive");
    uint64_t archive_min_height = prepared_get<int>("SELECT MIN(height) FROM batched_payments_accrued_archive");
    uint64_t archive_max_height = prepared_get<int>("SELECT MAX(height) FROM batched_payments_accrued_archive");

    log::info(
            globallogcat,
            "{} recent state rows [blks {}-{}], {} historical [blks {}-{}] loaded @ height: {}",
            recent_count,
            recent_min_height,
            recent_max_height,
            archive_count,
            archive_min_height,
            archive_max_height,
            height);
}

void BlockchainSQLite::create_schema() {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    auto& netconf = cryptonote::get_config(m_nettype);

    db.exec(fmt::format(
            R"(
      CREATE TABLE batched_payments_accrued(
        address VARCHAR NOT NULL,
        amount BIGINT NOT NULL,
        payout_offset INTEGER NOT NULL,
        PRIMARY KEY(address),
        CHECK(amount >= 0)
      );

      CREATE INDEX batched_payments_accrued_payout_offset_idx ON batched_payments_accrued(payout_offset);

      CREATE TRIGGER batch_payments_delete_empty AFTER UPDATE ON batched_payments_accrued
      FOR EACH ROW WHEN NEW.amount = 0 BEGIN
          DELETE FROM batched_payments_accrued WHERE address = NEW.address;
      END;

      CREATE TABLE batched_payments_raw(
        address VARCHAR NOT NULL,
        amount BIGINT NOT NULL,
        height_paid BIGINT NOT NULL,
        PRIMARY KEY(address, height_paid),
        CHECK(amount >= 0)
      );

      CREATE INDEX batched_payments_raw_height_idx ON batched_payments_raw(height_paid);

      CREATE TABLE batch_db_info(
        height BIGINT NOT NULL
      );

      INSERT INTO batch_db_info(height) VALUES(0);

      CREATE TRIGGER batch_payments_prune AFTER UPDATE ON batch_db_info
      FOR EACH ROW BEGIN
          DELETE FROM batched_payments_raw WHERE height_paid < (NEW.height - 10000);
      END;

      CREATE VIEW batched_payments_paid AS SELECT * FROM batched_payments_raw;

      CREATE TRIGGER make_payment INSTEAD OF INSERT ON batched_payments_paid
      FOR EACH ROW BEGIN
          UPDATE batched_payments_accrued SET amount = (amount - NEW.amount) WHERE address = NEW.address;
          SELECT RAISE(ABORT, 'Address not found') WHERE changes() = 0;
          INSERT INTO batched_payments_raw(address, amount, height_paid) VALUES(NEW.address, NEW.amount, NEW.height_paid);
      END;

      CREATE TRIGGER rollback_payment INSTEAD OF DELETE ON batched_payments_paid
      FOR EACH ROW BEGIN
          DELETE FROM batched_payments_raw WHERE address = OLD.address AND height_paid = OLD.height_paid;
          INSERT INTO batched_payments_accrued(address, payout_offset, amount) VALUES(OLD.address, OLD.height_paid % {}, OLD.amount)
              ON CONFLICT(address) DO UPDATE SET amount = (amount + excluded.amount);
      END;
    )",
            netconf.BATCHING_INTERVAL));

    log::debug(logcat, "Database setup complete");
}

bool BlockchainSQLite::table_exists(const std::string& table_name) {
    return prepared_get<int>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)", table_name);
}

bool BlockchainSQLite::trigger_exists(const std::string& trigger_name) {
    return prepared_get<int>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?)",
            trigger_name);
}

void BlockchainSQLite::upgrade_schema() {
    bool have_offset = false;
    SQLite::Statement msg_cols{db, "PRAGMA main.table_info(batched_payments_accrued)"};
    while (msg_cols.executeStep()) {
        auto [cid, name] = db::get<int64_t, std::string>(msg_cols);
        if (name == "payout_offset")
            have_offset = true;
    }

    SQLite::Transaction transaction{db, SQLite::TransactionBehavior::DEFERRED};
    // NOTE: Rename 'batched_payments_accrued_archive' 'archive_height' column to 'height'. This
    // unifies the height label across the batch payment, recent and archive table making querying
    // from them require less code.
    // TODO: After HF20 we can remove this code as everyone will have upgraded their schema.
    {
        bool has_deprecated_archive_height_column = false;
        SQLite::Statement msg_cols{db, "PRAGMA main.table_info(batched_payments_accrued_archive)"};
        while (msg_cols.executeStep()) {
            auto [cid, name] = db::get<int64_t, std::string>(msg_cols);
            if (name == "archive_height") {
                has_deprecated_archive_height_column = true;
                break;
            }
        }

        if (has_deprecated_archive_height_column)
            db.exec("ALTER TABLE batched_payments_accrued_archive RENAME COLUMN archive_height to height;\n");
    }

    if (!have_offset) {
        log::debug(logcat, "Adding payout_offset to batching db");
        auto& netconf = get_config(m_nettype);

        db.exec(fmt::format(
                R"(
        ALTER TABLE batched_payments_accrued ADD COLUMN payout_offset INTEGER NOT NULL DEFAULT -1;

        CREATE INDEX batched_payments_accrued_payout_offset_idx ON batched_payments_accrued(payout_offset);

        DROP TRIGGER IF EXISTS rollback_payment;
        CREATE TRIGGER rollback_payment INSTEAD OF DELETE ON batched_payments_paid
        FOR EACH ROW BEGIN
            DELETE FROM batched_payments_raw WHERE address = OLD.address AND height_paid = OLD.height_paid;
            INSERT INTO batched_payments_accrued(address, payout_offset, amount) VALUES(OLD.address, OLD.height_paid % {}, OLD.amount)
                ON CONFLICT(address) DO UPDATE SET amount = (amount + excluded.amount);
        END;
        )",
                netconf.BATCHING_INTERVAL));

        auto st = prepared_st(
                "UPDATE batched_payments_accrued SET payout_offset = ? WHERE address = ?");
        for (const auto& address : prepared_results<std::string>("SELECT address from "
                                                                 "batched_payments_accrued")) {
            cryptonote::address_parse_info addr_info{};
            cryptonote::get_account_address_from_str(addr_info, m_nettype, address);
            auto offset = static_cast<int>(addr_info.address.modulus(netconf.BATCHING_INTERVAL));
            exec_query(st, offset, address);
            st->reset();
        }

        auto count = prepared_get<int>(
                "SELECT COUNT(*) FROM batched_payments_accrued WHERE payout_offset NOT BETWEEN 0 "
                "AND ?",
                static_cast<int>(netconf.BATCHING_INTERVAL));

        if (count != 0) {
            constexpr auto error =
                    "Batching db update to add offsets failed: not all addresses were converted";
            log::error(logcat, error);
            throw oxen::traced<std::runtime_error>{error};
        }
    }

    // NOTE: Stores time-locked payments that will be paid out once
    // 'payout_height' is met. This is typically then for when SN's exit the
    // network, their stake is locked for X amount of time before the network
    // merges these payments into 'batch_payments_accrued`.
    //
    // The network will then uniformly agree to sign a signature to permit the
    // address to withdraw those tokens from the smart contract.
    if (!table_exists("delayed_payments")) {
        log::debug(logcat, "Adding delayed payments table to batching db");
        db.exec(R"(
        CREATE TABLE delayed_payments(
          eth_address       VARCHAR NOT NULL,
          amount            BIGINT NOT NULL,
          payout_height     BIGINT NOT NULL,
          entry_height      INT NOT NULL,    -- Height that the payment was added to the DB
          block_height      INT NOT NULL,    -- Height that the TX with the SN exit event was mined in
          block_tx_index    INT NOT NULL,    -- Index of the TX in the block at 'block_height'
          contributor_index INT NOT NULL,    -- Index of the contributor in a multi-contributor SN's stake
          UNIQUE            (block_height, block_tx_index, contributor_index)
          CHECK(amount >= 0),
          CHECK(payout_height > 0),
          CHECK(block_height >= 0)
        );

        CREATE INDEX delayed_payments_payout_height_idx ON delayed_payments(payout_height);
        )");
    }

    if (!trigger_exists("delayed_payments_after_blocks_removed")) {
        db.exec(R"(
        CREATE TRIGGER delayed_payments_after_blocks_removed AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height < OLD.height BEGIN
            DELETE FROM delayed_payments WHERE block_height >= NEW.height;
        END;
        )");
    }

    // NOTE: The archive table stores copies of 'batch_payments_accrued' rows at
    // intervals of STORE_LONG_TERM_STATE_INTERVAL blocks in a rolling window.
    if (!table_exists("batched_payments_accrued_archive")) {
        log::debug(logcat, "Adding archiving to batching db");
        auto& netconf = get_config(m_nettype);
        db.exec(R"(
        -- Create archive table that stores the current accrued rows every 'HISTORY_ARCHIVE_INTERVAL'
        -- blocks
        CREATE TABLE batched_payments_accrued_archive(
          address VARCHAR NOT NULL,
          amount BIGINT NOT NULL,
          payout_offset INTEGER NOT NULL,
          height BIGINT NOT NULL, -- Height that the row was generated on
          CHECK(amount >= 0),
          CHECK(height >= 0)
        );

        CREATE INDEX batched_payments_accrued_archive_height_idx ON batched_payments_accrued_archive(height);
        )");
    }

    // NOTE: The recent table stores copies of 'batch_payments_accrued' rows at
    // each height in a rolling window consisting of the past
    // 'STORE_RECENT_REWARDS' heights.
    if (!table_exists("batched_payments_accrued_recent")) {
        // This table is effectively identical to the above, but because we insert and delete on it
        // for *every* height, partitioning the recent rows in a separate table makes deletions of
        // stale rows a bit faster because we can use a simple `height < x` query rather than a much
        // more complicated (and much less indexable) condition that also worries about not deleting
        // long-term archive rows.
        log::debug(logcat, "Adding recent rewards to batching db");
        auto& netconf = get_config(m_nettype);
        db.exec(fmt::format(
                R"(
        CREATE TABLE batched_payments_accrued_recent(
          address VARCHAR NOT NULL,
          amount BIGINT NOT NULL,
          payout_offset INTEGER NOT NULL,
          height BIGINT NOT NULL,
          CHECK(amount >= 0),
          CHECK(height >= 0)
        );

        CREATE INDEX batched_payments_accrued_recent_height_idx ON batched_payments_accrued_recent(height);
        )",
                netconf.HISTORY_RECENT_KEEP_WINDOW));
    }

    // TODO: Code block can be removed after HF20 on mainnet as everyone's
    // schema's will have been upgraded. Cut and paste into the SQL schema
    // creation code
    //
    // - make_archive into `batch_payments_accrued_archive`
    // - clear_archive into `batch_payments_accrued_archive`
    // - clear_recent into `batch_payments_accrued_recent`
    // - make_recent into `batch_payments_accrued_recent`
    // - delayed_payments_prune into `delayed_payments`
    {
        auto& netconf = get_config(m_nettype);
        db.exec(R"(
        -- Keep a copy of all the rows for earnt rewards for this height if it's on an archival
        -- interval. It allows the DB to gracefully handle block re-orgs without having to
        -- recalculate from scratch.
        --
        -- We archive state at every 'HISTORY_ARCHIVE_INTERVAL' height and we prune the stored
        -- archive to encompass the past 'HISTORY_ARCHIVE_WINDOW' blocks worth of history.
        --
        -- When pruning we floor to the closest interval to make the equivalent pruning math in the
        -- SNL at 'process_block()' simple which has additional constraints.
        DROP TRIGGER IF EXISTS make_archive;
        CREATE TRIGGER make_archive AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN (NEW.height % {}) = 0 AND NEW.height > OLD.height BEGIN
            INSERT INTO batched_payments_accrued_archive SELECT *, NEW.height FROM batched_payments_accrued;
            DELETE FROM batched_payments_accrued_archive WHERE height < ((NEW.height - {}) % {});
        END;

        -- On re-org to an older height delete all archive rows that are newer than the DB's height
        DROP TRIGGER IF EXISTS clear_archive;
        CREATE TRIGGER clear_archive AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height < OLD.height BEGIN
            DELETE FROM batched_payments_accrued_archive WHERE height > NEW.height;
        END;

        -- On re-org delete all recent rows that are newer than the DB's height
        DROP TRIGGER IF EXISTS clear_recent;
        CREATE TRIGGER clear_recent AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height < OLD.height BEGIN
            DELETE FROM batched_payments_accrued_recent WHERE height > NEW.height;
        END;

        -- Saves the current accrued rewards table into the recent table for the current height
        DROP TRIGGER IF EXISTS make_recent;
        CREATE TRIGGER make_recent AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height > OLD.height BEGIN
            INSERT INTO batched_payments_accrued_recent SELECT *, NEW.height FROM batched_payments_accrued;
            DELETE FROM batched_payments_accrued_recent WHERE height < NEW.height - {};
        END;

        -- Delete old delayed payments from the DB when they are processed
        DROP TRIGGER IF EXISTS delayed_payments_prune;
        CREATE TRIGGER delayed_payments_prune AFTER UPDATE ON batch_db_info
        FOR EACH ROW BEGIN
            DELETE FROM delayed_payments WHERE payout_height < NEW.height;
        END;
        )"_format(netconf.HISTORY_ARCHIVE_INTERVAL,
                  netconf.HISTORY_ARCHIVE_KEEP_WINDOW,
                  netconf.HISTORY_ARCHIVE_INTERVAL,
                  netconf.HISTORY_RECENT_KEEP_WINDOW));
    }

    transaction.commit();
}

void BlockchainSQLite::reset_database() {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    db.exec(R"(
      DROP TABLE IF EXISTS delayed_payments;

      DROP TABLE IF EXISTS batched_payments_accrued;

      DROP TABLE IF EXISTS batched_payments_accrued_archive;

      DROP TABLE IF EXISTS batched_payments_accrued_recent;

      DROP VIEW IF EXISTS batched_payments_paid;

      DROP TABLE IF EXISTS batched_payments_raw;

      DROP TABLE IF EXISTS batch_db_info;
    )");

    create_schema();
    upgrade_schema();
    update_height(0);
    log::debug(logcat, "Database reset complete");
}

void BlockchainSQLite::update_height(uint64_t new_height) {
    log::trace(
            logcat,
            "BlockchainDB_SQLITE::{} Changing to height: {}, prev: {}",
            __func__,
            new_height,
            height);
    height = new_height;
    prepared_exec("UPDATE batch_db_info SET height = ?", static_cast<int64_t>(height));
}

void BlockchainSQLite::blockchain_detached(DetachHistoryType history, uint64_t new_height) {
    const auto& netconf = get_config(m_nettype);

    // NOTE: Execute detach
    std::string detach_label = "";
    int rows_restored = 0;
    int rows_removed = prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued");
    switch (history) {
        case DetachHistoryType::Nil: {
            reset_database();
            detach_label = " (via reset)";
        } break;

        default: {
            std::string history_table = "batched_payments_accrued_{}"_format(
                    history == DetachHistoryType::Archive ? "archive" : "recent");
            rows_restored = prepared_get<int>(
                    "SELECT COUNT(*) FROM {} WHERE height = ?"_format(history_table),
                    static_cast<int64_t>(height));
            db.exec(R"(DELETE FROM batched_payments_raw WHERE height_paid > {0};
                       DELETE FROM batched_payments_accrued;
                       DELETE FROM batched_payments_accrued_recent WHERE height > {0};
                       DELETE FROM batched_payments_accrued_archive WHERE height > {0};

                       INSERT INTO batched_payments_accrued
                       SELECT address, amount, payout_offset
                       FROM {1} WHERE height = {0};
              )"_format(new_height, history_table));

            detach_label = history == DetachHistoryType::Archive ? " (from archive history)" : " (from recent history)";
        } break;
    }

    update_height(new_height);
    log::debug(
            logcat,
            "Detach request for SQL @ {} executed to {}{} (-{} rows deleted, +{} restored)",
            new_height,
            height,
            detach_label,
            rows_removed,
            rows_restored);
}

// Must be called with the address_str_cache_mutex held!
std::string BlockchainSQLite::get_address_str(const cryptonote::batch_sn_payment& addr) {
    if (addr.eth_address)
        return "0x{:x}"_format(addr.eth_address);
    auto& address_str = address_str_cache[addr.address_info.address];
    if (address_str.empty())
        address_str =
                cryptonote::get_account_address_as_str(m_nettype, 0, addr.address_info.address);
    return address_str;
}
std::pair<int, std::string> BlockchainSQLite::get_address_str(
        const std::variant<eth::address, cryptonote::account_public_address>& addr,
        uint64_t batching_interval) {
    std::pair<int, std::string> result;
    auto& [offset, address_str] = result;
    if (auto* eth_addr = std::get_if<eth::address>(&addr)) {
        offset = 0;  // ignored for SENT
        address_str = "0x{:x}"_format(*eth_addr);
    } else {
        auto* oxen_addr = std::get_if<cryptonote::account_public_address>(&addr);
        assert(oxen_addr);
        offset = batching_interval == 0 ? 0
                                        : static_cast<int>(oxen_addr->modulus(batching_interval));
        auto& cached = address_str_cache[*oxen_addr];
        if (cached.empty())
            cached = cryptonote::get_account_address_as_str(m_nettype, 0, *oxen_addr);
        address_str = cached;
    }
    return result;
}

bool BlockchainSQLite::add_sn_rewards(const block_payments& payments) {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);
    auto insert_payment = prepared_st(
            "INSERT INTO batched_payments_accrued (address, payout_offset, amount) VALUES (?, ?, ?)"
            " ON CONFLICT (address) DO UPDATE SET amount = amount + excluded.amount");

    const auto& netconf = get_config(m_nettype);

    for (auto& [addr, amt] : payments) {
        auto [offset, address_str] = get_address_str(addr, netconf.BATCHING_INTERVAL);
        auto amount = static_cast<int64_t>(amt);
        log::trace(
                logcat,
                "Adding record for SN reward contributor {} to database with amount {}",
                address_str,
                amt);
        db::exec_query(insert_payment, address_str, offset, amount);
        insert_payment->reset();
    }

    return true;
}

bool BlockchainSQLite::subtract_sn_rewards(const block_payments& payments) {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);
    auto update_payment = prepared_st(
            "UPDATE batched_payments_accrued SET amount = (amount - ?) WHERE address = ?");

    for (auto& [addr, amt] : payments) {
        auto [offset, address_str] = get_address_str(addr, 0);
        auto result = db::exec_query(update_payment, static_cast<int64_t>(amt), address_str);
        if (!result) {
            log::error(
                    logcat,
                    "tried to subtract payment from an address that doesn't exist or has "
                    "insufficient balance: {}",
                    address_str);
            return false;
        }
        update_payment->reset();
    }

    return true;
}

std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::get_sn_payments(uint64_t block_height) {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    // <= here because we might have crap in the db that we don't clear until we actually add the HF
    // block later on.  (This is a pretty slim edge case that happened on devnet and is probably
    // virtually impossible on mainnet).
    if (m_nettype != cryptonote::network_type::FAKECHAIN &&
        block_height <=
                cryptonote::hard_fork_begins(m_nettype, hf::hf19_reward_batching).value_or(0))
        return {};

    const auto& conf = get_config(m_nettype);

    auto accrued_amounts = prepared_results<std::string_view, int64_t>(
            "SELECT address, amount FROM batched_payments_accrued WHERE payout_offset = ? AND "
            "amount >= ? ORDER BY address ASC",
            static_cast<int>(block_height % conf.BATCHING_INTERVAL),
            static_cast<int64_t>(conf.MIN_BATCH_PAYMENT_AMOUNT * BATCH_REWARD_FACTOR));

    std::vector<cryptonote::batch_sn_payment> payments;

    for (auto [address, amount] : accrued_amounts) {
        auto& p = payments.emplace_back();
        p.amount = reward_money::db_amount(
                amount / BATCH_REWARD_FACTOR * BATCH_REWARD_FACTOR); /* truncate to atomic OXEN */
        [[maybe_unused]] bool addr_ok =
                cryptonote::get_account_address_from_str(p.address_info, m_nettype, address);
        assert(addr_ok);
    }

    return payments;
}

static uint64_t get_accrued_rewards_impl(BlockchainSQLite& db, const std::string& address) {
    log::trace(logcat, "BlockchainDB_SQLITE {} for {}", __func__, address);
    auto rewards = db.prepared_maybe_get<int64_t>(
            R"(
        SELECT amount
        FROM batched_payments_accrued
        WHERE address = ?
    )",
            address);
    return static_cast<uint64_t>(rewards.value_or(0) / 1000);
}

static std::optional<uint64_t> get_accrued_rewards_at_impl(
        BlockchainSQLite& db,
        const std::string& address,
        uint64_t at_height,
        uint64_t curr_top_height) {
    log::trace(logcat, "BlockchainDB_SQLITE {} for {}", __func__, address);

    if (at_height > curr_top_height)
        return std::nullopt;
    if (at_height == curr_top_height)
        return get_accrued_rewards_impl(db, address);

    auto rewards = db.prepared_maybe_get<int64_t>(
            R"(
        SELECT amount
        FROM batched_payments_accrued_recent
        WHERE address = ? AND height = ?
    )",
            address,
            static_cast<int64_t>(at_height));
    if (!rewards) {
        // No rewards found; check to see if we actually have any recent records for that height and
        // if not, return a "don't know" nullopt value.  Otherwise we fall through and return an
        // authoritive 0 value.
        auto min_height = db.prepared_get<int64_t>(
                "SELECT COALESCE(MIN(height), 0) FROM batched_payments_accrued_recent");
        if (at_height < static_cast<uint64_t>(min_height))
            return std::nullopt;
    }
    return static_cast<uint64_t>(rewards.value_or(0) / 1000);
}

std::pair<uint64_t, uint64_t> BlockchainSQLite::get_accrued_rewards(const eth::address& address) {
    std::string address_string = fmt::format("0x{:x}", address);
    return {height, get_accrued_rewards_impl(*this, address_string)};
}

std::pair<uint64_t, uint64_t> BlockchainSQLite::get_accrued_rewards(
        const account_public_address& address) {
    std::string address_string =
            get_account_address_as_str(m_nettype, false /*subaddress*/, address);
    return {height, get_accrued_rewards_impl(*this, address_string)};
}

std::optional<uint64_t> BlockchainSQLite::get_accrued_rewards(
        const eth::address& address, uint64_t at_height) {
    std::string address_string = fmt::format("0x{:x}", address);
    return get_accrued_rewards_at_impl(*this, address_string, at_height, height);
}

std::optional<uint64_t> BlockchainSQLite::get_accrued_rewards(
        const account_public_address& address, uint64_t at_height) {
    std::string address_string =
            get_account_address_as_str(m_nettype, false /*subaddress*/, address);
    return get_accrued_rewards_at_impl(*this, address_string, at_height, height);
}

std::pair<std::vector<std::string>, std::vector<uint64_t>>
BlockchainSQLite::get_all_accrued_rewards() {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    std::pair<std::vector<std::string>, std::vector<uint64_t>> result;
    auto& [addresses, amounts] = result;

    for (auto [addr, amt] : prepared_results<std::string, int64_t>("SELECT address, amount FROM "
                                                                   "batched_payments_accrued")) {
        auto amount = static_cast<uint64_t>(amt / 1000);
        if (amount > 0) {
            addresses.push_back(std::move(addr));
            amounts.push_back(amount);
        }
    }

    return result;
}

void BlockchainSQLite::add_rewards(
        hf hf_version,
        uint64_t distribution_amount,
        const service_nodes::service_node_info& sn_info,
        block_payments& payments) const {
    // Find out how much is due for the operator: fee_portions/PORTIONS * reward
    assert(sn_info.portions_for_operator <= old::STAKING_PORTIONS);
    uint64_t operator_fee =
            mul128_div64(sn_info.portions_for_operator, distribution_amount, old::STAKING_PORTIONS);

    assert(operator_fee <= distribution_amount);

    // NOTE: Localdev does not have a cryptonote->ETH address step, so, old pre-ETH SN nodes don't
    // have an address assigned to it. This breaks tests that expect pre-ETH SN's to receive
    // funds in order to proceed.
    bool use_eth_address = hf_version >= hf::hf21_eth;
    if (use_eth_address && m_nettype == network_type::LOCALDEV) {
        if (!sn_info.operator_ethereum_address)
            use_eth_address = false;
    }

    // Pay the operator fee to the operator
    if (operator_fee > 0) {
        if (use_eth_address) {
            assert(sn_info.contributors.size());  // NOTE: Be paranoid, check contributors size
            eth::address fee_recipient = sn_info.contributors.size()
                                               ? sn_info.contributors[0].ethereum_beneficiary
                                               : sn_info.operator_ethereum_address;
            payments[fee_recipient] += operator_fee;
        } else {
            payments[sn_info.operator_address] += operator_fee;
        }
    }

    // Pay the balance to all the contributors (including the operator again)
    uint64_t total_contributed_to_sn = std::accumulate(
            sn_info.contributors.begin(),
            sn_info.contributors.end(),
            uint64_t(0),
            [](auto&& a, auto&& b) { return a + b.amount; });

    for (auto& contributor : sn_info.contributors) {
        // This calculates (contributor.amount / total_contributed_to_winner_sn) *
        // (distribution_amount - operator_fee) but using 128 bit integer math
        uint64_t c_reward = mul128_div64(
                contributor.amount, distribution_amount - operator_fee, total_contributed_to_sn);
        if (c_reward > 0) {
            // NOTE: At minimum, when we parsed the contributor if no benficiary is set, it should
            // be assigned to the ethereum address by default.
            auto& balance = use_eth_address ? payments[contributor.ethereum_beneficiary]
                                            : payments[contributor.address];
            balance += c_reward;
        }
    }
}

// Calculates block rewards, then invokes either `add_sn_rewards` (if `add`) or
// `subtract_sn_rewards` (if `!add`) to process them.
bool BlockchainSQLite::reward_handler(
        const cryptonote::block& block,
        const service_nodes::service_node_list::state_t& service_nodes_state,
        bool add,
        block_payments payments) {
    // The method we call do actually handle the change: either `add_sn_payments` if add is true,
    // `subtract_sn_payments` otherwise:
    auto add_or_subtract =
            add ? &BlockchainSQLite::add_sn_rewards : &BlockchainSQLite::subtract_sn_rewards;

    assert(block.major_version >= hf::hf19_reward_batching);

    // From here on we calculate everything in milli-atomic OXEN/SENT (i.e. thousanths of an atomic
    // unit) so that our integer math has reduced loss from integer division.
    if (block.reward > std::numeric_limits<uint64_t>::max() / BATCH_REWARD_FACTOR)
        throw oxen::traced<std::logic_error>{"Reward distribution amount is too large"};

    uint64_t block_reward = block.reward * BATCH_REWARD_FACTOR;

    std::lock_guard a_s_lock{address_str_cache_mutex};

    if (block.major_version < feature::ETH_BLS) {
        // Step 1 (pre-ETH only): Pay out the block producer their tx fees (note that, unlike the
        // below, this applies even if the SN isn't currently payable).
        constexpr uint64_t base_sn_reward = oxen::SN_REWARD_HF15 * BATCH_REWARD_FACTOR;
        if (block_reward < base_sn_reward)
            throw oxen::traced<std::logic_error>{"Invalid payment: block reward is too small"};
        if (uint64_t tx_fees = block_reward - base_sn_reward; tx_fees > 0 && block.has_pulse()) {
            auto pulse_leader = service_nodes_state.get_block_producer();
            if (!pulse_leader && !service_nodes_state.sn_list)
                // No sn_list means we're in the test suite, so to make this work, we'll use the
                // block_leader.  (NOTE: this will break if some new core_tests tries expects to
                // award batched backup pulse quorum tx fees as they'll go to the first round
                // leader, rather than the actual producer, but it isn't worth adding to every
                // single state_t to avoid that).
                pulse_leader = service_nodes_state.block_leader;

            if (pulse_leader)
                add_rewards(
                        block.major_version,
                        tx_fees,
                        *service_nodes_state.service_nodes_infos.at(pulse_leader),
                        payments);
        }
        block_reward = base_sn_reward;
    }

    // Step 2: Iterate over the payable (active for >=24h) N service nodes and pay each node 1/N
    // fraction of the total block reward.
    const auto payable_service_nodes =
            service_nodes_state.payable_service_nodes_infos(block.get_height(), m_nettype);
    const uint64_t N = payable_service_nodes.size();
    for (const auto& [node_pubkey, node_info] : payable_service_nodes)
        add_rewards(block.major_version, block_reward / N, *node_info, payments);

    // Step 3: Add Governance reward to the list
    if (m_nettype != cryptonote::network_type::FAKECHAIN &&
        block.major_version < feature::ETH_BLS) {
        if (parsed_governance_addr.first != block.major_version) {
            cryptonote::get_account_address_from_str(
                    parsed_governance_addr.second,
                    m_nettype,
                    cryptonote::get_config(m_nettype).governance_wallet_address(
                            block.major_version));
            parsed_governance_addr.first = block.major_version;
        }
        uint64_t foundation_reward =
                cryptonote::governance_reward_formula(block.major_version) * BATCH_REWARD_FACTOR;
        payments[parsed_governance_addr.second.address] += foundation_reward;
    }

    if (!(this->*add_or_subtract)(payments))
        return false;

    return true;
}

block_payments BlockchainSQLite::get_delayed_payments(uint64_t height) {
    block_payments payments;
    auto delayed_payments_st = prepared_results<std::string_view, int64_t>(
            "SELECT eth_address, amount FROM delayed_payments WHERE payout_height = ?",
            static_cast<int64_t>(height));
    for (auto [addr_str, amount] : delayed_payments_st)
        payments[tools::make_from_hex_guts<eth::address>(addr_str)] += amount;
    return payments;
}

bool BlockchainSQLite::add_block(
        const cryptonote::block& block,
        const service_nodes::service_node_list::state_t& service_nodes_state) {
    auto block_height = block.get_height();
    log::trace(logcat, "BlockchainDB_SQLITE::{} called on height: {}", __func__, block_height);

    auto hf_version = block.major_version;
    if (hf_version < hf::hf19_reward_batching) {
        update_height(block_height);
        return true;
    }

    if (block_height ==
        cryptonote::hard_fork_begins(m_nettype, hf::hf19_reward_batching).value_or(0)) {
        log::debug(logcat, "Batching of Service Node Rewards Begins");
        reset_database();
        update_height(block_height - 1);
    }

    if (block_height != height + 1) {
        log::error(
                logcat,
                "Block height ({}) out of sync with batching database ({})",
                block_height,
                (height + 1));
        return false;
    }

    // We query our own database as a source of truth to verify the blocks payments against. The
    // calculated_rewards variable contains a known good list of who should have been paid in this
    // block this only applies before the ETH BLS hard fork. After that the rewards are claimed by
    // the users when they wish
    std::vector<cryptonote::batch_sn_payment> calculated_rewards;
    if (hf_version < cryptonote::feature::ETH_BLS) {
        calculated_rewards = get_sn_payments(block_height);
    }

    // We iterate through the block's coinbase payments and build a copy of our own list of the
    // payments miner_tx_vouts this will be compared against calculated_rewards and if they match we
    // know the block is paying the correct people only.
    std::vector<std::pair<crypto::public_key, uint64_t>> miner_tx_vouts;
    if (block.miner_tx)
        for (auto& vout : block.miner_tx->vout)
            miner_tx_vouts.emplace_back(var::get<txout_to_key>(vout.target).key, vout.amount);

    try {
        SQLite::Transaction transaction{db, SQLite::TransactionBehavior::IMMEDIATE};

        // Goes through the miner transactions vouts checks they are right and marks them as paid in
        // the database
        if (!validate_batch_payment(miner_tx_vouts, calculated_rewards, block_height)) {
            return false;
        }

        if (!reward_handler(
                    block, service_nodes_state, /*add=*/true, get_delayed_payments(block_height)))
            return false;

        update_height(height + 1);

        transaction.commit();
    } catch (std::exception& e) {
        log::error(logcat, "Error adding reward payments: {}", e.what());
        return false;
    }
    return true;
}

bool BlockchainSQLite::return_staked_amount_to_user(
        std::span<const exit_stake> payments, uint64_t delay_blocks) {
    log::trace(logcat, "BlockchainSQLite::{} called", __func__);
    try {
        SQLite::Transaction transaction{db, SQLite::TransactionBehavior::IMMEDIATE};

        // Basic checks can be done here
        // if (amount > max_staked_amount)
        // throw std::logic_error{"Invalid payment: staked returned is too large"};

        std::lock_guard<std::mutex> a_s_lock{address_str_cache_mutex};

        int64_t payout_height = height + (delay_blocks > 0 ? delay_blocks : 1);
        auto insert_payment = prepared_st(
                "INSERT INTO delayed_payments (eth_address, amount, payout_height, entry_height, "
                "block_height, block_tx_index, contributor_index) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)");

        for (auto& payment : payments) {
            const auto amount = static_cast<int64_t>(payment.amount.to_db());
            const auto eth_address = "0x{:x}"_format(payment.addr);
            log::trace(
                    logcat,
                    "Adding delayed payment for SN reward contributor {} to database with amount "
                    "{}; height {}; payout height {}",
                    eth_address,
                    amount,
                    height,
                    payout_height);
            db::exec_query(
                    insert_payment,
                    eth_address,
                    amount,
                    payout_height,
                    static_cast<int64_t>(height),  // entry_height
                    payment.block_height,
                    payment.tx_index,
                    payment.contributor_index);
            insert_payment->reset();
        }

        transaction.commit();
    } catch (std::exception& e) {
        log::error(logcat, "Error returning stakes: {}", e.what());
        return false;
    }
    return true;
}

bool BlockchainSQLite::validate_batch_payment(
        const std::vector<std::pair<crypto::public_key, uint64_t>>& miner_tx_vouts,
        const std::vector<cryptonote::batch_sn_payment>& calculated_payments_from_batching_db,
        uint64_t block_height) {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    if (miner_tx_vouts.size() != calculated_payments_from_batching_db.size()) {
        log::error(
                logcat,
                "Length of batch payments ({}) does not match block vouts ({})",
                calculated_payments_from_batching_db.size(),
                miner_tx_vouts.size());
        return false;
    }

    uint64_t total_oxen_payout_in_our_db = std::accumulate(
            calculated_payments_from_batching_db.begin(),
            calculated_payments_from_batching_db.end(),
            uint64_t(0),
            [](auto&& a, auto&& b) { return a + b.coin_amount(); });
    uint64_t total_oxen_payout_in_vouts = 0;
    std::vector<batch_sn_payment> finalised_payments;
    cryptonote::keypair const deterministic_keypair =
            cryptonote::get_deterministic_keypair_from_height(block_height);
    for (size_t vout_index = 0; vout_index < miner_tx_vouts.size(); vout_index++) {
        const auto& [pubkey, amt] = miner_tx_vouts[vout_index];
        auto amount = reward_money::coin_amount(amt);
        const auto& from_db = calculated_payments_from_batching_db[vout_index];
        if (amount.to_db() != from_db.amount.to_db()) {
            log::error(
                    logcat,
                    "Batched payout amount incorrect. Should be {}, not {}",
                    from_db.amount.to_db(),
                    amount.to_db());
            return false;
        }
        crypto::public_key out_eph_public_key{};
        if (!cryptonote::get_deterministic_output_key(
                    from_db.address_info.address,
                    deterministic_keypair,
                    vout_index,
                    out_eph_public_key)) {
            log::error(logcat, "Failed to generate output one-time public key");
            return false;
        }
        if (tools::view_guts(pubkey) != tools::view_guts(out_eph_public_key)) {
            log::error(logcat, "Output ephemeral public key does not match");
            return false;
        }
        total_oxen_payout_in_vouts += amount.to_coin();
        finalised_payments.emplace_back(from_db.address_info, amount);
    }
    if (total_oxen_payout_in_vouts != total_oxen_payout_in_our_db) {
        log::error(
                logcat,
                "Total batched payout amount incorrect. Should be {}, not {}",
                total_oxen_payout_in_our_db,
                total_oxen_payout_in_vouts);
        return false;
    }

    return save_payments(block_height, finalised_payments);
}

bool BlockchainSQLite::save_payments(
        uint64_t block_height, const std::vector<batch_sn_payment>& paid_amounts) {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    auto select_sum = prepared_st("SELECT amount from batched_payments_accrued WHERE address = ?");

    auto update_paid = prepared_st(
            "INSERT INTO batched_payments_paid (address, amount, height_paid) VALUES (?,?,?)");

    std::lock_guard a_s_lock{address_str_cache_mutex};

    for (const auto& payment : paid_amounts) {
        const auto address_str = get_address_str(payment);
        if (auto maybe_amount = db::exec_and_maybe_get<int64_t>(select_sum, address_str)) {
            // Truncate the thousanths amount to an atomic OXEN:
            auto amount = static_cast<uint64_t>(*maybe_amount) / BATCH_REWARD_FACTOR *
                          BATCH_REWARD_FACTOR;

            if (amount != payment.amount.to_db()) {
                log::error(
                        logcat,
                        "Invalid amounts passed in to save payments for address {}: received {}, "
                        "expected {} (truncated from {})",
                        address_str,
                        payment.amount.to_db(),
                        amount,
                        *maybe_amount);
                return false;
            }

            db::exec_query(
                    update_paid,
                    address_str,
                    static_cast<int64_t>(amount),
                    static_cast<int64_t>(block_height));
            update_paid->reset();
        } else {
            // This shouldn't occur: we validate payout addresses much earlier in the block
            // validation.
            log::error(
                    logcat,
                    "Internal error: Invalid amounts passed in to save payments for address {}: "
                    "that address has no accrued rewards",
                    address_str);
            return false;
        }

        select_sum->reset();
    }
    return true;
}

bool BlockchainSQLite::delete_block_payments(uint64_t block_height) {
    log::trace(logcat, "BlockchainDB_SQLITE::{} Called with height: {}", __func__, block_height);
    prepared_exec(
            "DELETE FROM batched_payments_paid WHERE height_paid >= ?",
            static_cast<int64_t>(block_height));
    return true;
}

}  // namespace cryptonote
