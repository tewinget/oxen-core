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

#pragma once

#include <chrono>
#include <concepts>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <type_traits>

#include "common/util.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_config.h"
#include "cryptonote_core/ethereum_transactions.h"
#include "cryptonote_core/service_node_quorum_cop.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_core/service_node_voting.h"
#include "l2_tracker/events.h"
#include "networks.h"
#include "serialization/crypto.h"
#include "serialization/map.h"
#include "serialization/serialization.h"
#include "serialization/vector_bool.h"
#include "uptime_proof.h"

namespace cryptonote {
class Blockchain;
class BlockchainDB;
struct checkpoint_t;
};  // namespace cryptonote

namespace service_nodes {
inline constexpr uint64_t INVALID_HEIGHT = static_cast<uint64_t>(-1);

struct checkpoint_participation_entry {
    uint64_t height = INVALID_HEIGHT;
    bool voted = true;

    bool pass() const { return voted; };
};
struct pulse_participation_entry {
    uint64_t height = INVALID_HEIGHT;
    uint8_t round = 0;
    bool voted = true;

    bool pass() const { return voted; }
};
struct timestamp_participation_entry {
    bool participated = true;
    bool pass() const { return participated; };
};
struct timesync_entry {
    bool in_sync = true;
    bool pass() const { return in_sync; }
};

template <typename ValueType, size_t Count = QUORUM_VOTE_CHECK_COUNT>
struct participation_history {
    std::array<ValueType, Count> history;
    size_t write_index = 0;

    void reset() { write_index = 0; }

    void add(const ValueType& entry) { history[write_index++ % history.size()] = entry; }
    void add(ValueType&& entry) { history[write_index++ % history.size()] = std::move(entry); }

    // Returns the number of failures we have stored (of the last Count records).
    size_t failures() const {
        return std::count_if(begin(), end(), [](auto& e) { return !e.pass(); });
    }
    size_t passes() const { return size() - failures(); }

    bool empty() const { return write_index == 0; }
    size_t size() const { return std::min(history.size(), write_index); }
    constexpr size_t max_size() const noexcept { return Count; }

    ValueType* begin() { return history.data(); }
    ValueType* end() { return history.data() + size(); }
    const ValueType* begin() const { return history.data(); }
    const ValueType* end() const { return history.data() + size(); }
};

inline constexpr auto NEVER = std::chrono::steady_clock::time_point::min();

struct proof_info {
    proof_info();

    participation_history<pulse_participation_entry> pulse_participation;
    participation_history<checkpoint_participation_entry> checkpoint_participation;
    participation_history<timestamp_participation_entry> timestamp_participation;
    participation_history<timesync_entry> timesync_status;

    uint64_t timestamp = 0;  // The actual time we last received an uptime proof (serialized)
    uint64_t effective_timestamp =
            0;  // Typically the same, but on recommissions it is set to the recommission block time
                // to fend off instant obligation checks
    std::array<std::pair<uint32_t, uint64_t>, 2> public_ips = {};  // (not serialized)

    // See set_storage_server_peer_reachable(...) and set_lokinet_peer_reachable(...)
    struct reachable_stats {
        std::chrono::steady_clock::time_point last_reachable = NEVER, first_unreachable = NEVER,
                                              last_unreachable = NEVER;

        // Returns whether or not this stats indicates a node that is currently (probably)
        // reachable:
        // - true if the last test was a pass (regardless of how long ago)
        // - false if the last test was a recent fail (i.e. less than REACHABLE_MAX_FAILURE_VALIDITY
        // ago)
        // - nullopt if the last test was a failure, but is considered stale.
        // Both true and nullopt are considered a pass for service node testing.
        std::optional<bool> reachable(
                const std::chrono::steady_clock::time_point& now =
                        std::chrono::steady_clock::now()) const;

        // Returns true if this stats indicates a node that has recently failed reachability (see
        // above) *and* has been unreachable for at least the given grace time (that is: there is
        // both a recent failure and a failure more than `grace` ago, with no intervening
        // reachability pass reports).
        bool unreachable_for(
                std::chrono::seconds threshold,
                const std::chrono::steady_clock::time_point& now =
                        std::chrono::steady_clock::now()) const;
    };
    reachable_stats ss_reachable{};
    reachable_stats lokinet_reachable{};

    // Unlike all of the above (except for timestamp), these values *do* get serialized
    std::unique_ptr<uptime_proof::Proof> proof{};

    // Derived from pubkey_ed25519, not serialized
    crypto::x25519_public_key pubkey_x25519 = crypto::null<crypto::x25519_public_key>;

    // Updates pubkey_ed25519 to the given key, re-deriving the x25519 key if it actually changes
    // (does nothing if the key is the same as the current value).  If x25519 derivation fails then
    // both pubkeys are set to null.
    void update_pubkey(const crypto::ed25519_public_key& pk);

    // Called to update data received from a proof is received, updating values in the local object.
    // Returns true if serializable data is changed (in which case `store()` should be called).
    // Note that this does not update the m_x25519_to_pub map if the x25519 key changes (that's the
    // caller's responsibility).
    bool update(
            uint64_t ts,
            std::unique_ptr<uptime_proof::Proof> new_proof,
            const crypto::x25519_public_key& pk_x2);

    // Stores this record in the database.
    void store(const crypto::public_key& pubkey, cryptonote::Blockchain& blockchain);
};

struct pulse_sort_key {
    uint64_t last_height_validating_in_quorum = 0;
    uint8_t quorum_index = 0;

    bool operator==(pulse_sort_key const& other) const {
        return last_height_validating_in_quorum == other.last_height_validating_in_quorum &&
               quorum_index == other.quorum_index;
    }
    bool operator<(pulse_sort_key const& other) const {
        bool result = std::make_pair(last_height_validating_in_quorum, quorum_index) <
                      std::make_pair(other.last_height_validating_in_quorum, other.quorum_index);
        return result;
    }

    template <class Archive>
    void serialize_object(Archive& ar) {
        field_varint(ar, "last_height_validating_in_quorum", last_height_validating_in_quorum);
        field(ar, "quorum_index", quorum_index);
    }
};

struct service_node_info  // registration information
{
    enum class version_t : uint8_t {
        v0_checkpointing,  // versioning reset in 4.0.0 (data structure storage changed)
        v1_add_registration_hf_version,
        v2_ed25519,
        v3_quorumnet,
        v4_noproofs,
        v5_pulse_recomm_credit,
        v6_reassign_sort_keys,
        v7_decommission_reason,
        v8_ethereum_address,
        _count
    };

    struct contribution_t {
        enum class version_t : uint8_t {
            v0,

            _count
        };

        version_t version{version_t::v0};
        crypto::public_key key_image_pub_key{};
        crypto::key_image key_image{};
        uint64_t amount = 0;

        contribution_t() = default;
        contribution_t(
                version_t version,
                const crypto::public_key& pubkey,
                const crypto::key_image& key_image,
                uint64_t amount) :
                version{version}, key_image_pub_key{pubkey}, key_image{key_image}, amount{amount} {}

        template <class Archive>
        void serialize_object(Archive& ar) {
            field_varint(ar, "version", version, [](auto& version) {
                return version < version_t::_count;
            });
            field(ar, "key_image_pub_key", key_image_pub_key);
            field(ar, "key_image", key_image);
            field_varint(ar, "amount", amount);
        }
    };

    struct contributor_t {
        uint8_t version = 2;
        uint64_t amount = 0;
        uint64_t reserved = 0;
        cryptonote::account_public_address address{};
        eth::address ethereum_address{};
        eth::address ethereum_beneficiary{};
        std::vector<contribution_t> locked_contributions;

        contributor_t() = default;
        contributor_t(uint64_t reserved_, const cryptonote::account_public_address& address_) :
                reserved(reserved_), address(address_) {
            *this = {};
            reserved = reserved_;
            address = address_;
        }

        template <class Archive>
        void serialize_object(Archive& ar) {
            field_varint(ar, "version", version);
            field_varint(ar, "amount", amount);
            field_varint(ar, "reserved", reserved);
            field(ar, "address", address);
            field(ar, "locked_contributions", locked_contributions);
            if (version >= 1)
                field(ar, "ethereum_address", ethereum_address);
            if (version >= 2)
                field(ar, "ethereum_beneficiary", ethereum_beneficiary);
        }
    };

    uint64_t registration_height = 0;
    uint64_t requested_unlock_height = 0;
    // block_height and transaction_index are to record when the service node last received a
    // reward.
    uint64_t last_reward_block_height = 0;
    uint32_t last_reward_transaction_index = 0;
    uint32_t decommission_count = 0;  // How many times this service node has been decommissioned
    int64_t active_since_height = 0;  // if decommissioned: equal to the *negative* height at which
                                      // you became active before the decommission
    uint64_t last_decommission_height = 0;  // The height at which the last (or current!)
                                            // decommissioning started, or 0 if never decommissioned
    uint16_t last_decommission_reason_consensus_all =
            0;  // The reason which the last (or current!) decommissioning occurred as voted by all
                // SNs, or 0 if never decommissioned
    uint16_t last_decommission_reason_consensus_any =
            0;  // The reason which the last (or current!) decommissioning occurred as voted by any
                // of the SNs, or 0 if never decommissioned
    int64_t recommission_credit = 0;  // The number of blocks of credit you started with or kept
                                      // when you were last activated (i.e. as of
                                      // `active_since_height`)
    std::vector<contributor_t> contributors;
    uint64_t total_contributed = 0;
    uint64_t total_reserved = 0;
    uint64_t staking_requirement = 0;
    uint64_t portions_for_operator = 0;
    swarm_id_t swarm_id = 0;
    cryptonote::account_public_address operator_address{};
    eth::address operator_ethereum_address{};
    eth::bls_public_key bls_public_key{};
    uint64_t last_ip_change_height = 0;  // The height of the last quorum penalty for changing IPs
    version_t version = tools::enum_top<version_t>;
    cryptonote::hf registration_hf_version = cryptonote::hf::none;
    pulse_sort_key pulse_sorter;

    service_node_info() = default;
    bool is_fully_funded() const { return total_contributed >= staking_requirement; }
    bool is_decommissioned() const { return active_since_height < 0; }

    bool is_active() const { return is_fully_funded() && !is_decommissioned(); }

    bool is_payable(uint64_t at_height, cryptonote::network_type nettype) const {
        auto& netconf = get_config(nettype);
        return is_active() &&
               at_height >= active_since_height + netconf.SERVICE_NODE_PAYABLE_AFTER_BLOCKS;
    }

    bool can_transition_to_state(
            cryptonote::hf hf_version, uint64_t block_height, new_state proposed_state) const;
    bool can_be_voted_on(uint64_t block_height) const;
    size_t total_num_locked_contributions() const;

    template <class Archive>
    void serialize_object(Archive& ar) {
        field_varint(
                ar, "version", version, [](auto& version) { return version < version_t::_count; });
        field_varint(ar, "registration_height", registration_height);
        field_varint(ar, "requested_unlock_height", requested_unlock_height);
        field_varint(ar, "last_reward_block_height", last_reward_block_height);
        field_varint(ar, "last_reward_transaction_index", last_reward_transaction_index);
        field_varint(ar, "decommission_count", decommission_count);
        field_varint(ar, "active_since_height", active_since_height);
        field_varint(ar, "last_decommission_height", last_decommission_height);
        field(ar, "contributors", contributors);
        field_varint(ar, "total_contributed", total_contributed);
        field_varint(ar, "total_reserved", total_reserved);
        field_varint(ar, "staking_requirement", staking_requirement);
        field_varint(ar, "portions_for_operator", portions_for_operator);
        field(ar, "operator_address", operator_address);
        field_varint(ar, "swarm_id", swarm_id);
        if (version < version_t::v4_noproofs) {
            uint32_t fake_ip = 0;
            uint16_t fake_port = 0;
            field_varint(ar, "public_ip", fake_ip);
            field_varint(ar, "storage_port", fake_port);
        }
        field_varint(ar, "last_ip_change_height", last_ip_change_height);
        if (version >= version_t::v1_add_registration_hf_version)
            field_varint(ar, "registration_hf_version", registration_hf_version);
        if (version >= version_t::v2_ed25519 && version < version_t::v4_noproofs) {
            crypto::ed25519_public_key fake_pk = crypto::null<crypto::ed25519_public_key>;
            field(ar, "pubkey_ed25519", fake_pk);
            if (version >= version_t::v3_quorumnet) {
                uint16_t fake_port = 0;
                field_varint(ar, "quorumnet_port", fake_port);
            }
        }
        if (version >= version_t::v5_pulse_recomm_credit) {
            field_varint(ar, "recommission_credit", recommission_credit);
            field(ar, "pulse_sorter", pulse_sorter);
        }
        if (version >= version_t::v7_decommission_reason) {
            field_varint(
                    ar,
                    "last_decommission_reason_consensus_all",
                    last_decommission_reason_consensus_all);
            field_varint(
                    ar,
                    "last_decommission_reason_consensus_any",
                    last_decommission_reason_consensus_any);
        }
        if (version >= version_t::v8_ethereum_address) {
            field(ar, "bls_public_key", bls_public_key);
            field(ar, "operator_ethereum_address", operator_ethereum_address);
        }
    }
};

struct service_node_address {
    crypto::public_key sn_pubkey;
    eth::bls_public_key bls_pubkey;
    crypto::x25519_public_key x_pubkey;
    uint32_t ip;
    uint16_t port;
};

using pubkey_and_sninfo = std::pair<crypto::public_key, std::shared_ptr<const service_node_info>>;
using service_nodes_infos_t =
        std::unordered_map<crypto::public_key, std::shared_ptr<const service_node_info>>;

struct service_node_pubkey_info {
    crypto::public_key pubkey;
    std::shared_ptr<const service_node_info> info;

    service_node_pubkey_info() = default;
    service_node_pubkey_info(const pubkey_and_sninfo& pair) :
            pubkey{pair.first}, info{pair.second} {}

    template <class Archive>
    void serialize_object(Archive& ar) {
        field(ar, "pubkey", pubkey);
        if (Archive::is_deserializer)
            info = std::make_shared<service_node_info>();
        field(ar, "info", const_cast<service_node_info&>(*info));
    }
};

struct key_image_blacklist_entry {
    enum struct version_t : uint8_t {
        version_0,
        version_1_serialize_amount,
        count,
    };
    version_t version{version_t::version_1_serialize_amount};
    crypto::key_image key_image;
    uint64_t unlock_height = 0;
    uint64_t amount = 0;

    key_image_blacklist_entry() = default;
    key_image_blacklist_entry(
            version_t version,
            const crypto::key_image& key_image,
            uint64_t unlock_height,
            uint64_t amount) :
            version{version}, key_image{key_image}, unlock_height{unlock_height}, amount(amount) {}

    bool operator==(const key_image_blacklist_entry& other) const {
        return key_image == other.key_image;
    }
    bool operator==(const crypto::key_image& image) const { return key_image == image; }

    template <class Archive>
    void serialize_object(Archive& ar) {
        field_varint(
                ar, "version", version, [](auto& version) { return version < version_t::count; });
        field(ar, "key_image", key_image);
        field_varint(ar, "unlock_height", unlock_height);
        if (version >= version_t::version_1_serialize_amount)
            field_varint(ar, "amount", amount);
    }
};

struct payout_entry {
    cryptonote::account_public_address address;
    uint64_t portions;

    constexpr bool operator==(const payout_entry& x) const {
        return portions == x.portions && address == x.address;
    }
};

struct payout {
    crypto::public_key key;
    std::vector<payout_entry> payouts;
};

crypto::x25519_public_key snpk_to_xpk(const crypto::public_key& snpk);

/// Collection of keys used by a service node
struct service_node_keys {
    /// The service node key pair used for registration-related data on the chain; is
    /// curve25519-based but with Monero-specific changes that make it useless for external tools
    /// supporting standard ed25519 or x25519 keys.
    /// TODO(oxen) - eventually drop this key and just do everything with the ed25519 key.
    crypto::secret_key key;
    crypto::public_key pub;

    /// A secondary SN key pair used for ancillary operations by tools (e.g. libsodium) that rely
    /// on standard cryptography keypair signatures.
    crypto::ed25519_secret_key key_ed25519;
    crypto::ed25519_public_key pub_ed25519;

    /// A x25519 key computed from the ed25519 key, above, that is used for SN-to-SN encryption.
    /// (Unlike this above two keys this is not stored to disk; it is generated on the fly from the
    /// ed25519 key).
    crypto::x25519_secret_key key_x25519;
    crypto::x25519_public_key pub_x25519;

    /// BLS keypair of this service node, used for SENT registrations and interacting with the SENT
    /// staking contract.
    eth::bls_secret_key key_bls;
    eth::bls_public_key pub_bls;
};

class service_node_list {
  public:
    explicit service_node_list(cryptonote::Blockchain& blockchain);
    ~service_node_list();

    // non-copyable:
    service_node_list(const service_node_list&) = delete;
    service_node_list& operator=(const service_node_list&) = delete;

    void block_add(
            const cryptonote::block& block,
            const std::vector<cryptonote::transaction>& txs,
            const cryptonote::checkpoint_t* checkpoint,
            bool skip_verify = false);
    void blockchain_detached(uint64_t height);
    void init();
    void validate_miner_tx(const cryptonote::miner_tx_info& info) const;
    void alt_block_add(const cryptonote::block_add_info& info);
    payout get_next_block_leader() const {
        std::lock_guard lock{m_sn_mutex};
        return m_state.get_next_block_leader();
    }

    // Checks whether a service node is registered, with an optional additional check.  If the
    // service node is *not* registered at all, this returns false.  Otherwise, if `check` is
    // provided, returns the result of invoking it with the service_node_info record.  Otherwise
    // (i.e. exists and no check given) returns true.
    bool is_service_node(
            const crypto::public_key& pubkey,
            const std::function<bool(const service_node_info&)>& check = nullptr) const;
    // Queries whether the given pubkey is that of a registered, fully funded service node that is
    // not current decommissioned.
    bool is_active_service_node(const crypto::public_key& pubkey) const;
    // Queries whether the given pubkey is that of a registered, fully funded service node,
    // regardless of whether the node is currently active or decommissioned.
    bool is_funded_service_node(const crypto::public_key& pubkey) const;

    bool is_key_image_locked(
            crypto::key_image const& check_image,
            uint64_t* unlock_height = nullptr,
            service_node_info::contribution_t* the_locked_contribution = nullptr) const;
    uint64_t height() const { return m_state.height; }

    /// Note(maxim): this should not affect thread-safety as the returned object is const
    ///
    /// For checkpointing, quorums are only generated when height % CHECKPOINT_INTERVAL == 0 (and
    /// the actual internal quorum used is for `height - REORG_SAFETY_BUFFER_BLOCKS_POST_HF12`, i.e.
    /// do no subtract off the buffer in advance).
    /// Similarly for blink (but on BLINK_QUORUM_INTERVAL, but without any buffer offset applied
    /// here). return: nullptr if the quorum is not cached in memory (pruned from memory).
    std::shared_ptr<const quorum> get_quorum(
            quorum_type type,
            uint64_t height,
            bool include_old = false,
            std::vector<std::shared_ptr<const quorum>>* alt_states = nullptr) const;
    bool get_quorum_pubkey(
            quorum_type type,
            quorum_group group,
            uint64_t height,
            size_t quorum_index,
            crypto::public_key& key) const;

    size_t get_service_node_count() const;
    std::vector<service_node_pubkey_info> get_service_node_list_state(
            const std::vector<crypto::public_key>& service_node_pubkeys = {}) const;
    const std::vector<key_image_blacklist_entry>& get_blacklisted_key_images() const {
        return m_state.key_image_blacklist;
    }

    /// Accesses a proof with the required lock held; used to extract needed proof values.  Func
    /// should be callable with a single `const proof_info &` argument.  If there is no proof info
    /// at all for the given pubkey then Func will not be called.
    template <typename Func>
    void access_proof(const crypto::public_key& pubkey, Func f) const {
        std::unique_lock lock{m_sn_mutex};
        auto it = proofs.find(pubkey);
        if (it != proofs.end())
            f(it->second);
    }

    /// Returns the primary SN pubkey associated with a x25519 pubkey.  Returns a null public key if
    /// not found.  (Note: this is just looking up the association, not derivation).
    ///
    /// As of feature::SN_PK_IS_ED25519 this is looked up in the state and will always be present
    /// (if the given pubkey actually belongs to an active service node).  Before that HF, the
    /// pubkey will only be available if a recent proof has been received from the SN.
    ///
    /// Note that, as of feature::ETH_BLS, this will return a match for recently removed nodes and
    /// so a non-null return does not necessarily mean the node is currently registered.
    crypto::public_key find_public_key(const crypto::x25519_public_key& x25519) const;

    /// Returns the primary SN pubkey associated with the given BLS pubkey (HF21+).  Returns a null
    /// public key if not found.  Note that this returns a pubkey for both current and recently
    /// removed nodes, so a non-null return here does *not* necessarily mean the pubkey belongs to
    /// an active node.
    ///
    /// Requires HF21+; earlier versions always return a null key.
    crypto::public_key find_public_key(const eth::bls_public_key& bls_pubkey) const;

    /// Works like `find_public_key`, except that it only returns the SN pubkey if the node is a
    /// currently registered service node on the Oxen chain (i.e. active or decommissioned, but
    /// *not* recently removed), whereas find_public_key will return the pubkey for either
    /// registered or recently removed nodes.  Requires HF21+; earlier versions always return null.
    crypto::public_key find_public_key_registered(const eth::bls_public_key& bls_pubkey) const;

    // Returns a pubkey of a random service node in the service node list
    crypto::public_key get_random_pubkey();

    /// Initializes the x25519 map from current pubkey state; called during initialization.
    ///
    /// TODO Deprecated: Can be removed after HF21 (replaced with a map in the state_t object).
    void initialize_x25519_map();

    /// Remote SN lookup address function for OxenMQ: given a string_view of a x25519 pubkey, this
    /// returns that service node's quorumnet contact information, if we have it, else empty string.
    std::string remote_lookup(std::string_view x25519_pk);

    /// Does something read-only for each registered service node in the range of pubkeys.  The SN
    /// lock is held while iterating, so the "something" should be quick.
    ///
    /// Unknown public keys are skipped.
    template <
            std::input_iterator It,
            std::sentinel_for<It> End,
            std::invocable<const crypto::public_key&, const service_node_info&, const proof_info&>
                    Func>
    void for_each_service_node_info_and_proof(It begin, End end, Func f) const {
        static const proof_info empty_proof{};
        std::lock_guard lock{m_sn_mutex};
        for (auto sni_end = m_state.service_nodes_infos.end(); begin != end; ++begin) {
            auto it = m_state.service_nodes_infos.find(*begin);
            if (it != sni_end) {
                auto pit = proofs.find(it->first);
                f(it->first, *it->second, (pit != proofs.end() ? pit->second : empty_proof));
            }
        }
    }

    /// Loops through all registered service nodes and calls `f` with the pubkey and basic service
    /// node info.  The SN lock is held while iterating, so the "something" should be quick.  If the
    /// callback returns bool then `true` means stop iterating (i.e. you'd found what you wanted),
    /// `false` means continue.  (Any other return type ignores the return value).
    template <std::invocable<const crypto::public_key&, const service_node_info&> Func>
    void for_each_service_node(Func f) const {
        std::lock_guard lock{m_sn_mutex};
        for (const auto& [pk, sni] : m_state.service_nodes_infos) {
            if constexpr (std::is_same_v<bool, decltype(f(pk, *sni))>) {
                if (f(pk, *sni))
                    break;
            } else {
                f(pk, *sni);
            }
        }
    }

    /// If the given pubkey is a registered service node then call f with its current info (with the
    /// service node lock held).  Doesn't call f if not a registered service node.
    template <std::invocable<const service_node_info&> Func>
    void if_service_node(const crypto::public_key& pk, Func f) const {
        std::lock_guard lock{m_sn_mutex};
        if (auto it = m_state.service_nodes_infos.find(pk); it != m_state.service_nodes_infos.end())
            f(*it->second);
    }

    struct recently_removed_node;

    /// Loops through all recently removed nodes, invoking the callback (with the SN list lock held)
    /// for each one.  If the function has a bool return then the return value indicates whether the
    /// invoker is done, i.e. returning true once you have found what you want to break the
    /// iteration.
    template <std::invocable<const recently_removed_node&> Func>
    void for_each_recently_removed_node(Func f) const {
        std::lock_guard lock{m_sn_mutex};
        for (const auto& node : m_state.recently_removed_nodes) {
            if constexpr (std::is_same_v<bool, decltype(f(node))>) {
                if (f(node))
                    break;
            } else {
                f(node);
            }
        }
    }

    /// If the pubkey belongs to a recently removed node then invoke the callback (with the SN list
    /// lock held) with the `const recently_removed_node&` information.  If not a recently removed
    /// node then the callback is not invoked.
    template <std::invocable<const recently_removed_node&> Func>
    void if_recently_removed_node(const crypto::public_key& pk, Func f) const {
        std::lock_guard lock{m_sn_mutex};
        for (const auto& node : m_state.recently_removed_nodes) {
            if (pk == node.service_node_pubkey) {
                f(node);
                break;
            }
        }
    }

    /// Copies x25519 pubkeys (as strings) of all currently registered SNs into the given output
    /// iterator.  (Before the feature::SN_PK_IS_ED25519 hardfork this only includes SNs with known
    /// proofs.)
    template <std::output_iterator<std::string> OutputIt>
    void copy_x25519_pubkeys(OutputIt out, cryptonote::network_type nettype) const {
        std::lock_guard lock{m_sn_mutex};
        if (cryptonote::is_hard_fork_at_least(
                    nettype, cryptonote::feature::SN_PK_IS_ED25519, m_state.height)) {
            for (const auto& [xpk, _ignore] : m_state.x25519_map)
                *out++ = std::string{reinterpret_cast<const char*>(&xpk), sizeof(xpk)};
        } else {
            for (const auto& pk_info : m_state.service_nodes_infos) {
                auto it = proofs.find(pk_info.first);
                if (it == proofs.end())
                    continue;
                if (const auto& x2_pk = it->second.pubkey_x25519)
                    *out++ = std::string{reinterpret_cast<const char*>(&x2_pk), sizeof(x2_pk)};
            }
        }
    }

    /// Copies `service_node_address`es (pubkeys, ip, port) of all current and expired (yet to be
    /// removed from smart contract) SNs with potentially reachable, known addresses (via a recently
    /// received valid proof) into the given output iterator.  Service nodes that for which we have
    /// not yet received/accepted a proof containing IP info are not included.
    template <std::output_iterator<service_node_address> OutputIt>
    void copy_reachable_service_node_addresses(
            OutputIt out, cryptonote::network_type nettype) const {
        std::lock_guard lock{m_sn_mutex};
        bool sn_pk_is_ed25519_hf = cryptonote::is_hard_fork_at_least(
                nettype, cryptonote::feature::SN_PK_IS_ED25519, m_state.height);

        // NOTE: Add nodes from the SNL (active & decomm)
        for (const auto& pk_info : m_state.service_nodes_infos) {
            auto it = proofs.find(pk_info.first);
            if (it == proofs.end())
                continue;
            // If we don't have a proof then we won't know the IP/port, and so this node isn't
            // considered reachable and shouldn't be returned.
            if (!it->second.proof)
                continue;
            auto& proof = *it->second.proof;

            crypto::x25519_public_key pubkey_x25519;
            if (sn_pk_is_ed25519_hf) {
                pubkey_x25519 = snpk_to_xpk(pk_info.first);
            } else {
                assert(it->second.pubkey_x25519);  // Should always be set to non-null if we have a
                                                   // proof
                pubkey_x25519 = it->second.pubkey_x25519;
            }
            *out++ = service_node_address{
                    pk_info.first,
                    pk_info.second->bls_public_key,
                    sn_pk_is_ed25519_hf ? snpk_to_xpk(pk_info.first) : it->second.pubkey_x25519,
                    proof.public_ip,
                    proof.qnet_port};
        }

        if (sn_pk_is_ed25519_hf) {
            // NOTE: Add nodes from the recently removed list
            for (const auto& recently_removed_it : m_state.recently_removed_nodes) {

                // NOTE: Look for their latest IP/port from an uptime proof
                auto it = proofs.find(recently_removed_it.service_node_pubkey);
                if (it != proofs.end() && it->second.proof) {
                    auto& proof = *it->second.proof;
                    *out++ = service_node_address{
                            recently_removed_it.service_node_pubkey,
                            recently_removed_it.info.bls_public_key,
                            it->second.pubkey_x25519,
                            proof.public_ip,
                            proof.qnet_port};
                    continue;
                }

                // NOTE: We don't have a proof, we defer to what we last stored for the node.
                if (recently_removed_it.public_ip == 0 || recently_removed_it.qnet_port == 0)
                    continue;
                *out++ = service_node_address{
                        recently_removed_it.service_node_pubkey,
                        recently_removed_it.info.bls_public_key,
                        snpk_to_xpk(recently_removed_it.service_node_pubkey),
                        recently_removed_it.public_ip,
                        recently_removed_it.qnet_port};
            }
        }
    }

    std::vector<pubkey_and_sninfo> active_service_nodes_infos() const {
        std::unique_lock lock{m_sn_mutex};
        return m_state.active_service_nodes_infos();
    }

    void set_my_service_node_keys(const service_node_keys* keys);
    void set_quorum_history_storage(
            uint64_t hist_size);  // 0 = none (default), 1 = unlimited, N = # of blocks
    bool store();

    uptime_proof::Proof generate_uptime_proof(
            cryptonote::hf hardfork,
            uint32_t public_ip,
            uint16_t storage_port,
            uint16_t storage_omq_port,
            std::array<uint16_t, 3> ss_version,
            uint16_t quorumnet_port,
            std::array<uint16_t, 3> lokinet_version) const;

    bool handle_uptime_proof(
            std::unique_ptr<uptime_proof::Proof> proof,
            bool& my_uptime_proof_confirmation,
            crypto::x25519_public_key& x25519_pkey);

    void record_checkpoint_participation(
            crypto::public_key const& pubkey, uint64_t height, bool participated);

    // Called every hour to remove proofs for expired SNs from memory and the database.
    void cleanup_proofs();

    // Called via RPC from storage server/lokinet to report a ping test result for a remote storage
    // server/lokinet.
    //
    // How this works:
    // - SS randomly picks probably-good nodes to test every 10s (with fuzz), and pings
    //   known-failing nodes to re-test them.
    // - SS re-tests nodes with a linear backoff: 10s+fuzz after the first failure, then 20s+fuzz,
    //   then 30s+fuzz, etc. (up to ~2min retest intervals)
    // - Whenever SS gets *any* ping result at all it notifies us via RPC (which lands here), and it
    //   is (as of 9.x) our responsibility to decide when too many bad pings should be penalized.
    //
    // Our rules are as follows:
    // - if we have received only failures for more than 1h5min *and* we have at least one failure
    //   in the last 10min then we consider SS reachability to be failing.
    // - otherwise we consider it good.  (Which means either it passed a reachability test at least
    //   once in the last 1h5min *or* SS stopped pinging it, perhaps because it restarted).
    //
    // Lokinet works essentially the same, except that its concept of a "ping" is being able to
    // successfully establish a session with the given remote lokinet snode.
    //
    // We do all this by tracking three values:
    // - last_reachable
    // - first_unreachable
    // - last_unreachable
    //
    // On a good ping, we set last_reachable to the current time and clear first_unreachable.  On a
    // bad ping we set last_unreachable to the current time and, if first_unreachable is empty, set
    // it to current time as well.
    //
    // This then lets us figure out:
    // - current status can be good (first_unreachable == 0), passable (last_unreachable < 10min
    // ago), or failing.
    // - current *failing* status (current status == failing && first_unreachable more than 1h5min
    // ago)
    // - last test time (max(last_reachable, last_unreachable), "not yet" if this is 0)
    // - last test result (last_reachable >= last_unreachable)
    // - how long it has been unreachable (now - first_unreachable, if first_unreachable is set)
    //
    // (Also note that the actual times references here are for convenience, 10min is actually
    // REACHABLE_MAX_FAILURE_VALIDITY, and 1h5min is actually
    // UPTIME_PROOF_VALIDITY-UPTIME_PROOF_FREQUENCY (which is actually 11min on testnet rather than
    // 1h5min)).
    bool set_storage_server_peer_reachable(crypto::public_key const& pubkey, bool value);
    bool set_lokinet_peer_reachable(crypto::public_key const& pubkey, bool value);

    struct recently_removed_node {
        enum struct type_t : uint8_t {
            voluntary_exit,
            deregister,
            purged,
        };

        uint64_t height;              // Height at which the SN exited/deregistered
        uint64_t liquidation_height;  // Height at which the SN is eligible for liquidation
        type_t type;                  // Event that occurred to remove this SN
        uint32_t public_ip;           // Last known public IP of this SN (may be outdated)
        uint16_t qnet_port;           // Last known quorumnet port of this SN (may be outdated)
        crypto::public_key service_node_pubkey;  // SN primary ed25519 key
        service_node_info info;  // Info copied from the SNL and frozen at point of exit

        template <class Archive>
        void serialize_object(Archive& ar) {
            uint8_t version = 1;
            field_varint(ar, "version", version);
            if (version == 0) {  // NOTE: v0 we completely discard and force a full-rescan
                crypto::public_key pubkey;
                eth::bls_public_key bls_pubkey;
                field(ar, "pubkey", pubkey);
                field(ar, "bls_pubkey", bls_pubkey);
            }
            field_varint(ar, "height", height);
            field_varint(ar, "liquidation_height", liquidation_height);
            field_varint(ar, "type", type);
            if (version == 0) {
                std::vector<service_node_info::contributor_t> contributors;
                field(ar, "contributors", contributors);
            }
            field_varint(ar, "public_ip", public_ip);
            field_varint(ar, "qnet_port", qnet_port);
            if (version >= 1) {
                field(ar, "service_node_pubkey", service_node_pubkey);
                field(ar, "info", info);
            }
        }
    };

  private:
    bool set_peer_reachable(bool storage_server, crypto::public_key const& pubkey, bool value);

  public:
    struct unconfirmed_l2_tx {
        // Height of the block in which this tx was mined/pulsed
        uint64_t height_added;
        // Number of confirmation or denial points.
        uint32_t confirmations;
        uint32_t denials;

        // Basis for confirmation points.  A initial inclusion or follow-up confirmation or denial
        // gets this value divided by (R+1), where R is the round number (e.g. R=0 is the initial
        // quorum; R=3 is the third backup quorum).
        //
        // The specific value here is the smallest number divisible by all integers from 1 to 10 so
        // that there is no integer precision loss of scores up to the first 10 quorum rounds.  (It
        // could go higher -- 219060189739591200 is divisible by all integers up to 42 without
        // leading to overflow --  but doing so increases serialized size and having some small
        // precision loss in backup quorum votes (especially beyond the first few rounds) really
        // doesn't matter that much.
        static constexpr uint32_t FULL_SCORE = 2 * 3 * 2 * 5 * 7 * 2 * 3;

        // Resolution rules:
        //
        // - we require at least 5 more (full) votes for the winning side than the losing side
        // - we require that the winning side votes is at least double the losing side (i.e. >= 2/3
        //   majority of votes)
        // - we require that it be resolved within 30 blocks, otherwise it loses (regarldess of the
        //   votes).
        static constexpr uint32_t MIN_FINALIZED_DIFFERENCE = FULL_SCORE * 5;
        static constexpr uint32_t MIN_FINALIZED_RATIO = 2;
        static constexpr uint64_t MAX_VOTING_BLOCKS = 30;

        // Returns true if the confirmation/denial votes determine that this transaction should be
        // confirmed as accepted.
        constexpr bool is_accepted() const {
            return confirmations >= denials + MIN_FINALIZED_DIFFERENCE &&
                   confirmations >= denials * MIN_FINALIZED_RATIO;
        }

        // Returns true if the confirmation/denial votes determine that this transaction should be
        // confirmed as denied.
        constexpr bool is_denied() const {
            return denials >= confirmations + MIN_FINALIZED_DIFFERENCE &&
                   denials >= confirmations * MIN_FINALIZED_RATIO;
        }

        // Returns true if this transaction should be denied due to taking too many blocks to reach
        // consensus.  (Note that it is possible for a tx to become properly confirmed/denied at the
        // same time it expires, in which case the proper confirmation/denial takes effect).
        constexpr bool is_expired(uint64_t curr_height) const {
            return curr_height >= height_added + MAX_VOTING_BLOCKS;
        }

        // Returns an optional bool indicating the confirmation status:
        // - std::nullopt -- not yet confirmed, denied, nor expired
        // - true -- confirmed accepted
        // - false -- confirmed denied or denied by expiry
        constexpr std::optional<bool> confirmed(uint64_t curr_height) const {
            if (is_accepted())
                return true;
            if (is_denied() || is_expired(curr_height))
                return false;
            return std::nullopt;
        }

        explicit unconfirmed_l2_tx(
                uint64_t height = 0, uint32_t confirmations = 0, uint32_t denials = 0) :
                height_added{height}, confirmations{confirmations}, denials{denials} {}
        unconfirmed_l2_tx(uint64_t height, const cryptonote::pulse_header& pulse) :
                unconfirmed_l2_tx{height, FULL_SCORE / (static_cast<uint32_t>(pulse.round) + 1)} {}

        template <class Archive>
        void serialize_object(Archive& ar) {
            // We don't include a version here because state_serialized is already versioned. If we
            // end up needing versioning on this specific value then we can use a class tag
            // extension to determine which serialization path to follow in state_serialized's
            // serialization.
            field_varint(ar, "height", height_added);
            field_varint(ar, "confirmations", confirmations);
            field_varint(ar, "denials", denials);
        }
    };

    struct state_t;
    using state_set = std::set<state_t, std::less<>>;
    using block_height = uint64_t;
    struct state_t {
        crypto::hash block_hash{};
        bool only_loaded_quorums{false};
        service_nodes_infos_t service_nodes_infos;
        std::vector<key_image_blacklist_entry> key_image_blacklist;
        std::unordered_map<crypto::x25519_public_key, crypto::public_key> x25519_map;
        std::unordered_map<eth::bls_public_key, crypto::public_key> bls_map;
        block_height height{0};
        // Mutable because we are allowed to (and need to) change it via std::set iterator:
        mutable quorum_manager quorums;

        // The block leader of the block this state_t belongs to.  Only stored for HF20+ blocks
        // (before HF20 the winner is in the block's miner tx).  See `get_block_leader()` for a
        // method that works both before and after HF20.
        crypto::public_key block_leader;

        // blockchaindb-global-transaction-index => confirmation metadata of unconfirmed L2 state
        // changes.  This is an *ordered* map because confirmation votes in a pulse block depend on
        // the order of txes in here.
        std::map<crypto::hash, unconfirmed_l2_tx> unconfirmed_l2_txes;

        // List of nodes that have been removed from the SNL. A SN leaves the SNL by
        // deregistration (by consensus) or requesting a voluntary exit (by initiating a request on
        // the smart contract and waiting the necessary unlock time). Nodes that have left the SNL
        // are added to this list at which point they are now eligible for exiting the smart
        // contract by requesting the network to aggregate a signature for said request.
        std::vector<recently_removed_node> recently_removed_nodes;

        // An overridden staking requirement from the L2 contract (after confirmations); if 0 then
        // the default staking requirement applies.
        uint64_t staking_requirement{0};

        service_node_list* sn_list;

        explicit state_t(service_node_list* snl) : sn_list{snl} {}
        state_t(service_node_list& snl, struct state_serialized&& state);

        friend bool operator<(const state_t& a, const state_t& b) { return a.height < b.height; }
        friend bool operator<(const state_t& s, block_height h) { return s.height < h; }
        friend bool operator<(block_height h, const state_t& s) { return h < s.height; }

        // Inserts/erase a service node_node_info from service_nodes_infos, with proper updating of
        // dependent fields (such as x25519_map).
        void insert_info(
                const crypto::public_key& pubkey, std::shared_ptr<service_node_info>&& info_ptr);

        service_nodes_infos_t::iterator erase_info(
                const service_nodes_infos_t::iterator& it, recently_removed_node::type_t exit_type);

        std::vector<pubkey_and_sninfo> active_service_nodes_infos() const;
        std::vector<pubkey_and_sninfo> decommissioned_service_nodes_infos()
                const;  // return: All nodes that are fully funded *and* decommissioned.
        std::vector<pubkey_and_sninfo> payable_service_nodes_infos(
                uint64_t height, cryptonote::network_type nettype)
                const;  // return: All nodes that are active and have been online for a period
                        // greater than SERVICE_NODE_PAYABLE_AFTER_BLOCKS

        // Takes a BLS pubkey, returns the SN pubkey if known, otherwise null.  Note that "known"
        // here includes both registered SNs and SNs in the recently expired list (i.e. left oxend,
        // but not yet confirmed gone from the contract).
        crypto::public_key find_public_key(const eth::bls_public_key& bls_pubkey) const;

        std::vector<crypto::public_key> get_expired_nodes(
                cryptonote::BlockchainDB const& db,
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t block_height) const;
        void update_from_block(
                cryptonote::BlockchainDB const& db,
                cryptonote::network_type nettype,
                state_set const& state_history,
                state_set const& state_archive,
                std::unordered_map<crypto::hash, state_t> const& alt_states,
                const cryptonote::block& block,
                const std::vector<cryptonote::transaction>& txs,
                const service_node_keys* my_keys);

        // Returns true if there was a registration:
        bool process_registration_tx(
                cryptonote::network_type nettype,
                cryptonote::block const& block,
                const cryptonote::transaction& tx,
                uint32_t index,
                const service_node_keys* my_keys);
        // Returns true if there was a successful contribution that fully funded a service node:
        bool process_contribution_tx(
                cryptonote::network_type nettype,
                cryptonote::block const& block,
                const cryptonote::transaction& tx,
                uint32_t index);
        // Returns true if a service node changed state (deregistered, decommissioned, or
        // recommissioned)
        bool process_state_change_tx(
                state_set const& state_history,
                state_set const& state_archive,
                std::unordered_map<crypto::hash, state_t> const& alt_states,
                cryptonote::network_type nettype,
                const cryptonote::block& block,
                const cryptonote::transaction& tx,
                const service_node_keys* my_keys);
        bool process_key_image_unlock_tx(
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t block_height,
                const cryptonote::transaction& tx);
        // TODO oxen delete this function after HF20
        bool is_premature_unlock(
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t block_height,
                const cryptonote::transaction& tx) const;
        // Processes a newly observed ETH transaction, starting the confirmation process.  This does
        // not validate it; that happens once confirmed by the network.
        void process_new_ethereum_tx(
                cryptonote::block const& block,
                const cryptonote::transaction& tx,
                const service_node_keys* my_keys);

        struct confirm_metadata {
            cryptonote::network_type nettype;
            cryptonote::hf hf_version;
            uint64_t height;            // Height that the event was mined in
            uint64_t confirmed_height;  // Height that the event was confirmed
            uint32_t vote_index;
            uint64_t tx_index;  // Index in the block that the event was mined in
            const service_node_keys* my_keys;
        };

        // Applies a pulse-quorums-confirmed L2 event to the service node list state.  Returns true
        // if processing the event affects swarms, false if it does not.
        bool process_confirmed_event(
                const eth::event::NewServiceNodeV2& new_sn, const confirm_metadata& confirm);
        bool process_confirmed_event(
                const eth::event::ServiceNodeExitRequest& rem_req, const confirm_metadata& confirm);
        bool process_confirmed_event(
                const eth::event::ServiceNodeExit& exit, const confirm_metadata& confirm);
        bool process_confirmed_event(
                const eth::event::StakingRequirementUpdated& req_change,
                const confirm_metadata& confirm);
        bool process_confirmed_event(
                const eth::event::ServiceNodePurge& purge, const confirm_metadata& confirm);
        bool process_confirmed_event(
                const std::monostate&,  // do-nothing fallback for "not an event" variant
                const confirm_metadata&) {
            return false;
        }

        // Returns the block leader of the next block: that is, the round 0 pulse quorum leader, and
        // (before HF19) the service node that earns the service node reward for the next block.
        // Returns a payout with a null key if the next block cannot be a pulse block.
        payout get_next_block_leader() const;

        // Returns the pubkey of the block leader of *this* block: that is, the round 0 pulse quorum
        // leader, and (before HF19) the service node that earned the service node reward for this
        // block.  Returns a null public key if this block was not a pulse block.
        //
        // A pointer to the block can be passed as `b` if precomputed as an optimization; if omitted
        // the block will be looked up from the database when needed (i.e. for HF19 and earlier).
        crypto::public_key get_block_leader(const cryptonote::block* b = nullptr) const;

        // Returns the pulse quorum for round `round` of the next expected block.  E.g. `round=0`
        // returns the primary quorum, `round=17` returns the 17th backup quorum.  Returns nullopt
        // if the next block cannot be a pulse block (e.g. because of insufficient active nodes to
        // form a full pulse quorum).
        //
        // `bdb` and `nettype` are usually just the values from sn_list, but can be provided
        // separately (this is mainly for use in the test suite that manipulates state_t's without
        // having a service node list).
        std::optional<quorum> get_next_pulse_quorum(
                cryptonote::hf hf_version,
                uint8_t round,
                const cryptonote::BlockchainDB& bdb,
                cryptonote::network_type nettype) const;

        // Returns the pulse quorum that actually produced this block.  In contrast to
        // `get_block_leader()`, this returns the leader of the actual pulse quorum, which could be
        // a backup round (for blocks that failed to produce a block in round 0 and fell back to a
        // backup round).  Up to the end of OXEN rewards (i.e. up until HF21), this is the service
        // node that earns any (OXEN) tx fees in the processed block.
        //
        // Returns nullopt if this was not a pulse block (i.e. a mined block).
        std::optional<quorum> get_pulse_quorum() const;
        // Wrapper around `get_pulse_quorum`, above, that returns just the SN pubkey of the pulse
        // quorum leader, or a null key if there was no pulse quorum for this state_t/block.
        crypto::public_key get_block_producer() const;

        // Returns the current staking requirement (which could, in HF21+, come from a confirmed
        // contract staking requirement update).
        uint64_t get_staking_requirement(cryptonote::network_type nettype) const;

      private:
        // Rebuilds the x25519_map and bls_map from the list of service nodes and recently removed
        // nodes.  Does nothing if the feature::ETH_BLS fork hasn't happened for this state height.
        void initialize_alt_pk_maps();

        mutable std::optional<service_nodes::payout> next_block_leader_cache;
    };

    // Can be set to true (via --dev-allow-local-ips) for debugging a new testnet on a local private
    // network.
    bool debug_allow_local_ips = false;
    void record_timestamp_participation(crypto::public_key const& pubkey, bool participated);
    void record_timesync_status(crypto::public_key const& pubkey, bool synced);

    // TODO oxen delete this function after HF20 (it is only used for mempool selection, not
    // consensus).
    bool is_premature_unlock(
            cryptonote::network_type nettype,
            cryptonote::hf hf_version,
            uint64_t block_height,
            const cryptonote::transaction& tx) const {
        return m_state.is_premature_unlock(nettype, hf_version, block_height, tx);
    }

    /**
     * @brief gets the L2 votes (confirm or deny) for all current pending unconfirmed L2 state
     * changes.
     *
     * This is used by pulse block producers and miners, and verified by pulse quorum signers, and
     * is a pulse quorum consensus value but *not* a chain consensus value.
     *
     * @returns vector of votes
     */
    std::vector<bool> l2_pending_state_votes() const;

    /**
     * @brief returns the current staking requirement.
     *
     * - Before HF16 on mainnet, this is a height-dependent value.
     * - Otherwise, before HF21 this is a fixed value.
     * - From HF21 this starts at a fixed value, but the staking contract can change it (and the
     *   change applies to the Oxen chain after SN confirmations of the change).
     *
     * @returns current staking requirement, in atomic currency units
     */
    uint64_t get_staking_requirement() const;

    /**
     * @brief iterates through all pending unconfirmed L2 state changes.  `func` should be a generic
     * lambda that will be called with const reference to one of the non-monostate
     * eth::StateChangeVariant types (e.g. eth::event::NewServiceNodeV2,
     * eth::event::ServiceNodeExitRequest, etc.).
     *
     * If `func` returns a bool then the return value is used to determine whether to break the loop
     * early: true means break, false means continue.
     */
    template <typename F>
        requires std::invocable<F, const eth::event::NewServiceNodeV2&, const unconfirmed_l2_tx&> &&
                 std::invocable<F, const eth::event::ServiceNodePurge&, const unconfirmed_l2_tx&> &&
                 std::invocable<
                         F,
                         const eth::event::StakingRequirementUpdated&,
                         const unconfirmed_l2_tx&> &&
                 std::invocable<
                         F,
                         const eth::event::ServiceNodeExitRequest&,
                         const unconfirmed_l2_tx&> &&
                 std::invocable<F, const eth::event::ServiceNodeExit&, const unconfirmed_l2_tx&>
    void for_each_pending_l2_state(F&& f) const {
        std::lock_guard lock{m_sn_mutex};
        for (auto& [txid, confirm_info] : m_state.unconfirmed_l2_txes) {
            bool done = std::visit(
                    [&f, &confirm_info]<typename T>(const T& evt) {
                        if constexpr (!std::is_same_v<T, std::monostate>) {
                            if constexpr (std::is_same_v<bool, decltype(f(evt, confirm_info))>)
                                return f(evt, confirm_info);
                            else
                                f(evt, confirm_info);
                        }
                        return false;
                    },
                    eth::extract_event(blockchain, txid));
            if (done)
                break;
        }
    }

    cryptonote::Blockchain& blockchain;

  private:
    bool m_rescanning = false; /* set to true when doing a rescan so we know not to reset proofs */
    void process_block(
            const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs);
    void record_pulse_participation(
            crypto::public_key const& pubkey, uint64_t height, uint8_t round, bool participated);

    // Verify block against Service Node state that has just been called with
    // 'state.update_from_block(block)'.
    void verify_block(
            const cryptonote::block& block,
            bool alt_block,
            cryptonote::checkpoint_t const* checkpoint) const;

    void reset(bool delete_db_entry = false);
    bool load(uint64_t current_height);

    mutable std::recursive_mutex m_sn_mutex;
    const service_node_keys* m_service_node_keys;
    uint64_t m_store_quorum_history = 0;
    mutable std::shared_mutex m_x25519_map_mutex;

    /// Maps x25519 pubkeys to registration pubkeys + last block seen value (used for expiry)
    std::unordered_map<crypto::x25519_public_key, std::pair<crypto::public_key, time_t>>
            x25519_to_pub;
    std::chrono::system_clock::time_point x25519_map_last_pruned =
            std::chrono::system_clock::from_time_t(0);
    std::unordered_map<crypto::public_key, proof_info> proofs;

    // Internal temporary storage for accelerating the book-keeping of the list that can be
    // regenerated by resetting the list.
    std::unique_ptr<struct service_node_list_transient_storage> m_transient;

    // Stores SNL data
    state_t m_state;

    // nodes that can't yet be liquidated; the .second value is the expiry block height at which we
    // remove them (and thus allow liquidation):
    std::unordered_map<eth::bls_public_key, uint64_t> recently_expired_nodes;
};

struct staking_components {
    crypto::public_key service_node_pubkey;
    cryptonote::account_public_address address;
    uint64_t transferred;
    crypto::secret_key tx_key;
    std::vector<service_node_info::contribution_t> locked_contributions;
};
bool tx_get_staking_components(
        cryptonote::transaction_prefix const& tx_prefix,
        staking_components* contribution,
        crypto::hash const& txid);
bool tx_get_staking_components(cryptonote::transaction const& tx, staking_components* contribution);
bool tx_get_staking_components_and_amounts(
        cryptonote::network_type nettype,
        cryptonote::hf hf_version,
        cryptonote::transaction const& tx,
        uint64_t block_height,
        staking_components* contribution);

using contribution = std::pair<cryptonote::account_public_address, uint64_t>;
struct registration_details {
    crypto::public_key service_node_pubkey;
    std::vector<contribution> reserved;
    uint64_t fee;
    uint64_t hf;         // expiration timestamp before HF19
    bool uses_portions;  // if true then `hf` is a timestamp
    union {
        // Up to HF20 we use a Monero-type signature (which is the same crypto, but incompatible
        // with standard Ed25519 signatures); starting at HF21 all registration signatures must be
        // proper Ed25519.
        crypto::signature signature;
        crypto::ed25519_signature ed_signature;
    };
    std::vector<eth::event::ContributorV2> eth_contributions;
    eth::bls_public_key bls_pubkey;
};

bool is_registration_tx(
        cryptonote::network_type nettype,
        cryptonote::hf hf_version,
        const cryptonote::transaction& tx,
        uint64_t block_timestamp,
        uint64_t block_height,
        uint64_t staking_requirement,
        uint32_t index,
        crypto::public_key& key,
        service_node_info& info);

std::optional<registration_details> reg_tx_extract_fields(const cryptonote::transaction& tx);

uint64_t offset_testing_quorum_height(quorum_type type, uint64_t height);

// Converts string input values into a partially filled `registration_details`; pubkey and
// signature will be defaulted.  Throws invalid_registration on any invalid input.
registration_details convert_registration_args(
        cryptonote::network_type nettype,
        cryptonote::hf hf_version,
        const std::vector<std::string>& args,
        uint64_t staking_requirement);

void validate_registration(
        cryptonote::hf hf_version,
        cryptonote::network_type nettype,
        uint64_t staking_requirement,
        uint64_t block_timestamp,
        const registration_details& registration);
void validate_registration_signature(const registration_details& registration);
crypto::hash get_registration_hash(const registration_details& registration);

std::basic_string<unsigned char> get_eth_registration_message_for_signing(
        const registration_details& registration);

bool make_registration_cmd(
        cryptonote::network_type nettype,
        cryptonote::hf hf_version,
        uint64_t staking_requirement,
        const std::vector<std::string>& args,
        const service_node_keys& keys,
        std::string& cmd,
        bool make_friendly);

service_nodes::quorum generate_pulse_quorum(
        cryptonote::network_type nettype,
        crypto::public_key const& leader,
        cryptonote::hf hf_version,
        std::vector<pubkey_and_sninfo> const& active_snode_list,
        std::vector<crypto::hash> const& pulse_entropy,
        uint8_t pulse_round);

// The pulse entropy is generated for the next block after the top_block passed in.
std::vector<crypto::hash> get_pulse_entropy_for_next_block(
        cryptonote::BlockchainDB const& db,
        cryptonote::block const& top_block,
        uint8_t pulse_round);
std::vector<crypto::hash> get_pulse_entropy_for_next_block(
        cryptonote::BlockchainDB const& db, crypto::hash const& top_hash, uint8_t pulse_round);
// Same as above, but uses the current blockchain top block and defaults to round 0 if not
// specified.
std::vector<crypto::hash> get_pulse_entropy_for_next_block(
        cryptonote::BlockchainDB const& db, uint8_t pulse_round = 0);

payout service_node_payout_portions(const crypto::public_key& key, const service_node_info& info);

const static payout_entry null_payout_entry = {
        cryptonote::null_address, cryptonote::old::STAKING_PORTIONS};
const static payout null_payout = {crypto::null<crypto::public_key>, {null_payout_entry}};
}  // namespace service_nodes
