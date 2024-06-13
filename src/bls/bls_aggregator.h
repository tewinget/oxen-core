#pragma once

#include <oxenmq/oxenmq.h>

#include <span>
#include <string>
#include <vector>

#include "bls_signer.h"
#include "crypto/crypto.h"
#include "cryptonote_core/service_node_list.h"

namespace eth {

struct AggregateSigned {
    crypto::hash signed_hash;
    std::vector<bls_public_key> signers_bls_pubkeys;
    bls_signature signature;
};

struct AggregateExitResponse : AggregateSigned {
    bls_public_key exit_pubkey;
};

struct BLSRewardsResponse : AggregateSigned {
    eth::address address;
    uint64_t amount;
    uint64_t height;
};

struct BLSRegistrationResponse {
    bls_public_key bls_pubkey;
    bls_signature proof_of_possession;
    eth::address address;
    crypto::public_key sn_pubkey;
    crypto::ed25519_signature ed_signature;
};

struct BLSRequestResult {
    service_nodes::service_node_address sn;
    bool success;
};

class BLSAggregator {
  private:
    cryptonote::core& core;

  public:
    using request_callback = std::function<void(
            const BLSRequestResult& request_result, const std::vector<std::string>& data)>;

    explicit BLSAggregator(cryptonote::core& core);

    /// Request the service node network to sign the requested amount of
    /// 'rewards' for the given Ethereum 'address' if by consensus they agree
    /// that the amount is valid. This node (the aggregator) will aggregate the
    /// signatures into the response.
    ///
    /// This function throws an `invalid_argument` exception if `address` is zero or, the `rewards`
    /// amount is `0` or height is greater than the current blockchain height.
    BLSRewardsResponse rewards_request(const eth::address& address);

    AggregateExitResponse aggregateExit(const bls_public_key& bls_pubkey);
    AggregateExitResponse aggregateLiquidation(const bls_public_key& bls_pubkey);
    BLSRegistrationResponse registration(
            const eth::address& sender, const crypto::public_key& serviceNodePubkey) const;

  private:
    void get_reward_balance(oxenmq::Message& m);
    void get_exit(oxenmq::Message& m);
    void get_liquidation(oxenmq::Message& m);

    AggregateExitResponse aggregateExitOrLiquidate(
            const bls_public_key& bls_pubkey,
            std::string_view hash_tag,
            std::string_view endpoint,
            std::string_view pubkey_key);

    // Goes out to the nodes on the network and makes oxenmq requests to all of them, when getting
    // the reply `callback` will be called to process their reply
    void nodesRequest(
            std::string_view request_name,
            std::string_view message,
            const request_callback& callback);
};

}  // namespace eth
