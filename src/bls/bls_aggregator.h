#pragma once

#include <oxenmq/oxenmq.h>

#include <string>
#include <vector>

#include "bls_signer.h"
#include "crypto/crypto.h"
#include "cryptonote_core/service_node_list.h"

struct AggregateSigned {
    crypto::hash signed_hash;
    std::vector<crypto::bls_public_key> signers_bls_pubkeys;
    crypto::bls_signature signature;
};

struct AggregateExitResponse : AggregateSigned {
    crypto::bls_public_key exit_pubkey;
};

struct AggregateWithdrawalResponse : AggregateSigned {
    crypto::eth_address address;
    uint64_t amount;
    uint64_t height;
};

struct BLSRegistrationResponse {
    crypto::bls_public_key bls_pubkey;
    crypto::bls_signature proof_of_possession;
    crypto::eth_address address;
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

    AggregateWithdrawalResponse aggregateRewards(const crypto::eth_address& address);
    AggregateExitResponse aggregateExit(const crypto::bls_public_key& bls_pubkey);
    AggregateExitResponse aggregateLiquidation(const crypto::bls_public_key& bls_pubkey);
    BLSRegistrationResponse registration(
            const crypto::eth_address& sender, const crypto::public_key& serviceNodePubkey) const;

  private:
    void get_reward_balance(oxenmq::Message& m);
    void get_exit(oxenmq::Message& m);
    void get_liquidation(oxenmq::Message& m);

    AggregateExitResponse aggregateExitOrLiquidate(
            const crypto::bls_public_key& bls_pubkey,
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
