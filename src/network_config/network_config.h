#pragma once

#include "../cryptonote_config.h"

namespace cryptonote{

struct network_config {
    network_type NETWORK_TYPE;
    uint64_t HEIGHT_ESTIMATE_HEIGHT;
    time_t HEIGHT_ESTIMATE_TIMESTAMP;
    uint64_t PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t P2P_DEFAULT_PORT;
    uint16_t RPC_DEFAULT_PORT;
    uint16_t QNET_DEFAULT_PORT;
    boost::uuids::uuid NETWORK_ID;
    std::string_view GENESIS_TX;
    uint32_t GENESIS_NONCE;
    uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    std::array<std::string_view, 2> GOVERNANCE_WALLET_ADDRESS;

    std::chrono::seconds UPTIME_PROOF_TOLERANCE;
    std::chrono::seconds UPTIME_PROOF_STARTUP_DELAY;
    std::chrono::seconds UPTIME_PROOF_CHECK_INTERVAL;
    std::chrono::seconds UPTIME_PROOF_FREQUENCY;
    std::chrono::seconds UPTIME_PROOF_VALIDITY;

    uint64_t BATCHING_INTERVAL;
    uint64_t MIN_BATCH_PAYMENT_AMOUNT;
    uint64_t LIMIT_BATCH_OUTPUTS;
    uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS;

    uint64_t HARDFORK_DEREGISTRATION_GRACE_PERIOD;

    uint64_t STORE_LONG_TERM_STATE_INTERVAL;

    uint64_t ETH_EXIT_BUFFER;

    uint32_t ETHEREUM_CHAIN_ID;
    std::string_view ETHEREUM_REWARDS_CONTRACT;
    std::string_view ETHEREUM_POOL_CONTRACT;

    inline constexpr std::string_view governance_wallet_address(hf hard_fork_version) const {
        const auto wallet_switch =
                (NETWORK_TYPE == network_type::MAINNET || NETWORK_TYPE == network_type::FAKECHAIN)
                        ? hf::hf11_infinite_staking
                        : hf::hf10_bulletproofs;
        return GOVERNANCE_WALLET_ADDRESS[hard_fork_version >= wallet_switch ? 1 : 0];
    }
};

}
