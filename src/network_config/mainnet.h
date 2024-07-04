#pragma once

#include <array>
#include <boost/uuid/uuid.hpp>
#include <cstdint>
#include <ctime>
#include <string_view>

#include "../cryptonote_config.h"
#include "network_config.h"

using namespace std::literals;

// Various configuration defaults and network-dependent settings
namespace cryptonote::config::mainnet {

// Used to estimate the blockchain height from a timestamp, with some grace time.  This can
// drift slightly over time (because average block time is not typically *exactly*
// DIFFICULTY_TARGET_V2).
inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 582088;
inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595359932;

inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 114;
inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 115;
inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 116;
inline constexpr uint16_t P2P_DEFAULT_PORT = 22022;
inline constexpr uint16_t RPC_DEFAULT_PORT = 22023;
inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 22024;
inline constexpr uint16_t QNET_DEFAULT_PORT = 22025;
inline constexpr boost::uuids::uuid const NETWORK_ID = {
        {0x46,
         0x61,
         0x72,
         0x62,
         0x61,
         0x75,
         0x74,
         0x69,
         0x2a,
         0x4c,
         0x61,
         0x75,
         0x66,
         0x65,
         0x79}};  // Bender's nightmare
inline constexpr std::string_view GENESIS_TX =
        "021e01ff000380808d93f5d771027c4fd4553bc9886f1f49e3f76d945bf71e8632a94e6c177b19cb"
        "c780e7e6bdb48080b4ccd4dfc60302c8b9f6461f58ef3f2107e577c7425d06af584a1c7482bf1906"
        "0e84059c98b4c3808088fccdbcc32302732b53b0b0db706fcc3087074fb4b786da5ab72b2065699f"
        "9453448b0db27f892101ed71f2ce3fc70d7b2036f8a4e4b3fb75c66c12184b55a908e7d1a1d69955"
        "66cf00"sv;
inline constexpr uint32_t GENESIS_NONCE = 1022201;

inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * cryptonote::BLOCKS_PER_DAY;
inline constexpr std::array GOVERNANCE_WALLET_ADDRESS = {
        // hardfork v7-10:
        "LCFxT37LAogDn1jLQKf4y7aAqfi21DjovX9qyijaLYQSdrxY1U5VGcnMJMjWrD9RhjeK5Lym67wZ73uh9AujXLQ1RKmXEyL"sv,
        // hardfork v11
        "LDBEN6Ut4NkMwyaXWZ7kBEAx8X64o6YtDhLXUP26uLHyYT4nFmcaPU2Z2fauqrhTLh4Qfr61pUUZVLaTHqAdycETKM1STrz"sv,
};

// After a hardfork we will decommission sns but won't dereg, allowing time to update
inline constexpr uint64_t HARDFORK_DEREGISTRATION_GRACE_PERIOD = 7 * cryptonote::BLOCKS_PER_DAY;
// How much an uptime proof timestamp can deviate from our timestamp before we refuse it:
inline constexpr auto UPTIME_PROOF_TOLERANCE = 5min;
// How long to wait after startup before broadcasting a proof
inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 30s;
// How frequently to check whether we need to broadcast a proof
inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 30s;
// How often to send proofs out to the network since the last proof we successfully sent.
// (Approximately; this can be up to CHECK_INTERFACE/2 off in either direction).  The minimum
// accepted time between proofs is half of this.
inline constexpr auto UPTIME_PROOF_FREQUENCY = 1h;
// The maximum time that we consider an uptime proof to be valid (i.e. after this time since the
// last proof we consider the SN to be down)
inline constexpr auto UPTIME_PROOF_VALIDITY = 2h + 5min;

// Batching SN Rewards
inline constexpr uint64_t BATCHING_INTERVAL = 2520;
inline constexpr uint64_t MIN_BATCH_PAYMENT_AMOUNT = 1'000'000'000;  // 1 OXEN (in atomic units)
inline constexpr uint64_t LIMIT_BATCH_OUTPUTS = 15;
// If a node has been online for this amount of blocks they will receive SN rewards
inline constexpr uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 720;

// batching and SNL will save the state every STORE_LONG_TERM_STATE_INTERVAL blocks
inline constexpr uint64_t STORE_LONG_TERM_STATE_INTERVAL = 10000;

/// (HF21+) Number of blocks after a registration expires (i.e. regular unlocks, *not* deregs)
/// during which the node is protected from liquidation-with-penalty.  Regular exits can still
/// be submitted to remove it from the ETH pubkey list, but *not* penalizing liquidation (which
/// also remove it but award a penalty reward to the liquidator).
inline constexpr uint64_t ETH_EXIT_BUFFER = 7 * cryptonote::BLOCKS_PER_DAY;

// Details of the ethereum smart contract managing rewards and chain its kept on
// TODO: To be set for mainnet during TGE
inline constexpr uint32_t ETHEREUM_CHAIN_ID = -1;
inline constexpr std::string_view ETHEREUM_REWARDS_CONTRACT =
        "0x0000000000000000000000000000000000000000";
inline constexpr std::string_view ETHEREUM_POOL_CONTRACT =
        "0x0000000000000000000000000000000000000000";

inline constexpr network_config config{
        network_type::MAINNET,
        HEIGHT_ESTIMATE_HEIGHT,
        HEIGHT_ESTIMATE_TIMESTAMP,
        PUBLIC_ADDRESS_BASE58_PREFIX,
        PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        PUBLIC_SUBADDRESS_BASE58_PREFIX,
        P2P_DEFAULT_PORT,
        RPC_DEFAULT_PORT,
        ZMQ_RPC_DEFAULT_PORT,
        QNET_DEFAULT_PORT,
        NETWORK_ID,
        GENESIS_TX,
        GENESIS_NONCE,
        GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
        GOVERNANCE_WALLET_ADDRESS,
        UPTIME_PROOF_TOLERANCE,
        UPTIME_PROOF_STARTUP_DELAY,
        UPTIME_PROOF_CHECK_INTERVAL,
        UPTIME_PROOF_FREQUENCY,
        UPTIME_PROOF_VALIDITY,
        BATCHING_INTERVAL,
        MIN_BATCH_PAYMENT_AMOUNT,
        LIMIT_BATCH_OUTPUTS,
        SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        STORE_LONG_TERM_STATE_INTERVAL,
        ETH_EXIT_BUFFER,
        ETHEREUM_CHAIN_ID,
        ETHEREUM_REWARDS_CONTRACT,
        ETHEREUM_POOL_CONTRACT,
};

}  // namespace cryptonote::config::mainnet
