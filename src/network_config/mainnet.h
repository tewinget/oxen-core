#pragma once

#include "../cryptonote_config.h"
#include "network_config.h"

using namespace std::literals;
namespace cryptonote::config::mainnet {
inline constexpr auto TARGET_BLOCK_TIME = 2min;
inline constexpr network_config config{
        .NETWORK_TYPE = network_type::MAINNET,
        .DEFAULT_CONFIG_SUBDIR = ""sv,
        .HEIGHT_ESTIMATE_HEIGHT = 582088,
        .HEIGHT_ESTIMATE_TIMESTAMP = 1595359932,
        .PUBLIC_ADDRESS_BASE58_PREFIX = 114,
        .PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 115,
        .PUBLIC_SUBADDRESS_BASE58_PREFIX = 116,
        .P2P_DEFAULT_PORT = 22022,
        .RPC_DEFAULT_PORT = 22023,
        .QNET_DEFAULT_PORT = 22025,
        .NETWORK_ID =
                {{0x46,
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
                  0x79}},
        .GENESIS_TX =
                "021e01ff000380808d93f5d771027c4fd4553bc9886f1f49e3f76d945bf71e8632a94e6c177b19cbc7"
                "80e7e6bdb48080b4ccd4dfc60302c8b9f6461f58ef3f2107e577c7425d06af584a1c7482bf19060e84"
                "059c98b4c3808088fccdbcc32302732b53b0b0db706fcc3087074fb4b786da5ab72b2065699f945344"
                "8b0db27f892101ed71f2ce3fc70d7b2036f8a4e4b3fb75c66c12184b55a908e7d1a1d6995566cf00"sv,
        .GENESIS_NONCE = 1022201,
        .GOVERNANCE_REWARD_INTERVAL = 7 * 24h,
        .GOVERNANCE_WALLET_ADDRESS =
                {
                        "LCFxT37LAogDn1jLQKf4y7aAqfi21DjovX9qyijaLYQSdrxY1U5VGcnMJMjWrD9RhjeK5Lym67"
                        "wZ73uh9AujXLQ1RKmXEyL",  // HF7-10
                        "LDBEN6Ut4NkMwyaXWZ7kBEAx8X64o6YtDhLXUP26uLHyYT4nFmcaPU2Z2fauqrhTLh4Qfr61pU"
                        "UZVLaTHqAdycETKM1STrz",  // HF11
                },
        .UPTIME_PROOF_TOLERANCE = 5min,
        .UPTIME_PROOF_STARTUP_DELAY = 30s,
        .UPTIME_PROOF_CHECK_INTERVAL = 30s,
        .UPTIME_PROOF_FREQUENCY = 1h,
        .UPTIME_PROOF_VALIDITY = 2h + 5min,
        .HAVE_STORAGE_AND_LOKINET = true,
        .TARGET_BLOCK_TIME = TARGET_BLOCK_TIME,
        .PULSE_STAGE_TIMEOUT = 10s,
        .PULSE_ROUND_TIMEOUT = 1min,
        .PULSE_MAX_START_ADJUSTMENT = 30s,
        .PULSE_MIN_SERVICE_NODES = 50,
        .BATCHING_INTERVAL = 2520,
        .MIN_BATCH_PAYMENT_AMOUNT = 1'000'000'000,  // 1 OXEN (in atomic units)
        .LIMIT_BATCH_OUTPUTS = 15,
        .SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 720,
        .DEREGISTRATION_LOCK_DURATION = 30 * 24h,
        .UNLOCK_DURATION = 15 * 24h,
        .HARDFORK_DEREGISTRATION_GRACE_PERIOD = 7 * 24h / TARGET_BLOCK_TIME,
        .STORE_LONG_TERM_STATE_INTERVAL = 10'000,
        .STORE_RECENT_REWARDS = 5,
        .ETH_EXIT_BUFFER = 7 * 24h / TARGET_BLOCK_TIME,
        .ETHEREUM_CHAIN_ID = 42161,  // Arbitrum One
        // TODO: To be set closer to mainnet TGE
        .ETHEREUM_REWARDS_CONTRACT = "",
        .ETHEREUM_POOL_CONTRACT = "",
        // Update every ~10 minutes with an Arbitrum ~250ms block time:
        .L2_REWARD_POOL_UPDATE_BLOCKS = 10min / L2_BLOCK_TIME,
        // The default is 70s behind with an Arbitrum ~250ms block time, so that pulse nodes using
        // 1min update period will work (with a few seconds for provider and request latencies).
        .L2_TRACKER_SAFE_BLOCKS = 70s / L2_BLOCK_TIME,
        // This relatively infrequent check is only for handling highly unusual cleanup cases where
        // a L2 disruption or bug between the contract and oxend results in oxend service nodes
        // state having nodes that *don't* exist in the contract (or vice versa) for some reason.
        .L2_NODE_LIST_PURGE_BLOCKS = 1h / L2_BLOCK_TIME,
        .L2_NODE_LIST_PURGE_MIN_OXEN_AGE = 24h / TARGET_BLOCK_TIME,
        .DEFAULT_STAKING_URL = "https://stake.getsession.org"sv,
};
}  // namespace cryptonote::config::mainnet
