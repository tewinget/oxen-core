#pragma once

#include "mainnet.h"

namespace cryptonote::config::testnet {
inline constexpr network_config config{
        .NETWORK_TYPE = network_type::TESTNET,
        .DEFAULT_CONFIG_SUBDIR = "testnet"sv,
        .HEIGHT_ESTIMATE_HEIGHT = 339767,
        .HEIGHT_ESTIMATE_TIMESTAMP = 1595360006,
        .PUBLIC_ADDRESS_BASE58_PREFIX = 156,
        .PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 157,
        .PUBLIC_SUBADDRESS_BASE58_PREFIX = 158,
        .P2P_DEFAULT_PORT = 38156,
        .RPC_DEFAULT_PORT = 38157,
        .QNET_DEFAULT_PORT = 38159,
        .NETWORK_ID = {{
                0x22,
                0x3a,
                0x78,
                0x65,
                0xe1,
                0x6f,
                0xca,
                0xb8,
                0x02,
                0xa1,
                0xdc,
                0x17,
                0x61,
                0x64,
                0x15,
                0xbf,
        }},
        .GENESIS_TX =
                "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec152"
                "6da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c"
                "656f247200000000000000000000000000000000000000000000000000000000000000000000"sv,
        .GENESIS_NONCE = 12345,
        .GOVERNANCE_REWARD_INTERVAL = 2000min,
        .GOVERNANCE_WALLET_ADDRESS =
                {
                        "T6Tnu9YUgVcSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M482ypm7"sv,  // HF7-9
                        "T6Tnu9YUgVcSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M482ypm7"sv,  // HF10
                },
        .UPTIME_PROOF_TOLERANCE = mainnet::config.UPTIME_PROOF_TOLERANCE,
        .UPTIME_PROOF_STARTUP_DELAY = mainnet::config.UPTIME_PROOF_STARTUP_DELAY,
        .UPTIME_PROOF_CHECK_INTERVAL = mainnet::config.UPTIME_PROOF_CHECK_INTERVAL,
        // Testnet uptime proofs are 6x faster than mainnet (devnet config also uses these)
        .UPTIME_PROOF_FREQUENCY = 10min,
        .UPTIME_PROOF_VALIDITY = 21min,
        .MAX_DEACTIVATE_PER_BLOCK = 1,
        .HAVE_STORAGE_AND_LOKINET = true,  // storage & lokinet
        .TARGET_BLOCK_TIME = mainnet::config.TARGET_BLOCK_TIME,
        .PULSE_STAGE_TIMEOUT = mainnet::config.PULSE_STAGE_TIMEOUT,
        .PULSE_ROUND_TIMEOUT = mainnet::config.PULSE_ROUND_TIMEOUT,
        .PULSE_MAX_START_ADJUSTMENT = mainnet::config.PULSE_MAX_START_ADJUSTMENT,
        .PULSE_MIN_SERVICE_NODES = 12,  // == pulse quorum size
        .BATCHING_INTERVAL = 20,
        .MIN_BATCH_PAYMENT_AMOUNT = mainnet::config.MIN_BATCH_PAYMENT_AMOUNT,
        .LIMIT_BATCH_OUTPUTS = mainnet::config.LIMIT_BATCH_OUTPUTS,
        .SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 4,
        .DEREGISTRATION_LOCK_DURATION = 48h,
        .UNLOCK_DURATION = 24h,
        .HARDFORK_DEREGISTRATION_GRACE_PERIOD =
                mainnet::config.HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        .HISTORY_ARCHIVE_INTERVAL = mainnet::config.HISTORY_ARCHIVE_INTERVAL,
        .HISTORY_ARCHIVE_KEEP_WINDOW = mainnet::config.HISTORY_ARCHIVE_KEEP_WINDOW,
        .HISTORY_RECENT_KEEP_WINDOW = mainnet::config.HISTORY_RECENT_KEEP_WINDOW,
        // Much shorter than mainnet so that you can test this more easily.
        .ETH_EXIT_BUFFER = 1h / mainnet::config.TARGET_BLOCK_TIME,
        // FIXME!
        .ETHEREUM_CHAIN_ID = 421614,  // Arbitrum Sepolia
        .ETHEREUM_REWARDS_CONTRACT = "0x0B5C58A27A41D5fE3FF83d74060d761D7dDDc1D2",
        .ETHEREUM_POOL_CONTRACT = "0x8D69Bb9D7b03993234bfd221aCB391Db597a920a",
        // Sepolia arbitrum sometimes slows down below the typical 250ms seen on mainnet, so for
        // testnet/devnet we shorten this to a quarter compared to mainnet:
        .L2_REWARD_POOL_UPDATE_BLOCKS = mainnet::config.L2_REWARD_POOL_UPDATE_BLOCKS / 4,
        .L2_TRACKER_SAFE_BLOCKS = mainnet::config.L2_TRACKER_SAFE_BLOCKS,
        // arb sepolia blocks are (sometimes) slower than mainnet, so reduce this a bit so that
        // we're probably still somewhere in the 1-2 hour range:
        .L2_NODE_LIST_PURGE_BLOCKS = mainnet::config.L2_NODE_LIST_PURGE_BLOCKS / 2,
        .L2_NODE_LIST_PURGE_MIN_OXEN_AGE = mainnet::config.L2_NODE_LIST_PURGE_MIN_OXEN_AGE,
        .DEFAULT_STAKING_URL = ""sv,
};
}  // namespace cryptonote::config::testnet
