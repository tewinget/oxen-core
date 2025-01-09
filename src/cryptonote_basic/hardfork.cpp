// Copyright (c) 2018-2021, The Loki Project
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

#include "hardfork.h"

#include <array>

namespace cryptonote {

// version 7 from the start of the blockchain, inhereted from Monero mainnet
static constexpr std::array mainnet_hard_forks = {
        hard_fork{hf::hf7, 0, 0, 1503046577},  // Loki 0.1: Loki is born
        hard_fork{
                hf::hf8,
                0,
                64324,
                1533006000 /*2018-07-31 03:00 UTC*/},  // Loki 0.2: New emissions schedule
        hard_fork{
                hf::hf9_service_nodes,
                0,
                101250,
                1537444800 /*2018-09-20 12:00 UTC*/},  // Loki 1: Service nodes launched
        hard_fork{
                hf::hf10_bulletproofs,
                0,
                161849,
                1544743800 /*2018-12-13 23:30 UTC*/},  // Loki 2: Bulletproofs, gov fee batching
        hard_fork{
                hf::hf11_infinite_staking,
                0,
                234767,
                1554170400 /*2019-03-26 13:00 AEDT*/},  // Loki 3: Infinite staking, CN-Turtle
        hard_fork{
                hf::hf12_checkpointing,
                0,
                321467,
                1563940800 /*2019-07-24 14:00 AEDT*/},  // Loki 4: Checkpointing, RandomXL,
                                                        // decommissioning, Storage Server launched
        hard_fork{
                hf::hf13_enforce_checkpoints,
                0,
                385824,
                1571850000 /*2019-10-23 19:00 AEDT*/},  // Loki 5: Checkpointing enforced
        hard_fork{
                hf::hf14_blink,
                0,
                442333,
                1578528000 /*2020-01-09 00:00 UTC*/},  // Loki 6: Blink, Lokinet launched on mainnet
        hard_fork{
                hf::hf15_ons,
                0,
                496969,
                1585105200 /*2020-03-25 14:00 AEDT (03:00 UTC)*/},  // Loki 7: ONS (Session)
        hard_fork{
                hf::hf16_pulse,
                0,
                641111,
                1602464400 /*2020-10-12 12:00 AEDT (01:00 UTC)*/},  // Loki 8: Pulse
        hard_fork{
                hf::hf17,
                0,
                770711,
                1618016400 /*Saturday, April 10, 2021 1:00:00 UTC*/},  // Oxen 8: Eliminate 6/block
                                                                       // emissions after 180 days
                                                                       // (not a separate release)
        hard_fork{
                hf::hf18,
                0,
                785000,
                1619736143 /*Thursday, April 29, 2021 22:42:23 UTC*/},  // Oxen 9: Timesync, new
                                                                        // proofs, reasons, wallet
                                                                        // ONS
        hard_fork{
                hf::hf18,
                1,
                839009,
                1626217200 /*Tuesday, July 13, 2021 23:00 UTC */},  // Oxen 9.2: mandatory SS 2.2.0
                                                                    // & lokinet 0.9.5 updates
        hard_fork{
                hf::hf19_reward_batching,
                0,
                1080149,
                1655154000 /*Monday, June 13, 2022 21:00 UTC */},  // Oxen 10.1: Service Node Reward
                                                                   // Batching
        hard_fork{
                hf::hf19_reward_batching,
                1,
                1090229,
                1656363600 /*Monday, June 27, 2022 21:00 UTC */},  // Minor hardfork, upgrades to
                                                                   // session.
        hard_fork{
                hf::hf19_reward_batching,
                2,
                1146479,
                1663113600 /*Wednesday, September 14, 2022 0:00 UTC */},  // Oxen 10.2: Unlock
                                                                          // fixes, mandatory
                                                                          // SS 2.4.0 update
        hard_fork{
                hf::hf19_reward_batching,
                3,
                1253039,
                1675900800 /*Thursday, February 9, 2023 0:00 UTC */},  // Oxen 10.3: Mandatory
                                                                       // SS 2.5.0 update
};

static constexpr std::array testnet_hard_forks = {
        hard_fork{hf::hf7, 0, 0, 1653632397},  // Testnet was rebooted during HF19 - Oxen 10
        hard_fork{hf::hf11_infinite_staking, 0, 2, 1653632397},
        hard_fork{hf::hf12_checkpointing, 0, 3, 1653632397},
        hard_fork{hf::hf13_enforce_checkpoints, 0, 4, 1653632397},
        hard_fork{hf::hf14_blink, 0, 5, 1653632397},
        hard_fork{hf::hf15_ons, 0, 6, 1653632397},
        hard_fork{hf::hf16_pulse, 0, 200, 1653632397},
        hard_fork{hf::hf17, 0, 251, 1653632397},
        hard_fork{hf::hf18, 0, 252, 1653632397},
        hard_fork{hf::hf19_reward_batching, 0, 253, 1653632397},
        hard_fork{hf::hf19_reward_batching, 1, 254, 1653632397},     // 2022-05-27T06:19:57.000Z UTC
        hard_fork{hf::hf19_reward_batching, 2, 62885, 1661205699},   // 2022-08-22T22:01:39.000Z UTC
        hard_fork{hf::hf19_reward_batching, 3, 161000, 1673385120},  // 2023-01-10T21:12:00.000Z UTC
        hard_fork{hf::hf20_eth_transition, 0, 629500, 1729215000},   // 2024-10-17T01:30:00.000Z UTC
        hard_fork{hf::hf21_eth, 0, 689990, 1736459037},   // 2025-01-09T20:45:00.000Z UTC (ish)
};

static constexpr std::array devnet_hard_forks = {
        hard_fork{hf::hf7, 0, 0, 1716310007},
        hard_fork{hf::hf14_blink, 0, 1, 1716310014},
        hard_fork{hf::hf16_pulse, 0, 250, 1716310016},
        hard_fork{hf::hf17, 0, 255, 1716310017},
        hard_fork{hf::hf18, 0, 256, 1716310018},
        hard_fork{hf::hf19_reward_batching, 0, 257, 1716310019},
        hard_fork{hf::hf20_eth_transition, 0, 379, 1716310020},
        hard_fork{hf::hf21_eth, 0, 444, 1716310021},
};

static constexpr std::array local_devnet_hard_forks = {
        hard_fork{hf::hf7, 0, 0, 1716310007},
        hard_fork{hf::hf14_blink, 0, 1, 1716310014},
        hard_fork{hf::hf16_pulse, 0, 40, 1716310016},
        hard_fork{hf::hf17, 0, 45, 1716310017},
        hard_fork{hf::hf18, 0, 46, 1716310018},
        hard_fork{hf::hf19_reward_batching, 0, 47, 1716310019},
        hard_fork{hf::hf20_eth_transition, 0, 170, 1716310020},
        hard_fork{hf::hf21_eth, 0, 171, 1716310020},
};

static constexpr std::array stagenet_hard_forks = {
        hard_fork{hf::hf7, 0, 0, 1724084000},
        hard_fork{hf::hf14_blink, 0, 1, 1724084014},
        hard_fork{hf::hf21_eth, 3, 250, 1724084021},
};

template <size_t N>
static constexpr bool is_ordered(const std::array<hard_fork, N>& forks) {
    if (N == 0 || forks[0].version < hf::hf7)
        return false;
    for (size_t i = 1; i < N; i++) {
        auto& hf = forks[i];
        auto& prev = forks[i - 1];
        if (  // [major,snoderevision] pair must be strictly increasing (lexicographically)
                std::make_pair(hf.version, hf.snode_revision) <=
                        std::make_pair(prev.version, prev.snode_revision)
                // height must be strictly increasing; time must be weakly increasing
                || hf.height <= prev.height || hf.time < prev.time)
            return false;
    }
    return true;
}

static_assert(
        is_ordered(mainnet_hard_forks),
        "Invalid mainnet hard forks: version must start at 7, major versions and heights must be "
        "strictly increasing, and timestamps must be non-decreasing");
static_assert(
        is_ordered(testnet_hard_forks),
        "Invalid testnet hard forks: version must start at 7, versions and heights must be "
        "strictly increasing, and timestamps must be non-decreasing");
static_assert(
        is_ordered(devnet_hard_forks),
        "Invalid devnet hard forks: version must start at 7, versions and heights must be strictly "
        "increasing, and timestamps must be non-decreasing");
static_assert(
        is_ordered(stagenet_hard_forks),
        "Invalid devnet hard forks: version must start at 7, versions and heights must be strictly "
        "increasing, and timestamps must be non-decreasing");

std::vector<hard_fork> fakechain_hardforks;

std::span<const hard_fork> get_hard_forks(network_type type) {
    switch (type) {
        case network_type::MAINNET: return mainnet_hard_forks;
        case network_type::STAGENET: return stagenet_hard_forks;
        case network_type::TESTNET: return testnet_hard_forks;
        case network_type::DEVNET: return devnet_hard_forks;
        case network_type::LOCALDEV: return local_devnet_hard_forks;
        case network_type::FAKECHAIN: return fakechain_hardforks;
        case network_type::UNDEFINED:;
    }
    return {};
}

std::pair<std::optional<uint64_t>, std::optional<uint64_t>> get_hard_fork_heights(
        network_type nettype, hf version) {
    std::pair<std::optional<uint64_t>, std::optional<uint64_t>> found;
    for (auto& hf : get_hard_forks(nettype)) {
        if (hf.version > version) {  // This (and anything else) are in the future
            if (found.first)         // Found something suitable in the previous iteration, so one
                                     // before this hf is the max
                found.second = hf.height - 1;
            break;
        } else if (hf.version == version && !found.first) {
            found.first = hf.height;
        }
    }
    return found;
}

hard_fork get_latest_hard_fork(network_type nettype) {
    return get_hard_forks(nettype).back();
}

hf hard_fork_ceil(network_type nettype, hf version) {
    for (auto& hf : get_hard_forks(nettype))
        if (hf.version >= version)
            return hf.version;

    return version;
}

std::pair<hf, uint8_t> get_network_version_revision(network_type nettype, uint64_t height) {
    std::pair<hf, uint8_t> result;
    for (auto& h : get_hard_forks(nettype)) {
        if (h.height <= height)
            result = {h.version, h.snode_revision};
        else
            break;
    }
    return result;
}

bool is_hard_fork_at_least(network_type type, hf version, uint64_t height) {
    return get_network_version(type, height) >= version;
}

std::pair<hf, uint8_t> get_ideal_block_version(network_type nettype, uint64_t height) {
    std::pair<hf, uint8_t> result;
    for (auto& h : get_hard_forks(nettype)) {
        if (h.height <= height) {
            result.first = h.version;
            result.second = h.snode_revision;
        }
        if (result.first < hf::hf19_reward_batching)
            result.second = static_cast<uint8_t>(h.version);
    }
    return result;
}

}  // namespace cryptonote
