#pragma once

#include <string_view>
#include <boost/uuid/uuid.hpp>

#include "common/fs.h"
#include "cryptonote_config.h"
#include "network_config/mainnet.h"
#include "network_config/devnet.h"
#include "network_config/testnet.h"
#include "network_config/fakechain.h"
#include "network_config/network_config.h"


using namespace std::literals;

namespace cryptonote {

constexpr network_type network_type_from_string(std::string_view s) {
    if (s == "mainnet")
        return network_type::MAINNET;
    if (s == "testnet")
        return network_type::TESTNET;
    if (s == "devnet")
        return network_type::DEVNET;
    if (s == "fakechain")
        return network_type::FAKECHAIN;

    return network_type::UNDEFINED;
}

constexpr std::string_view network_type_to_string(network_type t) {
    switch (t) {
        case network_type::MAINNET: return "mainnet";
        case network_type::TESTNET: return "testnet";
        case network_type::DEVNET: return "devnet";
        case network_type::FAKECHAIN: return "fakechain";
        default: return "undefined";
    }
    return "undefined";
}

inline std::filesystem::path network_config_subdir(network_type t) {
    if (t == network_type::MAINNET)
        return {};
    return tools::utf8_path(network_type_to_string(t));
}

inline constexpr const network_config& get_config(network_type nettype) {
    switch (nettype) {
        case network_type::MAINNET: return config::mainnet::config;
        case network_type::TESTNET: return config::testnet::config;
        case network_type::DEVNET: return config::devnet::config;
        case network_type::FAKECHAIN: return config::fakechain::config;
        default: throw std::runtime_error{"Invalid network type"};
    }
}

}
