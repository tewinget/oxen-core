#include "ethereum_transactions.h"

#include "cryptonote_basic/cryptonote_format_utils.h"

using cryptonote::hf;

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

namespace ethereum {

template <typename... T>
static bool check_condition(
        bool condition, std::string* reason, fmt::format_string<T...> format, T&&... args) {
    if (condition && reason)
        *reason = fmt::format(format, std::forward<T>(args)...);
    return condition;
}

bool validate_ethereum_new_service_node_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_new_service_node& eth_extra,
        std::string* reason) {

    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum_new_service_node,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum_new_service_node))
            return false;
        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum new service node data in the tx_extra",
                    tx))
            return false;
    }

    return true;
}

bool validate_ethereum_service_node_leave_request_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_leave_request& eth_extra,
        std::string* reason) {

    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum_service_node_leave_request,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum_service_node_leave_request))
            return false;

        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum service node leave request data in the tx_extra",
                    tx))
            return false;
    }

    return true;
}

bool validate_ethereum_service_node_exit_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_exit& eth_extra,
        std::string* reason) {

    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum_service_node_exit,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum_service_node_exit))
            return false;

        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum service node exit data in the tx_extra",
                    tx))
            return false;
    }

    return true;
}

bool validate_ethereum_service_node_deregister_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_deregister& eth_extra,
        std::string* reason) {

    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum_service_node_deregister,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum_service_node_deregister))
            return false;

        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum service node deregister data in the tx_extra",
                    tx))
            return false;
    }

    return true;
}

}  // namespace ethereum