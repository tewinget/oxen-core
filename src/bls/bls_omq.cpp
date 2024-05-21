#include "bls_omq.h"

#include "blockchain_db/sqlite/db_sqlite.h"
#include "bls/bls_signer.h"
#include "bls/bls_utils.h"
#include "common/util.h"
#include "ethyl/utils.hpp"
#include "fmt/format.h"
#include "logging/oxen_logger.h"
#include "oxenmq/message.h"

static auto logcat = oxen::log::Cat("bls_omq");

namespace oxen::bls {
std::string get_reward_balance_request_message(BLSSigner* signer, const crypto::eth_address& eth_address, uint64_t amount)
{
    std::string result;
    if (signer) {
        result = fmt::format(
                "0x{}{}{}",
                signer->buildTag(signer->rewardTag),
                ethyl::utils::padToNBytes(oxenc::type_to_hex(eth_address), 20, ethyl::utils::PaddingDirection::LEFT),
                ethyl::utils::padTo32Bytes(ethyl::utils::decimalToHex(amount), ethyl::utils::PaddingDirection::LEFT));
    }
    return result;
}

static void write_and_3_dot_truncate(fmt::memory_buffer& buffer, std::string_view data, size_t threshold_for_3_dots) {
    if (data.size() > threshold_for_3_dots) {
        fmt::format_to_n(std::back_inserter(buffer), threshold_for_3_dots, "{}", data);
        fmt::format_to(std::back_inserter(buffer), "...");
    } else {
        fmt::format_to(std::back_inserter(buffer), "{}", data);
    }
}

// TODO(doyle): Need to 3 dot truncate because this is all untrusted input
struct PayloadResult
{
    bool good;
    std::string error;
};

static PayloadResult payload_is_hex(
        std::string_view payload_description,
        std::string_view payload,
        size_t required_hex_size) {
    PayloadResult result = {};
    payload = oxenc::trim_prefix(payload, "0x");
    payload = oxenc::trim_prefix(payload, "0x");

    if (payload.size() != required_hex_size) {
        result.error = fmt::format(
                "Specified an {} '{}' with length {} which does not have the "
                "correct length ({}) to be an {}",
                payload_description,
                payload,
                payload.size(),
                required_hex_size,
                payload_description);
        return result;
    }

    if (!oxenc::is_hex(payload)) {
        result.error = fmt::format(
                "Specified a {} '{}' which contains non-hex characters",
                payload_description,
                payload,
                payload.size());
        return result;
    }

    result.good = true;
    return result;
}

static PayloadResult payload_to_number(
        std::string_view payload_description,
        std::string_view payload,
        uint64_t& number) {

    PayloadResult result = {};
    if (!tools::parse_int(payload, number)) {
        result.error = fmt::format(
                "Specified {} '{}' that is not a valid number",
                payload_description,
                payload);
        return result;
    }

    result.good = true;
    return result;
}

enum class GetRewardBalanceRequestField
{
    Address,
    Amount,
    _count,
};

struct GetRewardBalanceRequest {
    crypto::eth_address address;
    uint64_t amount;
};

GetRewardBalanceResponse create_reward_balance_request(
        const oxenmq::Message& m, BLSSigner* signer, cryptonote::BlockchainSQLite* sql_db) {

    GetRewardBalanceResponse result = {};
    oxen::log::trace(logcat, "Received omq rewards signature request");

    // NOTE: Validate arguments
    if (!sql_db) {
        result.error = "Service node does not have a SQL DB setup to handle BLS OMQ requests";
        return result;
    }

    if (!signer) {
        result.error = "Service node does not have a SQL signer setup to handle BLS OMQ requests";
        return result;
    }

    // NOTE: Verify the data-segment count
    size_t field_count = tools::enum_count<GetRewardBalanceRequestField>;
    if (m.data.size() != field_count) {

        auto fmt_buffer = fmt::memory_buffer();
        fmt::format_to(
                std::back_inserter(fmt_buffer),
                "Bad request: BLS rewards command should have {} part(s), we received {}. The data was:\n",
                field_count,
                m.data.size());

        // NOTE: Dump the data
        for (size_t index = 0; index < m.data.size(); index++) {
            std::string_view part = m.data[index];
            fmt::format_to(std::back_inserter(fmt_buffer), "{}{} - ", index ? "\n" : "", index);
            write_and_3_dot_truncate(fmt_buffer, part, 48);
        }

        result.error = fmt::to_string(fmt_buffer);
        return result;
    }

    // NOTE: Validate and parse the received data
    const std::string_view cmd = oxen::bls::BLS_OMQ_REWARD_BALANCE_CMD;
    GetRewardBalanceRequest request = {};

    for (size_t field_index = 0; field_index < field_count; field_index++) {
        auto field_value = static_cast<GetRewardBalanceRequestField>(field_index);
        std::string_view payload = m.data[field_index];
        switch (field_value) {
            case GetRewardBalanceRequestField::Address: {
                size_t required_hex_size = sizeof(crypto::eth_address) * 2;
                PayloadResult to_result = payload_is_hex("BLS public key", payload, required_hex_size);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
                oxenc::from_hex(payload.begin(), payload.end(), reinterpret_cast<char*>(&request.address));
            } break;

            case GetRewardBalanceRequestField::Amount: {
                PayloadResult to_result = payload_to_number("rewards amount", payload, request.amount);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
            } break;

            case GetRewardBalanceRequestField::_count: {
                assert(!"Invalid code path");
            } break;
        }
    }

    // NOTE: Get the rewards amount from the DB
    std::string address_str = fmt::format("0x{}", request.address);
    auto [batchdb_height, amount] = sql_db->get_accrued_earnings(address_str);
    if (amount == 0) {
        result.error = fmt::format(
                "OMQ command '{}' requested an address '{}' that has a zero balance in the "
                "database",
                cmd,
                request.address);
        return result;
    }

    // NOTE: Verify the amount matches what the invoker requested
    if (request.amount != amount) {
        result.error = fmt::format(
                "OMQ command '{}' requested a reward amount {} for '{}' that does not match the rewards "
                "amount ({}) from this node's database",
                cmd,
                request.amount,
                request.address,
                amount);
        return result;
    }

    // NOTE: Prepare the signature
    // bytes memory encodedMessage = abi.encodePacked(rewardTag, recipientAddress, recipientAmount);
    std::string encoded_message = fmt::format(
            "0x{}{}{}",
            signer->buildTag(signer->rewardTag),
            ethyl::utils::padToNBytes(fmt::format("{}", request.address), 20, ethyl::utils::PaddingDirection::LEFT),
            ethyl::utils::padTo32Bytes(ethyl::utils::decimalToHex(amount), ethyl::utils::PaddingDirection::LEFT));

    std::string const message_to_sign =
            oxen::bls::get_reward_balance_request_message(signer, request.address, amount);
    crypto::bytes<32> const hash_message = signer->hash(encoded_message);

    // NOTE: Fill a response
    assert(result.error.empty());
    result.success                = true;
    result.status                 = "200";
    result.address                = request.address;
    result.amount                 = amount;
    result.height                 = batchdb_height;
    result.bls_pkey               = signer->getPublicKey();
    result.message_hash_signature = signer->signHash(hash_message);
    return result;
}

GetRewardBalanceResponse parse_get_reward_balance_response(std::span<const std::string> data) {
    GetRewardBalanceResponse result = {};
    size_t field_count = tools::enum_count<GetRewardBalanceResponseField>;
    if (data.size() != field_count) {
        return result;
    }

    // NOTE: Validate and parse the received data
    for (size_t enum_index = 0; enum_index < field_count; enum_index++) {
        std::string_view payload = data[enum_index];
        auto enum_value          = static_cast<oxen::bls::GetRewardBalanceResponseField>(enum_index);
        switch (enum_value) {

            case oxen::bls::GetRewardBalanceResponseField::Status: {
                if (payload != "200") {
                    // TODO(doyle): Better error message
                    oxen::log::error(
                            logcat,
                            "error message received when getting reward balance {} : "
                            "{}",
                            data[0],
                            data[1]);
                    return result;
                }
                result.status = payload;
            } break;

            case oxen::bls::GetRewardBalanceResponseField::Address: {
                size_t required_hex_size = sizeof(crypto::bls_public_key) * 2;
                PayloadResult to_result = payload_is_hex("Ethereum address", payload, required_hex_size);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
                oxenc::from_hex(payload.begin(), payload.end(), reinterpret_cast<char*>(&result.address));
            } break;

            case oxen::bls::GetRewardBalanceResponseField::Amount: {
                PayloadResult to_result = payload_to_number("rewards amount", payload, result.height);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
            } break;

            case oxen::bls::GetRewardBalanceResponseField::Height: {
                PayloadResult to_result = payload_to_number("height", payload, result.height);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
            } break;

            case oxen::bls::GetRewardBalanceResponseField::BLSPKeyHex: {
                size_t required_hex_size = sizeof(crypto::bls_public_key) * 2;
                PayloadResult to_result = payload_is_hex("BLS public key", payload, required_hex_size);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
                result.bls_pkey = bls_utils::HexToPublicKey(payload);
            } break;

            case oxen::bls::GetRewardBalanceResponseField::MessageHashSignature: {
                size_t required_hex_size = sizeof(blsSignature) * 2;
                PayloadResult to_result = payload_is_hex("BLS signature", payload, required_hex_size);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
                result.message_hash_signature = bls_utils::HexToSignature(payload);
            } break;

            case oxen::bls::GetRewardBalanceResponseField::_count: {
                assert(!"Invalid code path");
            } break;
        }
    }

    result.success = true;
    return result;
}
}  // namespace oxenbls
