#include <span>
#include <string>
#include <string_view>

#include "crypto/crypto.h"

#define BLS_ETH
#define MCLBN_FP_UNIT_SIZE 4
#define MCLBN_FR_UNIT_SIZE 4
#include <bls/bls.hpp>

namespace oxenmq {
class Message;
};
namespace cryptonote {
class BlockchainSQLite;
};
class BLSSigner;

namespace oxen::bls {

enum class GetRewardBalanceResponseField
{
    Status,
    Address,
    Amount,
    Height,
    BLSPKeyHex,
    MessageHashSignature,
    _count,
};

struct GetRewardBalanceResponse {
    bool success;
    std::string error;  // Set if 'success' is false
    std::string_view status;
    crypto::eth_address address;
    uint64_t amount;
    uint64_t height;
    ::bls::PublicKey bls_pkey;
    ::bls::Signature message_hash_signature;
};

struct GetRewardBalanceSignatureParts
{
    std::string message_to_sign;    // Message in hex that must be signed via BLSSigner::hasHex
    crypto::bytes<32> hash_to_sign; // Hash that must be signed via BLSSigner::signHash
};

constexpr static inline std::string_view BLS_OMQ_REWARD_BALANCE_CMD = "bls.get_reward_balance";

GetRewardBalanceSignatureParts get_reward_balance_request_message(
        BLSSigner* signer, const crypto::eth_address& address, uint64_t amount);
GetRewardBalanceResponse create_reward_balance_request(
        const oxenmq::Message& m, BLSSigner* signer, cryptonote::BlockchainSQLite* sql_db);
GetRewardBalanceResponse parse_get_reward_balance_response(std::span<const std::string> data);
};  // namespace oxen::bls
