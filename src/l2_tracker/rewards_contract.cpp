#include "rewards_contract.h"

#include <ethyl/utils.hpp>

#include "common/bigint.h"
#include "common/guts.h"
#include "contracts.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "logging/oxen_logger.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

namespace eth {

namespace {
    auto logcat = oxen::log::Cat("l2_tracker");

    TransactionType getLogType(const ethyl::LogEntry& log) {
        if (log.topics.empty())
            throw std::runtime_error("No topics in log entry");

        auto event_sig = tools::make_from_hex_guts<crypto::hash>(log.topics[0]);

        return event_sig == contract::event::NewServiceNode ? TransactionType::NewServiceNode
             : event_sig == contract::event::ServiceNodeRemovalRequest
                     ? TransactionType::ServiceNodeLeaveRequest
             : event_sig == contract::event::ServiceNodeRemoval ? TransactionType::ServiceNodeExit
                                                                : TransactionType::Other;
    }

}  // namespace

using u256 = std::array<std::byte, 32>;
using tools::skip;
using tools::skip_t;

TransactionStateChangeVariant getLogTransaction(const ethyl::LogEntry& log) {
    TransactionStateChangeVariant result;
    switch (getLogType(log)) {
        case TransactionType::NewServiceNode: {
            // event NewServiceNode(
            //      uint64 indexed serviceNodeID,
            //      address recipient,
            //      { // struct ServiceNodeParams
            //          BN256G1.G1Point pubkey,
            //          uint256 serviceNodePubkey,
            //          (uint256,uint256) serviceNodeSignature,
            //          uint256 fee,
            //      },
            //      Contributors[] contributors);
            //
            // Note:
            // - address is 32 bytes, the first 12 of which are padding
            // - fee is between 0 and 10000, despite being packed into a gigantic 256-bit int.

            auto& [bls_pk, eth_addr, sn_pubkey, sn_sig, fee, contributors] =
                    result.emplace<NewServiceNodeTx>();

            u256 fee256, c_size, c_len;
            std::string_view contrib_hex;
            std::tie(eth_addr, bls_pk, sn_pubkey, sn_sig, fee256, c_size, c_len, contrib_hex) =
                    tools::split_hex_into<
                            skip<12>,
                            eth::address,
                            bls_public_key,
                            crypto::public_key,
                            crypto::ed25519_signature,
                            u256,
                            u256,
                            u256,
                            std::string_view>(log.data);

            fee = tools::decode_integer_be(fee256);
            if (fee > cryptonote::STAKING_FEE_BASIS)
                throw std::invalid_argument{
                        "Invalid NewServiceNode data: fee must be in [0, {}]"_format(
                                cryptonote::STAKING_FEE_BASIS)};
            auto num_contributors = tools::decode_integer_be(c_len);
            if (tools::decode_integer_be(c_size) != 64 ||
                contrib_hex.size() != 2 * num_contributors * (32 + 32))
                throw std::invalid_argument{
                        "Invalid NewServiceNode data: invalid contributor data"};

            contributors.resize(num_contributors);
            for (auto& [addr, amt] : contributors) {
                u256 amt256;
                std::tie(addr, amt256, contrib_hex) =
                        tools::split_hex_into<skip<12>, eth::address, u256, std::string_view>(
                                contrib_hex);
                amt = tools::decode_integer_be(amt256);
            }
            break;
        }
        case TransactionType::ServiceNodeLeaveRequest: {
            // event ServiceNodeRemovalRequest(
            //      uint64 indexed serviceNodeID,
            //      address recipient,
            //      BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes (with 12-byte prefix padding)
            // pubkey is 64 bytes,
            auto& [bls_pk] = result.emplace<ServiceNodeLeaveRequestTx>();
            std::tie(bls_pk) = tools::split_hex_into<skip<12 + 20>, bls_public_key>(log.data);
            break;
        }
        case TransactionType::ServiceNodeDeregister: {
            // event ServiceNodeLiquidated(
            //      uint64 indexed serviceNodeID,
            //      address recipient,
            //      BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes (with 12-byte prefix padding)
            // pubkey is 64 bytes
            auto& [bls_pk] = result.emplace<ServiceNodeDeregisterTx>();
            std::tie(bls_pk) = tools::split_hex_into<skip<12 + 20>, bls_public_key>(log.data);
            break;
        }
        case TransactionType::ServiceNodeExit: {
            // event ServiceNodeRemoval(
            //      uint64 indexed serviceNodeID,
            //      address recipient,
            //      uint256 returnedAmount,
            //      BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes (with 12-byte prefix padding)
            // pubkey is 64 bytes
            auto& [eth_addr, amount, bls_pk] = result.emplace<ServiceNodeExitTx>();
            u256 amt256;
            std::tie(eth_addr, amt256, bls_pk) =
                    tools::split_hex_into<skip<12>, eth::address, u256, bls_public_key>(log.data);
            amount = tools::decode_integer_be(amt256);
            break;
        }
        case TransactionType::Other:;
    }
    return result;
}

RewardsContract::RewardsContract(cryptonote::network_type nettype, ethyl::Provider& provider) :
        contractAddress{contract::rewards_address(nettype)}, provider{provider} {}

std::vector<bls_public_key> RewardsContract::getAllBLSPubkeys(uint64_t blockNumber) {
    // Get the sentinel node to start the iteration
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode sentinelNode = serviceNodes(service_node_sentinel_id, blockNumber);
    uint64_t currentNodeId = sentinelNode.next;

    std::vector<bls_public_key> blsPublicKeys;

    // Iterate over the linked list of service nodes
    while (currentNodeId != service_node_sentinel_id) {
        ContractServiceNode serviceNode = serviceNodes(currentNodeId, blockNumber);
        blsPublicKeys.push_back(serviceNode.pubkey);
        currentNodeId = serviceNode.next;
    }

    return blsPublicKeys;
}

static std::string service_node_blob_debug(
        const ContractServiceNode& result, std::string_view full_hex) {
    return "Service node blob components were:\n"
           "\n"
           "  - next:                   {}\n"
           "  - prev:                   {}\n"
           "  - operator:               {}\n"
           "  - pubkey:                 {}\n"
           "  - leaveRequestTimestamp:  {}\n"
           "  - deposit:                {}\n"
           "  - num contributors:       {}\n"
           "\n"
           "The raw blob was:\n\n{}"_format(
                   result.next,
                   result.prev,
                   result.operatorAddr,
                   result.pubkey,
                   result.leaveRequestTimestamp,
                   result.deposit,
                   result.contributorsSize,
                   full_hex);
}

ContractServiceNode RewardsContract::serviceNodes(
        uint64_t index, std::optional<uint64_t> blockNumber) {
    // callData.contractAddress = contractAddress;
    auto callData = "0x{:x}{:032x}"_format(contract::call::ServiceNodeRewards_serviceNodes, index);

    // FIXME(OXEN11): we *cannot* make a blocking request here like this because we are blocking
    // some other thread from doing work; we either need to get this from a local cache of the info,
    // or make it asynchronous (i.e. with a completion/timeout callback), or both (i.e. try cache,
    // make request asynchronously if not found).
    //
    // FIXME(OXEN11): nor can we make recursive linked lists requests like this!
    std::string blockNumArg = blockNumber ? "0x{:x}"_format(*blockNumber) : "latest";
    nlohmann::json callResult =
            provider.callReadFunctionJSON(contractAddress, callData, blockNumArg);
    auto callResultHex = callResult.get<std::string_view>();

    // NOTE: The ServiceNode struct is a dynamic type (because its child `Contributor` field is
    // dynamic) hence the offset struct is encoded in the first 32 byte element.
    auto [sn_data_offset] = tools::split_hex_into<u256, tools::ignore>(callResultHex);
    auto sn_data = callResultHex.substr(tools::decode_integer_be(sn_data_offset));
    auto [next, prev, op_addr, pubkey, leaveRequestTimestamp, deposit, contr_offset] =
            tools::split_hex_into<
                    u256,
                    u256,
                    skip<12>,
                    eth::address,
                    bls_public_key,
                    u256,
                    u256,
                    u256,
                    tools::ignore>(sn_data);

    ContractServiceNode result{};
    result.good = false;  // until proven otherwise
    result.next = tools::decode_integer_be(next);
    result.prev = tools::decode_integer_be(prev);
    result.operatorAddr = op_addr;
    result.pubkey = pubkey;
    result.leaveRequestTimestamp = tools::decode_integer_be(leaveRequestTimestamp);
    result.deposit = tools::decode_integer_be(deposit);

    auto contrib_data = sn_data.substr(tools::decode_integer_be(contr_offset));
    auto [contrib_len] = tools::split_hex_into<u256, tools::ignore>(contrib_data);

    // NOTE: Start parsing the contributors blobs
    if (auto contributorSize = tools::decode_integer_be(contrib_len);
        contributorSize <= result.contributors.max_size())
        result.contributorsSize = contributorSize;
    else {
        oxen::log::error(
                logcat,
                "The number of contributors ({}) in the service node blob exceeded the available "
                "storage ({}) for service node {} with BLS public key {} at height {}",
                contributorSize,
                result.contributors.max_size(),
                index,
                result.pubkey,
                blockNumber ? "{}"_format(*blockNumber) : "(latest)");
        oxen::log::debug(logcat, "{}", service_node_blob_debug(result, callResultHex));
        return result;
    }

    for (size_t i = 0; i < result.contributorsSize; i++) {
        try {
            auto& [addr, amount] = result.contributors[i];
            u256 amt;
            std::tie(addr, amt, contrib_data) =
                    tools::split_hex_into<skip<12>, eth::address, u256, std::string_view>(
                            contrib_data);
            amount = tools::decode_integer_be(amt);
        } catch (const std::exception& e) {
            oxen::log::error(
                    logcat,
                    "Failed to parse contributor/contribution [{}] for service node {} with BLS "
                    "pubkey {} at height {}: {}",
                    i,
                    index,
                    result.pubkey,
                    blockNumber ? "{}"_format(*blockNumber) : "(latest)",
                    e.what());
            oxen::log::debug(logcat, "{}", service_node_blob_debug(result, callResultHex));
            return result;
        }
    }

    oxen::log::trace(
            logcat,
            "Successfully parsed new SN. {}",
            service_node_blob_debug(result, callResultHex));

    result.good = true;
    return result;
}

std::vector<uint64_t> RewardsContract::getNonSigners(
        const std::unordered_set<bls_public_key>& bls_public_keys) {
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode service_node_end = serviceNodes(service_node_sentinel_id);
    uint64_t service_node_id = service_node_end.next;
    std::vector<uint64_t> non_signers;

    while (service_node_id != service_node_sentinel_id) {
        ContractServiceNode service_node = serviceNodes(service_node_id);
        if (!bls_public_keys.count(service_node.pubkey))
            non_signers.push_back(service_node_id);
        service_node_id = service_node.next;
    }

    return non_signers;
}

std::string NewServiceNodeTx::to_string() const {
    return "{} [bls_pubkey={}, addr={}, sn_pubkey={}]"_format(
            state_change_name<NewServiceNodeTx>(), bls_pubkey, eth_address, sn_pubkey);
}

std::string ServiceNodeLeaveRequestTx::to_string() const {
    return "{} [bls_pubkey={}]"_format(state_change_name<ServiceNodeLeaveRequestTx>(), bls_pubkey);
}

std::string ServiceNodeDeregisterTx::to_string() const {
    return "{} [bls_pubkey={}]"_format(state_change_name<ServiceNodeDeregisterTx>(), bls_pubkey);
}

std::string ServiceNodeExitTx::to_string() const {
    return "{} [bls_pubkey={}, addr={}, amount={}]"_format(
            state_change_name<ServiceNodeExitTx>(), bls_pubkey, eth_address, amount);
}

}  // namespace eth
