#include "rewards_contract.h"

#include <ethyl/utils.hpp>

#include "crypto/crypto.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

#include "common/bigint.h"
#include "common/guts.h"
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

TransactionType getLogType(const LogEntry& log) {
    if (log.topics.empty()) {
        throw std::runtime_error("No topics in log entry");
    }
    // keccak256('NewServiceNode(uint64,address,(uint256,uint256),(uint256,uint256,uint256,uint16),(address,uint256)[])')
    if (log.topics[0] == "0xe82ed1bfc15e6602fba1a19273171c8a63c1d40b0e0117be4598167b8655498f") {
        return TransactionType::NewServiceNode;
        // keccak256('ServiceNodeRemovalRequest(uint64,address,(uint256,uint256))')
    } else if (
            log.topics[0] == "0x89477e9f4ddcb5eb9f30353ab22c31ef9a91ab33fd1ffef09aadb3458be7775d") {
        return TransactionType::ServiceNodeLeaveRequest;
        // keccak256('ServiceNodeRemoval(uint64,address,uint256,(uint256,uint256))')
    } else if (
            log.topics[0] == "0x130a7be04ef1f87b2b436f68f389bf863ee179b95399a3a8444196fab7a4e54c") {
        return TransactionType::ServiceNodeExit;
    }
    return TransactionType::Other;
}

using u256 = std::array<std::byte, 32>;
using tools::skip;
using tools::skip_t;

TransactionStateChangeVariant getLogTransaction(const LogEntry& log) {
    TransactionStateChangeVariant result;
    TransactionType type = getLogType(log);
    switch (type) {
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
            // Service node id is a topic so only address, pubkeys, signature, fee and contributors
            // are in data Address is 32 bytes, the first 12 of which are padding pubkey is 64 bytes
            // serviceNodePubkey is 64 bytes
            // contributors starts with a u256 of the contributor data length (=64), u256 of the
            // array length, followed by the contributor info:
            //     - address (with 12 byte prefix padding)
            //     - amount (u256)

            auto& [bls_pk, eth_addr, sn_pubkey, sn_sig, fee, contributors] =
                    result.emplace<NewServiceNodeTx>();

            u256 fee256, c_size, c_len;
            std::string_view contrib_hex;
            std::tie(eth_addr, bls_pk, sn_pubkey, sn_sig, fee256, c_size, c_len, contrib_hex) =
                    tools::split_hex_into<
                            skip<12>,
                            crypto::eth_address,
                            crypto::bls_public_key,
                            crypto::public_key,
                            crypto::ed25519_signature,
                            u256,
                            u256,
                            u256,
                            std::string_view>(log.data);

            fee = tools::decode_integer_be(fee256);
            auto num_contributors = tools::decode_integer_be(c_len);
            if (tools::decode_integer_be(c_size) != 64 ||
                contrib_hex.size() != 2 * num_contributors * (32 + 32))
                throw std::invalid_argument{
                        "Invalid NewServiceNode data: invaliad contributor data"};

            contributors.resize(num_contributors);
            for (auto& [addr, amt] : contributors) {
                u256 amt256;
                std::tie(addr, amt256, contrib_hex) = tools::
                        split_hex_into<skip<12>, crypto::eth_address, u256, std::string_view>(
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
            std::tie(bls_pk) =
                    tools::split_hex_into<skip<12 + 20>, crypto::bls_public_key>(log.data);
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
            std::tie(bls_pk) =
                    tools::split_hex_into<skip<12 + 20>, crypto::bls_public_key>(log.data);
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
            std::tie(eth_addr, amt256, bls_pk) = tools::
                    split_hex_into<skip<12>, crypto::eth_address, u256, crypto::bls_public_key>(
                            log.data);
            amount = tools::decode_integer_be(amt256);
            break;
        }
        case TransactionType::Other:;
    }
    return result;
}

RewardsContract::RewardsContract(const std::string& _contractAddress, ethyl::Provider& _provider) :
        contractAddress(_contractAddress), provider(_provider) {}

StateResponse RewardsContract::State() {
    return State(provider.getLatestHeight());
}

StateResponse RewardsContract::State(uint64_t height) {
    std::string blockHash = provider.getContractStorageRoot(contractAddress, height);
    std::string_view bh{blockHash};
    if (bh.starts_with("0x"))
        bh.remove_prefix(2);
    return {height, tools::make_from_hex_guts<crypto::hash>(bh)};
}

std::vector<LogEntry> RewardsContract::Logs(uint64_t height) {
    return provider.getLogs(height, contractAddress);
}

std::vector<crypto::bls_public_key> RewardsContract::getAllBLSPubkeys(uint64_t blockNumber) {
    // Get the sentinel node to start the iteration
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode sentinelNode = serviceNodes(service_node_sentinel_id, blockNumber);
    uint64_t currentNodeId = sentinelNode.next;

    std::vector<crypto::bls_public_key> blsPublicKeys;

    // Iterate over the linked list of service nodes
    while (currentNodeId != service_node_sentinel_id) {
        ContractServiceNode serviceNode = serviceNodes(currentNodeId, blockNumber);
        blsPublicKeys.push_back(serviceNode.pubkey);
        currentNodeId = serviceNode.next;
    }

    return blsPublicKeys;
}

ContractServiceNode RewardsContract::serviceNodes(
        uint64_t index, std::optional<uint64_t> blockNumber) {
    ethyl::ReadCallData callData = {};
    std::string indexABI =
            utils::padTo32Bytes(utils::decimalToHex(index), utils::PaddingDirection::LEFT);
    callData.contractAddress = contractAddress;
    callData.data = utils::getFunctionSignature("serviceNodes(uint64)") + indexABI;
    // FIXME(OXEN11): we *cannot* make a blocking request here like this because we are blocking
    // some other thread from doing work; we either need to get this from a local cache of the info,
    // or make it asynchronous (i.e. with a completion/timeout callback), or both (i.e. try cache,
    // make request asynchronously if not found).
    //
    // FIXME(OXEN11): nor can we make recursive linked lists requests like this!
    std::string blockNumArg = blockNumber ? "0x{:x}"_format(*blockNumber) : "latest";
    nlohmann::json callResult = provider.callReadFunctionJSON(callData, blockNumArg);
    auto callResultHex = callResult.get<std::string_view>();

    auto [next, prev, recipient, pubkey, leaveRequestTimestamp, deposit] = tools::split_hex_into<
            skip<32>,
            u256,
            u256,
            skip<12>,
            crypto::eth_address,
            crypto::bls_public_key,
            u256,
            u256>(callResultHex);

    ContractServiceNode result{};

    result.next = tools::decode_integer_be(next);
    result.prev = tools::decode_integer_be(prev);
    result.recipient = recipient;
    result.pubkey = pubkey;
    result.leaveRequestTimestamp = tools::decode_integer_be(leaveRequestTimestamp);
    result.deposit = tools::decode_integer_be(deposit);
    return result;
}

std::vector<uint64_t> RewardsContract::getNonSigners(
        const std::unordered_set<crypto::bls_public_key>& bls_public_keys) {
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