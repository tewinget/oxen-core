#include "rewards_contract.h"

#include <ethyl/utils.hpp>
#include <common/oxen.h>
#include <common/string_util.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

#include <common/string_util.h>
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

TransactionType RewardsLogEntry::getLogType() const {
    if (topics.empty()) {
        throw std::runtime_error("No topics in log entry");
    }
    // keccak256('NewServiceNode(uint64,address,(uint256,uint256),(uint256,uint256,uint256,uint16),(address,uint256)[])')
    if (topics[0] == "0xe82ed1bfc15e6602fba1a19273171c8a63c1d40b0e0117be4598167b8655498f") {
        return TransactionType::NewServiceNode;
        // keccak256('ServiceNodeRemovalRequest(uint64,address,(uint256,uint256))')
    } else if (topics[0] == "0x89477e9f4ddcb5eb9f30353ab22c31ef9a91ab33fd1ffef09aadb3458be7775d") {
        return TransactionType::ServiceNodeLeaveRequest;
        // keccak256('ServiceNodeRemoval(uint64,address,uint256,(uint256,uint256))')
    } else if (topics[0] == "0x130a7be04ef1f87b2b436f68f389bf863ee179b95399a3a8444196fab7a4e54c") {
        return TransactionType::ServiceNodeExit;
    }
    return TransactionType::Other;
}

std::optional<TransactionStateChangeVariant> RewardsLogEntry::getLogTransaction() const {
    TransactionType type = getLogType();
    switch (type) {
        case TransactionType::NewServiceNode: {
            // event NewServiceNode(uint64 indexed serviceNodeID, address recipient, BN256G1.G1Point
            // pubkey, uint256 serviceNodePubkey, uint256 serviceNodeSignature, uint16 fee,
            // Contributors[] contributors); service node id is a topic so only address, pubkeys,
            // signature, fee and contributors are in data address is 32 bytes , pubkey is 64 bytes
            // and serviceNodePubkey is 64 bytes
            //
            // The address is in 32 bytes, but actually only uses 20 bytes and the first 12 are
            // padding
            int pos = 2;  // Start after the 0x prefix
            std::string eth_address_str =
                    data.substr(pos + 24, 40);  // Skip 24 characters which are always blank
            crypto::eth_address eth_address;
            tools::hex_to_type(eth_address_str, eth_address);
            pos += 64;
            // pull 64 bytes (128 characters) for the BLS pubkey
            std::string bls_key_str = data.substr(pos, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            pos += 128;
            // pull 32 bytes (64 characters) ed pubkey
            std::string service_node_pubkey = data.substr(pos, 64);
            pos += 64;
            // pull 64 bytes (128 characters) for ed signature
            std::string signature = data.substr(pos, 128);
            pos += 128;
            // pull 32 bytes (64 characters) for fee
            std::string fee_str = data.substr(pos, 64);
            uint64_t fee = ethyl::utils::hexStringToU64(fee_str);
            pos += 64;
            // There are 32 bytes describing the size of contributors data here, ignore because we
            // always get the same data out of it
            pos += 64;
            // pull 32 bytes (64 characters) for the number of elements in the array
            std::vector<Contributor> contributors;
            std::string num_contributors_str = data.substr(pos, 64);

            uint64_t num_contributors = ethyl::utils::hexStringToU64(num_contributors_str);
            pos += 64;
            std::string contributor_address_str;
            std::string contributor_amount_str;
            for (uint64_t i = 0; i < num_contributors; ++i) {
                // Each loop iteration processes one contributor
                contributor_address_str = data.substr(pos + 24, 40);
                crypto::eth_address contributor_address;
                tools::hex_to_type(contributor_address_str, contributor_address);
                pos += 64;
                contributor_amount_str = data.substr(pos, 64);
                uint64_t contributor_amount = ethyl::utils::hexStringToU64(contributor_amount_str);
                pos += 64;
                contributors.emplace_back(contributor_address, contributor_amount);
            }

            return NewServiceNodeTx(
                    bls_key, eth_address, service_node_pubkey, signature, fee, contributors);
        }
        case TransactionType::ServiceNodeLeaveRequest: {
            // event ServiceNodeRemovalRequest(uint64 indexed serviceNodeID, address recipient,
            // BN256G1.G1Point pubkey); service node id is a topic so only address and pubkey are in
            // data address is 32 bytes and pubkey is 64 bytes,
            //
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128
            // characters)
            std::string bls_key_str = data.substr(64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeLeaveRequestTx(bls_key);
        }
        case TransactionType::ServiceNodeDeregister: {
            // event ServiceNodeLiquidated(uint64 indexed serviceNodeID, address recipient,
            // BN256G1.G1Point pubkey); service node id is a topic so only address and pubkey are in
            // data address is 32 bytes and pubkey is 64 bytes,
            //
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128
            // characters)
            std::string bls_key_str = data.substr(64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeDeregisterTx(bls_key);
        }
        case TransactionType::ServiceNodeExit: {
            // event ServiceNodeRemoval(uint64 indexed serviceNodeID, address recipient, uint256
            // returnedAmount, BN256G1.G1Point pubkey); address is 32 bytes, amount is 32 bytes and
            // pubkey is 64 bytes
            //
            // The address is in 32 bytes, but actually only uses 20 bytes and the first 12 are
            // padding
            std::string eth_address_str = data.substr(2 + 24, 40);
            crypto::eth_address eth_address;
            tools::hex_to_type(eth_address_str, eth_address);
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 32 bytes (64
            // characters)
            std::string amount_str = data.substr(64 + 2, 64);
            uint64_t amount = ethyl::utils::hexStringToU64(amount_str);
            // pull 64 bytes (128 characters)
            std::string bls_key_str = data.substr(64 + 64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeExitTx(eth_address, amount, bls_key);
        }
        default: return std::nullopt;
    }
}

RewardsContract::RewardsContract(const std::string& _contractAddress, ethyl::Provider& _provider) :
        contractAddress(_contractAddress), provider(_provider) {}

StateResponse RewardsContract::State() {
    return State(provider.getLatestHeight());
}

StateResponse RewardsContract::State(uint64_t height) {
    std::string blockHash = provider.getContractStorageRoot(contractAddress, height);
    // Check if blockHash starts with "0x" and remove it
    if (blockHash.size() >= 2 && blockHash[0] == '0' && blockHash[1] == 'x') {
        blockHash = blockHash.substr(2);  // Skip the first two characters
    }
    return StateResponse{height, blockHash};
}

std::vector<RewardsLogEntry> RewardsContract::Logs(uint64_t height) {
    std::vector<RewardsLogEntry> logEntries;
    // Make the RPC call
    const auto logs = provider.getLogs(height, contractAddress);

    for (const auto& log : logs) {
        logEntries.emplace_back(RewardsLogEntry(log));
    }

    return logEntries;
}

std::vector<std::string> RewardsContract::getAllBLSPubkeys(uint64_t blockNumber) {
    std::stringstream stream;
    stream << "0x" << std::hex << blockNumber;
    std::string blockNumberHex = stream.str();

    // Get the sentinel node to start the iteration
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode sentinelNode = serviceNodes(service_node_sentinel_id, blockNumberHex);
    uint64_t currentNodeId = sentinelNode.next;

    std::vector<std::string> blsPublicKeys;

    // Iterate over the linked list of service nodes
    while (currentNodeId != service_node_sentinel_id) {
        ContractServiceNode serviceNode = serviceNodes(currentNodeId, blockNumberHex);
        blsPublicKeys.push_back(serviceNode.pubkey);
        currentNodeId = serviceNode.next;
    }

    return blsPublicKeys;
}

ContractServiceNode RewardsContract::serviceNodes(uint64_t index, std::string_view blockNumber)
{
    ethyl::ReadCallData callData     = {};
    std::string  indexABI            = ethyl::utils::padTo32Bytes(ethyl::utils::decimalToHex(index), ethyl::utils::PaddingDirection::LEFT);
    callData.contractAddress         = contractAddress;
    callData.data                    = ethyl::utils::toEthFunctionSignature("serviceNodes(uint64)") + indexABI;
    nlohmann::json     callResult    = provider.callReadFunctionJSON(callData, blockNumber);
    const std::string& callResultHex = callResult.get_ref<nlohmann::json::string_t&>();
    std::string_view   callResultIt  = ethyl::utils::trimPrefix(callResultHex, "0x");

    const size_t U256_HEX_SIZE                  = (256 / 8) * 2;
    const size_t BLS_PKEY_XY_COMPONENT_HEX_SIZE = 32 * 2;
    const size_t BLS_PKEY_HEX_SIZE              = BLS_PKEY_XY_COMPONENT_HEX_SIZE + BLS_PKEY_XY_COMPONENT_HEX_SIZE;
    const size_t ADDRESS_HEX_SIZE               = 32 * 2;
    const size_t HEX_PER_CONTRIBUTOR            = ADDRESS_HEX_SIZE /*address of contributor*/ + U256_HEX_SIZE /*amount contributed*/;

    // NOTE: Parse the blob into chunks of hex
    ContractServiceNode result                     = {};
    size_t              parsingIt                  = 0;

    // NOTE: The ServiceNode struct is a dynamic type (because its child `Contributor` field is
    // dynamic) hence the offset struct is encoded in the first 32 byte element.
    std::string_view    offsetToServiceNodeBlobHex = tools::string_safe_substr(callResultIt, parsingIt, U256_HEX_SIZE);
    size_t              offsetToServiceNodeBlob    = ethyl::utils::hexStringToU64(offsetToServiceNodeBlobHex);
    const size_t        serviceNodeIt              = offsetToServiceNodeBlob;
    parsingIt                                      = serviceNodeIt;

    // NOTE: Walk and grab each static element of the struct
    std::string_view    nextHex                     = tools::string_safe_substr(callResultIt, parsingIt, U256_HEX_SIZE);     parsingIt += nextHex.size();
    std::string_view    prevHex                     = tools::string_safe_substr(callResultIt, parsingIt, U256_HEX_SIZE);     parsingIt += prevHex.size();
    std::string_view    operatorHex                 = tools::string_safe_substr(callResultIt, parsingIt, ADDRESS_HEX_SIZE);  parsingIt += operatorHex.size();
    std::string_view    pubkeyHex                   = tools::string_safe_substr(callResultIt, parsingIt, BLS_PKEY_HEX_SIZE); parsingIt += pubkeyHex.size();
    std::string_view    leaveRequestTimestampHex    = tools::string_safe_substr(callResultIt, parsingIt, U256_HEX_SIZE);     parsingIt += leaveRequestTimestampHex.size();
    std::string_view    depositHex                  = tools::string_safe_substr(callResultIt, parsingIt, U256_HEX_SIZE);     parsingIt += depositHex.size();

    // NOTE: `Contributor` field is dynamic, hence the static encoding of it is the offset to the
    // array.
    std::string_view    offsetToContributorArrayHex = tools::string_safe_substr(callResultIt, parsingIt, U256_HEX_SIZE);
    size_t              offsetToContributorArray    = ethyl::utils::hexStringToU64(offsetToContributorArrayHex);

    // NOTE: Now jump to parsing the contributor array, first the static field (number of
    // contributors)
    parsingIt                                       = serviceNodeIt + offsetToContributorArray;
    std::string_view    contributorSizeHex          = tools::string_safe_substr(callResultIt, parsingIt, U256_HEX_SIZE); parsingIt += contributorSizeHex.size();
    const size_t        contributorSize             = ethyl::utils::hexStringToU64(contributorSizeHex);

    // NOTE: Then the remaining stream is the blobs for each contributor
    std::string_view    contributorArrayHex         = tools::string_safe_substr(callResultIt, parsingIt, contributorSize * HEX_PER_CONTRIBUTOR);
    parsingIt += contributorArrayHex.size();

    // NOTE: Validate the parsing iterator
    if (parsingIt != callResultIt.size()) {
        oxen::log::error(
                logcat,
                "Deserializing error when attempting to unpack service node ABI blob from rewards "
                "contract. We parsed {} bytes but the payload had {} bytes. The payload was\n{}",
                parsingIt,
                callResultIt.size(),
                callResultHex);
        return result;
    }

    // NOTE: Start parsing the contributors blobs
    if (contributorSize > result.contributors.max_size()) {
        oxen::log::error(
                logcat,
                "The number of contributors ({}) in the service node blob exceeded the "
                "available storage ({}) for service node {} with BLS public key {} at height "
                "{}. The service node blob components were\n"
                "\n"
                "  - nextHex:                   {}\n"
                "  - prevHex:                   {}\n"
                "  - operatorHex:               {}\n"
                "  - pubkeyHex:                 {}\n"
                "  - leaveRequestTimestampHex:  {}\n"
                "  - depositHex:                {}\n"
                "  - contributorSize:           {}\n"
                "  - contributorArray:          {}\n"
                "\n"
                "The raw blob was:\n\n{}"
                ,
                contributorSize,
                result.contributors.max_size(),
                index,
                pubkeyHex,
                blockNumber
                ,
                nextHex,
                prevHex,
                operatorHex,
                pubkeyHex,
                leaveRequestTimestampHex,
                depositHex,
                contributorSizeHex,
                contributorArrayHex,
                callResultHex);
        return result;
    }

    size_t expectedContributorHexSize = contributorSize * HEX_PER_CONTRIBUTOR;
    if (contributorArrayHex.size() != expectedContributorHexSize) {
        oxen::log::error(
                logcat,
                "The contributor payload in the unpacked service node ABI blob does not have "
                "the correct amount of bytes. We parsed {} bytes but the payload had {} bytes "
                "for service node {} with BLS public key {} at height {}.\n"
                "The service node blob components were:\n"
                "\n"
                "  - nextHex:                   {}\n"
                "  - prevHex:                   {}\n"
                "  - operatorHex:               {}\n"
                "  - pubkeyHex:                 {}\n"
                "  - leaveRequestTimestampHex:  {}\n"
                "  - depositHex:                {}\n"
                "  - contributorSize:           {}\n"
                "  - contributorDataRemaining:  {}\n"
                "\n"
                "The raw blob was:\n\n{}"
                ,
                contributorArrayHex.size() / 2,
                expectedContributorHexSize,
                index,
                pubkeyHex,
                blockNumber
                ,
                nextHex,
                prevHex,
                operatorHex,
                pubkeyHex,
                leaveRequestTimestampHex,
                depositHex,
                contributorSizeHex,
                contributorArrayHex,
                callResultHex);
        return result;
    }

    oxen::log::trace(
            logcat,
            "We parsed service node {} with BLS public key {} at height {}.\n"
            "The service node blob components were:\n"
            "\n"
            "  - nextHex:                   {}\n"
            "  - prevHex:                   {}\n"
            "  - operatorHex:               {}\n"
            "  - pubkeyHex:                 {}\n"
            "  - leaveRequestTimestampHex:  {}\n"
            "  - depositHex:                {}\n"
            "  - contributorSize:           {}\n"
            "  - contributorDataRemaining:  {}\n"
            "\n"
            "The raw blob was:\n\n{}"
            ,
            index,
            pubkeyHex,
            blockNumber
            ,
            nextHex,
            prevHex,
            operatorHex,
            pubkeyHex,
            leaveRequestTimestampHex,
            depositHex,
            contributorSizeHex,
            contributorArrayHex,
            callResultHex);

    for (size_t it = 0; it < contributorArrayHex.size(); it += HEX_PER_CONTRIBUTOR) {
        std::string_view addressHex      = tools::string_safe_substr(contributorArrayHex, it + 0,                ADDRESS_HEX_SIZE);
        std::string_view stakedAmountHex = tools::string_safe_substr(contributorArrayHex, it + ADDRESS_HEX_SIZE, U256_HEX_SIZE);

        Contributor& contributor = result.contributors[result.contributorsSize++];
        if (!tools::hex_to_type(addressHex, contributor.addr)) {
            oxen::log::error(
                    logcat,
                    "Contributor address hex '{}' ({} bytes) failed to be parsed into address "
                    "({} bytes) for service node {} with BLS public key {} at height {}.",
                    addressHex,
                    addressHex.size(),
                    contributor.addr.data_.max_size(),
                    index,
                    pubkeyHex,
                    blockNumber);
            return result;
        }

        contributor.amount = ethyl::utils::hexStringToU64(stakedAmountHex);
    }

    // NOTE: Deserialize linked list
    result.next                = ethyl::utils::hexStringToU64(nextHex);
    result.prev                = ethyl::utils::hexStringToU64(prevHex);

    // NOTE: Deserialise recipient
    const size_t ETH_ADDRESS_HEX_SIZE = 20 * 2;
    std::vector<unsigned char> recipientBytes = ethyl::utils::fromHexString(operatorHex.substr(operatorHex.size() - ETH_ADDRESS_HEX_SIZE, ETH_ADDRESS_HEX_SIZE));
    assert(recipientBytes.size() == result.operatorAddr.data_.max_size());
    std::memcpy(result.operatorAddr.data(), recipientBytes.data(), recipientBytes.size());

    result.pubkey = std::string(pubkeyHex);

    // NOTE: Deserialise metadata
    result.leaveRequestTimestamp = ethyl::utils::hexStringToU64(leaveRequestTimestampHex);
    result.deposit = depositHex;
    result.good = true;
    return result;
}

std::vector<uint64_t> RewardsContract::getNonSigners(const std::vector<std::string>& bls_public_keys) {
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode service_node_end = serviceNodes(service_node_sentinel_id);
    uint64_t service_node_id = service_node_end.next;
    std::vector<uint64_t> non_signers;
    
    while (service_node_id != service_node_sentinel_id) {
        ContractServiceNode service_node = serviceNodes(service_node_id);
        if (std::find(bls_public_keys.begin(), bls_public_keys.end(), service_node.pubkey) == bls_public_keys.end()) {
            non_signers.push_back(service_node_id);
        }
        service_node_id = service_node.next;
    }

    return non_signers;
}
