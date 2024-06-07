#include "bls_aggregator.h"

#include "bls/bls_utils.h"
#include "bls/bls_omq.h"
#include "common/guts.h"
#include "ethyl/utils.hpp"
#include "common/string_util.h"
#include "logging/oxen_logger.h"

#define BLS_ETH
#define MCLBN_FP_UNIT_SIZE 4
#define MCLBN_FR_UNIT_SIZE 4

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <bls/bls.hpp>
#include <mcl/bn.hpp>
#undef MCLBN_NO_AUTOLINK
#pragma GCC diagnostic pop

static auto logcat = oxen::log::Cat("bls_aggregator");

BLSAggregator::BLSAggregator(
        service_nodes::service_node_list& _snl,
        std::shared_ptr<oxenmq::OxenMQ> _omq,
        std::shared_ptr<BLSSigner> _bls_signer) :
        bls_signer(std::move(_bls_signer)), omq(std::move(_omq)), service_node_list(_snl) {}

std::vector<std::pair<std::string, std::string>> BLSAggregator::getPubkeys() {
    std::vector<std::pair<std::string, std::string>> pubkeys;
    std::mutex pubkeys_mutex;

    processNodes(
            "bls.pubkey_request",
            [&pubkeys, &pubkeys_mutex](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {
                if (request_result.success) {
                    std::lock_guard<std::mutex> lock(pubkeys_mutex);
                    pubkeys.emplace_back(data[0], data[1]);
                }
            });

    return pubkeys;
}

blsRegistrationResponse BLSAggregator::registration(
        const std::string& senderEthAddress, const std::string& serviceNodePubkey) const {
    return blsRegistrationResponse{
            bls_signer->getPublicKeyHex(),
            bls_signer->proofOfPossession(senderEthAddress, serviceNodePubkey),
            senderEthAddress,
            serviceNodePubkey,
            ""};
}

void BLSAggregator::processNodes(
        std::string_view request_name,
        std::function<void(const BLSRequestResult&, const std::vector<std::string>&)> callback,
        std::span<const std::string> message,
        std::span<const crypto::x25519_public_key> exclude) {
    std::mutex connection_mutex;
    std::condition_variable cv;
    size_t active_connections = 0;
    const size_t MAX_CONNECTIONS = 900;

    std::vector<service_nodes::service_node_address> sn_nodes = {};
    service_node_list.copy_active_service_node_addresses(std::back_inserter(sn_nodes), exclude);

    for (const service_nodes::service_node_address& sn_address : sn_nodes) {
        if (1) {
            std::lock_guard<std::mutex> connection_lock(connection_mutex);
            ++active_connections;
        } else {
            // TODO(doyle): Rate limit
            std::unique_lock<std::mutex> connection_lock(connection_mutex);
            cv.wait(connection_lock,
                    [&active_connections] { return active_connections < MAX_CONNECTIONS; });
        }

        // NOTE:  Connect to the SN. Note that we do a request directly to the public key, this
        // should allow OMQ to re-use a connection (for potential subsequent calls) but also
        // automatically kill connections on our behalf.
        BLSRequestResult request_result = {};
        request_result.sn_address = sn_address;

        omq->request(
                oxenmq::ConnectionID(tools::copy_guts(sn_address.x_pkey)),
                request_name,
                [&connection_mutex, &active_connections, &cv, callback, &request_result](bool success, std::vector<std::string> data) {
                    request_result.success = success;
                    callback(request_result, data);

                    std::lock_guard<std::mutex> connection_lock(connection_mutex);
                    assert(active_connections);
                    --active_connections;
                    if (active_connections == 0) {
                        cv.notify_all();
                    }
                },
                oxenmq::send_option::data_parts(message.begin(), message.end()));
    }

    std::unique_lock<std::mutex> connection_lock(connection_mutex);
    cv.wait(connection_lock, [&active_connections] { return active_connections == 0; });
}

static void logNetworkRequestFailedWarning(
        const BLSRequestResult& result, std::string_view omq_cmd) {
    std::string ip_string = epee::string_tools::get_ip_string_from_int32(result.sn_address.ip);
    oxen::log::trace(
            logcat,
            "OMQ network request to {}:{} failed when executing '{}'",
            ip_string,
            std::to_string(result.sn_address.port),
            omq_cmd);
}

BLSRewardsResponse BLSAggregator::rewards_request(
        const crypto::eth_address& address,
        uint64_t amount,
        uint64_t height,
        std::span<const crypto::x25519_public_key> exclude) {
    oxen::log::trace(logcat, "Initiating rewards request of {} SENT for {} at height {}", amount, address, height);

    // NOTE: Validate the arguments
    if (address == crypto::eth_address{}) {
        throw std::invalid_argument(fmt::format(
                "Aggregating a rewards request for the zero address for {} SENT at height {} is "
                "invalid because address is invalid. Request rejected",
                address,
                amount,
                height,
                service_node_list.height()));
    }

    if (amount == 0) {
        throw std::invalid_argument(fmt::format(
                "Aggregating a rewards request for '{}' for 0 SENT at height {} is invalid because "
                "no rewards are available. Request rejected.",
                address,
                height));
    }

    if (height > service_node_list.height()) {
        throw std::invalid_argument(fmt::format(
                "Aggregating a rewards request for '{}' for {} SENT at height {} is invalid "
                "because the height is greater than the blockchain height {}. Request rejected",
                address,
                amount,
                height,
                service_node_list.height()));
    }

    // NOTE: Setup the work data for `processNodes`
    BLSSigner* signer = bls_signer.get();
    struct WorkPayload
    {
        std::mutex mutex;                   /// `processNodes` dispatches to a threadpool hence we require synchronisation
        std::vector<std::string> signers;   /// List of BLS public keys that signed the signature
        bls::Signature aggregate_signature; /// The signature we aggregate BLS responses to
        bls::PublicKey aggregate_pubkey;    /// Calculate the aggregate pubkey (for debugging purposes)
        std::string message_to_hash;        /// The message that each node must hash
        crypto::bytes<32> hash_to_sign;     /// The hash of the message that will be signed
    };

    WorkPayload work = {};
    work.aggregate_signature.clear();
    work.aggregate_pubkey.clear();

    // NOTE: Add our own signature to the aggregate signature
    {
        oxen::bls::GetRewardBalanceSignatureParts signature_parts = oxen::bls::get_reward_balance_request_message(signer, address, amount);
        work.message_to_hash = std::move(signature_parts.message_to_hash);
        work.hash_to_sign    = signature_parts.hash_to_sign;

        bls::Signature my_signature = signer->signHash(work.hash_to_sign);
        work.aggregate_signature.add(my_signature);
        work.aggregate_pubkey.add(signer->getPublicKey());
        work.signers.push_back(signer->getPublicKeyHex());
    }

    // NOTE: Send aggregate rewards request to the remainder of the network. This is a blocking
    // call!
    processNodes(
            oxen::bls::BLS_OMQ_REWARD_BALANCE_CMD,
            [&work, &address, amount, height](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {
                // NOTE: Sanity check the response
                if (!request_result.success) {
                    logNetworkRequestFailedWarning(request_result, oxen::bls::BLS_OMQ_REWARD_BALANCE_CMD);
                    return;
                }

                oxen::bls::GetRewardBalanceResponse response = oxen::bls::parse_get_reward_balance_response(data);
                if (!response.success) {
                    oxen::log::trace(logcat, "OMQ request '{}' rejected: {}", oxen::bls::BLS_OMQ_REWARD_BALANCE_CMD, response.error);
                    return;
                }

                // NOTE: Verify that the values that compose the signature are correct
                if (address != response.address || amount != response.amount || height != response.height) {
                    oxen::log::trace(
                            logcat,
                            "OMQ request '{}' rejected: Service node with BLS public key {} "
                            "(x25519 {} @ {}:{}) produced different values to sign than ours:\n"
                            "  - height:  {}\n"
                            "  - address: {}\n"
                            "  - amount:  {}\n"
                            "\n"
                            "Their values were:\n"
                            "  - height:  {}\n"
                            "  - address: {}\n"
                            "  - amount:  {}\n"
                            "\n"
                            "Signature was not aggregated into the response.",
                            oxen::bls::BLS_OMQ_REWARD_BALANCE_CMD,
                            bls_utils::PublicKeyToHex(response.bls_pkey),
                            request_result.sn_address.x_pkey,
                            epee::string_tools::get_ip_string_from_int32(request_result.sn_address.ip),
                            request_result.sn_address.port,
                            height,
                            address,
                            amount,
                            response.height,
                            response.address,
                            response.amount);
                    return;
                }

                // NOTE: Validate that the signature signed what we thought it
                // did by reconstructing the message.
                if (!response.message_hash_signature.verifyHash(response.bls_pkey, work.hash_to_sign.data(), work.hash_to_sign.size())) {
                    oxen::log::trace(
                            logcat,
                            "OMQ request '{}' rejected: Service node with BLS public key {} "
                            "(x25519 {} @ {}:{}) produced a signature that could not be verified "
                            "using the values:\n"
                            "  - height:          {}\n"
                            "  - address:         {}\n"
                            "  - amount:          {}\n"
                            "  - message to sign: {}\n"
                            "\n"
                            "They generated signature that didn't use the values "
                            "they reported in their response (above). Signature was not aggregated "
                            "into the response.",
                            oxen::bls::BLS_OMQ_REWARD_BALANCE_CMD,
                            bls_utils::PublicKeyToHex(response.bls_pkey),
                            request_result.sn_address.x_pkey,
                            epee::string_tools::get_ip_string_from_int32(request_result.sn_address.ip),
                            request_result.sn_address.port,
                            height,
                            address,
                            amount,
                            work.message_to_hash);
                    return;
                }

                std::lock_guard<std::mutex> lock(work.mutex);
                work.aggregate_signature.add(response.message_hash_signature);
                work.aggregate_pubkey.add(response.bls_pkey);
                work.signers.push_back(bls_utils::PublicKeyToHex(response.bls_pkey));
            },
            std::array{oxenc::type_to_hex(address), std::to_string(amount)},
            exclude);

    oxen::log::trace(logcat, "BLS aggregate pubkey for request calculated: {} ({} aggregations)", bls_utils::PublicKeyToHex(work.aggregate_pubkey), work.signers.size());
    const auto sig_str = bls_utils::SignatureToHex(work.aggregate_signature);
    BLSRewardsResponse result = {
            .address = "0x" + oxenc::type_to_hex(address),
            .amount = amount,
            .height = height,
            .signed_message = work.message_to_hash,
            .signers_bls_pubkeys = work.signers,
            .signature = sig_str};
    return result;
}

aggregateExitResponse BLSAggregator::aggregateExit(const std::string& bls_key) {
    bls::Signature agg_sig;
    agg_sig.clear();
    std::vector<std::string> signers;
    std::mutex signers_mutex;
    std::string signed_message = "";
    bool initial_data_set = false;

    std::string_view cmd = "bls.get_exit";
    processNodes(
            cmd,
            [&agg_sig, &signers, &signers_mutex, &bls_key, &signed_message, &initial_data_set, cmd](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {
                if (request_result.success) {
                    if (data[0] == "200") {

                        // Data contains -> status, bls_pubkey (signer), bls_pubkey (node being
                        // removed), signed message, signature
                        signers_mutex.lock();
                        if (!initial_data_set) {
                            signed_message = data[3];
                            initial_data_set = true;
                        }
                        signers_mutex.unlock();
                        if (data[1] != bls_key || data[3] != signed_message) {
                            // Log if the current data doesn't match the first set
                            oxen::log::warning(
                                    logcat,
                                    "Mismatch in data from node with bls pubkey {}. Expected "
                                    "bls_key: {}, signed message: {}. Received bls_key: {}, "
                                    "signed_message: {}.",
                                    data[2],
                                    bls_key,
                                    signed_message,
                                    data[1],
                                    data[3]);
                        } else {
                            bls::Signature external_signature;
                            external_signature.setStr(data[4]);
                            std::lock_guard<std::mutex> lock(signers_mutex);
                            agg_sig.add(external_signature);
                            signers.push_back(data[2]);
                        }
                    } else {
                        oxen::log::warning(
                                logcat,
                                "Error message received when requesting exit {} : {}",
                                data[0],
                                data[1]);
                    }
                } else {
                    logNetworkRequestFailedWarning(request_result, cmd);
                }
            },
            std::array{bls_key});
    const auto sig_str = bls_utils::SignatureToHex(agg_sig);
    return aggregateExitResponse{bls_key, signed_message, signers, sig_str};
}

aggregateExitResponse BLSAggregator::aggregateLiquidation(const std::string& bls_key) {
    bls::Signature agg_sig;
    agg_sig.clear();
    std::vector<std::string> signers;
    std::mutex signers_mutex;
    std::string signed_message = "";
    bool initial_data_set = false;

    std::string_view cmd = "bls.get_liquidation";
    processNodes(
            cmd,
            [&agg_sig, &signers, &signers_mutex, &bls_key, &signed_message, &initial_data_set, cmd](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {
                if (request_result.success) {
                    if (data[0] == "200") {

                        // Data contains -> status, bls_pubkey (signer), bls_pubkey (node being
                        // removed), signed message, signature
                        signers_mutex.lock();
                        if (!initial_data_set) {
                            signed_message = data[3];
                            initial_data_set = true;
                        }
                        signers_mutex.unlock();

                        if (data[1] != bls_key || data[3] != signed_message) {
                            // Log if the current data doesn't match the first set
                            oxen::log::warning(
                                    logcat,
                                    "Mismatch in data from node with bls pubkey {}. Expected "
                                    "bls_key: {}, signed message: {}. Received bls_key: {}, "
                                    "signed_message: {}.",
                                    data[2],
                                    bls_key,
                                    signed_message,
                                    data[1],
                                    data[3]);
                        } else {
                            bls::Signature external_signature;
                            external_signature.setStr(data[4]);
                            std::lock_guard<std::mutex> lock(signers_mutex);
                            agg_sig.add(external_signature);
                            signers.push_back(data[2]);
                        }
                    } else {
                        oxen::log::warning(
                                logcat,
                                "Error message received when requesting liquidation {} : {}",
                                data[0],
                                data[1]);
                    }
                } else {
                    logNetworkRequestFailedWarning(request_result, cmd);
                }
            },
            std::array{bls_key});
    const auto sig_str = bls_utils::SignatureToHex(agg_sig);
    return aggregateExitResponse{bls_key, signed_message, signers, sig_str};
}
