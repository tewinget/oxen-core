#include "bls_signer.h"

#include <epee/memwipe.h>
#include <fmt/core.h>
#include <oxenc/hex.h>

#include <bls/bls.hpp>
#include <ethyl/utils.hpp>

#include "bls_utils.h"
#include "common/oxen.h"
#include "common/string_util.h"
#include "crypto/crypto.h"
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("bls_signer");

BLSSigner::BLSSigner(const cryptonote::network_type nettype, const crypto::bls_secret_key* key) :
        chainID{get_config(nettype).ETHEREUM_CHAIN_ID},
        contractAddress{get_config(nettype).ETHEREUM_REWARDS_CONTRACT} {
    initCurve();
    const auto config = get_config(nettype);
    chainID = config.ETHEREUM_CHAIN_ID;
    contractAddress = config.ETHEREUM_REWARDS_CONTRACT;

    if (key) {
        // This interface to load a key from an existing chunk of memory by having to first copy it
        // into a std::string is just terrible.
        std::string key_bytes;
        OXEN_DEFER {
            memwipe(key_bytes.data(), key_bytes.size());
        };
        key_bytes.reserve(sizeof(crypto::bls_secret_key));
        key_bytes.append(reinterpret_cast<const char*>(key->data()), key->size());
        secretKey.setStr(key_bytes, bls::IoSerialize);
    } else {
        // This init function generates a secret key calling blsSecretKeySetByCSPRNG
        secretKey.init();
    }
}

void BLSSigner::initCurve() {
    static bool need_init = true;
    static std::mutex init_mutex;
    std::lock_guard lock{init_mutex};
    if (!need_init)
        return;

    // Initialize parameters for BN256 curve, this has a different name in our library
    bls::init(mclBn_CurveSNARK1);
    // Try and Inc method for hashing to the curve
    mclBn_setMapToMode(MCL_MAP_TO_MODE_TRY_AND_INC);
    // Our generator point was created using the old hash to curve method, redo it again using Try
    // and Inc method
    mcl::bn::G1 gen;
    bool b;
    mcl::bn::mapToG1(&b, gen, 1);

    blsPublicKey publicKey;
    static_assert(
            sizeof(publicKey.v) == sizeof(gen),
            "We memcpy into a C structure hence sizes must be the same");
    std::memcpy(&publicKey.v, &gen, sizeof(gen));

    blsSetGeneratorOfPublicKey(&publicKey);

    need_init = false;
}

std::string BLSSigner::buildTag(
        std::string_view baseTag, uint32_t chainID, std::string_view contractAddress) {
    std::string_view hexPrefix = "0x";
    std::string_view contractAddressOutput = utils::trimPrefix(contractAddress, hexPrefix);
    std::string baseTagHex = utils::toHexString(baseTag);
    std::string chainIDHex =
            utils::padTo32Bytes(utils::decimalToHex(chainID), utils::PaddingDirection::LEFT);

    std::string concatenatedTag;
    concatenatedTag.reserve(
            hexPrefix.size() + baseTagHex.size() + chainIDHex.size() +
            contractAddressOutput.size());
    concatenatedTag.append(hexPrefix);
    concatenatedTag.append(baseTagHex);
    concatenatedTag.append(chainIDHex);
    concatenatedTag.append(contractAddressOutput);

    std::array<unsigned char, 32> hash = utils::hash(concatenatedTag);
    std::string result = utils::toHexString(hash);
    return result;
}

std::string BLSSigner::buildTag(std::string_view baseTag) {
    return buildTag(baseTag, chainID, contractAddress);
}

bls::Signature BLSSigner::signHash(const crypto::bytes<32>& hash) {
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return sig;
}

std::string BLSSigner::proofOfPossession(
        std::string_view senderEthAddress, std::string_view serviceNodePubkey) {
    std::string fullTag = buildTag(proofOfPossessionTag, chainID, contractAddress);
    std::string_view hexPrefix = "0x";
    std::string_view senderAddressOutput = utils::trimPrefix(senderEthAddress, hexPrefix);

    std::string publicKeyHex = getPublicKeyHex();
    std::string serviceNodePubkeyHex =
            utils::padTo32Bytes(serviceNodePubkey, utils::PaddingDirection::LEFT);

    std::string message;
    message.reserve(
            hexPrefix.size() + fullTag.size() + publicKeyHex.size() + senderAddressOutput.size() +
            serviceNodePubkeyHex.size());
    message.append(hexPrefix);
    message.append(fullTag);
    message.append(publicKeyHex);
    message.append(senderAddressOutput);
    message.append(serviceNodePubkeyHex);

    const crypto::bytes<32> hash = BLSSigner::hash(message);  // Get the hash of the publickey
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return bls_utils::SignatureToHex(sig);
}

std::string BLSSigner::getPublicKeyHex() {
    bls::PublicKey publicKey;
    secretKey.getPublicKey(publicKey);
    return bls_utils::PublicKeyToHex(publicKey);
}

bls::PublicKey BLSSigner::getPublicKey() {
    bls::PublicKey publicKey;
    secretKey.getPublicKey(publicKey);
    return publicKey;
}

crypto::bls_public_key BLSSigner::getCryptoPubkey() {
    auto pk = getPublicKey().getStr(bls::IoSerialize);
    assert(pk.size() == sizeof(crypto::bls_public_key));

    crypto::bls_public_key cpk;
    std::memcpy(cpk.data(), pk.data(), sizeof(cpk));
    return cpk;
}

crypto::bls_secret_key BLSSigner::getCryptoSeckey() {
    std::string sec_key = secretKey.getStr(bls::IoSerialize);
    assert(sec_key.size() == sizeof(crypto::bls_secret_key));

    crypto::bls_secret_key csk;
    std::memcpy(csk.data(), sec_key.data(), sizeof(csk));
    memwipe(sec_key.data(), sec_key.size());
    return csk;
}

crypto::bytes<32> BLSSigner::hash(std::string_view in) {
    crypto::bytes<32> result = {};
    result.data_ = utils::hash(in);
    return result;
}

crypto::bytes<32> BLSSigner::hashModulus(std::string_view message) {
    crypto::bytes<32> hash = BLSSigner::hash(message);
    mcl::bn::Fp x;
    x.clear();
    x.setArrayMask(hash.data(), hash.size());
    crypto::bytes<32> serialized_hash;
    uint8_t* hdst = serialized_hash.data();
    if (x.serialize(hdst, serialized_hash.data_.max_size(), mcl::IoSerialize | mcl::IoBigEndian) ==
        0)
        throw std::runtime_error("size of x is zero");
    return serialized_hash;
}
