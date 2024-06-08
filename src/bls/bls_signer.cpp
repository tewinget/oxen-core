#include "bls_signer.h"

#include <epee/memwipe.h>
#include <fmt/core.h>
#include <oxenc/hex.h>

#include <bls/bls.hpp>
#include <ethyl/utils.hpp>
#include <mcl/op.hpp>

#include "bls_utils.h"
#include "common/bigint.h"
#include "common/guts.h"
#include "common/oxen.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("bls_signer");

BLSSigner::BLSSigner(const cryptonote::network_type nettype, const crypto::bls_secret_key* key) :
        nettype{nettype} {
    bls_utils::init();

    if (key) {
        // This interface to load a key from an existing chunk of memory by having to first copy it
        // into a std::string is just terrible.
        std::string key_bytes;
        OXEN_DEFER {
            memwipe(key_bytes.data(), key_bytes.size());
        };
        key_bytes.reserve(sizeof(crypto::bls_secret_key));
        key_bytes.append(reinterpret_cast<const char*>(key->data()), key->size());
        secretKey.setStr(key_bytes, mcl::IoSerialize | mcl::IoBigEndian);
    } else {
        // This init function generates a secret key calling blsSecretKeySetByCSPRNG
        secretKey.init();
    }
}

crypto::hash BLSSigner::buildTagHash(std::string_view baseTag, cryptonote::network_type nettype) {
    const auto config = get_config(nettype);
    return crypto::keccak(
            baseTag,
            tools::encode_integer_be<32>(config.ETHEREUM_CHAIN_ID),
            utils::fromHexString(config.ETHEREUM_REWARDS_CONTRACT));
}

crypto::hash BLSSigner::buildTagHash(std::string_view baseTag) {
    return buildTagHash(baseTag, nettype);
}

std::string BLSSigner::buildTagHex(std::string_view baseTag, cryptonote::network_type nettype) {
    return tools::hex_guts(buildTagHash(baseTag, nettype));
}

std::string BLSSigner::buildTagHex(std::string_view baseTag) {
    return buildTagHex(baseTag, nettype);
}

bls::Signature BLSSigner::signHashSig(const crypto::hash& hash) {
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return sig;
}

crypto::bls_signature BLSSigner::signHash(const crypto::hash& hash) {
    return tools::make_from_guts<crypto::bls_signature>(
            signHashSig(hash).getStr(bls_utils::BLS_MODE_BINARY));
}

crypto::bls_signature BLSSigner::proofOfPossession(
        crypto::eth_address sender, const crypto::public_key& serviceNodePubkey) {
    auto tag = buildTagHash(proofOfPossessionTag);

    auto hash = crypto::keccak(tag, getCryptoPubkey(), sender, serviceNodePubkey);

    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return bls_utils::to_crypto_signature(sig);
}

std::string BLSSigner::getPublicKeyHex() {
    auto pk = getCryptoPubkey();
    return oxenc::to_hex(pk.begin(), pk.end());
}

bls::PublicKey BLSSigner::getPublicKey() {
    bls::PublicKey publicKey;
    secretKey.getPublicKey(publicKey);
    return publicKey;
}

crypto::bls_public_key BLSSigner::getCryptoPubkey() {
    return bls_utils::to_crypto_pubkey(getPublicKey());
}

crypto::bls_secret_key BLSSigner::getCryptoSeckey() {
    std::string sec_key = secretKey.getStr(mcl::IoSerialize | mcl::IoBigEndian);
    assert(sec_key.size() == sizeof(crypto::bls_secret_key));

    crypto::bls_secret_key csk;
    std::memcpy(csk.data(), sec_key.data(), sizeof(csk));
    memwipe(sec_key.data(), sec_key.size());
    return csk;
}

crypto::hash BLSSigner::hashModulus(std::string_view message) {
    auto h = utils::hash(message);
    mcl::bn::Fp x;
    x.clear();
    x.setArrayMask(h.data(), h.size());
    crypto::hash serialized_hash;
    uint8_t* hdst = serialized_hash.data();
    if (x.serialize(hdst, serialized_hash.data_.max_size(), mcl::IoSerialize | mcl::IoBigEndian) ==
        0)
        throw std::runtime_error("size of x is zero");
    return serialized_hash;
}