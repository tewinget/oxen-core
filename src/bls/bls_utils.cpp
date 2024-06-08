#include "bls_utils.h"

#include <oxenc/hex.h>

#include <cstring>

#include "common/guts.h"
#include "crypto/crypto.h"

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

namespace bls_utils {

static bool _need_init = true;
static std::mutex _init_mutex;

void init() {
    if (!_need_init) [[likely]]
        return;

    std::lock_guard lock{_init_mutex};
    if (!_need_init) [[unlikely]]
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

    _need_init = false;
}

crypto::bls_signature to_crypto_signature(const bls::Signature& sig) {
    init();
    constexpr mclSize serializedSignatureSize = 32;
    crypto::bls_signature serialized_signature;
    static_assert(serialized_signature.size() == serializedSignatureSize * 4);

    auto* dst = serialized_signature.data();
    const blsSignature* blssig = sig.getPtr();
    const mcl::bn::G2* g2Point = reinterpret_cast<const mcl::bn::G2*>(&blssig->v);
    mcl::bn::G2 g2Point2 = *g2Point;
    g2Point2.normalize();
    if (g2Point2.x.a.serialize(dst, serializedSignatureSize, BLS_MODE_BINARY) == 0)
        throw std::runtime_error("size of x.a is zero");
    if (g2Point2.x.b.serialize(
                dst + serializedSignatureSize, serializedSignatureSize, BLS_MODE_BINARY) == 0)
        throw std::runtime_error("size of x.b is zero");
    if (g2Point2.y.a.serialize(
                dst + serializedSignatureSize * 2, serializedSignatureSize, BLS_MODE_BINARY) == 0)
        throw std::runtime_error("size of y.a is zero");
    if (g2Point2.y.b.serialize(
                dst + serializedSignatureSize * 3, serializedSignatureSize, BLS_MODE_BINARY) == 0)
        throw std::runtime_error("size of y.b is zero");
    return serialized_signature;
}

#ifndef BLS_ETH
#error "BLS_ETH not defined, this is bad"
#endif

bls::Signature from_crypto_signature(const crypto::bls_signature& sig) {
    init();
    bls::Signature bls_sig;
    bls_sig.clear();
    auto sig_bytes = tools::view_guts(sig);
    if (0 !=
        mclBnG2_setStr(&bls_sig.getPtr()->v, sig_bytes.data(), sig_bytes.size(), BLS_MODE_BINARY))
        throw std::runtime_error{"Invalid signature"};
    return bls_sig;
}

[[nodiscard]] bool verify(
        const crypto::bls_signature& sig,
        const crypto::hash& hash,
        const crypto::bls_public_key& pk) {
    init();

    blsPublicKey blspk{};
    if (0 !=
        mclBnG1_setStr(
                &blspk.v, reinterpret_cast<const char*>(pk.data()), pk.size(), BLS_MODE_BINARY))
        return false;

    blsSignature blssig{};
    if (0 !=
        mclBnG2_setStr(
                &blssig.v, reinterpret_cast<const char*>(sig.data()), sig.size(), BLS_MODE_BINARY))
        return false;

    return blsVerifyHash(&blssig, &blspk, hash.data(), hash.size()) == 1;
}

crypto::bls_public_key to_crypto_pubkey(const bls::PublicKey& publicKey) {
    init();
    constexpr mclSize KEY_SIZE = 32;
    crypto::bls_public_key serializedKey;
    static_assert(serializedKey.size() == KEY_SIZE * 2 /*X, Y component*/);

    auto* dst = serializedKey.data();
    const blsPublicKey* rawKey = publicKey.getPtr();

    mcl::bn::G1 g1Point = {};
    g1Point.clear();

    // NOTE: const_cast is legal because the original g1Point was not declared
    // const
    static_assert(
            sizeof(*g1Point.x.getUnit()) * g1Point.x.maxSize == sizeof(rawKey->v.x.d),
            "We memcpy the key X,Y,Z component into G1 point's X,Y,Z component, hence, the sizes "
            "must match");
    std::memcpy(const_cast<uint64_t*>(g1Point.x.getUnit()), rawKey->v.x.d, sizeof(rawKey->v.x.d));
    std::memcpy(const_cast<uint64_t*>(g1Point.y.getUnit()), rawKey->v.y.d, sizeof(rawKey->v.y.d));
    std::memcpy(const_cast<uint64_t*>(g1Point.z.getUnit()), rawKey->v.z.d, sizeof(rawKey->v.z.d));
    g1Point.normalize();

    if (g1Point.x.serialize(dst, KEY_SIZE, BLS_MODE_BINARY) == 0)
        throw std::runtime_error("size of x is zero");
    if (g1Point.y.serialize(dst + KEY_SIZE, KEY_SIZE, BLS_MODE_BINARY) == 0)
        throw std::runtime_error("size of y is zero");

    return serializedKey;
}

bls::PublicKey from_crypto_pubkey(const crypto::bls_public_key& pk) {
    init();
    bls::PublicKey pubkey;
    pubkey.clear();
    if (0 != mclBnG1_setStr(
                     &const_cast<blsPublicKey*>(pubkey.getPtr())->v,
                     reinterpret_cast<const char*>(pk.data()),
                     pk.size(),
                     BLS_MODE_BINARY))
        throw std::runtime_error{"Invalid BLS pubkey"};

    return pubkey;
}

std::string PublicKeyToHex(const bls::PublicKey& publicKey) {
    auto pk = to_crypto_pubkey(publicKey);
    return oxenc::to_hex(pk.begin(), pk.end());
}
std::string SignatureToHex(const bls::Signature& sig) {
    auto s = to_crypto_signature(sig);
    return oxenc::to_hex(s.begin(), s.end());
}

}  // namespace bls_utils
