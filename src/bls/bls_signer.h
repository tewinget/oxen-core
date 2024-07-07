#pragma once

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

#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_config.h"

namespace eth {

class BLSSigner {
  private:
    bls::SecretKey secretKey;
    cryptonote::network_type nettype;

  public:
    // Constructs a BLSSigner; if the `key` is nullptr, a key is generated; otherwise the key is
    // loaded from the given bls_secret_key data.
    explicit BLSSigner(const cryptonote::network_type nettype, const bls_secret_key* key = nullptr);

    bls::Signature signHashSig(const crypto::hash& hash) const;
    bls_signature signHash(const crypto::hash& hash) const;
    bls_signature proofOfPossession(
            const eth::address& sender, const crypto::public_key& serviceNodePubkey) const;
    std::string getPublicKeyHex() const;
    bls::PublicKey getPublicKey() const;

    // Gets the public key as our eth::bls_public_key type
    eth::bls_public_key getCryptoPubkey() const;
    // Gets the secret key as our eth::bls_secret_key type
    eth::bls_secret_key getCryptoSeckey() const;

    static std::string buildTagHex(std::string_view baseTag, cryptonote::network_type nettype);
    static crypto::hash buildTagHash(std::string_view baseTag, cryptonote::network_type nettype);
    std::string buildTagHex(std::string_view baseTag) const;
    crypto::hash buildTagHash(std::string_view baseTag) const;

    static constexpr inline std::string_view proofOfPossessionTag = "BLS_SIG_TRYANDINCREMENT_POP";
    static constexpr inline std::string_view rewardTag = "BLS_SIG_TRYANDINCREMENT_REWARD";
    static constexpr inline std::string_view removalTag = "BLS_SIG_TRYANDINCREMENT_REMOVE";
    static constexpr inline std::string_view liquidateTag = "BLS_SIG_TRYANDINCREMENT_LIQUIDATE";
};

}  // namespace eth
