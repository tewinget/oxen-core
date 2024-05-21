#pragma once

#include <string>

namespace bls {
class PublicKey;
class Signature;
};  // namespace bls

namespace bls_utils {
std::string PublicKeyToHex(const bls::PublicKey& publicKey);
bls::PublicKey HexToPublicKey(std::string_view hex);
std::string SignatureToHex(const bls::Signature& sig);
bls::Signature HexToSignature(std::string_view hex);
}  // namespace bls_utils
