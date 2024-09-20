
#include <gtest/gtest.h>
#include <oxenc/hex.h>

#include <cstdint>

#include "bls/bls_signer.h"
#include "bls/bls_utils.h"
#include "common/guts.h"
#include "crypto/eth.h"

using namespace oxenc::literals;

TEST(BLS, Format) {
    auto pk = tools::make_from_guts<eth::bls_public_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    EXPECT_EQ(
            "{}"_format(pk),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    EXPECT_EQ(
            "{:z}"_format(pk),
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    auto sig = tools::make_from_guts<eth::bls_signature>(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hex);
    EXPECT_EQ(
            "{}"_format(sig),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    EXPECT_EQ(
            "{:z}"_format(sig),
            "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
}

TEST(BLS, equality) {
    auto pk1 = tools::make_from_guts<eth::bls_public_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    eth::bls_public_key pk2{};
    EXPECT_TRUE(pk1);
    EXPECT_FALSE(pk2);
    EXPECT_NE(pk1, crypto::null<eth::bls_public_key>);
    EXPECT_EQ(pk2, crypto::null<eth::bls_public_key>);

    eth::bls_public_key pk3;
    std::copy(pk1.begin(), pk1.end(), pk3.begin());
    EXPECT_EQ("{}"_format(pk1), "{}"_format(pk3));
    pk3 = pk2;
    EXPECT_EQ("{}"_format(pk3), "{}"_format(pk2));

    EXPECT_LT(pk2, pk1);
    EXPECT_GT(pk1, pk2);
}

TEST(BLS, to_from_crypto) {
    auto pk = tools::make_from_guts<eth::bls_public_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    auto pk2 = bls_utils::to_crypto_pubkey(bls_utils::from_crypto_pubkey(pk));
    EXPECT_EQ("{}"_format(pk), "{}"_format(pk2));

    auto sig = tools::make_from_guts<eth::bls_signature>(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hex);

    auto sig2 = bls_utils::to_crypto_signature(bls_utils::from_crypto_signature(sig));
    EXPECT_EQ("{}"_format(sig), "{}"_format(sig2));

    auto sk = tools::make_from_guts<eth::bls_secret_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    eth::BLSSigner signer{cryptonote::network_type::MAINNET, &sk};
    EXPECT_EQ(
            oxenc::to_hex(signer.getPubkey().getStr(bls_utils::BLS_MODE_BINARY)),
            "2c325c9d9c9593096528b2aa9d0d2cce042915e87a19c2a2a4cfbe4f5c61c694");
    auto pk3 = signer.getCryptoPubkey();
    EXPECT_EQ(
            tools::hex_guts(pk3),
            "14c6615c4fbecfa4a2c2197ae8152904ce2c0d9daab228650993959c9d5c322c"
            "1310113ec96bd4f56c1a3abb96dea45ffb8d785ea7a55faf38e12bfd92ba179b");
    auto pk4 = bls_utils::from_crypto_pubkey(pk3);
    EXPECT_EQ(
            oxenc::to_hex(pk4.getStr(bls_utils::BLS_MODE_BINARY)),
            "2c325c9d9c9593096528b2aa9d0d2cce042915e87a19c2a2a4cfbe4f5c61c694");
}

TEST(BLS, signatures) {
    auto sk = tools::make_from_guts<eth::bls_secret_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    eth::BLSSigner signer{cryptonote::network_type::MAINNET, &sk};

    auto pk = signer.getCryptoPubkey();
    ASSERT_EQ(
            "{}"_format(pk),
            "14c6615c4fbecfa4a2c2197ae8152904ce2c0d9daab228650993959c9d5c322c"
            "1310113ec96bd4f56c1a3abb96dea45ffb8d785ea7a55faf38e12bfd92ba179b");

    auto hash1 = crypto::keccak("hello world!"sv);
    ASSERT_EQ(
            "{}"_format(hash1), "57caa176af1ac0433c5df30e8dabcd2ec1af1e92a26eced5f719b88458777cd6");

    auto hash2 = crypto::keccak("Hello World!\n"sv);
    ASSERT_EQ(
            "{}"_format(hash2), "dc85a6bbfd4658040ef305c9333cf0d5a82ede2854f112549f3925df6b2c0e71");

    auto sig1 = signer.signMsg(hash1);
    auto sig1a = bls_utils::from_crypto_signature(sig1);
    auto sig1b = bls_utils::to_crypto_signature(bls_utils::from_crypto_signature(sig1));
    EXPECT_EQ("{}"_format(sig1), "{}"_format(sig1b));
    EXPECT_EQ(sig1a.getStr(), bls_utils::from_crypto_signature(sig1b).getStr());
    EXPECT_TRUE(signer.verifyMsg(bls_utils::to_crypto_signature(sig1a), bls_utils::to_crypto_pubkey(signer.getPubkey()), hash1));
    EXPECT_TRUE(signer.verifyMsg(sig1b, pk, hash1));

    EXPECT_EQ(
            "{}"_format(sig1),
            "28dcb2b1512acd2eb2405c6e25cdfa3172b3f3244f4f13b32c5cb0a6e52de22f"
            "1d1c84e8b728675709c43c53d465601fb7cde902470547fc92e39f47820a2cc3"
            "25c76fabbab649f9e786d727cc4c5123e1ec677087b920cc3bcd7e6701ed3953"
            "236410a224c9ba5eccf6189533838c9ef8e0b4354ae11556c705650b9d6a7cc6");
    EXPECT_TRUE(signer.verifyMsg(sig1, pk, hash1));

    auto sig2 = signer.signMsg(hash2);
    EXPECT_EQ(
            "{}"_format(sig2),
            "04da80bc677397dbd11c1a1a68ba0525e5e461c0eed3011af2445173c5331536"
            "2f72a0cb8043ac3f5345b218e0cb4d5e2a76da9450d18eeccc8b10a0e97abed7"
            "2bd7d00154ca33fa1491457dddfcd3874c2892a1e7bead5b4a9b8a588bb8edfe"
            "23b92cef33ef5fe950f166b4902ac98d6b96c7bc6a537c275bc9044c6b42ff3d");
    EXPECT_TRUE(signer.verifyMsg(sig2, pk, hash2));
}
