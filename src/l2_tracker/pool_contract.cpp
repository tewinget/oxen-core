#include "pool_contract.h"

#include <ethyl/utils.hpp>

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

PoolContract::PoolContract(std::string _contractAddress, ethyl::Provider& _provider) :
        contractAddress(std::move(_contractAddress)), provider(_provider) {}

RewardRateResponse PoolContract::RewardRate(uint64_t timestamp, uint64_t ethereum_block_height) {
    ethyl::ReadCallData callData;
    callData.contractAddress = contractAddress;
    std::string timestampStr =
            ethyl::utils::padTo32Bytes(ethyl::utils::decimalToHex(timestamp), ethyl::utils::PaddingDirection::LEFT);
    // keccak256("rewardRate(uint256)")
    std::string functionABI = "0xcea01962";
    callData.data = functionABI + timestampStr;
    std::string result = provider.callReadFunction(callData, ethereum_block_height);
    return RewardRateResponse{timestamp, ethyl::utils::hexStringToU64(result)};
}
