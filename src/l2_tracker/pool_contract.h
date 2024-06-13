#pragma once

#include <ethyl/provider.hpp>
#include <memory>
#include <string>
#include <vector>

namespace eth {

class RewardRateResponse {
  public:
    uint64_t timestamp;
    uint64_t reward;
    RewardRateResponse(uint64_t _timestamp, uint64_t _reward) :
            timestamp(_timestamp), reward(_reward) {}
};

class PoolContract {
  public:
    PoolContract(std::string _contractAddress, ethyl::Provider& _provider);
    RewardRateResponse RewardRate(uint64_t timestamp, uint64_t ethereum_block_height);

  private:
    std::string contractAddress;
    ethyl::Provider& provider;
};

}  // namespace eth
