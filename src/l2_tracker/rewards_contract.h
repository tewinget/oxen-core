#pragma once
#include <crypto/crypto.h>

#include <ethyl/logs.hpp>
#include <ethyl/provider.hpp>
#include <memory>
#include <string>
#include <variant>

enum class TransactionType {
    NewServiceNode,
    ServiceNodeLeaveRequest,
    ServiceNodeDeregister,
    ServiceNodeExit,
    Other
};

struct Contributor {
    crypto::eth_address addr;
    uint64_t amount;

    Contributor() = default;
    Contributor(const crypto::eth_address& address, uint64_t amt) : addr(address), amount(amt) {}
};

class NewServiceNodeTx {
  public:
    crypto::bls_public_key bls_key;
    crypto::eth_address eth_address;
    std::string service_node_pubkey;
    std::string signature;
    uint64_t fee;
    std::vector<Contributor> contributors;

    NewServiceNodeTx(
            const crypto::bls_public_key& _bls_key,
            const crypto::eth_address& _eth_address,
            const std::string& _service_node_pubkey,
            const std::string& _signature,
            const uint64_t _fee,
            const std::vector<Contributor>& _contributors) :
            bls_key(_bls_key),
            eth_address(_eth_address),
            service_node_pubkey(_service_node_pubkey),
            signature(_signature),
            fee(_fee),
            contributors(_contributors) {}
};

class ServiceNodeLeaveRequestTx {
  public:
    crypto::bls_public_key bls_key;

    ServiceNodeLeaveRequestTx(const crypto::bls_public_key& _bls_key) : bls_key(_bls_key) {}
};

class ServiceNodeDeregisterTx {
  public:
    crypto::bls_public_key bls_key;

    ServiceNodeDeregisterTx(const crypto::bls_public_key& _bls_key) : bls_key(_bls_key) {}
};

class ServiceNodeExitTx {
  public:
    crypto::eth_address eth_address;
    uint64_t amount;
    crypto::bls_public_key bls_key;

    ServiceNodeExitTx(
            const crypto::eth_address& _eth_address,
            const uint64_t _amount,
            const crypto::bls_public_key& _bls_key) :
            eth_address(_eth_address), amount(_amount), bls_key(_bls_key) {}
};

using TransactionStateChangeVariant = std::variant<
        NewServiceNodeTx,
        ServiceNodeLeaveRequestTx,
        ServiceNodeDeregisterTx,
        ServiceNodeExitTx>;

class RewardsLogEntry : public ethyl::LogEntry {
  public:
    RewardsLogEntry(const ethyl::LogEntry& log) : ethyl::LogEntry(log) {}
    TransactionType getLogType() const;
    std::optional<TransactionStateChangeVariant> getLogTransaction() const;
};

struct StateResponse {
    uint64_t height;
    std::string state;
};

struct ContractServiceNode {
    bool good;
    uint64_t next;
    uint64_t prev;
    crypto::eth_address operatorAddr;
    std::string pubkey;
    uint64_t leaveRequestTimestamp;
    std::string deposit;
    std::array<Contributor, 10> contributors;
    size_t contributorsSize;
};

class RewardsContract {
  public:
    // Constructor
    RewardsContract(const std::string& _contractAddress, ethyl::Provider& provider);

    StateResponse State();
    StateResponse State(uint64_t height);

    std::vector<RewardsLogEntry> Logs(uint64_t height);
    ContractServiceNode serviceNodes(uint64_t index, std::string_view blockNumber = "latest");
    std::vector<uint64_t> getNonSigners(const std::vector<std::string>& bls_public_keys);
    std::vector<std::string> getAllBLSPubkeys(uint64_t blockNumber);

  private:
    std::string contractAddress;
    ethyl::Provider& provider;
};
