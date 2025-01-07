// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once
#include <fmt/format.h>

#include <array>
#include <atomic>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <functional>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "common/command_line.h"
#include "common/formattable.h"
#include "common/fs.h"
#include "common/periodic_task.h"
#include "common/util.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_config.h"
#include "cryptonote_protocol/levin_notify.h"
#include "epee/net/abstract_tcp_server2.h"
#include "epee/net/enums.h"
#include "epee/net/levin_protocol_handler.h"
#include "epee/net/levin_protocol_handler_async.h"
#include "epee/storages/levin_abstract_invoke2.h"
#include "epee/warnings.h"
#include "net/fwd.h"
#include "net_node_common.h"
#include "net_peerlist.h"
#include "p2p_protocol_defs.h"

PUSH_WARNINGS
DISABLE_VS_WARNINGS(4355)

namespace nodetool {
struct proxy {
    proxy() : max_connections(-1), address(), zone(epee::net_utils::zone::invalid), noise(true) {}

    std::int64_t max_connections;
    boost::asio::ip::tcp::endpoint address;
    epee::net_utils::zone zone;
    bool noise;
};

struct anonymous_inbound {
    anonymous_inbound() :
            max_connections(-1), local_ip(), local_port(), our_address(), default_remote() {}

    std::int64_t max_connections;
    std::string local_ip;
    std::string local_port;
    epee::net_utils::network_address our_address;
    epee::net_utils::network_address default_remote;
};

std::optional<std::vector<proxy>> get_proxies(const boost::program_options::variables_map& vm);
std::optional<std::vector<anonymous_inbound>> get_anonymous_inbounds(
        const boost::program_options::variables_map& vm);

//! \return True if `commnd` is filtered (ignored/dropped) for `address`
bool is_filtered_command(epee::net_utils::network_address const& address, int command);

// hides boost::future and chrono stuff from mondo template file
std::optional<boost::asio::ip::tcp::socket> socks_connect_internal(
        const std::atomic<bool>& stop_signal,
        boost::asio::io_service& service,
        const boost::asio::ip::tcp::endpoint& proxy,
        const epee::net_utils::network_address& remote);

template <class base_type>
struct p2p_connection_context_t : base_type  // t_payload_net_handler::connection_context //public
                                             // net_utils::connection_context_base
{
    p2p_connection_context_t() : peer_id(0), m_in_timedsync(false) {}

    peerid_type peer_id;
    bool m_in_timedsync;
    std::set<epee::net_utils::network_address> sent_addresses;
};

enum class PeerType { anchor = 0, white, gray };
inline constexpr std::string_view to_string(PeerType pt) {
    return pt == PeerType::anchor ? "anchor"
         : pt == PeerType::white  ? "white"
         : pt == PeerType::gray   ? "gray"
                                  : "unknown";
}

struct peer_stats {
  size_t successful_connections = 0;
  size_t failed_connections = 0;
  uint64_t last_connected_timestamp = 0;
  uint64_t total_connection_time = 0;
};



template <class t_payload_net_handler>
class node_server
        : public epee::levin::levin_commands_handler<
                  p2p_connection_context_t<typename t_payload_net_handler::connection_context>>,
          public i_p2p_endpoint<typename t_payload_net_handler::connection_context>,
          public epee::net_utils::i_connection_filter {
    struct by_conn_id {};
    struct by_peer_id {};
    struct by_addr {};

    using p2p_connection_context =
            p2p_connection_context_t<typename t_payload_net_handler::connection_context>;

    using net_server = epee::net_utils::boosted_tcp_server<
            epee::levin::async_protocol_handler<p2p_connection_context>>;

    struct network_zone;
    using connect_func = std::optional<p2p_connection_context>(
            network_zone&, epee::net_utils::network_address const&);

    struct config {
        network_config m_net_config{};
        uint64_t m_peer_id{crypto::rand<uint64_t>()};
    };

    struct network_zone {
        network_zone() :
                m_connect(nullptr),
                m_net_server(epee::net_utils::e_connection_type_P2P),
                m_bind_ip(),
                m_bind_ipv6_address(),
                m_port(),
                m_port_ipv6(),
                m_notifier(),
                m_our_address(),
                m_peerlist(),
                m_config{},
                m_proxy_address(),
                m_current_number_of_out_peers(0),
                m_current_number_of_in_peers(0),
                m_can_pingback(false) {
            set_config_defaults();
        }

        network_zone(boost::asio::io_service& public_service) :
                m_connect(nullptr),
                m_net_server(public_service, epee::net_utils::e_connection_type_P2P),
                m_bind_ip(),
                m_bind_ipv6_address(),
                m_port(),
                m_port_ipv6(),
                m_notifier(),
                m_our_address(),
                m_peerlist(),
                m_config{},
                m_proxy_address(),
                m_current_number_of_out_peers(0),
                m_current_number_of_in_peers(0),
                m_can_pingback(false) {
            set_config_defaults();
        }

        connect_func* m_connect;
        net_server m_net_server;
        std::string m_bind_ip;
        std::string m_bind_ipv6_address;
        std::string m_port;
        std::string m_port_ipv6;
        cryptonote::levin::notify m_notifier;
        epee::net_utils::network_address m_our_address;  // in anonymity networks
        peerlist_manager m_peerlist;
        config m_config;
        boost::asio::ip::tcp::endpoint m_proxy_address;
        std::atomic<unsigned int> m_current_number_of_out_peers;
        std::atomic<unsigned int> m_current_number_of_in_peers;
        bool m_can_pingback;


      private:
        void set_config_defaults() noexcept {
            // at this moment we have a hardcoded config
            m_config.m_net_config.handshake_interval =
                    tools::to_seconds(cryptonote::p2p::DEFAULT_HANDSHAKE_INTERVAL);
            m_config.m_net_config.packet_max_size = cryptonote::p2p::DEFAULT_PACKET_MAX_SIZE;
            m_config.m_net_config.config_id = 0;
            m_config.m_net_config.connection_timeout = cryptonote::p2p::DEFAULT_CONNECTION_TIMEOUT;
            m_config.m_net_config.ping_connection_timeout =
                    cryptonote::p2p::DEFAULT_PING_CONNECTION_TIMEOUT;
            m_config.m_net_config.send_peerlist_sz = cryptonote::p2p::DEFAULT_PEERS_IN_HANDSHAKE;
        }
    };

  public:
    typedef t_payload_net_handler payload_net_handler;

    node_server(t_payload_net_handler& payload_handler) :
            m_payload_handler(payload_handler),
            m_external_port(0),
            m_allow_local_ip(false),
            m_hide_my_port(false),
            m_offline(false),
            is_closing(false) {}
    virtual ~node_server();

    static void init_options(
            boost::program_options::options_description& desc,
            boost::program_options::options_description& hidden);

    bool run();
    network_zone& add_zone(epee::net_utils::zone zone);
    bool init(const boost::program_options::variables_map& vm);
    bool deinit();
    bool send_stop_signal();
    uint32_t get_this_peer_port() { return m_listening_port; }
    t_payload_net_handler& get_payload_object();

    // debug functions
    bool log_peerlist();
    bool log_connections();

    // These functions only return information for the "public" zone
    virtual uint64_t get_public_connections_count();
    size_t get_public_outgoing_connections_count();
    size_t get_public_white_peers_count();
    size_t get_public_gray_peers_count();
    void get_public_peerlist(std::vector<peerlist_entry>& gray, std::vector<peerlist_entry>& white);
    void get_peerlist(std::vector<peerlist_entry>& gray, std::vector<peerlist_entry>& white);

    void change_max_out_public_peers(size_t count);
    uint32_t get_max_out_public_peers() const;
    void change_max_in_public_peers(size_t count);
    uint32_t get_max_in_public_peers() const;
    virtual bool block_host(
            const epee::net_utils::network_address& adress,
            time_t seconds = tools::to_seconds(cryptonote::p2p::IP_BLOCK_TIME));
    virtual bool unblock_host(const epee::net_utils::network_address& address);
    virtual bool block_subnet(
            const epee::net_utils::ipv4_network_subnet& subnet,
            time_t seconds = tools::to_seconds(cryptonote::p2p::IP_BLOCK_TIME));
    virtual bool unblock_subnet(const epee::net_utils::ipv4_network_subnet& subnet);
    virtual bool is_host_blocked(const epee::net_utils::network_address& address, time_t* seconds) {
        return !is_remote_host_allowed(address, seconds);
    }
    virtual std::map<std::string, time_t> get_blocked_hosts() {
        std::shared_lock lock{m_blocked_hosts_lock};
        return m_blocked_hosts;
    }
    virtual std::map<epee::net_utils::ipv4_network_subnet, time_t> get_blocked_subnets() {
        std::shared_lock lock{m_blocked_hosts_lock};
        return m_blocked_subnets;
    }

    virtual void add_used_stripe_peer(
            const typename t_payload_net_handler::connection_context& context);
    virtual void remove_used_stripe_peer(
            const typename t_payload_net_handler::connection_context& context);
    virtual void clear_used_stripe_peers();

  private:
    bool islimitup = false;
    bool islimitdown = false;

    fs::path get_peerlist_file() const;

    CHAIN_LEVIN_INVOKE_MAP2(p2p_connection_context);  // move levin_commands_handler interface
                                                      // invoke(...) callbacks into invoke map
    CHAIN_LEVIN_NOTIFY_MAP2(p2p_connection_context);  // move levin_commands_handler interface
                                                      // notify(...) callbacks into nothing

    BEGIN_INVOKE_MAP2(node_server)
    if (is_filtered_command(context.m_remote_address, command))
        return LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED;

    HANDLE_INVOKE_T2(COMMAND_HANDSHAKE, handle_handshake)
    HANDLE_INVOKE_T2(COMMAND_TIMED_SYNC, handle_timed_sync)
    HANDLE_INVOKE_T2(COMMAND_PING, handle_ping)
    // TODO: remove after HF19
    HANDLE_INVOKE_T2(COMMAND_REQUEST_SUPPORT_FLAGS, handle_get_support_flags)
    CHAIN_INVOKE_MAP_TO_OBJ_FORCE_CONTEXT(
            m_payload_handler, typename t_payload_net_handler::connection_context&)
    END_INVOKE_MAP2()

    //----------------- commands handlers ----------------------------------------------
    int handle_handshake(
            int command,
            typename COMMAND_HANDSHAKE::request& arg,
            typename COMMAND_HANDSHAKE::response& rsp,
            p2p_connection_context& context);
    int handle_timed_sync(
            int command,
            typename COMMAND_TIMED_SYNC::request& arg,
            typename COMMAND_TIMED_SYNC::response& rsp,
            p2p_connection_context& context);
    int handle_ping(
            int command,
            COMMAND_PING::request& arg,
            COMMAND_PING::response& rsp,
            p2p_connection_context& context);
    // TODO: remove after HF19
    int handle_get_support_flags(
            int command,
            COMMAND_REQUEST_SUPPORT_FLAGS::request& arg,
            COMMAND_REQUEST_SUPPORT_FLAGS::response& rsp,
            p2p_connection_context& context);
    bool init_config();
    bool make_default_peer_id();
    bool make_default_config();
    bool store_config();

    //----------------- levin_commands_handler
    //-------------------------------------------------------------
    virtual void on_connection_new(p2p_connection_context& context);
    virtual void on_connection_close(p2p_connection_context& context);
    virtual void callback(p2p_connection_context& context);
    //----------------- i_p2p_endpoint -------------------------------------------------------------
    virtual bool relay_notify_to_list(
            int command,
            const epee::span<const uint8_t> data_buff,
            std::vector<std::pair<epee::net_utils::zone, connection_id_t>> connections);
    virtual epee::net_utils::zone send_txs(
            std::vector<std::string> txs,
            const epee::net_utils::zone origin,
            const connection_id_t& source,
            const bool pad_txs);
    virtual bool invoke_command_to_peer(
            int command,
            const epee::span<const uint8_t> req_buff,
            std::string& resp_buff,
            const epee::net_utils::connection_context_base& context);
    virtual bool invoke_notify_to_peer(
            int command,
            const epee::span<const uint8_t> req_buff,
            const epee::net_utils::connection_context_base& context);
    virtual bool drop_connection(const epee::net_utils::connection_context_base& context);
    virtual void request_callback(const epee::net_utils::connection_context_base& context);
    virtual void for_each_connection(
            std::function<bool(typename t_payload_net_handler::connection_context&, peerid_type)>
                    f);
    virtual bool for_connection(
            const connection_id_t&,
            std::function<bool(typename t_payload_net_handler::connection_context&, peerid_type)>
                    f);
    virtual bool add_host_fail(const epee::net_utils::network_address& address);
    //----------------- i_connection_filter --------------------------------------------------------
    virtual bool is_remote_host_allowed(
            const epee::net_utils::network_address& address, time_t* t = NULL);
    //-----------------------------------------------------------------------------------------------
    bool parse_peer_from_string(
            epee::net_utils::network_address& pe,
            const std::string& node_addr,
            uint16_t default_port = 0);
    bool handle_command_line(const boost::program_options::variables_map& vm);
    bool idle_worker();
    bool handle_remote_peerlist(
            const std::vector<peerlist_entry>& peerlist,
            const epee::net_utils::connection_context_base& context);
    bool get_local_node_data(basic_node_data& node_data, const network_zone& zone);
    // bool get_local_handshake_data(handshake_data& hshd);

    bool sanitize_peerlist(std::vector<peerlist_entry>& local_peerlist);

    bool connections_maker();
    bool peer_sync_idle_maker();
    bool do_handshake_with_peer(
            peerid_type& pi, p2p_connection_context& context, bool just_take_peerlist = false);
    bool do_peer_timed_sync(
            const epee::net_utils::connection_context_base& context, peerid_type peer_id);

    bool make_new_connection_from_anchor_peerlist(
            const std::vector<anchor_peerlist_entry>& anchor_peerlist);
    bool make_new_connection_from_peerlist(network_zone& zone, bool use_white_list);
    bool try_to_connect_and_handshake_with_new_peer(
            const epee::net_utils::network_address& na,
            bool just_take_peerlist = false,
            uint64_t last_seen_stamp = 0,
            PeerType peer_type = PeerType::white,
            uint64_t first_seen_stamp = 0);
    // Draw from a truncated exponential with the given rate, truncated to produce values in [0,
    // N), and then take the integer floor to get a [0, N-1] value.  This distribution prefers
    // earlier values: with the default rate and the *untruncated* distribution, [0] is selected
    // around 13% of the time, indices in 0-9 are selected with probability 0.75 (this is where the
    // default comes from), and indices < 20 are selected with probability 0.9375, and indices < 50
    // with probability ~0.999.
    //
    // The *truncated* distribution scales these probabilities up slightly depending on the amount
    // of truncation.  (For example, with max_index of 19, those probabilities increase by a factor
    // of 1.06667, and with max_index of 9, they increase by 4/3).
    size_t get_random_exp_index(size_t size, double rate = 0.13862943611198906);
    bool is_peer_used(const peerlist_entry& peer);
    bool is_peer_used(const anchor_peerlist_entry& peer);
    bool is_addr_connected(const epee::net_utils::network_address& peer);
    template <class t_callback>
    bool try_ping(
            basic_node_data& node_data, p2p_connection_context& context, const t_callback& cb);
    bool make_expected_connections_count(
            network_zone& zone, PeerType peer_type, size_t expected_connections);
    void record_addr_failed(const epee::net_utils::network_address& addr);
    bool is_addr_recently_failed(const epee::net_utils::network_address& addr);
    bool is_priority_node(const epee::net_utils::network_address& na);
    std::set<std::string> get_seed_nodes(cryptonote::network_type nettype) const;
    std::set<std::string> get_seed_nodes();
    bool connect_to_seed();

    template <class Container>
    bool connect_to_peerlist(const Container& peers);

    template <class Container>
    bool parse_peers_and_add_to_container(
            const boost::program_options::variables_map& vm,
            const command_line::arg_descriptor<std::vector<std::string>>& arg,
            Container& container);

    bool set_max_out_peers(network_zone& zone, int64_t max);
    bool set_max_in_peers(network_zone& zone, int64_t max);
    bool set_tos_flag(const boost::program_options::variables_map& vm, int limit);

    bool set_rate_up_limit(const boost::program_options::variables_map& vm, int64_t limit);
    bool set_rate_down_limit(const boost::program_options::variables_map& vm, int64_t limit);
    bool set_rate_limit(const boost::program_options::variables_map& vm, int64_t limit);

    bool has_too_many_connections(const epee::net_utils::network_address& address);
    size_t get_incoming_connections_count();
    size_t get_incoming_connections_count(network_zone&);
    size_t get_outgoing_connections_count();
    size_t get_outgoing_connections_count(network_zone&);

    bool check_connection_and_handshake_with_peer(
            const epee::net_utils::network_address& na, uint64_t last_seen_stamp);
    bool gray_peerlist_housekeeping();
    bool check_incoming_connections();

    void kill() {  ///< will be called e.g. from deinit()
        log::info(globallogcat, "Killing the net_node");
        is_closing = true;
        if (mPeersLoggerThread)
            mPeersLoggerThread->join();  // make sure the thread finishes
        log::info(globallogcat, "Joined extra background net_node threads");
    }

    // debug functions
    std::string print_connections_container();

  public:
    void reset_peer_handshake_timer() { m_peer_handshake_idle_maker_interval.reset(); }

  private:
    fs::path m_config_folder;

    bool m_have_address;
    bool m_first_connection_maker_call;
    uint32_t m_listening_port;
    uint32_t m_listening_port_ipv6;
    uint32_t m_external_port;
    bool m_allow_local_ip;
    bool m_hide_my_port;
    bool m_offline;
    bool m_use_ipv6;
    bool m_require_ipv4;
    std::atomic<bool> is_closing;
    std::optional<std::thread> mPeersLoggerThread;
    std::unordered_map<peerid_type, peer_stats> peer_stats_map;
    std::mutex peer_stats_map_mutex;

    t_payload_net_handler& m_payload_handler;
    peerlist_storage m_peerlist_storage;

    tools::periodic_task m_peer_handshake_idle_maker_interval{
            "p2p handshake cleanup", cryptonote::p2p::DEFAULT_HANDSHAKE_INTERVAL};
    tools::periodic_task m_connections_maker_interval{"p2p connection maker", 1s};
    tools::periodic_task m_peerlist_store_interval{"p2p peer storage", 30min};
    tools::periodic_task m_gray_peerlist_housekeeping_interval{"p2p graylist", 1min};
    tools::periodic_task m_incoming_connections_interval{"incoming connection warning", 1h};

    std::list<epee::net_utils::network_address> m_priority_peers;
    std::vector<epee::net_utils::network_address> m_exclusive_peers;
    std::vector<epee::net_utils::network_address> m_seed_nodes;
    std::atomic<bool> m_seed_nodes_initialized{false};
    std::shared_mutex m_seed_nodes_mutex;
    std::atomic_flag m_fallback_seed_nodes_added;
    std::vector<nodetool::peerlist_entry> m_command_line_peers;
    uint64_t m_peer_livetime;
    // keep connections to initiate some interactions

    static std::optional<p2p_connection_context> public_connect(
            network_zone&, epee::net_utils::network_address const&);
    static std::optional<p2p_connection_context> socks_connect(
            network_zone&, epee::net_utils::network_address const&);

    /* A `std::map` provides constant iterators and key/value pointers even with
    inserts/erases to _other_ elements. This makes the configuration step easier
    since references can safely be stored on the stack. Do not insert/erase
    after configuration and before destruction, lock safety would need to be
    added. `std::map::operator[]` WILL insert! */
    std::map<epee::net_utils::zone, network_zone> m_network_zones;

    std::map<std::string, time_t> m_conn_fails_cache;
    std::shared_mutex m_conn_fails_cache_lock;

    std::shared_mutex m_blocked_hosts_lock;  // for both hosts and subnets
    std::map<std::string, time_t> m_blocked_hosts;
    std::map<epee::net_utils::ipv4_network_subnet, time_t> m_blocked_subnets;

    std::mutex m_host_fails_score_lock;
    std::map<std::string, uint64_t> m_host_fails_score;

    std::mutex m_used_stripe_peers_mutex;
    std::array<std::list<epee::net_utils::network_address>, 1 << cryptonote::PRUNING_LOG_STRIPES>
            m_used_stripe_peers;

    epee::connection_id_t m_network_id{};
    cryptonote::network_type m_nettype;
};

extern const command_line::arg_descriptor<std::string> arg_p2p_bind_ip;
extern const command_line::arg_descriptor<std::string> arg_p2p_bind_ipv6_address;
extern const command_line::arg_descriptor<uint16_t> arg_p2p_bind_port;
extern const command_line::arg_descriptor<uint16_t> arg_p2p_bind_port_ipv6;
extern const command_line::arg_flag arg_p2p_use_ipv6;
extern const command_line::arg_flag arg_p2p_ignore_ipv4;
extern const command_line::arg_descriptor<uint32_t> arg_p2p_external_port;
extern const command_line::arg_flag arg_p2p_allow_local_ip;
extern const command_line::arg_descriptor<std::vector<std::string>> arg_p2p_add_peer;
extern const command_line::arg_descriptor<std::vector<std::string>> arg_p2p_add_priority_node;
extern const command_line::arg_descriptor<std::vector<std::string>> arg_p2p_add_exclusive_node;
extern const command_line::arg_descriptor<std::vector<std::string>> arg_p2p_seed_node;
extern const command_line::arg_descriptor<std::vector<std::string>> arg_tx_proxy;
extern const command_line::arg_descriptor<std::vector<std::string>> arg_anonymous_inbound;
extern const command_line::arg_flag arg_p2p_hide_my_port;
extern const command_line::arg_flag arg_no_sync;

extern const command_line::arg_flag arg_no_igd;
extern const command_line::arg_descriptor<std::string> arg_igd;
extern const command_line::arg_flag arg_offline;
extern const command_line::arg_descriptor<int64_t> arg_out_peers;
extern const command_line::arg_descriptor<int64_t> arg_in_peers;
extern const command_line::arg_descriptor<int> arg_tos_flag;

extern const command_line::arg_descriptor<int64_t> arg_limit_rate_up;
extern const command_line::arg_descriptor<int64_t> arg_limit_rate_down;
extern const command_line::arg_descriptor<int64_t> arg_limit_rate;
}  // namespace nodetool

template <>
inline constexpr bool formattable::via_to_string<nodetool::PeerType> = true;

POP_WARNINGS
