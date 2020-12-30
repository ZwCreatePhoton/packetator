#include <iostream>
#include <memory>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"


// IP address utils
//
std::pair<std::string, std::string> PcapReplayNetworkStack::get_source_dest_addresses(Tins::Packet &packet)
{
    std::string sip;
    std::string dip;

    auto *ip4 = packet.pdu()->find_pdu<Tins::IP>();
    if(ip4 != nullptr)
    {
        sip = ip4->src_addr().to_string();
        dip = ip4->dst_addr().to_string();
    }
    else
    {
        auto *ip6 = packet.pdu()->find_pdu<Tins::IPv6>();
        sip = ip6->src_addr().to_string();
        dip = ip6->dst_addr().to_string();
    }

    return std::pair<std::string, std::string>(sip, dip);
}

bool PcapReplayNetworkStack::is_tx_packet(const Tins::Packet& packet, bool original)
{
    std::string src_ip;
    auto *ip = packet.pdu()->find_pdu<Tins::IP>();
    if (ip != nullptr)
        src_ip = ip->src_addr().to_string();
    else
        src_ip = packet.pdu()->rfind_pdu<Tins::IPv6>().src_addr().to_string();
    if (original) src_ip = convert_ip_address(src_ip, true);
    bool is_tx_packet = (src_ip == netdev.ip_address);
    return is_tx_packet;
}

bool PcapReplayNetworkStack::is_tx_packet(int i)
{
    return is_tx_packet(packets[i], true);
}

bool PcapReplayNetworkStack::is_rx_packet(const Tins::Packet& packet, bool original)
{
    std::string dst_ip;
    auto *ip = packet.pdu()->find_pdu<Tins::IP>();
    if (ip != nullptr)
        dst_ip = ip->dst_addr().to_string();
    else
        dst_ip = packet.pdu()->rfind_pdu<Tins::IPv6>().dst_addr().to_string();
    if (original) dst_ip = convert_ip_address(dst_ip, true);
    bool is_rx_packet = dst_ip == netdev.ip_address;
    return is_rx_packet;
}

bool PcapReplayNetworkStack::is_rx_packet(int i)
{
    return is_rx_packet(packets[i], true);;
}

// if original == true then ip is converted using pcap_ip_map from key to value. (the argument "ip" is an ip address in the original pcap)
// else it's converted from value to key
std::string PcapReplayNetworkStack::convert_ip_address(const std::string& ip, bool original)
{
    if (original) return pcap_ip_map[ip];
    for (auto &x : pcap_ip_map)
        if (x.second == ip) return x.first;
    std::cout << "[!]\tFatal: Invalid IP address! (" << ip << ")" << std::endl;
    exit(1);
}
