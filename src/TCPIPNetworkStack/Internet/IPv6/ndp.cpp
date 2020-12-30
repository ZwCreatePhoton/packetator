#include <iostream>

#include "TCPIPNetworkStack/tcp_ip_network_stack.h"

void TCPIPNetworkStack::send_ndp_neighbor_solicitation(std::string target_ip, std::string source_ip, std::string source_mac)
{
    Tins::IPv6Address target_ip_address(target_ip);

    uint8_t last_3_bytes[3];
    Tins::IPv6Address::const_iterator iter = target_ip_address.begin() + (Tins::IPv6Address::address_size - 3);
    for (int i=0; iter != target_ip_address.end(); ++iter)
    {
        last_3_bytes[i] = *iter;
        i++;
    }

    uint8_t dip_bytes[Tins::IPv6Address::address_size] = {0xFF, 0x02, 0x00, 0x00,
                                                          0x00, 0x00, 0x00, 0x00,
                                                          0x00, 0x00, 0x00, 0x01,
                                                          0xFF, last_3_bytes[0], last_3_bytes[1], last_3_bytes[2]};
    std::string dip = Tins::IPv6Address(dip_bytes).to_string();

    uint8_t dmac_bytes[6] = {0x33, 0x33, 0xFF, last_3_bytes[0], last_3_bytes[1], last_3_bytes[2]};
    std::string dmac = Tins::HWAddress<6>(dmac_bytes).to_string();

    Tins::ICMPv6 icmp6(Tins::ICMPv6::NEIGHBOUR_SOLICIT);
    icmp6.target_addr(target_ip);
    icmp6.source_link_layer_addr(source_mac);
    Tins::IPv6 ip6(dip, source_ip);
    ip6.hop_limit(0xff);
    Tins::EthernetII frame = Tins::EthernetII(dmac, source_mac) / (ip6 / icmp6);
    netdev.transmit(frame);
}

void TCPIPNetworkStack::send_ndp_neighbor_advertisement(std::string dest_ip, std::string source_ip, std::string target_mac, std::string source_mac, bool solicited, bool override)
{
    Tins::ICMPv6 icmp6(Tins::ICMPv6::NEIGHBOUR_ADVERT);
    icmp6.solicited(solicited);
    icmp6.override(override);
    icmp6.target_addr(source_ip);
    icmp6.target_link_layer_addr(source_mac);
    Tins::IPv6 ip6(dest_ip, source_ip);
    ip6.hop_limit(0xff);
    Tins::EthernetII frame = Tins::EthernetII(target_mac, source_mac) / (ip6 / icmp6);
    netdev.transmit(frame);
}

void TCPIPNetworkStack::handle_ndp_neighbor_solicitation(Tins::Packet &packet)
{
    auto &ip6 = packet.pdu()->rfind_pdu<Tins::IPv6>();
    auto &icmp6 = packet.pdu()->rfind_pdu<Tins::ICMPv6>();

    bool has_source_link_layer_address_option = false;
    try
    {
        icmp6.source_link_layer_addr();
        has_source_link_layer_address_option = true;
    }
    catch (int e) {}

    if (icmp6.target_addr().to_string() == netdev.ip_address && has_source_link_layer_address_option)
    {
        send_ndp_neighbor_advertisement(ip6.src_addr().to_string() , netdev.ip_address, icmp6.source_link_layer_addr().to_string(), netdev.mac_address, true, true);
        neighbor_table.update(ip6.src_addr().to_string(), icmp6.source_link_layer_addr().to_string());
    }
    else
    {
//        std::cout << "[+]\tNDP: neighbor solicitation was not for us" << std::endl;
        return; // drop frame
    }
}

void TCPIPNetworkStack::handle_ndp_neighbor_advertisement(Tins::Packet &packet)
{
    auto &icmp6 = packet.pdu()->rfind_pdu<Tins::ICMPv6>();

    neighbor_table.update(icmp6.target_addr().to_string(), icmp6.target_link_layer_addr().to_string());
}

void TCPIPNetworkStack::handle_ndp_router_solicitation(Tins::Packet &packet) {}

void TCPIPNetworkStack::handle_ndp_router_advertisement(Tins::Packet &packet) {}

void TCPIPNetworkStack::handle_ndp_redirect_message(Tins::Packet &packet) {}