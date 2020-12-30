#include <iostream>

#include "TCPIPNetworkStack/tcp_ip_network_stack.h"


void TCPIPNetworkStack::handle_icmpv6_echo_request(Tins::Packet &packet)
{
    if (enable_ping_replay)
    {
        std::cout << "[+]\tICMPv6: We received an ICMPv6 ECHO_REQUEST message!" << std::endl;

        auto &ip6 = packet.pdu()->rfind_pdu<Tins::IPv6>();
        auto &icmp6 = packet.pdu()->rfind_pdu<Tins::ICMPv6>();
        icmp6.type(Tins::ICMPv6::ECHO_REPLY);
        Tins::Packet packet2(icmp6);
        output_packet(packet2, ip6.src_addr().to_string());
    }
}

void TCPIPNetworkStack::handle_icmpv6_echo_reply(Tins::Packet &packet)
{
    std::cout << "[+]\tICMPv6: We received an ICMPv6 ECHO_REPLY message!" << std::endl;
}

void TCPIPNetworkStack::handle_icmpv6_dest_unreachable(Tins::Packet &packet)
{
    // Is this how one would handle a destination unreachable ICMP message?
    std::cout << "[+]\tICMPv6: Oh nooooooooo. We received a destination unreachable ICMP message!" << std::endl;
}

void TCPIPNetworkStack::handle_icmpv6(Tins::Packet &packet)
{
    auto &icmp6 = packet.pdu()->rfind_pdu<Tins::ICMPv6>();

    switch(icmp6.type())
    {
        case Tins::ICMPv6::ROUTER_SOLICIT:
            handle_ndp_router_solicitation(packet);
            break;
        case Tins::ICMPv6::ROUTER_ADVERT:
            handle_ndp_router_advertisement(packet);
            break;
        case Tins::ICMPv6::NEIGHBOUR_SOLICIT:
            handle_ndp_neighbor_solicitation(packet);
            break;
        case Tins::ICMPv6::NEIGHBOUR_ADVERT:
            handle_ndp_neighbor_advertisement(packet);
            break;
        case Tins::ICMPv6::REDIRECT:
            handle_ndp_redirect_message(packet);
            break;
        case Tins::ICMPv6::ECHO_REQUEST:
            handle_icmpv6_echo_request(packet);
            break;
        case Tins::ICMPv6::ECHO_REPLY:
            handle_icmpv6_echo_reply(packet);
            break;
        case Tins::ICMPv6::DEST_UNREACHABLE:
            handle_icmpv6_dest_unreachable(packet);
            break;
        default:
            std::cout << "[!]\tICMPv6: Unsupported message type! (" << icmp6.type() << ")" << std::endl;
            return;
    }
}

void TCPIPNetworkStack::send_icmpv6_echo_request(const std::string& target_ip)
{
    Tins::ICMPv6 icmp6(Tins::ICMPv6::ECHO_REQUEST);
    Tins::Packet packet(icmp6);
    output_packet(packet, target_ip);
}
