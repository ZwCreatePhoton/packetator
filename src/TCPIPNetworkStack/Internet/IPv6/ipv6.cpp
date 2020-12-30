#include <iostream>

#include <unistd.h>

#include "tins/constants.h"

#include "TCPIPNetworkStack/tcp_ip_network_stack.h"


// Input

void TCPIPNetworkStack::handle_ipv6_fragment(Tins::Packet &packet)
{
    std::cout << "[!]\tIPv6: We received a fragment. Fragments are unsupported!" << std::endl;
}

void TCPIPNetworkStack::handle_ipv6_nonfragment(Tins::Packet &packet)
{
    auto &ip6 = packet.pdu()->rfind_pdu<Tins::IPv6>();

    switch(ip6.inner_pdu()->pdu_type())
    {
        case Tins::PDU::TCP:
            handle_tcp(packet);
            break;
        case Tins::PDU::UDP:
            handle_udp(packet);
            break;
        default:
            std::cout << "[!]\tIPv6: Unsupported protocol!" << std::endl;
            break;
    }
}

void TCPIPNetworkStack::handle_ipv6(Tins::Packet &packet)
{
    auto &ip6 = packet.pdu()->rfind_pdu<Tins::IPv6>();

//    std::cout << "[+]\tIPv4: Source IP: " << packet->src_addr() << std::endl;

    // Check if is a fragment (dont handle fragments for now)
    if (ip6.search_header(Tins::IPv6::FRAGMENT) != nullptr)
    {
        handle_ipv6_fragment(packet);
    }
    else
    {
        handle_ipv6_nonfragment(packet);
    }
}
