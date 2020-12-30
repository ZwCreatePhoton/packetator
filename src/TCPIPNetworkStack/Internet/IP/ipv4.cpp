#include <iostream>

#include <unistd.h>

#include "tins/constants.h"

#include "TCPIPNetworkStack/tcp_ip_network_stack.h"


void TCPIPNetworkStack::handle_ipv4_fragment(Tins::Packet &packet)
{
    std::cout << "[!]\tIPv4: We received a fragment. Fragments are unsupported!" << std::endl;
}

void TCPIPNetworkStack::handle_ipv4_nonfragment(Tins::Packet &packet)
{
    auto &ip = packet.pdu()->rfind_pdu<Tins::IP>();

    switch(ip.protocol())
    {
        case Tins::Constants::IP::PROTO_ICMP:
            handle_icmp(packet);
            break;
        case Tins::Constants::IP::PROTO_TCP:
            handle_tcp(packet);
            break;
        case Tins::Constants::IP::PROTO_UDP:
            handle_udp(packet);
            break;
        default:
            std::cout << "[!]\tIPv4: Unsupported protocol!" << std::endl;
            break;
    }
}

void TCPIPNetworkStack::handle_ipv4(Tins::Packet &packet)
{
    auto &ip = packet.pdu()->rfind_pdu<Tins::IP>();

//    std::cout << "[+]\tIPv4: Source IP: " << packet->src_addr() << std::endl;

    // Check if is a fragment (dont handle fragments for now)
    if (ip.is_fragmented())
    {
        handle_ipv4_fragment(packet);
    }
    else
    {
        handle_ipv4_nonfragment(packet);
    }
}
