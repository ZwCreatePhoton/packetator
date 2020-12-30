#include <iostream>

#include "TCPIPNetworkStack/tcp_ip_network_stack.h"


void TCPIPNetworkStack::handle_icmp_echo_request(Tins::Packet &packet)
{
    if (enable_ping_replay)
    {
        auto &ip = packet.pdu()->rfind_pdu<Tins::IP>();
        auto &icmp = packet.pdu()->rfind_pdu<Tins::ICMP>();
        icmp.type(Tins::ICMP::ECHO_REPLY);
        Tins::Packet packet2(icmp);
        output_packet(packet2, ip.src_addr().to_string());
    }
}

void TCPIPNetworkStack::handle_icmp_echo_reply(Tins::Packet &packet)
{
    std::cout << "[+]\tICMP: We received an ICMP ECHO_REPLY message!" << std::endl;
}

void TCPIPNetworkStack::handle_icmp_dest_unreachable(Tins::Packet &packet)
{
    // Is this how one would handle a destination unreachable ICMP message?
    std::cout << "[+]\tICMP: Oh nooooooooo. We received a destination unreachable ICMP message!" << std::endl;
}

void TCPIPNetworkStack::handle_icmp(Tins::Packet &packet)
{
    auto &icmp = packet.pdu()->rfind_pdu<Tins::ICMP>();

    switch(icmp.type())
    {
        case Tins::ICMP::ECHO_REQUEST:
            handle_icmp_echo_request(packet);
            break;
        case Tins::ICMP::ECHO_REPLY:
            handle_icmp_echo_reply(packet);
            break;
        case Tins::ICMP::DEST_UNREACHABLE:
            handle_icmp_dest_unreachable(packet);
            break;
        default:
            std::cout << "[!]\tICMPv4: Unsupported message type! (" << icmp.type() << ")" << std::endl;
            return;
    }
}

void TCPIPNetworkStack::send_icmp_echo_request(const std::string& target_ip)
{
    Tins::ICMP icmp(Tins::ICMP::ECHO_REQUEST);
    Tins::Packet packet(icmp);
    output_packet(packet, target_ip);
}