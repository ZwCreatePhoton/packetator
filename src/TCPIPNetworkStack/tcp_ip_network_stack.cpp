#include <iostream>

#include "TCPIPNetworkStack/tcp_ip_network_stack.h"

TCPIPNetworkStack::TCPIPNetworkStack(NetworkDevice &networkDevice) : NetworkStack(networkDevice)
{
    if (netdev.ip_address.empty())
    {
        enable_ping_replay = false;
    }
    if (!netdev.ip_address.empty())
    {
        route_table.add(netdev.ip_address, "", netdev.ip_mask, RT_HOST, 0);
        ipv4defragmenter_rx->SetCallback([&](Tins::Packet p){handle_ipv4_nonfragment(p);});
        ipv6defragmenter_rx->SetCallback([&](Tins::Packet p){handle_ipv6_nonfragment(p);});
    }
}

void TCPIPNetworkStack::handle_frame(Tins::Packet &packet)
{
    auto &frame = packet.pdu()->rfind_pdu<Tins::EthernetII>();

//    std::cout << "[+]\tWe received a frame!" << std::endl;
//    std::cout << "[+]\tDestination mac address: " << frame.dst_addr() << std::endl;
//    std::cout << "[+]\tSource mac address: " << frame.src_addr() << std::endl;

    switch (frame.inner_pdu()->pdu_type()) {
        case Tins::PDU::IP:
            if (!netdev.ip_address.empty())
                handle_ipv4(packet);
            break;
        case Tins::PDU::IPv6:
            if (!netdev.ip_address.empty())
                handle_ipv6(packet);
            break;
        case Tins::PDU::ARP:
        {
//            std::cout << "[+]\tWe received an ARP packet!" << std::endl;
            if (!netdev.ip_address.empty())
                handle_arp(packet);
            break;
        }
        default:
//            std::cout << "[!]\tFrame contains an unsupported inner pdu type :(" << std::endl;
            break;
    }
}


void TCPIPNetworkStack::init()
{
    NetworkStack::init();
}


