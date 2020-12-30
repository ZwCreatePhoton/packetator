#include <iostream>
#include "TCPIPNetworkStack/Transport/UDP/udp_flow.h"

UdpFlow::UdpFlow(Tuple::FiveTuple fiveTuple) :
        Flow(std::move(fiveTuple))
{}

void UdpFlow::update(Tins::Packet &packet)
{
    std::string sip;
    std::string dip;

    Tins::UDP *udp;
    auto *ip4 = packet.pdu()->find_pdu<Tins::IP>();
    if(ip4 != nullptr)
    {
        sip = ip4->src_addr().to_string();
        dip = ip4->dst_addr().to_string();
        udp = ip4->find_pdu<Tins::UDP>();
    }
    else
    {
        auto *ip6 = packet.pdu()->find_pdu<Tins::IPv6>();
        sip = ip6->src_addr().to_string();
        dip = ip6->dst_addr().to_string();
        udp = ip6->find_pdu<Tins::UDP>();
    }

    auto sport = udp->sport();
    auto dport = udp->dport();

    if (    !(
            (sip == five_tuple().source_ip && dip == five_tuple().destination_ip && sport == five_tuple().source_port && dport == five_tuple().destination_port) ||
            (sip == five_tuple().destination_ip && dip == five_tuple().source_ip && sport == five_tuple().destination_port && dport == five_tuple().source_port) ))
    {
        std::cout << "[!]\tThis packet does not correspond to this UDP connection!" << std::endl;
        return;
    }

    if (sip == five_tuple().source_ip)
        _local_datagram_count++;
    else
        _remote_datagram_count++;

    auto *raw = udp->find_pdu<Tins::RawPDU>();
    if (raw != nullptr)
    {
        for(uint8_t byte : raw->payload())
            (sip == five_tuple().source_ip ? _local_payload : _remote_payload).push_back(byte);
    }
}
