#include "TCPIPNetworkStack/tcp_ip_network_stack.h"

Tins::Packet TCPIPNetworkStack::packetize(Tins::PDU &pdu, const std::string& destination_ip, const std::string& source_ip)
{
    std::unique_ptr<Tins::PDU> new_pdu;
    auto *ip4p = pdu.find_pdu<Tins::IP>();
    auto *ip6p = pdu.find_pdu<Tins::IPv6>();
    if (ip4p == nullptr && ip6p == nullptr)
    {
        if (destination_ip.find('.') != std::string::npos) // ipv4
        {
            Tins::IP ip = Tins::IP(destination_ip, source_ip) / pdu;
            new_pdu = std::unique_ptr<Tins::PDU>(ip.clone());
        }
        else
        {
            Tins::IPv6 ip6 = Tins::IPv6(destination_ip, source_ip) / pdu;
            ip6.hop_limit(128);
            new_pdu = std::unique_ptr<Tins::PDU>(ip6.clone());
        }
    }
    else
    {
        //TODO: Go from IPv4 -> IPv6 and vice versa
        if (ip4p != nullptr)
        {
            auto *ip4p_clone = ip4p->clone();
            ip4p_clone->dst_addr(destination_ip);
            ip4p_clone->src_addr(source_ip);
            new_pdu = std::unique_ptr<Tins::PDU>(ip4p_clone);
        }
        else // if (ip6p != nullptr)
        {
            auto *ip6p_clone = ip6p->clone();
            ip6p_clone->dst_addr(destination_ip);
            ip6p_clone->src_addr(source_ip);
            new_pdu = std::unique_ptr<Tins::PDU>(ip6p_clone);
        }
    }
    return Tins::Packet(*new_pdu);
}
