#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "TCPIPNetworkStack/Internet/IP/IPv4Defragmenter.h"

void PcapReplayNetworkStack::preprocess_pcap_packets_ip()
{
    std::vector<Tins::Packet> _packets{};

    std::unique_ptr<Defragmenter> ipv4defragmenter = std::make_unique<IPv4Defragmenter>();
    std::unique_ptr<Defragmenter> ipv6defragmenter = std::make_unique<IPv6Defragmenter>();
    ipv4defragmenter->SetCallback([&](const Tins::Packet& p){ _packets.push_back(p); });
    ipv6defragmenter->SetCallback([&](const Tins::Packet& p){ _packets.push_back(p); });

    for (auto & packet : packets)
    {
        Tins::PDU *ip = packet.pdu()->find_pdu<Tins::IP>();
        if (ip != nullptr)
        {
            ipv4defragmenter->ProcessPacket(packet);
        }
        else
        {
            ip = packet.pdu()->find_pdu<Tins::IPv6>();
            ipv6defragmenter->ProcessPacket(packet);
        }
    }

    if (config.tx_event_transport)
        preprocess_pcap_packets_transport(_packets);
}

void PcapReplayNetworkStack::process_next_original_packet_ip_possible_fragments(Tins::Packet &packet)
{
    bool is_ipv4 = packet.pdu()->find_pdu<Tins::IP>() != nullptr;

    if (is_ipv4)
    {
        if (is_tx_packet(packet, true))
        {
            original_ipv4defragmenter_tx->ProcessPacket(packet);
        }
        else if (is_rx_packet(packet, true))
        {
            original_ipv4defragmenter_rx->ProcessPacket(packet);
        }
        else
        {
            original_ipv4defragmenter_other->ProcessPacket(packet);
        }
    }
    else
    {
        if (is_tx_packet(packet, true))
        {
            original_ipv6defragmenter_tx->ProcessPacket(packet);
        }
        else if (is_rx_packet(packet, true))
        {
            original_ipv6defragmenter_rx->ProcessPacket(packet);
        }
        else
        {
            original_ipv6defragmenter_other->ProcessPacket(packet);
        }
    }
}

// This function is called everytime there is a new reassembled IP / IPv6 datagram
void PcapReplayNetworkStack::process_next_original_packet_ip(Tins::Packet &packet)
{
    bool is_ipv4 = packet.pdu()->find_pdu<Tins::IP>() != nullptr;
    if (is_ipv4)
        process_next_original_packet_ipv4(packet);
    else
        process_next_original_packet_ipv6(packet);
    if (config.tx_event_transport)
        process_next_original_packet_transport(packet);
}

void PcapReplayNetworkStack::rewrite_packet_ip(Tins::Packet &packet)
{
    Tins::PDU *ip = packet.pdu()->find_pdu<Tins::IP>();
    if (ip != nullptr)
    {
        rewrite_packet_ipv4(packet);
    }
    else
    {
        ip = packet.pdu()->find_pdu<Tins::IPv6>();
        if (ip != nullptr)
        {
            rewrite_packet_ipv6(packet);
        }
        else
        {
            assert(false);
        }
    }

    if (config.modify_transport)
    {
        switch(ip->inner_pdu()->pdu_type())
        {
            case Tins::PDU::UDP:
                rewrite_packet_udp(packet);
                break;
            case Tins::PDU::TCP:
                rewrite_packet_tcp(packet);
                break;
            default:
                break;
        }
    }
}

void PcapReplayNetworkStack::update_output(Tins::Packet &packet)
{
    if (config.tx_event_transport)
    {
        update_output_transport(packet);
    }
}