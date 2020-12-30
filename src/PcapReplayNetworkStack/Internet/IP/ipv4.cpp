#include <iostream>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

using std::pair;

void PcapReplayNetworkStack::handle_ipv4(Tins::Packet &packet)
{
    ipv4defragmenter_rx->ProcessPacket(packet);
}

// reassembled datagrams will go here
void PcapReplayNetworkStack::handle_ipv4_nonfragment(Tins::Packet &packet)
{
    Tins::IP ip = packet.pdu()->rfind_pdu<Tins::IP>();
    if (config.tx_event_transport)
    {
        switch(ip.inner_pdu()->pdu_type())
        {
            case Tins::PDU::ICMP:
                handle_icmp(packet);
                break;
            case Tins::PDU::UDP:
                handle_udp(packet);
                break;
            case Tins::PDU::TCP:
                handle_tcp(packet);
                break;
            default:
                break;
        }
    }
}

void PcapReplayNetworkStack::process_next_original_packet_ipv4(Tins::Packet &packet)
{
    ;
}

void PcapReplayNetworkStack::rewrite_packet_ipv4(Tins::Packet &packet)
{
    auto &ip = packet.pdu()->rfind_pdu<Tins::IP>();
    // Modify IP addresses
    ip.src_addr(convert_ip_address(ip.src_addr().to_string(), true));
    ip.dst_addr(convert_ip_address(ip.dst_addr().to_string(), true));

    // Edit IP checksum
    ; // libtins will recalculate the IP checksum upon serialization before putting the packet on the wire.
    ; // Will need to fork libtins for incremental checksums (to maintain incorrect checksums if desired)
}
