#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"


void PcapReplayNetworkStack::handle_ipv6(Tins::Packet &packet)
{
    ipv6defragmenter_rx->ProcessPacket(packet);
}

// reassembled datagrams will go here
void PcapReplayNetworkStack::handle_ipv6_nonfragment(Tins::Packet &packet)
{
    Tins::IPv6 ip6 = packet.pdu()->rfind_pdu<Tins::IPv6>();
    if (config.tx_event_transport)
    {
        switch(ip6.inner_pdu()->pdu_type())
        {
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

void PcapReplayNetworkStack::process_next_original_packet_ipv6(Tins::Packet &packet)
{
    ;
}

void PcapReplayNetworkStack::rewrite_packet_ipv6(Tins::Packet &packet)
{
    auto &ip6 = packet.pdu()->rfind_pdu<Tins::IPv6>();
    // Modify IP addresses
    ip6.src_addr(convert_ip_address(ip6.src_addr().to_string(), true));
    ip6.dst_addr(convert_ip_address(ip6.dst_addr().to_string(), true));

    // Edit IP checksum
    ; // libtins will recalculate the IPv6 checksum upon serialization before putting the packet on the wire.
    ; // Will need to fork libtins for incremental checksums (to maintain incorrect checksums if desired)
}
