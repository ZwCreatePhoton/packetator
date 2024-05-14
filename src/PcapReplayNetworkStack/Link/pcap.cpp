#include <thread>
#include <sstream>

#include <tins/tins.h>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

// TODO: Capture only the packets that we process

void PcapReplayNetworkStack::start_packet_capture()
{

    bool is_ipv4 = netdev.ip_address.find('.') != std::string::npos;

    std::string pcap_output_path = convert_ip_address(netdev.ip_address, false) + "_" + netdev.ip_address + ".pcap";

    std::stringstream fmt;
    if (!netdev.mac_blocklist.empty())
    {
        for (auto &m : netdev.mac_blocklist)
            fmt << "(not ether host " << m << ") and ";
    }

    // Must include the MAC address of the interface or multicast
    fmt << "( (ether src " << netdev.mac_address << ") or ((ether dst "  << netdev.mac_address << ") or ether multicast) )"; // Capture all incoming frames destined for us (unicast or multicast or broadcast)

    // Must include at least one of the following:
    fmt << " and ";
    fmt << "(";
        // 1. Src or Dst IP address of any other replaying host
        if (!netdev.all_ipaddresses.empty())
        {
            for (auto &ip : netdev.all_ipaddresses)
            {
                if (ip == netdev.ip_address) continue;
                fmt << "dst " << ip << " or src " << ip << " ";
            }
        }
        // 2. ARP or RARP packets
        if (is_ipv4 && !netdev.all_ipaddresses.empty())
        {
            for (auto &ip : netdev.all_ipaddresses)
            {
                fmt << " or ";
                fmt << "arp host " << ip << " or rarp host " << ip;
            }
        }
//        fmt << " or ";
//        // 3. IP multicast packets
//        fmt << (is_ipv4 ? "ip multicast" : "ip6 multicast");
    fmt << ")";
    std::string filter = fmt.str();

    packet_capture_sniffer = netdev.SniffInterface(filter);
    packet_capture_writer = new Tins::PacketWriter(pcap_output_path, (Tins::PacketWriter::LinkType)packet_capture_sniffer->link_type());
    packet_capture_thread = new std::thread(&PcapReplayNetworkStack::packet_capture_loop, this);
    packet_capture_in_progress = true;
}

void PcapReplayNetworkStack::stop_packet_capture()
{
    if (packet_capture_in_progress)
    {
        packet_capture_sniffer->stop_sniff();
        packet_capture_thread->join();
        delete packet_capture_thread;
        packet_capture_thread = nullptr;
        delete packet_capture_sniffer;
        packet_capture_sniffer = nullptr;
        delete packet_capture_writer;
        packet_capture_writer = nullptr;
        packet_capture_in_progress = false;
    }
}

void PcapReplayNetworkStack::packet_capture_loop()
{
    Tins::Packet packet;
    while ((packet = packet_capture_sniffer->next_packet()))
    {
        if (packet.pdu() == nullptr) return;
        packet_capture_writer->write(packet);
    }
}