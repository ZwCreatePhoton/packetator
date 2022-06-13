#include <thread>
#include <sstream>

#include <tins/tins.h>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

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
    fmt << "( (ether src " << netdev.mac_address << ")"; // capture our outgoing frames
    fmt << " or ((ether dst " << netdev.mac_address << ") or ether multicast) )"; // Capture all incoming frames destined for us (unicast or multicast or broadcast)
    fmt << " and ((dst " << netdev.ip_address << " or src " << netdev.ip_address << ") or ";
    if (is_ipv4 && !netdev.all_ipaddresses.empty())
    {
        for (auto &ip : netdev.all_ipaddresses)
            fmt << "arp host " << ip << " or rarp host " << ip << " or ";
    }
    fmt << (is_ipv4 ? "ip multicast" : "ip6 multicast") << ")"; // Capture incoming/outgoing IP packets destined to/from our unicast IP address OR capture arp OR capture IP multicast
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