#include "PcapReplayNetworkStack/pcap_replay_network_stack_config.h"

#include <utility>
#include <iostream>

PcapReplayNetworkStackConfig::PcapReplayNetworkStackConfig(const std::string& pcap_filepath, std::map<std::string, std::string> &pcap_ip_map) : PcapReplayNetworkStackConfig(pcap_filepath, pcap_ip_map, std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string>>{})
{

}

PcapReplayNetworkStackConfig::PcapReplayNetworkStackConfig(const std::string &pcap_filepath,
                                                           std::map<std::string, std::string> &pcap_ip_map,
                                                           std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string>> pcap_macip_map) : pcap_ip_map(pcap_ip_map), pcap_macip_map(std::move(pcap_macip_map))
{
    Tins::FileSniffer sniffer(pcap_filepath);
    while (true)
    {
        Tins::Packet packet = sniffer.next_packet();
        if (packet.pdu() == nullptr) break;
        if (packet.pdu()->pdu_type() != Tins::PDU::ETHERNET_II)
            continue;
        auto *frame = (Tins::EthernetII *)packet.pdu();
        switch (frame->payload_type())
        {
            case 0x0800: // IPv4
                // filter out ICMP
                // TODO: use protocol field
                if (packet.pdu()->rfind_pdu<Tins::IP>().inner_pdu()->pdu_type() == Tins::PDU::ICMP)
                    continue;
                break;
            case 0x0806: // ARP
                continue;
                break;
            case 0x86dd: // IPv6
                // filter out ICMPv6 since we don't want to replay NDP
                // TODO: be more specific when filtering out ICMPv6
                if (packet.pdu()->find_pdu<Tins::IPv6>()->inner_pdu()->pdu_type() == Tins::PDU::ICMPv6)
                    continue;
                break;
            case 0x888E: // IEEE 802.1X
                break;
            default:
                continue;
                break;
        }
        packets->push_back(packet);
    }
    if (packets->empty())
    {
        std::cerr << "[!]\tFatal: No packets to replay" << std::endl;
        exit(3);
    }
}

void PcapReplayNetworkStackConfig::PostProcess()
{
    // assumes that packet timestamps are monotonically increasing
    // Only removes 1 outlier
    // TODO: take stats on the timestamps of all packets and remove packets with timestamps > 5 STD
    if (remove_time_outlier_packet && packets->size() > 1 && (std::chrono::seconds(packets->at(packets->size()-1).timestamp().seconds()) - std::chrono::seconds(packets->at(packets->size()-2).timestamp().seconds()) >= remove_time_outlier_seconds))
    {
        packets->pop_back();
    }
    if (packets->empty())
    {
        std::cerr << "[!]\tFatal: No packets to replay" << std::endl;
        exit(3);
    }
}
