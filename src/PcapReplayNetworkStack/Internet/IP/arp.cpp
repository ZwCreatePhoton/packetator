#include <iostream>

#include "unistd.h"

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

Tins::IP PcapReplayNetworkStack::early_arp_packet(std::string sip, std::string dip)
{
    return Tins::IP(dip, sip) / Tins::ICMP(Tins::ICMP::ECHO_REQUEST) / Tins::RawPDU("1123581321345589");
}

bool PcapReplayNetworkStack::is_early_arp_packet_response(Tins::Packet &packet)
{
    Tins::PDU *ip = packet.pdu()->find_pdu<Tins::IP>();
    if (ip == nullptr) return false;

    if (ip->inner_pdu()->pdu_type() == Tins::PDU::ICMP)
    {
        auto icmp = (Tins::ICMP *) (ip->inner_pdu());
        if (icmp->inner_pdu()->pdu_type() == Tins::PDU::RAW)
        {
            auto raw = (Tins::RawPDU *) (icmp->inner_pdu());
            if (raw->payload().size() == 16) // checking for equality to "1123581321345589" is expensive
            {
                std::cout << "[+] Detected early arp packet response; dropping" << std::endl;
                return true;
            }
        }
    }
    return false;
}

void PcapReplayNetworkStack::perform_early_address_resolution()
{
    bool is_ipv4 = netdev.ip_address.find('.') != std::string::npos;
    if (is_ipv4)
    {
        for (const auto& dip : dips)
        {
            std::string sip = netdev.ip_address;
            Tins::IP pkt_to_send = early_arp_packet(sip, dip);
            Tins::Packet packet(pkt_to_send);
            output_packet(packet);
        }
        std::cout << "[+] Waiting for the early address resolution wait period to end" << std::endl;
        usleep(early_arp_wait_time);
    }
}

void PcapReplayNetworkStack::perform_early_arp()
{
    bool is_ipv4 = netdev.ip_address.find('.') != std::string::npos;
    if (is_ipv4)
    {
        for (const auto& dip : dips)
        {
            // TODO: When multiple dip have the same gateway, only send 1 ARP request
            std::string sip = netdev.ip_address;
            auto daddr = Tins::IP::address_type(dip);

            // perform a route lookup for the intended host
            RouteTableEntry *route_table_entry = route_table.lookup(dip);
            if (!route_table_entry)
            {
                std::cout << "[!]\tIPv4: No route found for " << Tins::IP::address_type(dip) << std::endl;
                return;
            }

            if (route_table_entry->flags & RT_GATEWAY)
            {
                daddr = Tins::IPv4Address(route_table_entry->gateway);
            }

            send_arp_request(daddr.to_string(), sip, netdev.mac_address);
        }
        std::cout << "[+] Waiting for the early address resolution wait period to end" << std::endl;
        // TODO: Wait for each response sent one up to a timeout instead of waiting early_arp_wait_time.
        usleep(early_arp_wait_time);
    }
}

void PcapReplayNetworkStack::perform_early_garp_request()
{
    bool is_ipv4 = netdev.ip_address.find('.') != std::string::npos;
    if (is_ipv4)
    {
        std::string sip = netdev.ip_address;
        send_arp_request(sip, sip, netdev.mac_address);
        usleep(early_arp_wait_time);
    }
}

void PcapReplayNetworkStack::perform_early_garp_reply()
{
    bool is_ipv4 = netdev.ip_address.find('.') != std::string::npos;
    if (is_ipv4)
    {
        std::string sip = netdev.ip_address;
        send_arp_reply(sip, sip, "ff:ff:ff:ff:ff:ff", netdev.mac_address);
        usleep(early_arp_wait_time);
    }
}
