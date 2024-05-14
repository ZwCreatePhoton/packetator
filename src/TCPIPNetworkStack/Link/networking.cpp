#include <sstream>
#include <iostream>

#include "TCPIPNetworkStack/Link/networking.h"

Networking networking{};

void Networking::AddTransmitter(Tins::PacketSender *packetSender)
{
    std::lock_guard<std::mutex> lg(networking_mutex);
    transmitter_map.insert(std::pair<std::string, Tins::PacketSender *>(packetSender->default_interface().name(), packetSender));
}

Tins::PacketSender * Networking::GetTransmitter(const std::string& interfaceName)
{
    std::lock_guard<std::mutex> lg(networking_mutex);
    return transmitter_map[interfaceName];
}

Tins::Sniffer * Networking::GetReciever(const std::string& interfaceName, const std::string& mac_address, const std::string ip_address, const std::vector<std::string>& all_ipaddresses, const std::vector<std::string>& mac_blocklist)
{
    bool no_ip = ip_address.empty();
    bool is_ipv4 = ip_address.find('.') != std::string::npos;

    // Must not include the MAC address in the blocklist
    std::stringstream fmt;
    if (!mac_blocklist.empty())
    {
        for (auto &m : mac_blocklist)
            fmt << "(not ether host " << m << ") and ";
    }

    // Must include the MAC address of the interface or multicast as the destination
    fmt << "( (ether dst " << mac_address << ") or ether multicast)";

    // Must include at least one of the following:
    fmt << " and ";
    fmt << "(";
        // 1. Src or Dst IP address of any other replaying host
        if (!all_ipaddresses.empty())
        {
            for (auto &ip : all_ipaddresses)
            {
                if (ip == ip_address) continue;
                fmt << "dst " << ip << " or src " << ip << " ";
            }
        }
        // 2. ARP or RARP packets
        if (is_ipv4 && !all_ipaddresses.empty())
        {
            for (auto &ip : all_ipaddresses)
            {
                fmt << " or ";
                fmt << "arp host " << ip << " or rarp host " << ip ;
            }
        }
//        fmt << " or ";
//        // 3. IP multicast packets
//        fmt << (is_ipv4 ? "ip multicast" : "ip6 multicast");
    fmt << ")";

    //TODO: listen to specific (ipv6) multicast groups only (e.g. soliciatation)
    std::string filter = fmt.str();
    return SniffInterface(interfaceName, filter);
}

Tins::Sniffer * Networking::SniffInterface(const std::string & interfaceName, const std::string & filter)
{
    Tins::SnifferConfiguration config;
    config.set_filter(filter);
    config.set_promisc_mode(true);
    config.set_immediate_mode(true);
    config.set_buffer_size(10485760); // 10 MB
    return new Tins::Sniffer(interfaceName, config);
}