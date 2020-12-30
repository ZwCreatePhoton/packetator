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

Tins::Sniffer * Networking::GetReciever(const std::string& interfaceName, const std::string& mac_address, const std::string ip_address, const std::vector<std::string>& all_ipaddresses, const std::vector<std::string>& mac_blacklist)
{
    bool no_ip = ip_address.empty();
    bool is_ipv4 = ip_address.find('.') != std::string::npos;

    std::stringstream fmt;
    if (!mac_blacklist.empty())
    {
        for (auto &m : mac_blacklist)
            fmt << "(not ether host " << m << ") and ";
    }
    fmt << "not ether src " << mac_address; // Dont capture our outgoing frames
    fmt << " and ((ether dst " << mac_address << ") or ether multicast)"; // Capture all incoming frames destined for us (unicast or multicast or broadcast)
    if (!no_ip)
    {
        fmt << " and ((dst " << ip_address << ") or ";
        if (is_ipv4 && !all_ipaddresses.empty())
        {
            for (auto &ip : all_ipaddresses)
                fmt << "arp host " << ip << " or rarp host " << ip << " or ";
        }
        fmt << (is_ipv4 ? "ip multicast" : "ip6 multicast"); // Capture incoming IPv4 packets destined to our unicast IPv4 address OR capture arp
    }
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