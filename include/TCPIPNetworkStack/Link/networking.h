#include <mutex>

#include <tins/tins.h>

#pragma once

class Networking
{
    public:
        void AddTransmitter(Tins::PacketSender *);
        Tins::PacketSender * GetTransmitter(const std::string&);
        Tins::Sniffer * GetReciever(const std::string&, const std::string&, std::string ipaddress, const std::vector<std::string>& all_ipaddresses, const std::vector<std::string>& mac_blocklist); //interface name, macaddress, ipaddress
        static Tins::Sniffer * SniffInterface(const std::string&, const std::string&); //interface name, BPF filter
    private:
        std::mutex networking_mutex;
        std::map<std::string, Tins::PacketSender *> transmitter_map;
};

extern Networking networking;