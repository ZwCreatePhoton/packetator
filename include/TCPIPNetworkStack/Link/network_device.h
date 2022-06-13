#include <tins/tins.h>

#pragma once

#ifdef UNIT_TESTING
#define VIRTUAL virtual
#else
#define VIRTUAL
#endif

class NetworkDevice
{
    public:
        std::string name;
        std::string mac_address;
        std::string ip_address;
        std::string ip_mask = "0.0.0.0";
        std::string gateway = "";

        NetworkDevice(Tins::NetworkInterface, std::string ip_address);
        NetworkDevice(Tins::NetworkInterface, std::string ip_address, std::string mask);
        NetworkDevice(Tins::NetworkInterface, std::vector<std::string> all_ipaddresses, std::string ip_address, std::string mask);
        NetworkDevice(Tins::NetworkInterface networkInterface, std::vector<std::string> all_ipaddresses, std::string ip_address, std::string mask, std::string mac);
        NetworkDevice(Tins::NetworkInterface networkInterface, std::vector<std::string> all_ipaddresses, std::string ip_address, std::string mask, std::string mac,  std::vector<std::string> mac_blocklist);
#ifdef UNIT_TESTING
        virtual ~NetworkDevice() {};
#endif
        Tins::Sniffer * SniffInterface(std::string&);
        VIRTUAL void transmit(Tins::PDU&);
        VIRTUAL Tins::Packet receive();
        std::vector<std::string> all_ipaddresses{};
        std::vector<std::string> mac_blocklist{};

        void init();
//        void shutdown(); // Will need to clean up the sniffer pointer (since its 1 / host) if I plan on discarding the hosts / networkdevices often

    private:
        Tins::NetworkInterface _networkInterface; // represents the underlying network interface
        std::string _name; // name of the interface on the host running this program
        std::string _mac_address; // hw address on the nic of the host running this program

        Tins::Sniffer *sniffer{};
        Tins::PacketSender *sender{};
};
