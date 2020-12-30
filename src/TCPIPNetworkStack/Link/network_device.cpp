#include <utility>
#include <sstream>
#include <iostream>

#include "TCPIPNetworkStack/Link/network_device.h"
#include "TCPIPNetworkStack/Link/networking.h"

NetworkDevice::NetworkDevice(Tins::NetworkInterface networkInterface, std::string ip_address) : _networkInterface(networkInterface), ip_address(std::move(ip_address)), _mac_address(_networkInterface.hw_address().to_string()), mac_address(networkInterface.hw_address().to_string())
{
    init();
}

NetworkDevice::NetworkDevice(Tins::NetworkInterface networkInterface, std::string ip_address, std::string mask) : _networkInterface(networkInterface), ip_address(std::move(ip_address)), ip_mask(std::move(mask)), _mac_address(_networkInterface.hw_address().to_string()), mac_address(networkInterface.hw_address().to_string())
{
    init();
}

NetworkDevice::NetworkDevice(Tins::NetworkInterface networkInterface, std::vector<std::string> all_ipaddresses, std::string ip_address,
                             std::string mask) : _networkInterface(networkInterface), ip_address(std::move(ip_address)), ip_mask(std::move(mask)), all_ipaddresses(std::move(all_ipaddresses)), _mac_address(networkInterface.hw_address().to_string()), mac_address(networkInterface.hw_address().to_string())
{
    init();
}

NetworkDevice::NetworkDevice(Tins::NetworkInterface networkInterface, std::vector<std::string> all_ipaddresses, std::string ip_address,
                             std::string mask, std::string mac) : _networkInterface(networkInterface), ip_address(std::move(ip_address)), ip_mask(std::move(mask)), all_ipaddresses(std::move(all_ipaddresses)), _mac_address(networkInterface.hw_address().to_string()),  mac_address(std::move(mac))
{
    init();
}

NetworkDevice::NetworkDevice(Tins::NetworkInterface networkInterface, std::vector<std::string> all_ipaddresses, std::string ip_address,
                             std::string mask, std::string mac, std::vector<std::string> mac_blacklist) : _networkInterface(networkInterface), ip_address(std::move(ip_address)), ip_mask(std::move(mask)), all_ipaddresses(std::move(all_ipaddresses)), _mac_address(networkInterface.hw_address().to_string()),  mac_address(std::move(mac)), mac_blacklist(std::move(mac_blacklist))
{
    init();
}

Tins::Sniffer * NetworkDevice::SniffInterface(std::string &filter)
{
    return Networking::SniffInterface(_name, filter);
}

void NetworkDevice::transmit(Tins::PDU& pdu)
{
    try
    {
        sender->send(pdu);
    }
    catch (Tins::socket_write_error& e)
    {
        std::cerr << "[!]\tFatal: Message too long (MTU too small)" << std::endl;
        exit(2);
    }
}

Tins::Packet NetworkDevice::receive()
{
    return sniffer->next_packet();
}

void NetworkDevice::init()
{
    _name = _networkInterface.name();

    name = "whatever0";

    sender = networking.GetTransmitter(_name);
    sniffer = networking.GetReciever(_name, mac_address, ip_address, all_ipaddresses, mac_blacklist);
}
