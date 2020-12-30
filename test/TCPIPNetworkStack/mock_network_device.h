#include "gmock/gmock.h"

#include "TCPIPNetworkStack/Link/network_device.h"

class MockNetworkDevice : public NetworkDevice
{
    public:
        MockNetworkDevice(Tins::NetworkInterface interface, std::string ip_address, std::string mask) : NetworkDevice(interface, ip_address, mask) {};

        MOCK_METHOD(void, transmit, (Tins::PDU&));
        MOCK_METHOD(Tins::Packet, receive, ());
        MOCK_METHOD(void, init, ());
};
