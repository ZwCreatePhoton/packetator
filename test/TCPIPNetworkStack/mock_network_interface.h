#include <tins/tins.h>
#include "gmock/gmock.h"

class MockNetworkInterface : public Tins::NetworkInterface
{
    public:
        MockNetworkInterface() {};
        MOCK_METHOD(void, transmit, (Tins::PDU&));
        MOCK_METHOD(Tins::Packet, receive, ());
};
