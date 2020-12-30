#include "gmock/gmock.h"

#include "TCPIPNetworkStack/network_stack.h"

#include "mock_network_interface.h"
#include "mock_network_device.h"


TEST(NetworkStack, StopRxLoop)
{
    //Arrange

    //Act

    //Assert
}

TEST(NetworkStack, DisableRxLoop)
{
//    //Arrange
//    auto interface_name = Tins::NetworkInterface::default_interface().name();
//    auto ip_address = "1.2.3.4";
//    auto mask = "255.255.255.255";
//    Tins::NetworkInterface *interface = new Tins::NetworkInterface(interface_name);
//    MockNetworkDevice *netdev = new MockNetworkDevice(*interface, ip_address, mask);
//    NetworkStack netstack(*netdev);
//    netstack.disable_rx_loop();
//
//    //Anticipate
//    EXPECT_CALL(*netdev, receive())
//            .Times(0);
//
//    //Act
//    netstack.init();
//
//    //Assert
//    delete netdev;
}

TEST(NetworkStack, RxLoop)
{
    //Arrange

    //Act

    //Assert
}
