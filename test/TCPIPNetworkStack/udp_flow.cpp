#include <tins/tins.h>
#include "gtest/gtest.h"

#include <TCPIPNetworkStack/Link/network_device.h>
#include <TCPIPNetworkStack/tcp_ip_network_stack.h>

TEST(UdpFlow, datagram_count)
{
    // Arrange
    std::string ip0 = "10.1.33.81";
    std::string ip1 = "10.1.33.82";
    auto client_ip = ip0;
    auto server_ip = ip1;
    uint16_t client_port = 1337;
    uint16_t server_port = 80;
    uint8_t protocol = IPPROTO_UDP;
    auto client_5t = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
    auto server_5t = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
    auto client_flow = UdpFlow(client_5t);
    auto server_flow = UdpFlow(server_5t);
    auto client_ip_pdu = Tins::IP(server_ip, client_ip); // client -> server
    auto server_ip_pdu = Tins::IP(client_ip, server_ip); // server -> client
    std::string client_segment_data_1 = "AAAAA";
    std::string server_segment_data_1 = "BBBBBBBBBB";
    std::string server_segment_data_2 = "CCCCCCCCCCCCCCCC";

    auto client_segment_1 = Tins::UDP(client_5t.destination_port, client_5t.source_port) / Tins::RawPDU(client_segment_data_1);
    Tins::Packet client_segment_1_packet(client_ip_pdu / client_segment_1);
    auto server_segment_1 = Tins::UDP(server_5t.destination_port, server_5t.source_port) / Tins::RawPDU(server_segment_data_1);
    Tins::Packet server_segment_1_packet(server_ip_pdu / server_segment_1);
    auto server_segment_2 = Tins::UDP(server_5t.destination_port, server_5t.source_port) / Tins::RawPDU(server_segment_data_2);
    Tins::Packet server_segment_2_packet(server_ip_pdu / server_segment_2);

    //Act
    client_flow.update(client_segment_1_packet);
    server_flow.update(client_segment_1_packet);
    server_flow.update(server_segment_1_packet);
    client_flow.update(server_segment_1_packet);
    server_flow.update(server_segment_2_packet);
    client_flow.update(server_segment_2_packet);

    // Assert
    EXPECT_EQ(client_flow.local_datagram_count(), client_flow.local_datagram_count());
    EXPECT_EQ(client_flow.remote_datagram_count(), client_flow.remote_datagram_count());
    EXPECT_EQ(server_flow.local_datagram_count(), server_flow.local_datagram_count());
    EXPECT_EQ(server_flow.remote_datagram_count(), server_flow.remote_datagram_count());
    EXPECT_EQ(client_flow.local_datagram_count(), 1);
    EXPECT_EQ(client_flow.remote_datagram_count(), 2);
    EXPECT_EQ(server_flow.local_datagram_count(), 2);
    EXPECT_EQ(server_flow.remote_datagram_count(), 1);
}

