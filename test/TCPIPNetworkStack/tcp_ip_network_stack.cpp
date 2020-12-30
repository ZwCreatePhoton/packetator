#include <iostream>
#include <type_traits>


#include <unistd.h> // sleep

#include "TCPIPNetworkStack/Link/networking.h"
#include "TCPIPNetworkStack/host.h"
#include "TCPIPNetworkStack/tcp_ip_network_stack.h"
#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "PcapReplayNetworkStack/validator.h"

#include "gtest/gtest.h"

// These tests segfault when more than 1 is uncommented
// TODO: fix


////
////// Requires live server listening on 10.1.31.88:80
//TEST(TCPIPNetworkStack, handle_handshake_client)
//{
//    //Arrange
//    std::string iface = "eth3";
//    Tins::NetworkInterface interface0(iface);
//    std::string ip0 = "10.1.33.1";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack(netdev0);
//    netstack.init();
//    auto sip = ip0;
//    auto dip = "10.1.31.88";
//    uint16_t sport = (rand() % (65535-1024) )+ 1024;
//    uint16_t dport = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple = Tuple::FiveTuple{sip, sport, dip, dport, protocol};
//
//    //Act
//    netstack.connect<Application, Application>(fivetuple);
//
//    //Assert
//    auto cs5t = netstack.FiveTuple_to_ClientServerFiveTuple(fivetuple);
//    auto *connection = (TcpConnection *)netstack.connection_table.lookup(cs5t);
//    EXPECT_NE(connection, nullptr);
//    EXPECT_EQ (connection->client_flow().state, TcpFlow::ESTABLISHED);
//    EXPECT_EQ (connection->server_flow().state, TcpFlow::ESTABLISHED);
//}
//
//// requires a live client on 10.1.31.88 to connect to 10.1.33.21:80
//TEST(TCPIPNetworkStack, handle_handshake_server)
//{
//    //Arrange
//    std::string iface0 = "eth3";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.21";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    auto client_ip = "10.1.31.88";
//    auto server_ip = ip0;
//    uint16_t server_port = 80;
//    uint16_t client_port = 0;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple0 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//
//    //Act
//    netstack0.listen(fivetuple0);
//    sleep(10);
//
//    //Assert
//    auto cs5t0 = netstack0.FiveTuple_to_ClientServerFiveTuple(fivetuple0);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0, 0);
//    EXPECT_NE(connection0, nullptr);
//    EXPECT_EQ (connection0->client_flow().state, TcpFlow::ESTABLISHED);
//    EXPECT_EQ (connection0->server_flow().state, TcpFlow::ESTABLISHED);
//}
//

//TEST(TCPIPNetworkStack, handle_handshake_client_and_server)
//{
//    //Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.11";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.12";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//
//    //Act
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//
//    //Assert
//    auto cs5t0 = netstack0.FiveTuple_to_ClientServerFiveTuple(fivetuple0);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    EXPECT_NE(connection0, nullptr);
//    EXPECT_EQ (connection0->client_flow().state, TcpFlow::ESTABLISHED);
//    EXPECT_EQ (connection0->server_flow().state, TcpFlow::ESTABLISHED);
//
//    auto cs5t1 = netstack1.FiveTuple_to_ClientServerFiveTuple(fivetuple1);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//    EXPECT_NE(connection1, nullptr);
//    EXPECT_EQ (connection1->client_flow().state, TcpFlow::ESTABLISHED);
//    EXPECT_EQ (connection1->server_flow().state, TcpFlow::ESTABLISHED);
//}

//
//TEST(TCPIPNetworkStack, handle_data_ack)
//{
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.81";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.82";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//
//    std::string data = "AAAAA";
//    auto data_seg = Tins::TCP(fivetuple0.destination_port, fivetuple0.source_port) / Tins::RawPDU(data);
//    data_seg.seq(connection0->client_flow().SND_NXT);
//    data_seg.ack_seq(connection0->client_flow().RCV_NXT);
//    auto data_ip = Tins::IP(fivetuple0.destination_ip, fivetuple0.source_ip);
//    Tins::Packet data_packet(data_ip / data_seg);
//    connection0->update(data_packet); // We're not sending data_pack though the wire ; we're faking it.
//
//    // Act
//    netstack1.handle_tcp(data_packet);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().SND_UNA, connection0->client_flow().SND_NXT);
//    EXPECT_EQ(connection0->client_flow().SND_UNA, connection1->server_flow().RCV_NXT);
//    EXPECT_EQ(connection1->client_flow().SND_UNA, connection1->client_flow().SND_NXT);
//    EXPECT_EQ(connection1->client_flow().SND_UNA, connection0->server_flow().RCV_NXT);
//}

//TEST(TCPIPNetworkStack, handle_tcp_termination_server)
//{
//    // Test server initiated connection termination
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.141";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.142";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//
//    // Act
//    netstack1.close(*connection1);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().state, connection1->client_flow().state);
//    EXPECT_EQ(connection0->server_flow().state, connection1->server_flow().state);
//    EXPECT_EQ(connection0->client_flow().state, TcpFlow::State::CLOSE_WAIT);
//    EXPECT_EQ(connection0->server_flow().state, TcpFlow::State::FIN_WAIT_2);
//}
//
//
//TEST(TCPIPNetworkStack, handle_tcp_termination_server_client)
//{
//    // Test server initiated connection termination followed by a client initiated connection termination
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.161";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.162";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//
//    // Act
//    netstack1.close(*connection1);
//    sleep(1);
//    netstack0.close(*connection0);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().state, connection1->client_flow().state);
//    EXPECT_EQ(connection0->server_flow().state, connection1->server_flow().state);
//    EXPECT_EQ(connection0->client_flow().state, TcpFlow::State::CLOSED2);
//    EXPECT_EQ(connection0->server_flow().state, TcpFlow::State::TIME_WAIT);
//}
//
//TEST(TCPIPNetworkStack, handle_tcp_termination_client)
//{
//    // Test client initiated connection termination
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.151";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.152";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//
//    // Act
//    netstack0.close(*connection0);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().state, connection1->client_flow().state);
//    EXPECT_EQ(connection0->server_flow().state, connection1->server_flow().state);
//    EXPECT_EQ(connection0->server_flow().state, TcpFlow::State::CLOSE_WAIT);
//    EXPECT_EQ(connection0->client_flow().state, TcpFlow::State::FIN_WAIT_2);
//}
//
//TEST(TCPIPNetworkStack, handle_tcp_termination_client_server)
//{
//    // Test client initiated connection termination followed by server initiated connection termination
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.171";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.172";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//
//    //Act
//    netstack0.close(*connection0);
//    sleep(1);
//    netstack1.close(*connection1);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().state, connection1->client_flow().state);
//    EXPECT_EQ(connection0->server_flow().state, connection1->server_flow().state);
//    EXPECT_EQ(connection0->server_flow().state, TcpFlow::State::CLOSED2);
//    EXPECT_EQ(connection0->client_flow().state, TcpFlow::State::TIME_WAIT);
//}
//
//TEST(TCPIPNetworkStack, handle_tcp_send_client)
//{
//    // Tests client sending data to a server
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.181";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.182";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//    std::string data_str = "DEADBEEF";
//    std::vector<uint8_t> data(data_str.begin(), data_str.end());
//    std::vector<uint8_t> empty{};
//
//    //Act
//    netstack0.send(*connection0, data);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().local_payload(), connection1->client_flow().local_payload());
//    EXPECT_EQ(connection0->client_flow().remote_payload(), connection1->client_flow().remote_payload());
//    EXPECT_EQ(connection0->server_flow().local_payload(), connection1->server_flow().local_payload());
//    EXPECT_EQ(connection0->server_flow().remote_payload(), connection1->server_flow().remote_payload());
//    EXPECT_EQ(connection0->client_flow().local_payload(), data);
//    EXPECT_EQ(connection0->client_flow().remote_payload(), empty);
//    EXPECT_EQ(connection0->server_flow().local_payload(), empty);
//    EXPECT_EQ(connection0->server_flow().remote_payload(), data);
//}
//
//TEST(TCPIPNetworkStack, handle_tcp_send_server)
//{
//    // Tests server sending data to a client
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.191";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.192";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//    std::string data_str = "DEADBEEF";
//    std::vector<uint8_t> data(data_str.begin(), data_str.end());
//    std::vector<uint8_t> empty{};
//
//    //Act
//    netstack1.send(*connection1, data);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().local_payload(), connection1->client_flow().local_payload());
//    EXPECT_EQ(connection0->client_flow().remote_payload(), connection1->client_flow().remote_payload());
//    EXPECT_EQ(connection0->server_flow().local_payload(), connection1->server_flow().local_payload());
//    EXPECT_EQ(connection0->server_flow().remote_payload(), connection1->server_flow().remote_payload());
//    EXPECT_EQ(connection0->client_flow().local_payload(), empty);
//    EXPECT_EQ(connection0->client_flow().remote_payload(), data);
//    EXPECT_EQ(connection0->server_flow().local_payload(), data);
//    EXPECT_EQ(connection0->server_flow().remote_payload(), empty);
//}
//
//TEST(TCPIPNetworkStack, handle_tcp_send_client_server)
//{
//    // Tests client sending data to a server followed by the server sending data to the client
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.201";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.202";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//    std::string data_str = "DEADBEEF";
//    std::string data_str2 = "AYYYY";
//    std::vector<uint8_t> data(data_str.begin(), data_str.end());
//    std::vector<uint8_t> data2(data_str2.begin(), data_str2.end());
//    std::vector<uint8_t> empty{};
//
//    //Act
//    netstack0.send(*connection0, data);
//    sleep(1);
//    netstack1.send(*connection1, data2);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().local_payload(), connection1->client_flow().local_payload());
//    EXPECT_EQ(connection0->client_flow().remote_payload(), connection1->client_flow().remote_payload());
//    EXPECT_EQ(connection0->server_flow().local_payload(), connection1->server_flow().local_payload());
//    EXPECT_EQ(connection0->server_flow().remote_payload(), connection1->server_flow().remote_payload());
//    EXPECT_EQ(connection0->client_flow().local_payload(), data);
//    EXPECT_EQ(connection0->client_flow().remote_payload(), data2);
//    EXPECT_EQ(connection0->server_flow().local_payload(), data2);
//    EXPECT_EQ(connection0->server_flow().remote_payload(), data);
//}
//
//TEST(TCPIPNetworkStack, handle_tcp_send_server_client)
//{
//    // Tests server sending data to a client followed by the client sending data to the server
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.33.211";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.33.212";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_TCP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (TcpConnection *)netstack0.connection_table.lookup(cs5t0);
//    auto *connection1 = (TcpConnection *)netstack1.connection_table.lookup(cs5t1);
//    std::string data_str = "DEADBEEF";
//    std::string data_str2 = "AYYYY";
//    std::vector<uint8_t> data(data_str.begin(), data_str.end());
//    std::vector<uint8_t> data2(data_str2.begin(), data_str2.end());
//    std::vector<uint8_t> empty{};
//
//    //Act
//    netstack1.send(*connection1, data);
//    sleep(1);
//    netstack0.send(*connection0, data2);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().local_payload(), connection1->client_flow().local_payload());
//    EXPECT_EQ(connection0->client_flow().remote_payload(), connection1->client_flow().remote_payload());
//    EXPECT_EQ(connection0->server_flow().local_payload(), connection1->server_flow().local_payload());
//    EXPECT_EQ(connection0->server_flow().remote_payload(), connection1->server_flow().remote_payload());
//    EXPECT_EQ(connection0->client_flow().local_payload(), data2);
//    EXPECT_EQ(connection0->client_flow().remote_payload(), data);
//    EXPECT_EQ(connection0->server_flow().local_payload(), data);
//    EXPECT_EQ(connection0->server_flow().remote_payload(), data2);
//}

//
//
//TEST(TCPIPNetworkStack, handle_udp_send_client)
//{
//    // Tests client sending data to a server (UDP)
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.34.181";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.34.182";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_UDP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (UdpConnection *)netstack0.connection_table.lookup(cs5t0);
//    std::string data_str = "DEADBEEF";
//    std::vector<uint8_t> data(data_str.begin(), data_str.end());
//    std::vector<uint8_t> empty{};
//
//    //Act
//    netstack0.send(*connection0, data);
//    sleep(1);
//    auto *connection1 = (UdpConnection *)netstack1.connection_table.lookup(cs5t1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().local_payload(), connection1->client_flow().local_payload());
//    EXPECT_EQ(connection0->client_flow().remote_payload(), connection1->client_flow().remote_payload());
//    EXPECT_EQ(connection0->server_flow().local_payload(), connection1->server_flow().local_payload());
//    EXPECT_EQ(connection0->server_flow().remote_payload(), connection1->server_flow().remote_payload());
//    EXPECT_EQ(connection0->client_flow().local_payload(), data);
//    EXPECT_EQ(connection0->client_flow().remote_payload(), empty);
//    EXPECT_EQ(connection0->server_flow().local_payload(), empty);
//    EXPECT_EQ(connection0->server_flow().remote_payload(), data);
//}

//TEST(TCPIPNetworkStack, handle_udp_send_client_server)
//{
//    // Tests client sending data to a server followed by the server sending data to the client (UDP)
//
//    // Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.1.34.201";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    std::string iface1 = "eth3";
//    Tins::NetworkInterface interface1(iface1);
//    std::string ip1 = "10.1.34.202";
//    std::string mask1 = "255.255.0.0";
//    NetworkDevice netdev1 = NetworkDevice(interface1, ip1, mask1);
//    TCPIPNetworkStack netstack1(netdev1);
//    netstack1.init();
//    auto client_ip = ip0;
//    auto server_ip = ip1;
//    uint16_t client_port = (rand() % (65535-1024) )+ 1024;
//    uint16_t server_port = 80;
//    uint8_t protocol = IPPROTO_UDP;
//    auto fivetuple1 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//    auto fivetuple0 = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
//    netstack1.listen(fivetuple1);
//    netstack0.connect<Application, Application>(fivetuple0);
//    sleep(1);
//    auto cs5t0 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple0, false);
//    auto cs5t1 = Tuple::FiveTuple_to_ClientServerFiveTuple(fivetuple1, true);
//    auto *connection0 = (UdpConnection *)netstack0.connection_table.lookup(cs5t0);
//    std::string data_str = "DEADBEEF";
//    std::string data_str2 = "AYYYY";
//    std::vector<uint8_t> data(data_str.begin(), data_str.end());
//    std::vector<uint8_t> data2(data_str2.begin(), data_str2.end());
//    std::vector<uint8_t> empty{};
//
//    //Act
//    netstack0.send(*connection0, data);
//    sleep(1);
//    auto *connection1 = (UdpConnection *)netstack1.connection_table.lookup(cs5t1);
//    netstack1.send(*connection1, data2);
//    sleep(1);
//
//    // Assert
//    EXPECT_EQ(connection0->client_flow().local_payload(), connection1->client_flow().local_payload());
//    EXPECT_EQ(connection0->client_flow().remote_payload(), connection1->client_flow().remote_payload());
//    EXPECT_EQ(connection0->server_flow().local_payload(), connection1->server_flow().local_payload());
//    EXPECT_EQ(connection0->server_flow().remote_payload(), connection1->server_flow().remote_payload());
//    EXPECT_EQ(connection0->client_flow().local_payload(), data);
//    EXPECT_EQ(connection0->client_flow().remote_payload(), data2);
//    EXPECT_EQ(connection0->server_flow().local_payload(), data2);
//    EXPECT_EQ(connection0->server_flow().remote_payload(), data);
//}


//
//
//TEST(TCPIPNetworkStack, connect_udp)
//{
//    //Arrange
//    std::string iface = "eth3";
//    Tins::NetworkInterface interface0(iface);
//    std::string ip0 = "10.1.33.32";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack(netdev0);
//    netstack.init();
//    auto sip = ip0;
//    auto dip = "10.3.31.65";
//    uint16_t sport = (rand() % (65535-1024) )+ 1024;
//    uint16_t dport = 4444;
//    uint8_t protocol = IPPROTO_UDP;
//    auto fivetuple = Tuple::FiveTuple{sip, sport, dip, dport, protocol};
//
//    //Act
//    netstack.connect<Application, Application>(fivetuple);
//
//    //Assert
//    auto cs5t = netstack.FiveTuple_to_ClientServerFiveTuple(fivetuple);
//    auto *connection = (UdpConnection *)netstack.connection_table.lookup(cs5t);
//    EXPECT_NE(connection, nullptr);
//}

//// Requires a live UDP client to connect to 10.3.33.51:4444 and send at least 1 byte of data to the server
//TEST(TCPIPNetworkStack, udp_server_data_receive)
//{
//    //Arrange
//    std::string iface0 = "eth2";
//    Tins::NetworkInterface interface0(iface0);
//    std::string ip0 = "10.3.33.51";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack0(netdev0);
//    netstack0.init();
//    auto client_ip = "10.3.31.65";
//    auto server_ip = ip0;
//    uint16_t server_port = 4444;
//    uint16_t client_port = 0;
//    uint8_t protocol = IPPROTO_UDP;
//    auto fivetuple0 = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
//
//    //Act
//    netstack0.listen(fivetuple0);
//    sleep(10);
//
//    //Assert
//    auto cs5t0 = netstack0.FiveTuple_to_ClientServerFiveTuple(fivetuple0);
//    auto *connection0 = (UdpConnection *)netstack0.connection_table.lookup(cs5t0, 0);
//    EXPECT_NE(connection0, nullptr);
//    EXPECT_EQ (connection0->client_flow().remote_payload().size(), 0);
//    EXPECT_GT (connection0->client_flow().local_payload().size(), 0);
//    EXPECT_EQ (connection0->server_flow().local_payload().size(), 0);
//    EXPECT_GT (connection0->server_flow().remote_payload().size(), 0);
//}




// TODO: Port old tests to gtest
//void test_arp_table()
//{
//    // Sends out an ARP request to target_ip
//    // Processes the ARP reply from target_ip
//    // Adds the new arp table entry
//    // queries for the new arp table entry
//
//    // Arrange
//    Tins::NetworkInterface interface0(iface);
//    std::string ip0 = "10.3.32.1";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack(netdev0);
//    netstack.init();
//
//    // Act
//    netstack.send_arp_request(target_ip, netstack.netdev.ip_address, netstack.netdev.mac_address);
//    // wait for the arp cache entry to be added
//    std::string dmac;
//    // TODO: timeout
////    while (dmac.empty())
////    {
////        dmac = netstack.neighbor_table.lookup(target_ip);
////        std::this_thread::yield();
////    }
//    sleep(1);
//    dmac = netstack.neighbor_table.lookup(target_ip);
//
//    // Assert
//    assert(!dmac.empty());
//    std::cout << "[+] sARP table entry for " << target_ip << " " << "is " << dmac << std::endl;
//
//    // Cleanup
//    netstack.enable_rx_loop = false;
//    netstack.rx_producer_thread->join(); // blocks until we receive another packet. TODO: fix
//}
//
//void test_icmp_echo_request(const std::string& iface, const std::string& target_ip)
//{
//    // Assumes that a live host with ip: target_ip is up and responding to icmp echo requests
//    // Sends out an icmp echo request to target_ip.
//    // performs address resolution before sending the echo request out
//
//    // Arrange
//    Tins::NetworkInterface interface0(iface);
//    std::string ip0 = "10.3.32.2";
//    std::string mask0 = "255.255.0.0";
//    NetworkDevice netdev0(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack(netdev0);
//    netstack.init();
//
//    // Act
//    netstack.send_icmp_echo_request(target_ip);
//    sleep(1);
//
//    // Assert
//
//    // Cleanup
//    netstack.enable_rx_loop = false;
//    netstack.rx_producer_thread->join(); // blocks until we receive another packet. TODO: fix
//}
//
//void test_handle_neighbor_advertisment(const std::string& iface, const std::string& target_ip)
//{
//    // Assumes that iface has an IPv6 global address that ends with "aa:aaab"
//    // Assumes that a live host with ip: target_ip is up and sends a neighbor solicitation to us
//    // Sends out a neighbor solicitation in response to a neighbor solicitations.
//
//    // Arrange
//    Tins::NetworkInterface interface0(iface);
//    std::string ip0 = "fdda:dead:beef:dab1:2222:dddd:abaa:aaab";
//    std::string mask0 = "FFFF:FFFF:FFFF:FFFF:0000:0000:0000:0000";
//    NetworkDevice netdev0(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack(netdev0);
//    netstack.init();
//    std::string dmac = "";
//
//    // Act
//    for (int i=0; i<30; i++)
//    {
//        sleep(1);
//        dmac = netstack.neighbor_table.lookup(target_ip);
//        if (!dmac.empty()) break;
//    }
//
//    // Assert
//    assert(!dmac.empty());
//    std::cout << "[+] Neighbor table entry for " << target_ip << " " << "is " << dmac << std::endl;
//
//    // Cleanup
//    netstack.enable_rx_loop = false;
//    netstack.rx_producer_thread->join(); // blocks until we receive another packet. TODO: fix
//}
//
//
//void test_neighbor_solicitation(const std::string& iface, const std::string& target_ip)
//{
//    // Assumes that a live host with ip: target_ip is up and responding to neighbor solicitations
//    // Sends out a neighbor solicitation with target_ip.
//
//    // Arrange
//    Tins::NetworkInterface interface0(iface);
//    std::string ip0 = "fdda:dead:beef:dab1:2222:dddd:abaa:aaab";
//    std::string mask0 = "FFFF:FFFF:FFFF:FFFF:0000:0000:0000:0000";
//    NetworkDevice netdev0(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack(netdev0);
//    netstack.init();
//    std::string dmac = "";
//
//    // Act
//    netstack.send_ndp_neighbor_solicitation(target_ip, netstack.netdev.ip_address, netstack.netdev.mac_address);
//    sleep(1);
//    dmac = netstack.neighbor_table.lookup(target_ip);
//
//    // Assert
//    assert(!dmac.empty());
//    std::cout << "[+] Neighbor table entry for " << target_ip << " " << "is " << dmac << std::endl;
//
//    // Cleanup
//    netstack.enable_rx_loop = false;
//    netstack.rx_producer_thread->join(); // blocks until we receive another packet. TODO: fix
//}
//
//void test_send_icmpv6_echo_request(const std::string& iface, const std::string& target_ip)
//{
//    // Assumes that iface has an IPv6 global address that ends with "aa:aaab"
//    // Assumes that a live host with ip: target_ip is up and (optionally) responds to ICMPv6 echo request
//    // Sends out an ICMPv6 echo request to target_ip
//
//    // Arrange
//    Tins::NetworkInterface interface0(iface);
//    std::string ip0 = "fdda:dead:beef:dab1:2222:dddd:abaa:aaab";
//    std::string mask0 = "FFFF:FFFF:FFFF:FFFF:0000:0000:0000:0000";
//    NetworkDevice netdev0(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack(netdev0);
//    netstack.init();
//
//    // Act
//    netstack.send_icmpv6_echo_request(target_ip);
//    sleep(1);
//
//    // Assert
//
//
//    // Cleanup
//    netstack.enable_rx_loop = false;
//    netstack.rx_producer_thread->join(); // blocks until we receive another packet. TODO: fix
//}
//
//void test_handle_icmpv6_echo_request(const std::string& iface, const std::string& target_ip)
//{
//    // Assumes that iface has an IPv6 global address that ends with "aa:aaab"
//    // Assumes that a live host with ip: target_ip is up and will sends a ping6 request to us
//    // Sends out a ping6 response in response to a ping6 request
//
//    // Arrange
//    Tins::NetworkInterface interface0(iface);
//    std::string ip0 = "fdda:dead:beef:dab1:2222:dddd:abaa:aaab";
//    std::string mask0 = "FFFF:FFFF:FFFF:FFFF:0000:0000:0000:0000";
//    NetworkDevice netdev0(interface0, ip0, mask0);
//    TCPIPNetworkStack netstack(netdev0);
//    netstack.init();
//    std::string dmac = "";
//
//    // Act
//    sleep(10);
//
//    // Assert
//
//    // Cleanup
//    netstack.enable_rx_loop = false;
//    netstack.rx_producer_thread->join(); // blocks until we receive another packet. TODO: fix
//}
