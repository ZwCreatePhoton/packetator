#include <iostream>
#include <type_traits>


#include <unistd.h> // sleep

#include "gtest/gtest.h"

// Hack to access restricted class members
#define private public
#define protected public

#include "TCPIPNetworkStack/Link/networking.h"
#include "TCPIPNetworkStack/host.h"
#include "TCPIPNetworkStack/tcp_ip_network_stack.h"
#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "PcapReplayNetworkStack/validator.h"

TEST(PcapReplayNetworkStack, modify_udp_data_no_modification_no_map_entry)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.31.68";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/host_dns_query_python.pcapng";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["10.3.31.1"] = "10.3.31.68"; // client
    pcap_ip_map["10.3.31.65"] = "10.3.31.65"; // server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    config.modify_udp_data = true;
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;
    auto original_query1_packet = netstack.packets[0];
    auto rewritten_query1_packet = original_query1_packet;
    netstack.process_next_original_packet(original_query1_packet);

    // Act
    netstack.rewrite_packet(rewritten_query1_packet);

    // Assert
    auto original_query1 = original_query1_packet.pdu()->rfind_pdu<Tins::RawPDU>().payload();
    auto rewritten_query1 = rewritten_query1_packet.pdu()->rfind_pdu<Tins::RawPDU>().payload();
    EXPECT_EQ(original_query1, rewritten_query1);
}


TEST(PcapReplayNetworkStack, modify_udp_data_request_modification)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.31.68";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/host_dns_query_python.pcapng";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["10.3.31.1"] = "10.3.31.68"; // client
    pcap_ip_map["10.3.31.65"] = "10.3.31.65"; // server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    config.modify_udp_data = true;
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;
    auto original_query1_packet = netstack.packets[0];
    auto rewritten_query1_packet = original_query1_packet;
    netstack.process_next_original_packet(original_query1_packet);
    auto original_5t = Tuple::packet_to_FiveTuple(original_query1_packet);
    auto original_cs5t = Tuple::FiveTuple_to_ClientServerFiveTuple(*original_5t, false);
    auto *original_connection = (UdpConnection *)netstack.original_connection_table.lookup(original_cs5t);
    auto original_query1 = original_query1_packet.pdu()->rfind_pdu<Tins::RawPDU>().payload();
    std::map<std::tuple<uint32_t, uint16_t, uint16_t>, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> rewrite_map{};
    std::vector<uint8_t> old_bytes = {original_query1[0], original_query1[1], original_query1[2]};
    std::vector<uint8_t> new_bytes = {0xDE, 0xAD, 0xBE};
    rewrite_map[std::tuple<uint32_t, uint16_t, uint16_t>(0,0,3)] = std::pair<std::vector<uint8_t>, std::vector<uint8_t>>(old_bytes, new_bytes); // rewrite the first 2 bytes with '0xDEAD'
    netstack.udp_rewrite_maps[original_connection] = rewrite_map;

    // Act
    netstack.rewrite_packet(rewritten_query1_packet);

    // Assert
    auto rewritten_query1 = rewritten_query1_packet.pdu()->rfind_pdu<Tins::RawPDU>().payload();
    // Only the first 3 bytes should have changed
    EXPECT_EQ(std::vector<uint8_t>(original_query1.begin()+3, original_query1.end()), std::vector<uint8_t>(rewritten_query1.begin()+3, rewritten_query1.end()));
    EXPECT_EQ(rewritten_query1[0], new_bytes[0]);
    EXPECT_EQ(rewritten_query1[1], new_bytes[1]);
    EXPECT_EQ(rewritten_query1[2], new_bytes[2]);
}

TEST(PcapReplayNetworkStack, modify_tcp_data_no_modification_no_map_entry)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.31.68";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/ben.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["10.141.41.101"] = "10.3.31.68"; // client
    pcap_ip_map["10.141.41.1"] = "10.3.31.65"; // server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    config.modify_tcp_data = true;
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;
    auto original_request1_packet = netstack.packets[3];
    auto rewritten_request1_packet = original_request1_packet;
    netstack.process_next_original_packet(netstack.packets[0]); // SYN
    netstack.rewrite_packet(netstack.packets[0]);
    netstack.process_next_original_packet(netstack.packets[1]); // SYN + ACK
    netstack.rewrite_packet(netstack.packets[1]);
    netstack.process_next_original_packet(netstack.packets[2]); // ACK
    netstack.rewrite_packet(netstack.packets[2]);
    netstack.process_next_original_packet(original_request1_packet); // HTTP request

    // Act
    netstack.rewrite_packet(rewritten_request1_packet);

    // Assert
    auto original_query1 = original_request1_packet.pdu()->rfind_pdu<Tins::RawPDU>().payload();
    auto rewritten_query1 = rewritten_request1_packet.pdu()->rfind_pdu<Tins::RawPDU>().payload();
    EXPECT_EQ(original_query1, rewritten_query1);
}


TEST(PcapReplayNetworkStack, modify_tcp_data_request_modification)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.31.68";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/ben.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["10.141.41.101"] = "10.3.31.68"; // client
    pcap_ip_map["10.141.41.1"] = "10.3.31.65"; // server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    config.modify_tcp_data = true;
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;
    auto original_request1_packet = netstack.packets[3];
    auto rewritten_request1_packet = original_request1_packet;
    netstack.process_next_original_packet(netstack.packets[0]); // SYN
    netstack.rewrite_packet(netstack.packets[0]);
    auto original_5t = Tuple::packet_to_FiveTuple(original_request1_packet);
    auto original_cs5t = Tuple::FiveTuple_to_ClientServerFiveTuple(*original_5t, false);
    auto *original_connection = (TcpConnection *)netstack.original_connection_table.lookup(original_cs5t);
    Connection *replayed_connection = netstack.convert_Connection(original_connection, true);
    replayed_connection->update(netstack.packets[0]);
    netstack.process_next_original_packet(netstack.packets[1]); // SYN + ACK
    netstack.rewrite_packet(netstack.packets[1]);
    replayed_connection->update(netstack.packets[1]);
    netstack.process_next_original_packet(netstack.packets[2]); // ACK
    netstack.rewrite_packet(netstack.packets[2]);
    replayed_connection->update(netstack.packets[2]);
    netstack.process_next_original_packet(original_request1_packet); // HTTP request

    auto original_request1 = original_request1_packet.pdu()->rfind_pdu<Tins::RawPDU>().payload();
    std::map<std::tuple<uint32_t, uint32_t>, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> rewrite_map{};
    std::vector<uint8_t> old_bytes = {original_request1[0], original_request1[1], original_request1[2]};
    std::vector<uint8_t> new_bytes = {'P', 'U', 'T'};
    rewrite_map[std::tuple<uint32_t, uint32_t>(1+0, 3)] = std::pair<std::vector<uint8_t>, std::vector<uint8_t>>(old_bytes, new_bytes); // rewrite the first 3 bytes with 'PUT'
    netstack.tcp_rewrite_maps[original_connection] = rewrite_map;

    // Act
    netstack.rewrite_packet(rewritten_request1_packet);

    // Assert
    auto rewritten_request1 = rewritten_request1_packet.pdu()->rfind_pdu<Tins::RawPDU>().payload();
    // Only the first 3 bytes should have changed
    EXPECT_EQ(std::vector<uint8_t>(original_request1.begin()+3, original_request1.end()), std::vector<uint8_t>(original_request1.begin()+3, original_request1.end()));
    EXPECT_EQ(rewritten_request1[0], new_bytes[0]);
    EXPECT_EQ(rewritten_request1[1], new_bytes[1]);
    EXPECT_EQ(rewritten_request1[2], new_bytes[2]);
}


TEST(PcapReplayNetworkStack, tftp_client_preprocess_ports)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    std::vector<uint16_t> listening_tcp_ports = {};
    std::vector<uint16_t> listening_udp_ports = {};
    std::vector<std::pair<std::string, uint16_t>> remote_listening_udp_ports = {std::pair<std::string, uint16_t>("172.16.8.80", 69)};
    std::vector<uint16_t> listening_udp_client_ports = {51231};
    std::vector<std::pair<std::string, uint16_t>> remote_listening_udp_client_ports = {};

    // Act

    // Assert
    EXPECT_EQ(netstack.listening_tcp_ports, listening_tcp_ports);
    EXPECT_EQ(netstack.listening_udp_ports, listening_udp_ports);
    EXPECT_EQ(netstack.remote_listening_udp_ports, remote_listening_udp_ports);
    EXPECT_EQ(netstack.listening_udp_client_ports, listening_udp_client_ports);
    EXPECT_EQ(netstack.remote_listening_udp_client_ports, remote_listening_udp_client_ports);
}

TEST(PcapReplayNetworkStack, tftp_server_preprocess_ports)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    std::vector<uint16_t> listening_tcp_ports = {};
    std::vector<uint16_t> listening_udp_ports = {69};
    std::vector<std::pair<std::string, uint16_t>> remote_listening_udp_ports = {};
    std::vector<uint16_t> listening_udp_client_ports = {};
    std::vector<std::pair<std::string, uint16_t>> remote_listening_udp_client_ports = {std::pair<std::string, uint16_t>("172.16.8.132", 51231)};

    // Act

    // Assert
    EXPECT_EQ(netstack.listening_tcp_ports, listening_tcp_ports);
    EXPECT_EQ(netstack.listening_udp_ports, listening_udp_ports);
    EXPECT_EQ(netstack.remote_listening_udp_ports, remote_listening_udp_ports);
    EXPECT_EQ(netstack.listening_udp_client_ports, listening_udp_client_ports);
    EXPECT_EQ(netstack.remote_listening_udp_client_ports, remote_listening_udp_client_ports);
}



TEST(PcapReplayNetworkStack, is_source_server_tcp_client_original_source_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.destination_ip = "172.16.8.132";
    ft.destination_port = 4444;
    ft.source_ip = "172.16.8.80";
    ft.source_port = 80;
    ft.protocol = IPPROTO_TCP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tcp_server_original_source_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {80};

    Tuple::FiveTuple ft{};
    ft.destination_ip = "172.16.8.132";
    ft.destination_port = 4444;
    ft.source_ip = "172.16.8.80";
    ft.source_port = 80;
    ft.protocol = IPPROTO_TCP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tcp_client_original_destination_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.source_ip = "172.16.8.132";
    ft.source_port = 4444;
    ft.destination_ip = "172.16.8.80";
    ft.destination_port = 80;
    ft.protocol = IPPROTO_TCP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tcp_server_original_destination_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {80};

    Tuple::FiveTuple ft{};
    ft.source_ip = "172.16.8.132";
    ft.source_port = 4444;
    ft.destination_ip = "172.16.8.80";
    ft.destination_port = 80;
    ft.protocol = IPPROTO_TCP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tcp_client_replayed_source_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.destination_ip = "10.3.76.0";
    ft.destination_port = 5555;
    ft.source_ip = "10.3.38.203";
    ft.source_port = 80;
    ft.protocol = IPPROTO_TCP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tcp_server_replayed_source_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {80};

    Tuple::FiveTuple ft{};
    ft.destination_ip = "10.3.76.0";
    ft.destination_port = 5555;
    ft.source_ip = "10.3.38.203";
    ft.source_port = 80;
    ft.protocol = IPPROTO_TCP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tcp_client_replayed_destination_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.source_ip = "10.3.76.0";
    ft.source_port = 5555;
    ft.destination_ip = "10.3.38.203";
    ft.destination_port = 80;
    ft.protocol = IPPROTO_TCP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tcp_server_replayed_destination_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tcp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tcp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {80};

    Tuple::FiveTuple ft{};
    ft.source_ip = "10.3.76.0";
    ft.source_port = 5555;
    ft.destination_ip = "10.3.38.203";
    ft.destination_port = 80;
    ft.protocol = IPPROTO_TCP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, false);
}










TEST(PcapReplayNetworkStack, is_source_server_udp_client_original_source_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // udp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {};
    netstack.listening_udp_ports = {};
    netstack.remote_listening_udp_ports = {std::pair<std::string, uint16_t>("172.16.8.80", 80)};
    netstack.listening_udp_client_ports = {};
    netstack.remote_listening_udp_client_ports = {};

    Tuple::FiveTuple ft{};
    ft.destination_ip = "172.16.8.132";
    ft.destination_port = 4444;
    ft.source_ip = "172.16.8.80";
    ft.source_port = 80;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_udp_server_original_source_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // udp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {};
    netstack.listening_udp_ports = {80};
    netstack.remote_listening_udp_ports = {};
    netstack.listening_udp_client_ports = {};
    netstack.remote_listening_udp_client_ports = {};

    Tuple::FiveTuple ft{};
    ft.destination_ip = "172.16.8.132";
    ft.destination_port = 4444;
    ft.source_ip = "172.16.8.80";
    ft.source_port = 80;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_udp_client_original_destination_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // udp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {};
    netstack.listening_udp_ports = {};
    netstack.remote_listening_udp_ports = {std::pair<std::string, uint16_t>("172.16.8.80", 80)};
    netstack.listening_udp_client_ports = {};
    netstack.remote_listening_udp_client_ports = {};

    Tuple::FiveTuple ft{};
    ft.source_ip = "172.16.8.132";
    ft.source_port = 4444;
    ft.destination_ip = "172.16.8.80";
    ft.destination_port = 80;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_udp_server_original_destination_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // udp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {};
    netstack.listening_udp_ports = {80};
    netstack.remote_listening_udp_ports = {};
    netstack.listening_udp_client_ports = {};
    netstack.remote_listening_udp_client_ports = {};

    Tuple::FiveTuple ft{};
    ft.source_ip = "172.16.8.132";
    ft.source_port = 4444;
    ft.destination_ip = "172.16.8.80";
    ft.destination_port = 80;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_udp_client_replayed_source_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // udp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {};
    netstack.listening_udp_ports = {};
    netstack.remote_listening_udp_ports = {std::pair<std::string, uint16_t>("172.16.8.80", 80)};
    netstack.listening_udp_client_ports = {};
    netstack.remote_listening_udp_client_ports = {};

    Tuple::FiveTuple ft{};
    ft.destination_ip = "10.3.76.0";
    ft.destination_port = 5555;
    ft.source_ip = "10.3.38.203";
    ft.source_port = 80;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_udp_server_replayed_source_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // udp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {};
    netstack.listening_udp_ports = {80};
    netstack.remote_listening_udp_ports = {};
    netstack.listening_udp_client_ports = {};
    netstack.remote_listening_udp_client_ports = {};

    Tuple::FiveTuple ft{};
    ft.destination_ip = "10.3.76.0";
    ft.destination_port = 5555;
    ft.destination_port = 5555;
    ft.source_ip = "10.3.38.203";
    ft.source_port = 80;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_udp_client_replayed_destination_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // udp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {};
    netstack.listening_udp_ports = {};
    netstack.remote_listening_udp_ports = {std::pair<std::string, uint16_t>("172.16.8.80", 80)};
    netstack.listening_udp_client_ports = {};
    netstack.remote_listening_udp_client_ports = {};

    Tuple::FiveTuple ft{};
    ft.source_ip = "10.3.76.0";
    ft.source_port = 5555;
    ft.destination_ip = "10.3.38.203";
    ft.destination_port = 80;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_udp_server_replayed_destination_is_server)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // udp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    netstack.listening_tcp_ports = {};
    netstack.listening_udp_ports = {80};
    netstack.remote_listening_udp_ports = {};
    netstack.listening_udp_client_ports = {};
    netstack.remote_listening_udp_client_ports = {};

    Tuple::FiveTuple ft{};
    ft.source_ip = "10.3.76.0";
    ft.source_port = 5555;
    ft.destination_ip = "10.3.38.203";
    ft.destination_port = 80;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, false);
}








TEST(PcapReplayNetworkStack, is_source_server_tftp_client_original_source_is_server1)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.destination_ip = "172.16.8.132";
    ft.destination_port = 51231;
    ft.source_ip = "172.16.8.80";
    ft.source_port = 69;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_server_original_source_is_server1)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.destination_ip = "172.16.8.132";
    ft.destination_port = 51231;
    ft.source_ip = "172.16.8.80";
    ft.source_port = 69;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_client_original_destination_is_server1)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.source_ip = "172.16.8.132";
    ft.source_port = 51231;
    ft.destination_ip = "172.16.8.80";
    ft.destination_port = 69;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_server_original_destination_is_server1)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.source_ip = "172.16.8.132";
    ft.source_port = 51231;
    ft.destination_ip = "172.16.8.80";
    ft.destination_port = 69;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_client_replayed_source_is_server1)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.destination_ip = "10.3.76.0";
    ft.destination_port = 5555;
    ft.source_ip = "10.3.38.203";
    ft.source_port = 69;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_server_replayed_source_is_server1)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.destination_ip = "10.3.76.0";
    ft.destination_port = 5555;
    ft.source_ip = "10.3.38.203";
    ft.source_port = 69;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_client_replayed_destination_is_server1)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.source_ip = "10.3.76.0";
    ft.source_port = 5555;
    ft.destination_ip = "10.3.38.203";
    ft.destination_port = 69;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_server_replayed_destination_is_server1)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.source_ip = "10.3.76.0";
    ft.source_port = 5555;
    ft.destination_ip = "10.3.38.203";
    ft.destination_port = 69;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, false);
}



TEST(PcapReplayNetworkStack, is_source_server_tftp_client_original_source_is_server2)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.destination_ip = "172.16.8.132";
    ft.destination_port = 51231;
    ft.source_ip = "172.16.8.80";
    ft.source_port = 36762;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_server_original_source_is_server2)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.destination_ip = "172.16.8.132";
    ft.destination_port = 51231;
    ft.source_ip = "172.16.8.80";
    ft.source_port = 36762;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_client_original_destination_is_server2)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.source_ip = "172.16.8.132";
    ft.source_port = 51231;
    ft.destination_ip = "172.16.8.80";
    ft.destination_port = 36762;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_server_original_destination_is_server2)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    Tuple::FiveTuple ft{};
    ft.source_ip = "172.16.8.132";
    ft.source_port = 51231;
    ft.destination_ip = "172.16.8.80";
    ft.destination_port = 36762;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, true);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_client_replayed_source_is_server2)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    netstack.rewrite_packet(replayed_write_request_packet);

    Tuple::FiveTuple ft{};
    ft.destination_ip = "10.3.76.0";
    ft.destination_port = replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>().sport();
    ft.source_ip = "10.3.38.203";
    ft.source_port = 7777;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_server_replayed_source_is_server2)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // udp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    auto &replayed_write_request_packet_ip = replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_write_request_packet_ip.src_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_write_request_packet_ip.dst_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_write_request_packet_udp = replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_write_request_packet_udp.sport(5555);
    netstack.handle_rx_packet(replayed_write_request_packet);

    Tuple::FiveTuple ft{};
    ft.destination_ip = "10.3.76.0";
    ft.destination_port = 5555;
    ft.source_ip = "10.3.38.203";
    ft.source_port = 7777;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, false);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_client_replayed_destination_is_server2)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    netstack.rewrite_packet(replayed_write_request_packet);

    Tuple::FiveTuple ft{};
    ft.source_ip = "10.3.76.0";
    ft.source_port = replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>().sport();
    ft.destination_ip = "10.3.38.203";
    ft.destination_port = 7777;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, true);
}

TEST(PcapReplayNetworkStack, is_source_server_tftp_server_replayed_destination_is_server2)
{
    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    auto &replayed_write_request_packet_ip = replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_write_request_packet_ip.src_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_write_request_packet_ip.dst_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_write_request_packet_udp = replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_write_request_packet_udp.sport(5555);
    netstack.handle_rx_packet(replayed_write_request_packet);

    Tuple::FiveTuple ft{};
    ft.source_ip = "10.3.76.0";
    ft.source_port = 5555;
    ft.destination_ip = "10.3.38.203";
    ft.destination_port = 7777;
    ft.protocol = IPPROTO_UDP;

    // Act
    bool result = netstack.is_source_server(ft, false);

    // Assert
    EXPECT_EQ(result, true);
}




// tftp_*_*_table_size* tests depend on is_source_server_tfp_*_*_*_is_server* tests

// Guess: tftp_*_*_table_size* tests don't work because of is_source_server (tests) is incorrect

TEST(PcapReplayNetworkStack, tftp_client_complete_original_table_size2)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    // Act

    // Assert
    EXPECT_EQ(netstack.complete_original_connection_table.all()->size(), 2);
}

TEST(PcapReplayNetworkStack, tftp_server_complete_original_table_size2)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    // Act

    // Assert
    EXPECT_EQ(netstack.complete_original_connection_table.all()->size(), 2);
}

TEST(PcapReplayNetworkStack, tftp_client_original_table_size)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client

    // Act
    netstack.process_next_original_packet(original_write_request_packet);
    netstack.process_next_original_packet(original_acknowledgement_packet);

    // Assert
    EXPECT_EQ(netstack.original_connection_table.all()->size(), 2);
}

TEST(PcapReplayNetworkStack, tftp_server_original_table_size)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    // Act

    // Assert
    EXPECT_EQ(netstack.original_connection_table.all()->size(), 2);
}


TEST(PcapReplayNetworkStack, tftp_client_replayed_table_size)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    netstack.rewrite_packet(replayed_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto replayed_acknowledgement_packet = original_acknowledgement_packet; // tftp server -> tftp client
    auto &replayed_acknowledgement_packet_ip = replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_acknowledgement_packet_ip.src_addr(pcap_ip_map[original_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_acknowledgement_packet_ip.dst_addr(pcap_ip_map[original_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_acknowledgement_packet_udp = replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_acknowledgement_packet_udp.sport(5555);
    replayed_acknowledgement_packet_udp.dport(replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>().sport());
    netstack.handle_rx_packet(replayed_acknowledgement_packet);

    // Act

    // Assert
    EXPECT_EQ(netstack.connection_table.all()->size(), 2);
}

TEST(PcapReplayNetworkStack, tftp_server_replayed_table_size)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    auto &replayed_write_request_packet_ip = replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_write_request_packet_ip.src_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_write_request_packet_ip.dst_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_write_request_packet_udp = replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_write_request_packet_udp.sport(4444);
    netstack.handle_rx_packet(replayed_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto replayed_acknowledgement_packet = original_acknowledgement_packet; // tftp server -> tftp client
    netstack.rewrite_packet(replayed_acknowledgement_packet);

    // Act

    // Assert
    EXPECT_EQ(netstack.connection_table.all()->size(), 2);
}

TEST(PcapReplayNetworkStack, tftp_client_original_table_size2)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_mal_packet);

    // Act

    // Assert
    EXPECT_EQ(netstack.original_connection_table.all()->size(), 2);
}

TEST(PcapReplayNetworkStack, tftp_server_original_table_size2)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_mal_packet);

    // Act

    // Assert
    EXPECT_EQ(netstack.original_connection_table.all()->size(), 2);
}

TEST(PcapReplayNetworkStack, tftp_client_replayed_table_size2)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    netstack.rewrite_packet(replayed_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto replayed_acknowledgement_packet = original_acknowledgement_packet; // tftp server -> tftp client
    auto &replayed_acknowledgement_packet_ip = replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_acknowledgement_packet_ip.src_addr(pcap_ip_map[original_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_acknowledgement_packet_ip.dst_addr(pcap_ip_map[original_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_acknowledgement_packet_udp = replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_acknowledgement_packet_udp.sport(5555);
    replayed_acknowledgement_packet_udp.dport(replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>().sport());
    netstack.handle_rx_packet(replayed_acknowledgement_packet);

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_mal_packet);

    auto replayed_mal_packet = original_mal_packet; // tftp client -> tftp server
    netstack.rewrite_packet(replayed_mal_packet);

    // Act

    // Assert
    EXPECT_EQ(netstack.connection_table.all()->size(), 2);
}

TEST(PcapReplayNetworkStack, tftp_server_replayed_table_size2)
{

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    auto &replayed_write_request_packet_ip = replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_write_request_packet_ip.src_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_write_request_packet_ip.dst_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_write_request_packet_udp = replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_write_request_packet_udp.sport(4444);
    netstack.handle_rx_packet(replayed_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto replayed_acknowledgement_packet = original_acknowledgement_packet; // tftp server -> tftp client
    netstack.rewrite_packet(replayed_acknowledgement_packet);

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_mal_packet);

    auto replayed_mal_packet = original_mal_packet; // tftp client -> tftp server
    auto &replayed_mal_packet_ip = replayed_mal_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_mal_packet_ip.src_addr(pcap_ip_map[replayed_mal_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_mal_packet_ip.dst_addr(pcap_ip_map[replayed_mal_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_mal_packet_udp = replayed_mal_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_mal_packet_udp.sport(replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::UDP>().dport());
    replayed_mal_packet_udp.dport(replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::UDP>().sport());
    netstack.handle_rx_packet(replayed_mal_packet);

    // Act

    // Assert
    EXPECT_EQ(netstack.connection_table.all()->size(), 2);
}


//tftp_*_*_response_connection_to_*_request_connection* tests depend on tftp_*_*_table_size* tests


/*

TEST(PcapReplayNetworkStack, tftp_client_original_response_connection_to_original_request_connection)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto original_connection1 = (*netstack.original_connection_table.all())[0];
    auto original_connection2 = (*netstack.original_connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(original_connection2, netstack.original_connection_table);

    // Assert
    EXPECT_EQ(request_connection, original_connection1);
}

TEST(PcapReplayNetworkStack, tftp_server_original_response_connection_to_original_request_connection)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto original_connection1 = (*netstack.original_connection_table.all())[0];
    auto original_connection2 = (*netstack.original_connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(original_connection2, netstack.original_connection_table);

    // Assert
    EXPECT_EQ(request_connection, original_connection1);
}

TEST(PcapReplayNetworkStack, tftp_client_complete_original_response_connection_to_complete_original_request_connection)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client

    auto complete_original_connection1 = (*netstack.complete_original_connection_table.all())[0];
    auto complete_original_connection2 = (*netstack.complete_original_connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(complete_original_connection2, netstack.complete_original_connection_table);

    // Assert
    EXPECT_EQ(request_connection, complete_original_connection1);
}

TEST(PcapReplayNetworkStack, tftp_server_complete_original_response_connection_to_complete_original_request_connection)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client

    auto complete_original_connection1 = (*netstack.complete_original_connection_table.all())[0];
    auto complete_original_connection2 = (*netstack.complete_original_connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(complete_original_connection2, netstack.complete_original_connection_table);

    // Assert
    EXPECT_EQ(request_connection, complete_original_connection1);
}

TEST(PcapReplayNetworkStack, tftp_client_replayed_response_connection_to_replayed_request_connection)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    netstack.rewrite_packet(replayed_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto replayed_acknowledgement_packet = original_acknowledgement_packet; // tftp server -> tftp client
    auto &replayed_acknowledgement_packet_ip = replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_acknowledgement_packet_ip.src_addr(pcap_ip_map[original_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_acknowledgement_packet_ip.dst_addr(pcap_ip_map[original_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_acknowledgement_packet_udp = replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_acknowledgement_packet_udp.sport(5555);
    replayed_acknowledgement_packet_udp.dport(replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>().sport());
    netstack.handle_rx_packet(replayed_acknowledgement_packet);

    auto replayed_connection1 = (*netstack.connection_table.all())[0];
    auto replayed_connection2 = (*netstack.connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(replayed_connection2, netstack.connection_table);

    // Assert
    EXPECT_EQ(request_connection, replayed_connection1);
}

TEST(PcapReplayNetworkStack, tftp_server_replayed_response_connection_to_replayed_request_connection)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    auto &replayed_write_request_packet_ip = replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_write_request_packet_ip.src_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_write_request_packet_ip.dst_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_write_request_packet_udp = replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_write_request_packet_udp.sport(4444);
    netstack.handle_rx_packet(replayed_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto replayed_acknowledgement_packet = original_acknowledgement_packet; // tftp server -> tftp client
    netstack.rewrite_packet(replayed_acknowledgement_packet);

    auto replayed_connection1 = (*netstack.connection_table.all())[0];
    auto replayed_connection2 = (*netstack.connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(replayed_connection2, netstack.connection_table);

    // Assert
    EXPECT_EQ(request_connection, replayed_connection1);
}

TEST(PcapReplayNetworkStack, tftp_client_complete_original_response_connection_to_complete_original_request_connection2)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server

    auto complete_original_connection1 = (*netstack.complete_original_connection_table.all())[0];
    auto complete_original_connection2 = (*netstack.complete_original_connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(complete_original_connection2, netstack.complete_original_connection_table);

    // Assert
    EXPECT_EQ(request_connection, complete_original_connection1);
}

TEST(PcapReplayNetworkStack, tftp_server_complete_original_response_connection_to_complete_original_request_connection2)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server

    auto complete_original_connection1 = (*netstack.complete_original_connection_table.all())[0];
    auto complete_original_connection2 = (*netstack.complete_original_connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(complete_original_connection2, netstack.complete_original_connection_table);

    // Assert
    EXPECT_EQ(request_connection, complete_original_connection1);
}

TEST(PcapReplayNetworkStack, tftp_client_original_response_connection_to_original_request_connection2)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_mal_packet);

    auto original_connection1 = (*netstack.original_connection_table.all())[0];
    auto original_connection2 = (*netstack.original_connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(original_connection2, netstack.original_connection_table);

    // Assert
    EXPECT_EQ(request_connection, original_connection1);
}

TEST(PcapReplayNetworkStack, tftp_server_original_response_connection_to_original_request_connection2)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_mal_packet);

    auto original_connection1 = (*netstack.original_connection_table.all())[0];
    auto original_connection2 = (*netstack.original_connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(original_connection2, netstack.original_connection_table);

    // Assert
    EXPECT_EQ(request_connection, original_connection1);
}

TEST(PcapReplayNetworkStack, tftp_client_replayed_response_connection_to_replayed_request_connection2)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.76.0";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    netstack.rewrite_packet(replayed_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto replayed_acknowledgement_packet = original_acknowledgement_packet; // tftp server -> tftp client
    auto &replayed_acknowledgement_packet_ip = replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_acknowledgement_packet_ip.src_addr(pcap_ip_map[original_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_acknowledgement_packet_ip.dst_addr(pcap_ip_map[original_acknowledgement_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_acknowledgement_packet_udp = replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_acknowledgement_packet_udp.sport(5555);
    replayed_acknowledgement_packet_udp.dport(replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>().sport());
    netstack.handle_rx_packet(replayed_acknowledgement_packet);

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_mal_packet);

    auto replayed_mal_packet = original_mal_packet; // tftp client -> tftp server
    netstack.rewrite_packet(replayed_mal_packet);

    auto replayed_connection1 = (*netstack.connection_table.all())[0];
    auto replayed_connection2 = (*netstack.connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(replayed_connection2, netstack.connection_table);

    // Assert
    EXPECT_EQ(request_connection, replayed_connection1);
}

TEST(PcapReplayNetworkStack, tftp_server_replayed_response_connection_to_replayed_request_connection2)
{
    // Tests: convert_connection_to_request_connection

    // Arrange
    std::string iface = "eth3";
    Tins::NetworkInterface interface0(iface);
    std::string ip0 = "10.3.38.203";
    std::string mask0 = "255.255.0.0";
    std::string pcap_path = "../../resources/pcaps/2019-262.pcap";
    std::map<std::string, std::string> pcap_ip_map;
    pcap_ip_map["172.16.8.132"] = "10.3.76.0"; // tftp client
    pcap_ip_map["172.16.8.80"] = "10.3.38.203"; // tftp server
    NetworkDevice netdev0 = NetworkDevice(interface0, ip0, mask0);
    PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
    PcapReplayNetworkStack netstack(netdev0, config);
    netstack.disable_rx_loop();
    netstack.enable_tx_loop = false;

    auto original_write_request_packet = netstack.packets[0]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_write_request_packet);

    auto replayed_write_request_packet = original_write_request_packet; // tftp client -> tftp server
    auto &replayed_write_request_packet_ip = replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_write_request_packet_ip.src_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_write_request_packet_ip.dst_addr(pcap_ip_map[replayed_write_request_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_write_request_packet_udp = replayed_write_request_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_write_request_packet_udp.sport(4444);
    netstack.handle_rx_packet(replayed_write_request_packet);

    auto original_acknowledgement_packet = netstack.packets[1]; // tftp server -> tftp client
    netstack.process_next_original_packet(original_acknowledgement_packet);

    auto replayed_acknowledgement_packet = original_acknowledgement_packet; // tftp server -> tftp client
    netstack.rewrite_packet(replayed_acknowledgement_packet);

    auto original_mal_packet = netstack.packets[2]; // tftp client -> tftp server
    netstack.process_next_original_packet(original_mal_packet);

    auto replayed_mal_packet = original_mal_packet; // tftp client -> tftp server
    auto &replayed_mal_packet_ip = replayed_mal_packet.pdu()->rfind_pdu<Tins::IP>();
    replayed_mal_packet_ip.src_addr(pcap_ip_map[replayed_mal_packet.pdu()->rfind_pdu<Tins::IP>().src_addr().to_string()]);
    replayed_mal_packet_ip.dst_addr(pcap_ip_map[replayed_mal_packet.pdu()->rfind_pdu<Tins::IP>().dst_addr().to_string()]);
    auto &replayed_mal_packet_udp = replayed_mal_packet.pdu()->rfind_pdu<Tins::UDP>();
    replayed_mal_packet_udp.sport(replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::UDP>().dport());
    replayed_mal_packet_udp.dport(replayed_acknowledgement_packet.pdu()->rfind_pdu<Tins::UDP>().sport());
    netstack.handle_rx_packet(replayed_mal_packet);

    auto replayed_connection1 = (*netstack.connection_table.all())[0];
    auto replayed_connection2 = (*netstack.connection_table.all())[1];

    // Act
    auto request_connection = netstack.convert_connection_to_request_connection(replayed_connection2, netstack.connection_table);

    // Assert
    EXPECT_EQ(request_connection, replayed_connection1);
}

 */