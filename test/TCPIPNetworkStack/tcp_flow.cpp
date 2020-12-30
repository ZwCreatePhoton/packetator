#include <tins/tins.h>
#include "gtest/gtest.h"

#include <TCPIPNetworkStack/tcp_ip_network_stack.h>


TEST(TcpFlow, happy_flow_tcb)
{
    // This test checks TCB variables: ISS, IRS, SND_NXT, RCV_NXT, SND_UNA
    // at various stages during the following "happy path" TCP flow:
    // 1.) client -> server: SYN
    // 2.) server -> client: SYN + ACK
    // 3.) client -> server: ACK
    // 4.) client -> server: "AAAAA"
    // 5.) server -> client: ACK
    // 6.) server -> client: "BBBBBBBBBB"
    // 7.) client -> server: ACK
    // 8.) client -> server: FIN
    // 9.) server -> client: ACK
    // 10.) server -> client: FIN
    // 11.) client -> server: ACK

    //Arrange
    // Happy path setup
    std::string ip0 = "10.1.33.81";
    std::string ip1 = "10.1.33.82";
    auto client_ip = ip0;
    auto server_ip = ip1;
    uint16_t client_port = 1337;
    uint16_t server_port = 80;
    uint8_t protocol = IPPROTO_TCP;
    auto client_5t = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
    auto server_5t = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
    auto client_flow = TcpFlow(client_5t);
    auto server_flow = TcpFlow(server_5t);
    server_flow.state = TcpFlow::LISTEN;
    auto client_ip_pdu = Tins::IP(server_ip, client_ip); // client -> server
    auto server_ip_pdu = Tins::IP(client_ip, server_ip); // server -> client
    auto client_initial_seq = 1000;
    auto server_initial_seq = 2000;
    std::string client_segment_data_1 = "AAAAA";
    std::string server_segment_data_1 = "BBBBBBBBBB";

    auto syn = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    syn.set_flag(Tins::TCP::SYN, 1);
    syn.seq(client_initial_seq);
    syn.ack_seq(0);
    Tins::Packet syn_packet(client_ip_pdu / syn);

    auto synack = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    synack.set_flag(Tins::TCP::SYN, 1);
    synack.set_flag(Tins::TCP::ACK, 1);
    synack.seq(server_initial_seq);
    synack.ack_seq(client_initial_seq + 1);
    Tins::Packet synack_packet(server_ip_pdu / synack);

    auto ack = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    ack.set_flag(Tins::TCP::ACK, 1);
    ack.seq(client_initial_seq + 1);
    ack.ack_seq(server_initial_seq + 1);
    Tins::Packet ack_packet(client_ip_pdu / ack);

    auto client_segment_1 = Tins::TCP(client_5t.destination_port, client_5t.source_port) / Tins::RawPDU(client_segment_data_1);
    client_segment_1.seq(client_initial_seq + 1);
    client_segment_1.ack_seq(server_initial_seq + 1);
    Tins::Packet client_segment_1_packet(client_ip_pdu / client_segment_1);

    auto server_ack_1 = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    server_ack_1.set_flag(Tins::TCP::ACK, 1);
    server_ack_1.seq(server_initial_seq + 1);
    server_ack_1.ack_seq(client_initial_seq + 1 + client_segment_data_1.length());
    Tins::Packet server_ack_1_packet(server_ip_pdu / server_ack_1);

    auto server_segment_1 = Tins::TCP(server_5t.destination_port, server_5t.source_port) / Tins::RawPDU(server_segment_data_1);
    server_segment_1.seq(server_initial_seq + 1);
    server_segment_1.ack_seq(server_initial_seq + 1 + client_segment_data_1.length());
    Tins::Packet server_segment_1_packet(server_ip_pdu / server_segment_1);

    auto client_ack_1 = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    client_ack_1.set_flag(Tins::TCP::ACK, 1);
    client_ack_1.seq(client_initial_seq + 1 + client_segment_data_1.length());
    client_ack_1.ack_seq(server_initial_seq + 1 + server_segment_data_1.length());
    Tins::Packet client_ack_1_packet(client_ip_pdu / client_ack_1);

    auto client_fin = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    client_fin.set_flag(Tins::TCP::FIN, 1);
    client_fin.seq(client_initial_seq + 1 + client_segment_data_1.length());
    client_fin.ack_seq(server_initial_seq + 1 + server_segment_data_1.length());
    Tins::Packet client_fin_packet(client_ip_pdu / client_fin);

    auto server_ack_2 = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    server_ack_2.set_flag(Tins::TCP::ACK, 1);
    server_ack_2.seq(server_initial_seq + 1 + server_segment_data_1.length());
    server_ack_2.ack_seq(client_initial_seq + 1 + client_segment_data_1.length() + 1);
    Tins::Packet server_ack_2_packet(server_ip_pdu / server_ack_2);

    auto server_fin = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    server_fin.set_flag(Tins::TCP::FIN, 1);
    server_fin.seq(server_initial_seq + 1 + server_segment_data_1.length());
    server_fin.ack_seq(client_initial_seq + 1 + client_segment_data_1.length() + 1);
    Tins::Packet server_fin_packet(server_ip_pdu / server_fin);

    auto client_ack_2 = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    client_ack_2.set_flag(Tins::TCP::ACK, 1);
    client_ack_2.seq(client_initial_seq + 1 + client_segment_data_1.length() + 1);
    client_ack_2.ack_seq(server_initial_seq + 1 + server_segment_data_1.length() + 1);
    Tins::Packet client_ack_2_packet(client_ip_pdu / client_ack_2);

    // Act & Assert

    client_flow.update(syn_packet);
    server_flow.update(syn_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
//    EXPECT_EQ (client_flow.IRS, 0); // ill-defined right now
//    EXPECT_EQ (server_flow.ISS, 0); // ill-defined right now
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1);
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1);
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq);
//    EXPECT_EQ (server_flow.SND_NXT, ); // ill-defined right now
//    EXPECT_EQ (client_flow.RCV_NXT, ); // ill-defined right now
//    EXPECT_EQ (server_flow.SND_NXT, ); // ill-defined right now

    client_flow.update(synack_packet);
    server_flow.update(synack_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1);
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1);
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1);
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1);
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1);
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq);

    client_flow.update(ack_packet);
    server_flow.update(ack_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1);
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1);
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1);
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1);
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1);
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1);

    client_flow.update(client_segment_1_packet);
    server_flow.update(client_segment_1_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1);
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1);
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1);
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1);

    client_flow.update(server_ack_1_packet);
    server_flow.update(server_ack_1_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1);
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1);
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1);

    client_flow.update(server_segment_1_packet);
    server_flow.update(server_segment_1_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1 + server_segment_data_1.length());
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1 + server_segment_data_1.length());
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1);

    client_flow.update(client_ack_1_packet);
    server_flow.update(client_ack_1_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1 + server_segment_data_1.length());
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1 + server_segment_data_1.length());
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1 + server_segment_data_1.length());

    client_flow.update(client_fin_packet);
    server_flow.update(client_fin_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1 + client_segment_data_1.length());
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1 + server_segment_data_1.length());
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1 + server_segment_data_1.length());
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1 + server_segment_data_1.length());

    client_flow.update(server_ack_2_packet);
    server_flow.update(server_ack_2_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1 + server_segment_data_1.length());
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1 + server_segment_data_1.length());
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1 + server_segment_data_1.length());

    client_flow.update(server_fin_packet);
    server_flow.update(server_fin_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1 + server_segment_data_1.length() + 1);
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1 + server_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1 + server_segment_data_1.length());

    client_flow.update(client_ack_2_packet);
    server_flow.update(client_ack_2_packet);
    EXPECT_EQ (client_flow.ISS, client_initial_seq);
    EXPECT_EQ (server_flow.IRS, client_initial_seq);
    EXPECT_EQ (client_flow.IRS, server_initial_seq);
    EXPECT_EQ (server_flow.ISS, server_initial_seq);
    EXPECT_EQ (client_flow.SND_NXT, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.RCV_NXT, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (client_flow.SND_UNA, client_initial_seq + 1 + client_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.SND_NXT, server_initial_seq + 1 + server_segment_data_1.length() + 1);
    EXPECT_EQ (client_flow.RCV_NXT, server_initial_seq + 1 + server_segment_data_1.length() + 1);
    EXPECT_EQ (server_flow.SND_UNA, server_initial_seq + 1 + server_segment_data_1.length() + 1);
}


TEST(TcpFlow, happy_flow_state)
{
    // This test checks TCP states.
    // at various stages during the following "happy path" TCP flow:
    // 1.) client -> server: SYN
    // 2.) server -> client: SYN + ACK
    // 3.) client -> server: ACK
    // 4.) client -> server: "AAAAA"
    // 5.) server -> client: ACK
    // 6.) server -> client: "BBBBBBBBBB"
    // 7.) client -> server: ACK
    // 8.) client -> server: FIN
    // 9.) server -> client: ACK
    // 10.) server -> client: FIN
    // 11.) client -> server: ACK

    //Arrange
    // Happy path setup
    // Happy path setup
    std::string ip0 = "10.1.33.81";
    std::string ip1 = "10.1.33.82";
    auto client_ip = ip0;
    auto server_ip = ip1;
    uint16_t client_port = 1337;
    uint16_t server_port = 80;
    uint8_t protocol = IPPROTO_TCP;
    auto client_5t = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
    auto server_5t = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
    auto client_flow = TcpFlow(client_5t);
    auto server_flow = TcpFlow(server_5t);
    server_flow.state = TcpFlow::LISTEN;
    auto client_ip_pdu = Tins::IP(server_ip, client_ip); // client -> server
    auto server_ip_pdu = Tins::IP(client_ip, server_ip); // server -> client
    auto client_initial_seq = 1000;
    auto server_initial_seq = 2000;
    std::string client_segment_data_1 = "AAAAA";
    std::string server_segment_data_1 = "BBBBBBBBBB";

    auto syn = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    syn.set_flag(Tins::TCP::SYN, 1);
    syn.seq(client_initial_seq);
    syn.ack_seq(0);
    Tins::Packet syn_packet(client_ip_pdu / syn);

    auto synack = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    synack.set_flag(Tins::TCP::SYN, 1);
    synack.set_flag(Tins::TCP::ACK, 1);
    synack.seq(server_initial_seq);
    synack.ack_seq(client_initial_seq + 1);
    Tins::Packet synack_packet(server_ip_pdu / synack);

    auto ack = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    ack.set_flag(Tins::TCP::ACK, 1);
    ack.seq(client_initial_seq + 1);
    ack.ack_seq(server_initial_seq + 1);
    Tins::Packet ack_packet(client_ip_pdu / ack);

    auto client_segment_1 = Tins::TCP(client_5t.destination_port, client_5t.source_port) / Tins::RawPDU(client_segment_data_1);
    client_segment_1.seq(client_initial_seq + 1);
    client_segment_1.ack_seq(server_initial_seq + 1);
    Tins::Packet client_segment_1_packet(client_ip_pdu / client_segment_1);

    auto server_ack_1 = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    server_ack_1.set_flag(Tins::TCP::ACK, 1);
    server_ack_1.seq(server_initial_seq + 1);
    server_ack_1.ack_seq(client_initial_seq + 1 + client_segment_data_1.length());
    Tins::Packet server_ack_1_packet(server_ip_pdu / server_ack_1);

    auto server_segment_1 = Tins::TCP(server_5t.destination_port, server_5t.source_port) / Tins::RawPDU(server_segment_data_1);
    server_segment_1.seq(server_initial_seq + 1);
    server_segment_1.ack_seq(server_initial_seq + 1 + client_segment_data_1.length());
    Tins::Packet server_segment_1_packet(server_ip_pdu / server_segment_1);

    auto client_ack_1 = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    client_ack_1.set_flag(Tins::TCP::ACK, 1);
    client_ack_1.seq(client_initial_seq + 1 + client_segment_data_1.length());
    client_ack_1.ack_seq(server_initial_seq + 1 + server_segment_data_1.length());
    Tins::Packet client_ack_1_packet(client_ip_pdu / client_ack_1);

    auto client_fin = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    client_fin.set_flag(Tins::TCP::FIN, 1);
    client_fin.seq(client_initial_seq + 1 + client_segment_data_1.length());
    client_fin.ack_seq(server_initial_seq + 1 + server_segment_data_1.length());
    Tins::Packet client_fin_packet(client_ip_pdu / client_fin);

    auto server_ack_2 = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    server_ack_2.set_flag(Tins::TCP::ACK, 1);
    server_ack_2.seq(server_initial_seq + 1 + server_segment_data_1.length());
    server_ack_2.ack_seq(client_initial_seq + 1 + client_segment_data_1.length() + 1);
    Tins::Packet server_ack_2_packet(server_ip_pdu / server_ack_2);

    auto server_fin = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    server_fin.set_flag(Tins::TCP::FIN, 1);
    server_fin.seq(server_initial_seq + 1 + server_segment_data_1.length());
    server_fin.ack_seq(client_initial_seq + 1 + client_segment_data_1.length() + 1);
    Tins::Packet server_fin_packet(server_ip_pdu / server_fin);

    auto client_ack_2 = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    client_ack_2.set_flag(Tins::TCP::ACK, 1);
    client_ack_2.seq(client_initial_seq + 1 + client_segment_data_1.length() + 1);
    client_ack_2.ack_seq(server_initial_seq + 1 + server_segment_data_1.length() + 1);
    Tins::Packet client_ack_2_packet(client_ip_pdu / client_ack_2);


    // Act & Assert
    EXPECT_EQ (client_flow.state, TcpFlow::State::CLOSED1);
    EXPECT_EQ (server_flow.state, TcpFlow::State::LISTEN);

    client_flow.update(syn_packet);
    server_flow.update(syn_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::SYN_SENT);
    EXPECT_EQ (server_flow.state, TcpFlow::State::SYN_RECEIVED);

    client_flow.update(synack_packet);
    server_flow.update(synack_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::ESTABLISHED); // Will transitioning here instead of when the clint sends that ACK be fine?
    EXPECT_EQ (server_flow.state, TcpFlow::State::SYN_RECEIVED);

    client_flow.update(ack_packet);
    server_flow.update(ack_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::ESTABLISHED);
    EXPECT_EQ (server_flow.state, TcpFlow::State::ESTABLISHED);

    client_flow.update(client_segment_1_packet);
    server_flow.update(client_segment_1_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::ESTABLISHED);
    EXPECT_EQ (server_flow.state, TcpFlow::State::ESTABLISHED);

    client_flow.update(server_ack_1_packet);
    server_flow.update(server_ack_1_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::ESTABLISHED);
    EXPECT_EQ (server_flow.state, TcpFlow::State::ESTABLISHED);

    client_flow.update(server_segment_1_packet);
    server_flow.update(server_segment_1_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::ESTABLISHED);
    EXPECT_EQ (server_flow.state, TcpFlow::State::ESTABLISHED);

    client_flow.update(client_ack_1_packet);
    server_flow.update(client_ack_1_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::ESTABLISHED);
    EXPECT_EQ (server_flow.state, TcpFlow::State::ESTABLISHED);

    client_flow.update(client_fin_packet);
    server_flow.update(client_fin_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::FIN_WAIT_1);
    EXPECT_EQ (server_flow.state, TcpFlow::State::CLOSE_WAIT);

    client_flow.update(server_ack_2_packet);
    server_flow.update(server_ack_2_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::FIN_WAIT_2);
    EXPECT_EQ (server_flow.state, TcpFlow::State::CLOSE_WAIT);

    client_flow.update(server_fin_packet);
    server_flow.update(server_fin_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::TIME_WAIT);
    EXPECT_EQ (server_flow.state, TcpFlow::State::LAST_ACK);

    client_flow.update(client_ack_2_packet);
    server_flow.update(client_ack_2_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::TIME_WAIT);
    EXPECT_EQ (server_flow.state, TcpFlow::State::CLOSED2);
}


TEST(TcpFlow, ECN_CWR_handshake_state)
{
    // This test checks TCP states
    // at various stages during the handshake with flags ECN/CWR:
    // 1.) client -> server: SYN + ECN + CWR
    // 2.) server -> client: SYN + ACK + ECN
    // 3.) client -> server: ACK

    //Arrange
    // Happy path setup
    std::string ip0 = "10.1.33.81";
    std::string ip1 = "10.1.33.82";
    auto client_ip = ip0;
    auto server_ip = ip1;
    uint16_t client_port = 1337;
    uint16_t server_port = 80;
    uint8_t protocol = IPPROTO_TCP;
    auto client_5t = Tuple::FiveTuple{client_ip, client_port, server_ip, server_port, protocol};
    auto server_5t = Tuple::FiveTuple{server_ip, server_port, client_ip, client_port, protocol};
    auto client_flow = TcpFlow(client_5t);
    auto server_flow = TcpFlow(server_5t);
    server_flow.state = TcpFlow::LISTEN;
    auto client_ip_pdu = Tins::IP(server_ip, client_ip); // client -> server
    auto server_ip_pdu = Tins::IP(client_ip, server_ip); // server -> client
    auto client_initial_seq = 1000;
    auto server_initial_seq = 2000;

    auto syn = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    syn.set_flag(Tins::TCP::SYN, 1);
    syn.set_flag(Tins::TCP::Flags::ECE, 1);
    syn.set_flag(Tins::TCP::CWR, 1);
    syn.seq(client_initial_seq);
    syn.ack_seq(0);
    Tins::Packet syn_packet(client_ip_pdu / syn);

    auto synack = Tins::TCP(server_5t.destination_port, server_5t.source_port);
    synack.set_flag(Tins::TCP::SYN, 1);
    synack.set_flag(Tins::TCP::ACK, 1);
    synack.set_flag(Tins::TCP::ECE, 1);
    synack.seq(server_initial_seq);
    synack.ack_seq(client_initial_seq + 1);
    Tins::Packet synack_packet(server_ip_pdu / synack);

    auto ack = Tins::TCP(client_5t.destination_port, client_5t.source_port);
    ack.set_flag(Tins::TCP::ACK, 1);
    ack.seq(client_initial_seq + 1);
    ack.ack_seq(server_initial_seq + 1);
    Tins::Packet ack_packet(client_ip_pdu / ack);

    // Act & Assert
    EXPECT_EQ (client_flow.state, TcpFlow::State::CLOSED1);
    EXPECT_EQ (server_flow.state, TcpFlow::State::LISTEN);

    client_flow.update(syn_packet);
    server_flow.update(syn_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::SYN_SENT);
    EXPECT_EQ (server_flow.state, TcpFlow::State::SYN_RECEIVED);

    client_flow.update(synack_packet);
    server_flow.update(synack_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::ESTABLISHED);
    EXPECT_EQ (server_flow.state, TcpFlow::State::SYN_RECEIVED);

    client_flow.update(ack_packet);
    server_flow.update(ack_packet);
    EXPECT_EQ (client_flow.state, TcpFlow::State::ESTABLISHED);
    EXPECT_EQ (server_flow.state, TcpFlow::State::ESTABLISHED);

}
