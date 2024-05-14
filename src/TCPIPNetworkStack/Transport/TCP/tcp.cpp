#include <TCPIPNetworkStack/Transport/tuple.h>
#include <TCPIPNetworkStack/Transport/TCP/tcp_connection.h>
#include <TCPIPNetworkStack/Application/dynamic_application.h>
#include "TCPIPNetworkStack/tcp_ip_network_stack.h"

void TCPIPNetworkStack::handle_tcp(Tins::Packet &packet)
{
    auto &tcp = packet.pdu()->rfind_pdu<Tins::TCP>();

    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
    Tuple::ClientServerFiveTuple cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple);
    auto * connection = (TcpConnection *)connection_table.lookup(cs5t);
    if (connection == nullptr)
    {
        // Only create connections for SYN packets
        // TODO: Need to also add a check for if there is an application with a socket open on the destination port
        if ( tcp.flags() & Tins::TCP::SYN )
        {
            connection = new TcpConnection(cs5t); //TODO: handle this memory leak
            // TODO: lookup the Application to use for the server when we are listening on tcp.dst_port() and use that instead of DynamicApplication
            connection_table.add(connection);
        }
        else
        {
            return;
        }
    }
    connection->update(packet);

    // Handle 3 way handshake
    if (    (tcp.flags() & Tins::TCP::SYN) &&
            (connection->client_flow().state < TcpFlow::ESTABLISHED ||
            connection->server_flow().state < TcpFlow::ESTABLISHED) )
    {
        handle_tcp_connection_attempt(packet, *connection);
    }

    // Handle the acknowledgment of incoming segments
    auto *raw = tcp.find_pdu<Tins::RawPDU>();
    if (raw != nullptr && !raw->payload().empty())
    {
        handle_tcp_data_ack(packet, *connection);
    }

    if ((tcp.flags() & Tins::TCP::FIN))
    {
        handle_tcp_connection_termination(packet, *connection);
    }

}

void TCPIPNetworkStack::handle_tcp_connection_attempt(Tins::Packet &packet, TcpConnection &connection)
{
    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
    auto &tcp = packet.pdu()->rfind_pdu<Tins::TCP>();

    if (tcp.flags() == Tins::TCP::SYN)
    {
        auto &syn_tcp = tcp;

        Tins::TCP synack_tcp(fivetuple->source_port, fivetuple->destination_port);
        synack_tcp.set_flag(Tins::TCP::SYN, 1);
        synack_tcp.set_flag(Tins::TCP::ACK, 1);
        auto seq_number = (rand() % 65535);
        synack_tcp.seq(seq_number + 1);
        synack_tcp.ack_seq(syn_tcp.seq() + 1);
        Tins::Packet synack_packet = packetize(synack_tcp, fivetuple->source_ip, fivetuple->destination_ip);
        connection.update(synack_packet);
        output_packet(synack_packet, fivetuple->source_ip);
    }
    else if (tcp.flags() == (Tins::TCP::SYN | Tins::TCP::ACK))
    {
        auto &synack_tcp = tcp;

        Tins::TCP ack_tcp(fivetuple->source_port, fivetuple->destination_port);
        ack_tcp.set_flag(Tins::TCP::ACK, 1);
        ack_tcp.seq(connection.client_flow().ISS + 1);
        ack_tcp.ack_seq(connection.client_flow().IRS + 1);
        Tins::Packet ack_packet = packetize(ack_tcp, fivetuple->source_ip, fivetuple->destination_ip);
        connection.update(ack_packet);
        output_packet(ack_packet, fivetuple->source_ip);
    }
    else
    {
        ;
    }
}

void TCPIPNetworkStack::handle_tcp_data_ack(Tins::Packet &packet, TcpConnection &connection)
{
    bool is_server = connection.server_ip() == netdev.ip_address;
    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
    auto &tcp = packet.pdu()->rfind_pdu<Tins::TCP>();
    uint32_t seq = is_server ? connection.server_flow().SND_NXT : connection.client_flow().SND_NXT;
    uint32_t ack = is_server ? connection.server_flow().RCV_NXT : connection.client_flow().RCV_NXT;
    Tins::TCP ack_tcp(fivetuple->source_port, fivetuple->destination_port);
    ack_tcp.set_flag(Tins::TCP::ACK, 1);
    ack_tcp.seq(seq);
    ack_tcp.ack_seq(ack);
    Tins::Packet ack_packet = packetize(ack_tcp, fivetuple->source_ip, fivetuple->destination_ip);
    connection.update(ack_packet);
    output_packet(ack_packet, fivetuple->source_ip);
}

void TCPIPNetworkStack::handle_tcp_connection_termination(Tins::Packet &packet, TcpConnection &connection)
{
    bool is_server = connection.server_ip() == netdev.ip_address;
    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
    auto &tcp = packet.pdu()->rfind_pdu<Tins::TCP>();
    uint32_t seq = is_server ? connection.server_flow().SND_NXT : connection.client_flow().SND_NXT;
    uint32_t ack = is_server ? connection.server_flow().RCV_NXT : connection.client_flow().RCV_NXT;
    Tins::TCP ack_tcp(fivetuple->source_port, fivetuple->destination_port);
    ack_tcp.set_flag(Tins::TCP::ACK, 1);
    ack_tcp.seq(seq);
    ack_tcp.ack_seq(ack);
    Tins::Packet ack_packet = packetize(ack_tcp, fivetuple->source_ip, fivetuple->destination_ip);
    connection.update(ack_packet);
    output_packet(ack_packet, fivetuple->source_ip);
}
