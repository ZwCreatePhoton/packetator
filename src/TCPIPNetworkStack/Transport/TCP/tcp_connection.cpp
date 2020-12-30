#include "TCPIPNetworkStack/Transport/TCP/tcp_connection.h"

TcpConnection::TcpConnection(const Tuple::ClientServerFiveTuple &cs5t) :
        Connection(cs5t),
        _client_flow(ClientServerFiveTuple_to_FiveTuple(cs5t, false)),
        _server_flow(ClientServerFiveTuple_to_FiveTuple(cs5t, true))
{
    server_flow().state = TcpFlow::LISTEN;
}

void TcpConnection::update_application(Tins::Packet &packet)
{
    Connection::update_application(packet);

    // Signal to the application that the stream(s) have closed by sending the application a 0 length segment
    if (!client_rx_closed && client_flow().remote_payload_complete())
    {
        client_rx_closed = true;
        client_application().update_rx(empty_segment);
    }
    if (!client_tx_closed && client_flow().local_payload_complete())
    {
        client_tx_closed = true;
        client_application().update_tx(empty_segment);
    }
    if (!server_rx_closed && server_flow().remote_payload_complete())
    {
        server_rx_closed = true;
        server_application().update_rx(empty_segment);
    }
    if (!server_tx_closed && server_flow().local_payload_complete())
    {
        server_tx_closed = true;
        server_application().update_tx(empty_segment);
    }
}
