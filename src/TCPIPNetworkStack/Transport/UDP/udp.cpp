#include <TCPIPNetworkStack/Application/dynamic_application.h>
#include "TCPIPNetworkStack/tcp_ip_network_stack.h"

void TCPIPNetworkStack::handle_udp(Tins::Packet &packet)
{
    auto &udp = packet.pdu()->rfind_pdu<Tins::UDP>();

    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
    Tuple::ClientServerFiveTuple cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple);
    auto * connection = (UdpConnection *)connection_table.lookup(cs5t);
    if (connection == nullptr)
    {
        connection = new UdpConnection(cs5t); //TODO: handle this memory leak
        connection_table.add(connection);
    }
    connection->update(packet);
}
