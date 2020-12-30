#include "TCPIPNetworkStack/Transport/UDP/udp_connection.h"

UdpConnection::UdpConnection(const Tuple::ClientServerFiveTuple& cs5t) :
        Connection(cs5t),
        _client_flow(ClientServerFiveTuple_to_FiveTuple(cs5t, false)),
        _server_flow(ClientServerFiveTuple_to_FiveTuple(cs5t, true))
{}
