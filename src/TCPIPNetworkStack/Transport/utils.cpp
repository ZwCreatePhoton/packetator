#include <iostream>
#include "TCPIPNetworkStack/tcp_ip_network_stack.h"

bool TCPIPNetworkStack::is_source_server(const Tuple::FiveTuple& ft)
{
    bool source_is_server;
    auto &listening_ports = ft.protocol == IPPROTO_TCP ? listening_tcp_ports : listening_udp_ports;
    if (ft.source_ip == netdev.ip_address)
    {
        // we are the source
        bool sport_is_listening = std::find(listening_ports.begin(), listening_ports.end(), ft.source_port) != listening_ports.end();
        source_is_server = sport_is_listening;
    }
    else if (ft.destination_ip == netdev.ip_address)
    {
        // we are the destination
        bool dport_is_listening = std::find(listening_ports.begin(), listening_ports.end(), ft.destination_port) != listening_ports.end();
        source_is_server = !dport_is_listening;
    }
    else
    {
        std::cout << "[!]\tFatal. Dont have enough information to construct ClientServerFourTuple" << std::endl;
        exit(1);
    }
    return source_is_server;
}

Tuple::ClientServerFiveTuple TCPIPNetworkStack::FiveTuple_to_ClientServerFiveTuple(const Tuple::FiveTuple& ft)
{
    bool source_is_server = is_source_server(ft);
    return Tuple::FiveTuple_to_ClientServerFiveTuple(ft, source_is_server);
}