#include <TCPIPNetworkStack/Application/dynamic_application.h>
#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "utils.h"

void PcapReplayNetworkStack::preprocess_pcap_packets_transport(std::vector<Tins::Packet> &_packets)
{
    preprocess_pcap_packets_udp(_packets);
    preprocess_pcap_packets_tcp(_packets);

    // Keep track of connections in the original pcap so that we can reference the complete picture if needed
    for (auto & packet : _packets)
    {
        std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
        if (fivetuple == nullptr) // No (supported) Transport present
            continue;
        Tuple::ClientServerFiveTuple cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple, true);
        auto *connection = complete_original_connection_table.lookup(cs5t);
        if (connection == nullptr)
        {
            switch (cs5t.protocol)
            {
                case IPPROTO_UDP:
                    connection = new UdpConnection(cs5t);
                    if (!config.tx_event_udp_application)
                        connection->disable_application_processing();
                    break;
                case IPPROTO_TCP:
                    connection = new TcpConnection(cs5t);
                    if (!config.tx_event_tcp_application)
                        connection->disable_application_processing();
                    break;
                default:
                    std::cout << "[!]\tWhat in tarnation? (unknown transport protocol)" << std::endl;
                    exit(1);
            }
            complete_original_connection_table.add(connection);
        }
        connection->update(packet);
    }

    if (config.tx_event_tcp_application || config.tx_event_udp_application)
        preprocess_pcap_packets_application();
}

void PcapReplayNetworkStack::process_next_original_packet_transport(Tins::Packet packet)
{
    // Keep track of connections in the original pcap as the pcap is replayed
    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
    if (fivetuple == nullptr) // No (supported) Transport
        return;
    Tuple::ClientServerFiveTuple cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple, true);
    auto *connection = original_connection_table.lookup(cs5t);
    if (connection == nullptr)
    {
        switch (cs5t.protocol)
        {
            case IPPROTO_UDP:
                connection = new UdpConnection(cs5t);
                if (!config.tx_event_udp_application)
                    connection->disable_application_processing();
                break;
            case IPPROTO_TCP:
                connection = new TcpConnection(cs5t);
                if (!config.tx_event_tcp_application)
                    connection->disable_application_processing();
                break;
            default:
                std::cout << "[!]\tWhat in tarnation? (unknown transport protocol)" << std::endl;
                exit(1);
        }
        original_connection_table.add(connection);
        set_application_types(connection, true);
    }
    connection->update(packet);

    switch (cs5t.protocol)
    {
        case IPPROTO_UDP:
            process_next_original_packet_udp(packet);
            break;
        case IPPROTO_TCP:
            process_next_original_packet_tcp(packet);
            break;
        default:
            std::cout << "[!]\tWhat in tarnation? (unknown transport protocol)" << std::endl;
            exit(1);
    }
}

void PcapReplayNetworkStack::update_output_transport(Tins::Packet &packet)
{
    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet); // server_ip and client_ip are the simulated/replayed IPs
    if (fivetuple == nullptr) // No (supported) Transport
        return;
    Tuple::ClientServerFiveTuple cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple, false);
    Connection *connection = connection_table.lookup(cs5t);
    connection->update(packet);
}
