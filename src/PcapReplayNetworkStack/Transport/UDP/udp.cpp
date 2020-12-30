#include <TCPIPNetworkStack/Application/dynamic_application.h>
#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

void PcapReplayNetworkStack::preprocess_pcap_packets_udp(std::vector<Tins::Packet> &_packets)
{
    // Init listening_udp_ports
    // Define: listening port = destination ports that this stack receives
    std::vector<uint16_t> client_ports{};
    std::vector<uint16_t> remote_client_ports{};
    std::vector<std::pair<uint16_t, uint16_t >> port_pairs{};
    for (int i=0; i < _packets.size(); i++)
    {
        std::string sip;
        std::string dip;
        Tins::PDU *packet = _packets[i].pdu()->find_pdu<Tins::IP>();
        if (packet != nullptr)
        {
            sip = ((Tins::IP *)packet)->src_addr().to_string();
            dip = ((Tins::IP *)packet)->dst_addr().to_string();
        }
        else
        {
            packet = _packets[i].pdu()->find_pdu<Tins::IPv6>();
            sip = ((Tins::IPv6 *)packet)->src_addr().to_string();
            dip = ((Tins::IPv6 *)packet)->dst_addr().to_string();
        }

        auto *payload = packet->inner_pdu();
        if (payload->pdu_type() == Tins::PDU::UDP)
        {
            auto *udp = (Tins::UDP *) payload;
            std::pair<uint16_t, uint16_t> p1 = std::make_pair<uint16_t, uint16_t>(udp->sport(), udp->dport());
            std::pair<uint16_t, uint16_t> p2 = std::make_pair<uint16_t, uint16_t>(udp->dport(), udp->sport());
            if(!(   (std::find(port_pairs.begin(), port_pairs.end(), p1) != port_pairs.end()) ||
                    (std::find(port_pairs.begin(), port_pairs.end(), p2) != port_pairs.end()) ))
            {
                // port_pairs does not contain p1 or p2
                // Therefore _packets[i] is the first packet associated with this stream (if _packets[i] is to or from us)

                if (is_tx_packet(i)) // packet is from us
                {
                    // We are the client
                    port_pairs.push_back(p1);
                    uint16_t sport = udp->sport();
                    if(std::find(client_ports.begin(), client_ports.end(), sport) == client_ports.end())
                    {
                        // client_ports does not contain sport
                        client_ports.push_back(sport);
                    }

                    uint16_t dport = udp->dport();
                    std::pair<std::string, uint16_t> remote_addr(dip, dport);
                    if(std::find(remote_client_ports.begin(), remote_client_ports.end(), dport) != remote_client_ports.end())
                    {
                        // remote_client_ports does contain dport
                        if(std::find(remote_listening_udp_client_ports.begin(), remote_listening_udp_client_ports.end(), remote_addr) == remote_listening_udp_client_ports.end())
                        {
                            // remote_listening_udp_client_ports does not contain remote_addr
                            remote_listening_udp_client_ports.push_back(remote_addr);
                        }
                    }
                    else if(std::find(remote_listening_udp_ports.begin(), remote_listening_udp_ports.end(), remote_addr) == remote_listening_udp_ports.end())
                    {
                        // remote_listening_udp_ports does not contain remote_addr
                        remote_listening_udp_ports.push_back(remote_addr);
                    }
                }
                else if (is_rx_packet(i)) // packet is to us
                {
                    // We are the server
                    port_pairs.push_back(p1);

                    uint16_t sport = udp->sport();
                    if(std::find(remote_client_ports.begin(), remote_client_ports.end(), sport) == remote_client_ports.end())
                    {
                        // remote_client_ports does not contain sport
                        remote_client_ports.push_back(sport);
                    }

                    uint16_t dport = udp->dport();
                    if(std::find(client_ports.begin(), client_ports.end(), dport) != client_ports.end())
                    {
                        // client_ports does contain dport
                        if(std::find(listening_udp_client_ports.begin(), listening_udp_client_ports.end(), dport) == listening_udp_client_ports.end())
                        {
                            // listening_udp_client_ports does not contain dport
                            listening_udp_client_ports.push_back(dport);
                        }
                    }
                    else if(std::find(listening_udp_ports.begin(), listening_udp_ports.end(), dport) == listening_udp_ports.end())
                    {
                        // listening_udp_ports does not contain dport
                        listening_udp_ports.push_back(dport);
                    }
                }
                else // packet was not from us or to us.
                    continue;
            }
        }
    }
}

void PcapReplayNetworkStack::process_next_original_packet_udp(Tins::Packet packet)
{}

void PcapReplayNetworkStack::rewrite_packet_udp(Tins::Packet &packet)
{
    //TODO: Merge rewrite_packet_udp and the first part of rewrite_packet_tcp into rewrite_packet_transport ?

    auto &udp = packet.pdu()->rfind_pdu<Tins::UDP>();

    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet); // server_ip and client_ip are the simulated/replayed IPs
    fivetuple->source_ip = convert_ip_address(fivetuple->source_ip, false);
    fivetuple->destination_ip = convert_ip_address(fivetuple->destination_ip, false);
    Tuple::ClientServerFiveTuple original_cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple, true);
    std::unique_ptr<Tuple::ClientServerFourTuple> original_cs4t = Tuple::ClientServerFiveTuple_to_ClientServerFourTuple(original_cs5t);
    Tuple::ClientServerFourTuple replayed_cs4t = convert_ClientServerFourTuple(*original_cs4t, true);
    std::unique_ptr<Tuple::ClientServerFiveTuple> replayed_cs5t = Tuple::ClientServerFourTuple_to_ClientServerFiveTuple(replayed_cs4t); // client_port is the default value
    bool is_server = replayed_cs5t->server_ip == netdev.ip_address;
    auto *original_connection = (UdpConnection *)original_connection_table.lookup(original_cs5t);
    UdpConnection * replayed_connection = (UdpConnection *)convert_Connection(original_connection, true);
    if (replayed_connection == nullptr)
    {
        assert(!is_server);

        std::pair<std::string, uint16_t> original_server_addr = std::pair(original_cs5t.server_ip, original_cs5t.server_port);
        if(std::find(remote_listening_udp_client_ports.begin(), remote_listening_udp_client_ports.end(), original_server_addr) != remote_listening_udp_client_ports.end())
        {
            // remote_listening_udp_client_ports contains original_server_addr

            // Is all this equivalent to ?:
            // Connection *original_request_connection = convert_connection_to_request_connection(original_connection, original_connection_table)

            // Assumes that original_cs5t.server_port is not reused (appears as client port in exactly 1 stream / "connection")
            Connection *original_request_connection = nullptr;
            Tuple::ClientServerFiveTuple original_request_cs5t;
            original_request_cs5t.client_ip = original_cs5t.server_ip;
            original_request_cs5t.client_port = original_cs5t.server_port;
            original_request_cs5t.server_ip = original_cs5t.client_ip;
            original_request_cs5t.protocol = IPPROTO_UDP;
            for (auto listening_port : listening_udp_ports)
            {
                original_request_cs5t.server_port = listening_port;
                original_request_connection = original_connection_table.lookup(original_request_cs5t);
                if (original_request_connection == nullptr)
                    continue;
            }
            assert(original_request_connection != nullptr);
            Connection *replayed_request_connection = convert_Connection(original_request_connection, true);
            assert(replayed_request_connection != nullptr);
            replayed_cs5t->server_port = replayed_request_connection->client_port();
        }

        while (true)
        {
            replayed_cs5t->client_port = (rand() % (65535 - 1024)) + 1024;
            if(std::find(listening_udp_ports.begin(), listening_udp_ports.end(), replayed_cs5t->client_port) == listening_udp_ports.end() && // the potential client_port is not a listening port
               connection_table.lookup(*replayed_cs5t) == nullptr) // the potential client_port is currently not in use
            {
                break;
            }
        }
    }
    else
    {
        replayed_cs5t->client_port = replayed_connection->client_port();
        replayed_cs5t->server_port = replayed_connection->server_port();
    }

    if (!is_server)
    {
        if (config.modify_udp_dport_if_client)
            udp.dport(replayed_cs5t->server_port);
        else
            replayed_cs5t->server_port = udp.dport();

        if (config.modify_udp_sport_if_client)
            udp.sport(replayed_cs5t->client_port);
        else
            replayed_cs5t->client_port = udp.sport();
    }
    else
    {
        if (config.modify_udp_sport_if_server)
            udp.sport(replayed_cs5t->server_port);
        else
            replayed_cs5t->server_port = udp.sport();

        if (config.modify_udp_dport_if_server)
            udp.dport(replayed_connection->client_port());
    }

    auto *connection = (UdpConnection *)connection_table.lookup(*replayed_cs5t);
    if (connection == nullptr)
    {
        connection = new UdpConnection(*replayed_cs5t);
        if (!config.tx_event_udp_application)
            connection->disable_application_processing();
        connection_table.add(connection);
        set_application_types(connection, false);
    }

    // Edit UDP checksum
    ; // libtins will recalculate the UDP checksum upon serialization before putting the packet on the wire.
    ; // Will need to fork libtins for incremental checksums (to maintain incorrect checksums if desired)

    if (config.modify_udp_data)
    {
        auto *complete_original_connection = (UdpConnection *)convert_Connection_to_complete_original(original_connection, true);
        refresh_rewrite_map_application(complete_original_connection);
        auto &rewrite_map = udp_rewrite_maps[complete_original_connection];

        auto datagram_number = is_server ? connection->server_flow().local_datagram_count() : connection->client_flow().local_datagram_count();
        auto *raw = udp.find_pdu<Tins::RawPDU>();
        if (raw != nullptr && !raw->payload().empty())
        {
            auto &raw_payload = raw->payload();
            auto raw_size = raw_payload.size();
            for( auto const& [key, val] : rewrite_map )
            {
                auto dn = std::get<0>(key);
                auto offset = std::get<1>(key);
                auto len = std::get<2>(key);
                assert(val.first.size() == len); // enforce the relationship between the length to replace (key[2]) and old bytes to replace (val.first)
                if (!config.modify_udp_data_allow_shrinkage)
                {
                    assert(val.first.size() <= val.second.size());
                }
                if (!config.modify_udp_data_allow_growth)
                {
                    assert(val.first.size() >= val.second.size());
                }
                if (dn == datagram_number && offset + len <= raw_size)
                {
                    if (std::vector<uint8_t>(raw_payload.begin() + offset, raw_payload.begin() + offset + len) == val.first)
                    {
                        raw_payload.erase(raw_payload.begin() + offset, raw_payload.begin() + offset + len);
                        raw_payload.insert(raw_payload.begin() + offset, val.second.begin(), val.second.end());
                    }
                }
            }
        }
    }
}

void PcapReplayNetworkStack::handle_udp(Tins::Packet &packet)
{
    auto old_table_size = connection_table.all()->size();
    TCPIPNetworkStack::handle_udp(packet);
    auto new_table_size = connection_table.all()->size();
    if (new_table_size > old_table_size)
    {
        std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
        Tuple::ClientServerFiveTuple cs5t = TCPIPNetworkStack::FiveTuple_to_ClientServerFiveTuple(*fivetuple);
        auto *connection = connection_table.lookup(cs5t);
        assert(connection != nullptr);
        if (!config.tx_event_udp_application)
            connection->disable_application_processing();
        if (config.tx_event_udp_application)
            set_application_types(connection, false);
    }
}
