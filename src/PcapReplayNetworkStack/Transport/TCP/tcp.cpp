#include <iostream>
#include <cassert>
#include <random>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "TCPIPNetworkStack/Transport/TCP/tcp_reassembler.h"
#include "TCPIPNetworkStack/Application/dynamic_application.h"

using std::pair;

void PcapReplayNetworkStack::preprocess_pcap_packets_tcp(std::vector<Tins::Packet> &_packets)
{
    // Init listening_tcp_ports
    // Define: listening port = destination ports that receive segments with the tcp SYN flag set and no ACK flag
    // OR       destination ports that receive segments with a previously unseen 5tuple
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
        if (payload->pdu_type() == Tins::PDU::TCP)
        {
            auto tcp = (Tins::TCP *) payload;
            // listening port definition #1
            if (is_tx_packet(i)) // packet is from us
            {
                ;
            }
            else if (is_rx_packet(i)) // packet is to us
            {
                uint16_t dport = tcp->dport();
                if (tcp->flags() & Tins::TCP::SYN && !(tcp->flags() & Tins::TCP::ACK)) // SYN
                    listening_tcp_ports.push_back(dport);
            }
            else
            {
                uint16_t dport = tcp->dport();
                if (tcp->flags() & Tins::TCP::SYN && !(tcp->flags() & Tins::TCP::ACK)) // SYN
                {
                    std::pair<std::string, uint16_t> p(dip, dport);
                    if(std::find(remote_listening_tcp_ports.begin(), remote_listening_tcp_ports.end(), p) == remote_listening_tcp_ports.end())
                    {
                        // remote_listening_tcp_ports doesnt contain p
                        remote_listening_tcp_ports.push_back(p);
                    }
                }
            }
        }
    }


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
        if (payload->pdu_type() == Tins::PDU::TCP)
        {
            auto tcp = (Tins::TCP *) payload;

            // listening port definition #2. This is separated from #1 for cleanness ; not ready to merge both yet
            std::pair<uint16_t, uint16_t> p1 = std::make_pair<uint16_t, uint16_t>(tcp->sport(), tcp->dport());
            std::pair<uint16_t, uint16_t> p2 = std::make_pair<uint16_t, uint16_t>(tcp->dport(), tcp->sport());
            if (!((std::find(port_pairs.begin(), port_pairs.end(), p1) != port_pairs.end()) ||
                  (std::find(port_pairs.begin(), port_pairs.end(), p2) != port_pairs.end())))
            {
                // port_pairs does not contain p1 or p2
                // Therefore _packets[i] is the first packet associated with this stream (if _packets[i] is to or from us)

                if (is_tx_packet(i)) // packet is from us
                {
                    // We are the client
                    port_pairs.push_back(p1);
                }
                else if (is_rx_packet(i)) // packet is to us
                {
                    // We are the server
                    port_pairs.push_back(p1);
                    uint16_t dport = tcp->dport();
                    uint16_t sport = tcp->sport();
                    std::pair<std::string, uint16_t> source_pair(sip, sport);
                    if (std::find(listening_tcp_ports.begin(), listening_tcp_ports.end(), dport) == listening_tcp_ports.end() &&
                        std::find(remote_listening_tcp_ports.begin(), remote_listening_tcp_ports.end(), source_pair) != remote_listening_tcp_ports.end() ) // source is the server
                    {
                        // listening_tcp_ports does not contain dport
                        listening_tcp_ports.push_back(dport);
                    }
                }
            }
        }
    }
}

void PcapReplayNetworkStack::process_next_original_packet_tcp(Tins::Packet packet)
{}

void PcapReplayNetworkStack::rewrite_packet_tcp(Tins::Packet &packet)
{
    auto &tcp = packet.pdu()->rfind_pdu<Tins::TCP>();

    std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet); // server_ip and client_ip are the simulated/replayed IPs
    fivetuple->source_ip = convert_ip_address(fivetuple->source_ip, false);
    fivetuple->destination_ip = convert_ip_address(fivetuple->destination_ip, false);
    Tuple::ClientServerFiveTuple original_cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple, true);
    std::unique_ptr<Tuple::ClientServerFourTuple> original_cs4t = Tuple::ClientServerFiveTuple_to_ClientServerFourTuple(original_cs5t);
    Tuple::ClientServerFourTuple replayed_cs4t = convert_ClientServerFourTuple(*original_cs4t, true);
    std::unique_ptr<Tuple::ClientServerFiveTuple> replayed_cs5t = Tuple::ClientServerFourTuple_to_ClientServerFiveTuple(replayed_cs4t); // client_port is the default value
    bool is_server = replayed_cs5t->server_ip == netdev.ip_address;
    auto *original_connection = (TcpConnection *)original_connection_table.lookup(original_cs5t);
    TcpConnection * replayed_connection = (TcpConnection *)convert_Connection(original_connection, true);
    if (replayed_connection == nullptr)
    {
        // Can no longer make this assumption since some pcaps will have a TCP server sending a client a RST without any prior segments between the server and client
//        assert(!is_server);
        if (is_server)
            std::cout << "[!]\tWarning: assert(!is_server) failed. (PcapReplayNetworkStack::rewrite_packet_tcp)" << std::endl;

        while (true)
        {
            replayed_cs5t->client_port = (rand() % (65535 - 1024)) + 1024;
            if(std::find(listening_tcp_ports.begin(), listening_tcp_ports.end(), replayed_cs5t->client_port) == listening_tcp_ports.end() && // the potential client_port is not a listening port
                connection_table.lookup(*replayed_cs5t) == nullptr) // the potential client_port is currently not in use
            {
                break;
            }
        }
    }
    else
        replayed_cs5t->client_port = replayed_connection->client_port();

    if (!is_server)
    {
        if (config.modify_tcp_sport_if_client)
            tcp.sport(replayed_cs5t->client_port);
        else
            replayed_cs5t->client_port = tcp.sport();
    }
    if (is_server && config.modify_tcp_dport_if_server)
    {
        if (replayed_connection == nullptr)
        {
            // some pcaps contains a single RST for a connection that is not present in the connection. When this happens the Warning a few lines up will be hit.
            if (config.modify_tcp_sport_if_client)
                tcp.dport(replayed_cs5t->client_port);
            else
                replayed_cs5t->client_port = tcp.dport();
        }
        else
        {
            tcp.dport(replayed_connection->client_port());
        }
    }

    auto *connection = (TcpConnection *)connection_table.lookup(*replayed_cs5t);
    if (connection == nullptr)
    {
        connection = new TcpConnection(*replayed_cs5t);
        if (!config.tx_event_tcp_application)
            connection->disable_application_processing();
        connection_table.add(connection);
        set_application_types(connection, false);
    }

    // TODO: Edit TCP SEQ (optional for all cases?)
    ;

    if (config.modify_ack_2)
    {
        // TODO: replace this is TCB vars (SND_NXT, etc..)
        uint32_t ack = 0;
        bool initiated = is_server ?
                (connection->server_flow().state != TcpFlow::CLOSED1 && connection->server_flow().state != TcpFlow::LISTEN) :
                (connection->client_flow().state != TcpFlow::CLOSED1 && connection->client_flow().state != TcpFlow::SYN_SENT);
        if (initiated)
        {
            uint32_t remote_init_seq = is_server ? connection->server_flow().IRS : connection->client_flow().IRS;
            uint32_t bytes_received = is_server ? connection->client_payload().size() : connection->server_payload().size();
            // Can I handle the case where the client initiates the connection termination?
            bool fin_recv = (connection->server_flow().state == TcpFlow::CLOSING || connection->server_flow().state == TcpFlow::TIME_WAIT) ||
                            (connection->client_flow().state == TcpFlow::CLOSE_WAIT || connection->client_flow().state == TcpFlow::LAST_ACK);
            ack = remote_init_seq + 1 + bytes_received + (int)fin_recv;
        }
        tcp.ack_seq(ack);
    }

    if (config.modify_tcp_timestamps)
    {
        // Enabling will breaking Evasions that relay on PAWS. How to not do so? Maybe keep sudden changes in TS value
        const Tins::TCP::option *ts_opt = tcp.search_option(Tins::TCP::TSOPT);
        if (ts_opt != nullptr) // the packet we're sending has a TCP TimeStamp option
        {
            uint32_t tsval = ts_opt->to<pair<uint32_t, uint32_t>>().first;
            uint32_t tsecr = 0;
            if (is_server ? connection->server_flow().remote_timestamps : connection->client_flow().remote_timestamps)
                tsecr = is_server ? connection->server_flow().remote_tsval : connection->client_flow().remote_tsval;
            uint64_t buffer = (uint64_t(tsval) << 32) | tsecr;
            buffer = Tins::Endian::host_to_be(buffer);
            std::memcpy((void *) (ts_opt->data_ptr()), &buffer, 8);
        }
    }

    // Edit TCP checksum
    ; // libtins will recalculate the TCP checksum upon serialization before putting the packet on the wire.
    ; // Will need to fork libtins for incremental checksums (to maintain incorrect checksums if desired)

    if (config.modify_tcp_data)
    {
        auto *complete_original_connection = (TcpConnection *)convert_Connection_to_complete_original(original_connection, true);
        refresh_rewrite_map_application(complete_original_connection);
        auto &rewrite_map = tcp_rewrite_maps[complete_original_connection];

        uint32_t seq_adjustment = 0;

        if (config.modify_seq)
        {
            if ((is_server ? connection->server_flow().state : connection->client_flow().state) >= TcpFlow::ESTABLISHED)
            {
                uint32_t rel_seq = tcp.seq() - (is_server ? connection->server_flow().ISS : connection->client_flow().ISS);
                auto adjusted_rel_seq = rel_seq;
                // assumes no overlap across maps
                for( auto const& [key, val] : rewrite_map )
                {
                    auto offset = std::get<0>(key);
                    if (offset < rel_seq)
                    {
                        adjusted_rel_seq += val.second.size() - val.first.size(); // every change in size for segments before rel_seq will cause us to adjust
                    }
                }
                seq_adjustment = adjusted_rel_seq - rel_seq;
                tcp.seq(tcp.seq() + seq_adjustment);
            }
        }

        auto *raw = tcp.find_pdu<Tins::RawPDU>();
        if (raw != nullptr && !raw->payload().empty())
        {
            auto &raw_payload = raw->payload();
            uint32_t rel_seq = tcp.seq() - (is_server ? connection->server_flow().ISS : connection->client_flow().ISS);

            std::vector<std::pair<uint32_t, uint32_t>> adjustments{}; // (rel seq, change in size)

            for( auto const& [key, val] : rewrite_map )
            {
                auto offset = std::get<0>(key);
                auto adjusted_offset = seq_adjustment + offset;
                for (auto &p : adjustments)
                {
                    if (offset > p.first)
                    {
                        adjusted_offset += p.second;
                    }
                }
                auto len = std::get<1>(key);
                assert(val.first.size() == len); // enforce the relationship between the length to replace (key[1]) and old bytes to replace (val.first)
                if (!config.modify_tcp_data_allow_shrinkage)
                {
                    assert(val.first.size() <= val.second.size());
                }
                if (!config.modify_tcp_data_allow_growth)
                {
                    assert(val.first.size() >= val.second.size());
                }
                if (rel_seq <= adjusted_offset && adjusted_offset + len <= rel_seq + raw_payload.size())
                {
                    if (std::vector<uint8_t>(raw_payload.begin() + (adjusted_offset-rel_seq), raw_payload.begin() + (adjusted_offset-rel_seq) + len) == val.first)
                    {
                        raw_payload.erase(raw_payload.begin() + (adjusted_offset-rel_seq), raw_payload.begin() + (adjusted_offset-rel_seq) + len);
                        raw_payload.insert(raw_payload.begin() + (adjusted_offset-rel_seq), val.second.begin(), val.second.end());
                        adjustments.emplace_back(offset, val.second.size() - val.first.size());
                    }
                }
            }
        }
    }
}

bool PcapReplayNetworkStack::any_unexpected_resets()
{
    std::vector<Connection *> *connections = connection_table.all();
    for (auto connection : *connections)
    {
        if (connection->protocol() == IPPROTO_TCP)
        {
            auto *tcp_connection = (TcpConnection *)connection;
            auto *complete_original_connection = (TcpConnection *)convert_Connection_to_complete_original(connection, false);
            if (complete_original_connection == nullptr)
                continue;
            bool is_server = tcp_connection->server_ip() == netdev.ip_address;
            auto original_rst_count = is_server ? complete_original_connection->server_flow().remote_rst_count : complete_original_connection->client_flow().remote_rst_count;
            auto rst_count = is_server ? tcp_connection->server_flow().remote_rst_count : tcp_connection->client_flow().remote_rst_count;
            if (rst_count > original_rst_count)
            {
                std::cout << "[+]\tUnexpected connection reset"<< std::endl;
                return true;
            }
        }
    }
    delete connections;
    return false;
}

// TODO: make this compatible with modify_tcp_data
bool PcapReplayNetworkStack::any_unexpected_fins()
{
    std::vector<Connection *> *connections = connection_table.all();
    for (auto connection : *connections)
    {
        if (connection->protocol() == IPPROTO_TCP)
        {
            auto *tcp_connection = (TcpConnection *) connection;
            auto *original_connection = (TcpConnection *) convert_Connection(tcp_connection, false);
            bool is_server = tcp_connection->server_ip() == netdev.ip_address;
            bool fin_recv;
            if (is_server)
            {
                fin_recv =  tcp_connection->server_flow().state == TcpFlow::CLOSING ||
                            tcp_connection->server_flow().state == TcpFlow::TIME_WAIT ||
                            tcp_connection->server_flow().state == TcpFlow::CLOSE_WAIT ||
                            tcp_connection->server_flow().state == TcpFlow::LAST_ACK;
            }
            else
            {
                fin_recv =  tcp_connection->client_flow().state == TcpFlow::CLOSING ||
                            tcp_connection->client_flow().state == TcpFlow::TIME_WAIT ||
                            tcp_connection->client_flow().state == TcpFlow::CLOSE_WAIT ||
                            tcp_connection->client_flow().state == TcpFlow::LAST_ACK;
            }

            if (fin_recv && !received_expected_transport_data(original_connection, !is_server))
            {
                std::cout << "[+]\tUnexpected connection teardown"<< std::endl;
                return true;
            }
        }
    }
    delete connections;
    return false;
}

bool PcapReplayNetworkStack::exit_tx_loop_early_tcp()
{
    if (config.stop_on_unexpected_rst && any_unexpected_resets()) return true;
    if (config.stop_on_unexpected_fin && any_unexpected_fins()) return true;
    return false;
}

void PcapReplayNetworkStack::handle_tcp_connection_attempt(Tins::Packet &packet, TcpConnection &connection)
{
    // if we should let TCPIPNetworkStack handle connection attempts, then ...
//    TCPIPNetworkStack::handle_connection_attempt(packet, connection);
}

void PcapReplayNetworkStack::handle_tcp_data_ack(Tins::Packet &packet, TcpConnection &connection)
{
    // if we should let TCPIPNetworkStack handle acknowlegemnets , then ...
//    TCPIPNetworkStack::handle_tcp_data_ack(packet, connection);
}

void PcapReplayNetworkStack::handle_tcp_connection_termination(Tins::Packet &packet, TcpConnection &connection)
{
    // if we should let TCPIPNetworkStack handle acknowlegemnets , then ...
//    TCPIPNetworkStack::handle_tcp_data_ack(packet, connection);
}

void PcapReplayNetworkStack::handle_tcp(Tins::Packet &packet)
{
    auto old_table_size = connection_table.all()->size();
    TCPIPNetworkStack::handle_tcp(packet);
    auto new_table_size = connection_table.all()->size();
    if (new_table_size > old_table_size)
    {
        std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
        Tuple::ClientServerFiveTuple cs5t = TCPIPNetworkStack::FiveTuple_to_ClientServerFiveTuple(*fivetuple);
        auto *connection = connection_table.lookup(cs5t);
        assert(connection != nullptr);
        if (!config.tx_event_tcp_application)
            connection->disable_application_processing();
        if (config.tx_event_tcp_application)
            set_application_types(connection, false);
    }
}
