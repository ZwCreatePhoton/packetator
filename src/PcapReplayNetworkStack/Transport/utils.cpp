#include <iostream>
#include <TCPIPNetworkStack/Application/dynamic_application.h>
#include <TCPIPNetworkStack/Application/ftp_application.h>
#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"


// Hackish
// assumes that ft is a replay ft
bool PcapReplayNetworkStack::is_source_server(const Tuple::FiveTuple& ft)
{
    // ft is a replay ft

    bool source_is_server;
    if (ft.protocol == IPPROTO_TCP)
    {
        if (ft.source_ip == netdev.ip_address)
        {
            // we are the source
            bool sport_is_listening = std::find(listening_tcp_ports.begin(), listening_tcp_ports.end(), ft.source_port) != listening_tcp_ports.end();
            source_is_server = sport_is_listening;
        }
        else if (ft.destination_ip == netdev.ip_address)
        {
            // we are the destination
            bool dport_is_listening = std::find(listening_tcp_ports.begin(), listening_tcp_ports.end(), ft.destination_port) != listening_tcp_ports.end();
            source_is_server = !dport_is_listening;
        }
        else
        {
            assert(false);
        }
    }
    else if (ft.protocol == IPPROTO_UDP)
    {
        bool sport_is_listening;
        bool dport_is_listening;
        if (ft.source_ip == netdev.ip_address)
        {
            // we are the source
            std::pair<std::string, uint16_t> original_destination_addr(convert_ip_address(ft.destination_ip, false), ft.destination_port);
            sport_is_listening = std::find(listening_udp_ports.begin(), listening_udp_ports.end(), ft.source_port) != listening_udp_ports.end();
            dport_is_listening = std::find(remote_listening_udp_ports.begin(), remote_listening_udp_ports.end(), original_destination_addr) != remote_listening_udp_ports.end();
        }
        else if (ft.destination_ip == netdev.ip_address)
        {
            // we are the destination
            std::pair<std::string, uint16_t> original_source_addr(convert_ip_address(ft.source_ip, false), ft.source_port);
            dport_is_listening = std::find(listening_udp_ports.begin(), listening_udp_ports.end(), ft.destination_port) != listening_udp_ports.end();
            sport_is_listening = std::find(remote_listening_udp_ports.begin(), remote_listening_udp_ports.end(), original_source_addr) != remote_listening_udp_ports.end();
        }
        else
        {
            assert(false);
        }
        if (sport_is_listening || dport_is_listening)
        {
            source_is_server = sport_is_listening || !(dport_is_listening);
        }
        else
        {
            // We will assume that we will only land here for TFTP (or similar protocols were the response is sent out of a port different than the TFTP server's listening port)
            // Therefore we expect (and will assume) that FiveTuple, ft, is the FiveTuple for the Connection for the TFTP (or similar protocol) response in this->connection_table
            // Therefore we expect (and will assume) that the Connection for the TFTP (or similar protocol) request is in this->connection_table
            // So the source will be the server (source_is_server = true) when the source is the client in the request

            // This won't work when a client makes 2 requests to a (TFTP) server and reuses the source port

            Connection *request_connection = nullptr;

            auto assume_source_server_cs5t = Tuple::FiveTuple_to_ClientServerFiveTuple(ft, true);
            auto assume_source_not_server_cs5t = Tuple::FiveTuple_to_ClientServerFiveTuple(ft, false);

            // connection might already exist, if it does we'll use the server from the connection's cs5t to determine if the source is the server
            // There is technically a very unlikey edge case that well miss here where there are Connection entries for both assume_source_server_cs5t and assume_source_not_server_cs5t
            auto assume_source_server_connection = connection_table.lookup(assume_source_server_cs5t);
            if (assume_source_server_connection != nullptr)
                return true;
            auto assume_source_not_server_connection = connection_table.lookup(assume_source_not_server_cs5t);
            if (assume_source_not_server_connection != nullptr)
                return false;

            // Below assumes that no connections for the response are in the connection table

            std::vector<Tuple::ClientServerFiveTuple> cs5ts = {assume_source_server_cs5t, assume_source_not_server_cs5t};
            auto *connections = connection_table.all();
            auto idk = connections->size();
            for (auto *conn : *connections)
            {
                for (const auto& cs5t : cs5ts)
                {
                    auto &response_cs5t = cs5t;
                    Tuple::ClientServerFiveTuple request_cs5t{};
                    request_cs5t.server_ip = response_cs5t.client_ip;
                    request_cs5t.client_ip = response_cs5t.server_ip;
                    request_cs5t.client_port = response_cs5t.server_port;
                    request_cs5t.protocol = response_cs5t.protocol;

                    if (    conn->server_ip() == request_cs5t.server_ip &&
                            conn->client_ip() == request_cs5t.client_ip &&
                            conn->client_port() == request_cs5t.client_port &&
                            conn->protocol() == request_cs5t.protocol )
                    {
                        request_connection = conn;
                        break;
                    }
                }

                if (request_connection != nullptr)
                    break;
            }
            delete connections;

            assert(request_connection != nullptr);

            source_is_server = ft.source_ip == request_connection->client_ip();
        }
    }
    else
    {
        assert(false);
    }
    return source_is_server;
}

// original / replay ft determined by bool: "original"
bool PcapReplayNetworkStack::is_source_server(const Tuple::FiveTuple& ft, bool original)
{
    if (!original)
        return is_source_server(ft);

    // ft is an original ft

    bool source_is_server;
    if (ft.protocol == IPPROTO_TCP)
    {
        bool sport_is_listening;
        bool dport_is_listening;
        if (convert_ip_address(ft.source_ip, true) == netdev.ip_address)
        {
            // we are the source
            std::pair<std::string, uint16_t> destination_addr(ft.destination_ip, ft.destination_port);
            sport_is_listening = std::find(listening_tcp_ports.begin(), listening_tcp_ports.end(), ft.source_port) != listening_tcp_ports.end();
            dport_is_listening = std::find(remote_listening_tcp_ports.begin(), remote_listening_tcp_ports.end(), destination_addr) != remote_listening_tcp_ports.end();

            source_is_server = sport_is_listening;
        }
        else if (convert_ip_address(ft.destination_ip, true) == netdev.ip_address)
        {
            // we are the destination
            std::pair<std::string, uint16_t> source_addr(ft.source_ip, ft.source_port);
            dport_is_listening = std::find(listening_tcp_ports.begin(), listening_tcp_ports.end(), ft.destination_port) != listening_tcp_ports.end();
            sport_is_listening = std::find(remote_listening_udp_ports.begin(), remote_listening_udp_ports.end(), source_addr) != remote_listening_udp_ports.end();

            source_is_server = !dport_is_listening;
        }
        else
        {
            assert(false);
        }
    }
    else if (ft.protocol == IPPROTO_UDP)
    {
        bool sport_is_listening;
        bool dport_is_listening;
        bool sport_is_listening_client_port;
        bool dport_is_listening_client_port;
        if (convert_ip_address(ft.source_ip, true) == netdev.ip_address)
        {
            // we are the source
            std::pair<std::string, uint16_t> destination_addr(ft.destination_ip, ft.destination_port);
            sport_is_listening = std::find(listening_udp_ports.begin(), listening_udp_ports.end(), ft.source_port) != listening_udp_ports.end();
            dport_is_listening = std::find(remote_listening_udp_ports.begin(), remote_listening_udp_ports.end(), destination_addr) != remote_listening_udp_ports.end();
            sport_is_listening_client_port = std::find(listening_udp_client_ports.begin(), listening_udp_client_ports.end(), ft.source_port) != listening_udp_client_ports.end();
             dport_is_listening_client_port = std::find(remote_listening_udp_client_ports.begin(), remote_listening_udp_client_ports.end(), destination_addr) != remote_listening_udp_client_ports.end();
        }
        else if (convert_ip_address(ft.destination_ip, true) == netdev.ip_address)
        {
            // we are the destination
            std::pair<std::string, uint16_t> source_addr(ft.source_ip, ft.source_port);
            dport_is_listening = std::find(listening_udp_ports.begin(), listening_udp_ports.end(), ft.destination_port) != listening_udp_ports.end();
            sport_is_listening = std::find(remote_listening_udp_ports.begin(), remote_listening_udp_ports.end(), source_addr) != remote_listening_udp_ports.end();
            dport_is_listening_client_port = std::find(listening_udp_client_ports.begin(), listening_udp_client_ports.end(), ft.destination_port) != listening_udp_client_ports.end();
            sport_is_listening_client_port = std::find(remote_listening_udp_client_ports.begin(), remote_listening_udp_client_ports.end(), source_addr) != remote_listening_udp_client_ports.end();
        }
        else
        {
            assert(false);
        }
        if (sport_is_listening || dport_is_listening)
        {
            source_is_server = sport_is_listening || !(dport_is_listening);
        }
        else
        {
            // are any one of these better than the others?
            source_is_server = sport_is_listening_client_port;
//                source_is_server = sport_is_listening_client_port && !(dport_is_listening_client_port);
//                source_is_server = sport_is_listening_client_port || !(dport_is_listening_client_port);
        }
    }
    else
    {
        assert(false);
    }
    return source_is_server;
}

Tuple::ClientServerFiveTuple PcapReplayNetworkStack::FiveTuple_to_ClientServerFiveTuple(const Tuple::FiveTuple& ft, bool original)
{
    bool source_is_server = is_source_server(ft, original);
    return Tuple::FiveTuple_to_ClientServerFiveTuple(ft, source_is_server);
}

Tuple::ClientServerFourTuple PcapReplayNetworkStack::convert_ClientServerFourTuple(Tuple::ClientServerFourTuple cs4t, bool original)
{
    cs4t.client_ip = convert_ip_address(cs4t.client_ip, original);
    cs4t.server_ip = convert_ip_address(cs4t.server_ip, original);
    return cs4t;
}

// Returns nullptr if the corresponding connection does not exist
Connection * PcapReplayNetworkStack::convert_Connection_to_complete_original(Connection *connection, bool original)
{
    try
    {
        return convert_connection_to_complete_cache.at(connection);
    }
    catch (const std::out_of_range& oor)
    {}

    Connection * result = nullptr;

    switch (config.connection_conversion_method)
    {
        case PcapReplayNetworkStackConfig::FourTuple:
        {
            if (original)
            {
                result = complete_original_connection_table.lookup(connection->client_server_five_tuple());
            }
            else
            {
                int index = connection_table.lookup_index(*connection);
                assert(index != -1);
                Tuple::ClientServerFourTuple cs4t = Tuple::ClientServerFourTuple{connection->client_ip(), connection->server_ip(), connection->server_port(), connection->protocol()};
                Tuple::ClientServerFourTuple original_cs4t = convert_ClientServerFourTuple(cs4t, original);

                // mapping ports for UDP:TFTP is complicated
                Connection *replayed_request_connection = convert_connection_to_request_connection(connection, connection_table);
                if (replayed_request_connection != nullptr && replayed_request_connection != connection)
                {
                    Connection *original_request_connection = convert_Connection(replayed_request_connection, false);
                    if (original_request_connection == nullptr) // if the request doesn't exist yet then the connection we want to convert to would also not exist yet
                        return nullptr;
                    original_cs4t.server_port = original_request_connection->client_port();
                }

                result = complete_original_connection_table.lookup(original_cs4t, index);
            }
            break;
        }
        case PcapReplayNetworkStackConfig::FiveTuple:
        {
            if (original)
            {
                result = complete_original_connection_table.lookup(connection->client_server_five_tuple());
            }
            else
            {
                auto cs5t = connection->client_server_five_tuple();
                cs5t.server_ip = convert_ip_address(cs5t.server_ip, false);
                cs5t.client_ip = convert_ip_address(cs5t.client_ip, false);
                result = complete_original_connection_table.lookup(cs5t);
            }
            break;
        }
    }

    if (result != nullptr)
        convert_connection_to_complete_cache.emplace(connection, result);
    return result;
}

// Returns nullptr if the corresponding connection does not exist
Connection * PcapReplayNetworkStack::convert_Connection(Connection *connection, bool original)
{
    try
    {
        return convert_connection_cache.at(connection);
    }
    catch (const std::out_of_range& oor)
    {}

    Connection * result = nullptr;

    switch (config.connection_conversion_method)
    {
        case PcapReplayNetworkStackConfig::FourTuple:
        {
            Connection *complete_original_connection = convert_Connection_to_complete_original(connection, original);
            if (complete_original_connection == nullptr)
            {
                result = nullptr;
            }
            else
            {
                if (original)
                {
                    int index = original_connection_table.lookup_index(*connection);
                    assert(index != -1);
                    std::unique_ptr<Tuple::ClientServerFourTuple> cs4t = Tuple::ClientServerFiveTuple_to_ClientServerFourTuple(connection->client_server_five_tuple());
                    Tuple::ClientServerFourTuple replayed_cs4t = convert_ClientServerFourTuple(*cs4t, original);

                    // mapping ports for UDP:TFTP is complicated
                    Connection *complete_original_request_connection = convert_connection_to_request_connection(complete_original_connection, complete_original_connection_table);
                    if (complete_original_request_connection != nullptr && complete_original_request_connection != complete_original_connection)
                    {
                        Connection *original_request_connection = original_connection_table.lookup(complete_original_request_connection->client_server_five_tuple());
                        assert(original_request_connection != nullptr);
                        Connection *replayed_request_connection = convert_Connection(original_request_connection, true);
                        if (replayed_request_connection == nullptr) // if the request doesn't exist yet then the connection we want to convert to would also not exist yet
                            return nullptr;
                        replayed_cs4t.server_port = replayed_request_connection->client_port();
                    }

                    result = connection_table.lookup(replayed_cs4t, index);
                }
                else
                {
                    result = original_connection_table.lookup(complete_original_connection->client_server_five_tuple());
                }
            }
            break;
        }
        case PcapReplayNetworkStackConfig::FiveTuple:
        {
            if (original)
            {
                auto cs5t = connection->client_server_five_tuple();
                cs5t.server_ip = convert_ip_address(cs5t.server_ip, true);
                cs5t.client_ip = convert_ip_address(cs5t.client_ip, true);
                result = connection_table.lookup(cs5t);
            }
            else
            {
                auto cs5t = connection->client_server_five_tuple();
                cs5t.server_ip = convert_ip_address(cs5t.server_ip, false);
                cs5t.client_ip = convert_ip_address(cs5t.client_ip, false);
                result = original_connection_table.lookup(cs5t);
            }
            break;
        }
    }

    if (result != nullptr)
        convert_connection_cache.emplace(connection, result);
    return result;
}

// "request" connection is the initial connection / stream that contains the read / write request for TFTP protocol. May be applicable for other UDP Application protocols
// Returns nullptr if the corresponding connection does not exist or if input connection is TCP
// Returns the input Connection * if the input Connection * is the request connection
Connection * PcapReplayNetworkStack::convert_connection_to_request_connection(Connection *connection, ConnectionTable &ct)
{
    assert(ct.lookup(connection->client_server_five_tuple()) != nullptr);

    if (connection->protocol() != IPPROTO_UDP)
        return nullptr;

    // Assumes that connection->server_port() is not reused (appears as client port in exactly 1 stream / "connection")
    Connection *request_connection = nullptr;
    Tuple::ClientServerFiveTuple request_cs5t;
    request_cs5t.client_ip = connection->server_ip();
    request_cs5t.client_port = connection->server_port();
    request_cs5t.server_ip = connection->client_ip();
    request_cs5t.protocol = IPPROTO_UDP;

    std::vector<Connection *> *connections = ct.all();
    for (auto *c : *connections)
    {
        if (    c->client_ip() == request_cs5t.client_ip &&
                c->client_port() == request_cs5t.client_port &&
                c->server_ip() == request_cs5t.server_ip &&
                c->protocol() == request_cs5t.protocol )
        {
            request_connection = c;
            break;
        }
    }
    delete connections;

    if (request_connection == nullptr)
        return connection;
    return request_connection;
}

// Lookups Application types from complete_original_connection_table set sets the Application types to connection
void PcapReplayNetworkStack::set_application_types(Connection *connection, bool original)
{
    Connection *complete_original_connection = convert_Connection_to_complete_original(connection, original);

    // Will need to change this when mapping from Application::Protocol to Application type is no longer 1 to 1
    switch (complete_original_connection->client_application().protocol())
    {
        case Application::UNKNOWN:
            break;
        case Application::HTTP:
            connection->set_client_application_type<HttpApplication>();
            break;
        case Application::DNS:
            connection->set_client_application_type<DnsApplication>();
            break;
        case Application::FTP:
            connection->set_client_application_type<FtpApplication>();
            break;
    }
    switch (complete_original_connection->client_application().protocol()) // assumption: server and client use the same Application protocol
    {
        case Application::UNKNOWN:
            break;
        case Application::HTTP:
            connection->set_server_application_type<HttpApplication>();
            break;
        case Application::DNS:
            connection->set_server_application_type<DnsApplication>();
            break;
        case Application::FTP:
            connection->set_server_application_type<FtpApplication>();
            break;
    }
}