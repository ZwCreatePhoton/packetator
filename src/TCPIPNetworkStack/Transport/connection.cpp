#include <iostream>
#include <utility>

#include <TCPIPNetworkStack/Transport/connection.h>
#include "TCPIPNetworkStack/Transport/tuple.h"
#include "utils.h"


Connection::Connection(Tuple::ClientServerFiveTuple cs5t) :
        _cs5t(std::move(cs5t)),
        _client_application(new Application(false)),
        _server_application(new Application(true))
{}

void Connection::update(Tins::Packet &packet)
{
    std::unique_ptr<Tuple::FiveTuple> p5t = Tuple::packet_to_FiveTuple(packet);
    // packet is for this connection
    if (    p5t != nullptr &&
            ((p5t->source_ip == server_ip() && p5t->destination_ip == client_ip() && p5t->source_port == server_port() && p5t->destination_port == client_port() && p5t->protocol == protocol()) ||
            ( p5t->source_ip == client_ip() && p5t->destination_ip == server_ip() && p5t->source_port == client_port() && p5t->destination_port == server_port() && p5t->protocol == protocol()) ))
    {
        _updates = true;
        client_flow().update(packet);
        server_flow().update(packet);
        if (enable_application_processing)
            update_application(packet);
    }
}

void Connection::update_application(Tins::Packet &packet)
{
    bool client_data_changed = client_payload().size() > client_payload_size_cache;
    bool server_data_changed = server_payload().size() > server_payload_size_cache;
    std::vector<uint8_t> new_client_data{};
    std::vector<uint8_t> new_server_data{};

    // get the new data, if any
    if (client_data_changed)
    {
        for (unsigned long i = client_payload_size_cache; i < client_payload().size(); i++)
            new_client_data.push_back(client_payload()[i]); // TODO: make this efficient
        client_payload_size_cache = client_payload().size();
    }
    if (server_data_changed)
    {
        for (unsigned long i = server_payload_size_cache; i < server_payload().size(); i++)
            new_server_data.push_back(server_payload()[i]); // TODO: make this more efficient
        server_payload_size_cache = server_payload().size();
    }

    // forward the new data, if any, to the applications
    if (client_data_changed)
    {
        if (debug_output)
        {
            std::cout << "[+]\tConnection: server = " << server_ip() << ", client = " << client_ip() << std::endl;
            std::cout << "[+]\tConnection: New client data:" << std::endl << std::string(new_client_data.begin(), new_client_data.end()) << std::endl;
        }
        client_application().update_tx(new_client_data);
        server_application().update_rx(new_client_data);
    }
    if (server_data_changed)
    {
        if (debug_output)
        {
            std::cout << "[+]\tConnection: server = " << server_ip() << ", client = " << client_ip() << std::endl;
            std::cout << "[+]\tConnection: New server data:" << std::endl << std::string(new_server_data.begin(), new_server_data.end()) << std::endl;
        }
        server_application().update_tx(new_server_data);
        client_application().update_rx(new_server_data);
    }
}

const std::vector<uint8_t> &Connection::client_payload()
{
    return client_flow().local_payload();
}

const std::vector<uint8_t> &Connection::server_payload()
{
    return server_flow().local_payload();
}

void Connection::disable_application_processing()
{
    enable_application_processing = false;
}

void Connection::clear_updates()
{
    _updates = false;
}

bool Connection::updates()
{
    return _updates;
}
