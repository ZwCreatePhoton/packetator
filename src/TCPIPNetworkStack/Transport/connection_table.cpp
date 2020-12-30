#include "TCPIPNetworkStack/Transport/connection_table.h"

#include <memory>
#include <iostream>

ConnectionTable::ConnectionTable()
{
}

void ConnectionTable::add(Connection *connection)
{
    std::lock_guard<std::mutex> lg(table_mtx);

    std::tuple<uint8_t, std::string, std::string> key = {connection->protocol(), connection->client_ip(), connection->server_ip()};

    auto sp = std::make_shared<std::vector<Connection *>>();
    auto result = table.emplace(key, sp);
    std::shared_ptr<std::vector<Connection *>> &connection_list = table.at(key);
    if(std::find(connection_list->begin(), connection_list->end(), connection) == connection_list->end()) // connection is not in table (table does not already contain that exact same pointer)
    {
        connection_list->push_back(connection);
        _size++;
    }
    // TODO: handle the case where same connection is already in table (different pointers with identical 5 tuples)
}

// TODO: refactor this method to return a unique_ptr
std::vector<Connection *> * ConnectionTable::all()
{
    std::lock_guard<std::mutex> lg(table_mtx);
    auto *connections = new std::vector<Connection *>();

    for (auto &entry: table)
    {
        auto &connections_list = entry.second;
        connections->insert(connections->end(), connections_list->begin(), connections_list->end());
    }

    return connections;
}

void ConnectionTable::clear()
{
    std::lock_guard<std::mutex> lg(table_mtx);
    table.clear();
}

Connection *ConnectionTable::lookup(const Tuple::ClientServerFiveTuple& cs5t)
{
    std::lock_guard<std::mutex> lg(table_mtx);

    try
    {
        std::shared_ptr<std::vector<Connection *>> &connection_list = table.at({cs5t.protocol, cs5t.client_ip, cs5t.server_ip});
        if (connection_list == nullptr)
            return nullptr;
        for (auto &connection : *connection_list)
        {
            if( connection->client_port() == cs5t.client_port &&
                connection->server_port() == cs5t.server_port )
            {
                return connection;
            }
        }
        return nullptr;
    }
    catch (const std::out_of_range& oor)
    {}
    return nullptr;
}

Connection *ConnectionTable::lookup(const Tuple::ClientServerFourTuple &cs4t, int index)
{
    std::lock_guard<std::mutex> lg(table_mtx);

    try
    {
        auto connections = std::vector<Connection *>{};
        std::shared_ptr<std::vector<Connection *>> &connection_list = table.at({cs4t.protocol, cs4t.client_ip, cs4t.server_ip});
        if (connection_list == nullptr)
            return nullptr;
        int count = 0;
        for (auto &connection : *connection_list)
        {
            if( connection->server_port() == cs4t.server_port )
            {
                count++;
                if (index + 1 == count)
                    return connection;
            }
        }
    }
    catch (const std::out_of_range& oor)
    {}
    return nullptr;
}

Connection *ConnectionTable::lookup(const Tuple::ClientServerFiveTuple &cs5t, int index)
{
    return lookup(*ClientServerFiveTuple_to_ClientServerFourTuple(cs5t), index);
}

int ConnectionTable::lookup_index(Connection &connection)
{
    std::lock_guard<std::mutex> lg(table_mtx);

    int index = -1;

    try
    {
        auto cs5t = connection.client_server_five_tuple();
        std::shared_ptr<std::vector<Connection *>> &connection_list = table.at({cs5t.protocol, cs5t.client_ip, cs5t.server_ip});
        if (connection_list == nullptr)
            return -1;
        for (auto &c : *connection_list)
        {
            if( c->server_port() == cs5t.server_port )
            {
                index++;
                if (c->client_port() == cs5t.client_port) return index;
            }
        }
        return -1;
    }
    catch (const std::out_of_range& oor)
    {}
    return -1;
}

uint32_t ConnectionTable::size()
{
    return _size;
}
