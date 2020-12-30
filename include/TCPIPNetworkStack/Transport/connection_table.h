#include <mutex>

#include "connection.h"

#pragma once

class ConnectionTable
{
    public:
        ConnectionTable();
        void add(Connection *connection);
        Connection * lookup(const Tuple::ClientServerFiveTuple& cs5t); // Look up connection by ClientServerFiveTuple
        Connection * lookup(const Tuple::ClientServerFourTuple& cs4t, int); // Look up connection by 4 tuple (client_ip, server_ip, server_port, protocol) + index for client_port (cs5t.client_port will have no affect)
        Connection * lookup(const Tuple::ClientServerFiveTuple& cs5t, int); // Look up connection by 4 tuple (client_ip, server_ip, server_port, protocol) + index for client_port (cs5t.client_port will have no affect)
        int lookup_index(Connection &connection); // Looks up the index (or -1 if connection not present in the table) to be used with "Connection * lookup(const ClientServerFiveTuple& cs5t, int);" / "Connection * lookup(const ClientServerFiveTuple& cs5t, int);"
        std::vector<Connection *> *all(); // user must free the returned pointer
        [[ nodiscard]] uint32_t size();
        void clear();
    private:
        std::mutex table_mtx;
        std::map<std::tuple<uint8_t, std::string, std::string>, std::shared_ptr<std::vector<Connection *>>> table{}; // {protocol, client ip, server ip} -> unique_ptr<vector<Connection *>>
        uint32_t _size = 0;
};
