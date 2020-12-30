#include "TCPIPNetworkStack/Transport/connection.h"
#include "TCPIPNetworkStack/Transport/TCP/tcp_flow.h"

#pragma once

class TcpConnection final : public Connection
{
    public:
        explicit TcpConnection(const Tuple::ClientServerFiveTuple& cs5t);

    public:
        [[nodiscard]] TcpFlow &client_flow() final { return _client_flow; };
        [[nodiscard]] TcpFlow &server_flow() final { return _server_flow; };

    protected:
        void update_application(Tins::Packet &packet) final;

    private:
        TcpFlow _client_flow;
        TcpFlow _server_flow;
        static inline std::vector<uint8_t> empty_segment{};
        bool client_rx_closed = false;
        bool client_tx_closed = false;
        bool server_rx_closed = false;
        bool server_tx_closed = false;
};
