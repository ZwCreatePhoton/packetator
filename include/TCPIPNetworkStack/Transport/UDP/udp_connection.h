#include "TCPIPNetworkStack/Transport/connection.h"
#include "TCPIPNetworkStack/Transport/UDP/udp_flow.h"

class UdpConnection final : public Connection
{
    public:
        explicit UdpConnection(const Tuple::ClientServerFiveTuple& cs5t);

    public:
        [[nodiscard]] UdpFlow &client_flow() final { return _client_flow; };
        [[nodiscard]] UdpFlow &server_flow() final { return _server_flow; };

    private:
        UdpFlow _client_flow;
        UdpFlow _server_flow;
};
