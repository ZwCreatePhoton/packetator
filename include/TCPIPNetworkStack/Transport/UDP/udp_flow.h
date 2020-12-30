#include "TCPIPNetworkStack/Transport/flow.h"

#include <utility>

class UdpFlow final: public Flow
{
    public:
        explicit UdpFlow(Tuple::FiveTuple fiveTuple);

    public:
        void update(Tins::Packet &packet) final;
        [[nodiscard]] const std::vector<uint8_t> &local_payload() final { return _local_payload; };
        [[nodiscard]] const std::vector<uint8_t> &remote_payload() final { return _remote_payload; };

    public:
        [[nodiscard]] uint32_t local_datagram_count() { return _local_datagram_count; };
        [[nodiscard]] uint32_t remote_datagram_count() { return _remote_datagram_count; };

    private:
        std::vector<uint8_t> _local_payload{};
        std::vector<uint8_t> _remote_payload{};
        uint32_t _local_datagram_count = 0;
        uint32_t _remote_datagram_count = 0;
};