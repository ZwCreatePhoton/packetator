#include <string>
#include <utility>

#include <tins/tins.h>

#include "TCPIPNetworkStack/Transport/tuple.h"

#pragma once

class Flow
{
    // Flow is responsible for creating the transport level context to the packets it receives
    // One such context is reassembled data. Another example is any state information
    protected:
        explicit Flow(Tuple::FiveTuple fiveTuple) : _five_tuple(std::move(fiveTuple)) {}

    public:
        virtual void update(Tins::Packet &packet) = 0;
        [[nodiscard]] virtual const std::vector<uint8_t> &local_payload() = 0;
        [[nodiscard]] virtual const std::vector<uint8_t> &remote_payload() = 0;
        [[nodiscard]] Tuple::FiveTuple five_tuple() const { return _five_tuple; };

    private:
        const Tuple::FiveTuple _five_tuple;
};