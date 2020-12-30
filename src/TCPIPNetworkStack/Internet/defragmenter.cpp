#include <utility>

#include "TCPIPNetworkStack/Internet/defragmenter.h"


Defragmenter::Defragmenter() = default;

void Defragmenter::ProcessPackets(std::vector<Tins::Packet> &packets)
{
    for( auto &packet : packets)
        ProcessPacket(packet);
}

void Defragmenter::SetCallback(std::function<void(Tins::Packet)> cb)
{
    this->callback = std::move(cb);
}

bool Defragmenter::isCallbackSet()
{
    return callback != nullptr;
}

uint64_t Defragmenter::packet_count()
{
    return _packet_count;
}

uint64_t Defragmenter::datagram_count()
{
    return _datagram_count;
}
